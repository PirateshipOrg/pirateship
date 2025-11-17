use std::{
    cell::RefCell,
    io::{Error, ErrorKind},
    sync::Arc,
};

use log::{debug, error, info, trace};
use prost::Message;
use tokio::sync::{oneshot, Mutex};

use crate::{
    config::AtomicConfig,
    consensus::block_tipcut::BlockOrTipCut,
    crypto::{CachedBlock, CryptoServiceConnector, FutureHash},
    proto::{
        consensus::{
            HalfSerializedBlock, HalfSerializedTipCut, ProtoAppendEntries, ProtoFork,
            ProtoTipCutFork,
        },
        rpc::ProtoPayload,
    },
    rpc::{client::PinnedClient, server::LatencyProfile, PinnedMessage, SenderType},
    utils::{
        channel::{Receiver, Sender},
        PerfCounter, StorageAck, StorageServiceConnector,
    },
};

#[cfg(feature = "evil")]
use crate::proto::execution::ProtoTransaction;

use super::{
    app::AppCommand,
    fork_receiver::{AppendEntriesStats, BroadcasterMessage, ForkReceiverCommand, MultipartFork},
    staging::Proposal,
};

#[cfg(feature = "dag")]
use crate::{crypto::CachedTipCut, proto::consensus::ProtoTipCut};

#[cfg(feature = "dag")]
use super::fork_receiver::MultipartTipCut;

pub enum BlockBroadcasterCommand {
    UpdateCI(u64),
    NextAEForkPrefix(Vec<oneshot::Receiver<Result<BlockOrTipCut, Error>>>),
    // NextAETipCutForkPrefix(Vec<oneshot::Receiver<Result<CachedTipCut, Error>>>),
    // #[cfg(feature = "dag")]
    // BroadcastTipCut(Vec<CachedTipCut>, u64, bool, u64), // (tipcut fork, view, view_is_stable, config_num)
}

pub struct BlockBroadcaster {
    config: AtomicConfig,
    crypto: CryptoServiceConnector,

    ci: u64,
    fork_prefix_buffer: Vec<BlockOrTipCut>,

    // Input ports
    my_block_rx: Receiver<(u64, oneshot::Receiver<BlockOrTipCut>)>,
    other_block_rx: Receiver<BroadcasterMessage>,
    control_command_rx: Receiver<BlockBroadcasterCommand>,

    // Output ports
    storage: StorageServiceConnector,
    client: PinnedClient,
    staging_tx: Sender<Proposal>,

    // Command ports
    fork_receiver_command_tx: Sender<ForkReceiverCommand>,
    app_command_tx: Sender<AppCommand>,

    // Perf Counters
    my_block_perf_counter: RefCell<PerfCounter<u64>>,

    // For evil purposes
    evil_last_hash: FutureHash,
}

impl BlockBroadcaster {
    pub fn new(
        config: AtomicConfig,
        client: PinnedClient,
        crypto: CryptoServiceConnector,
        my_block_rx: Receiver<(u64, oneshot::Receiver<BlockOrTipCut>)>,
        other_block_rx: Receiver<BroadcasterMessage>,
        control_command_rx: Receiver<BlockBroadcasterCommand>,
        storage: StorageServiceConnector,
        staging_tx: Sender<Proposal>,
        fork_receiver_command_tx: Sender<ForkReceiverCommand>,
        app_command_tx: Sender<AppCommand>,
    ) -> Self {
        let my_block_event_order = vec![
            "Retrieve prepared block",
            "Store block",
            "Forward block to logserver",
            "Forward block to staging",
            "Serialize",
            "Forward block to other nodes",
        ];

        let my_block_perf_counter = RefCell::new(PerfCounter::new(
            "BlockBroadcasterMyBlock",
            &my_block_event_order,
        ));

        Self {
            config,
            crypto,
            ci: 0,
            fork_prefix_buffer: Vec::new(),
            my_block_rx,
            other_block_rx,
            control_command_rx,
            storage,
            client,
            staging_tx,
            fork_receiver_command_tx,
            app_command_tx,
            my_block_perf_counter,
            evil_last_hash: FutureHash::None,
        }
    }

    pub async fn run(block_broadcaster: Arc<Mutex<Self>>) {
        let mut block_broadcaster = block_broadcaster.lock().await;

        let mut total_work = 0;
        loop {
            if let Err(_e) = block_broadcaster.worker().await {
                break;
            }

            total_work += 1;
            if total_work % 1000 == 0 {
                block_broadcaster
                    .my_block_perf_counter
                    .borrow()
                    .log_aggregate();
            }
        }

        info!("Broadcasting worker exited.");
    }

    fn perf_register(&mut self, entry: u64) {
        #[cfg(feature = "perf")]
        self.my_block_perf_counter
            .borrow_mut()
            .register_new_entry(entry);
    }

    fn perf_add_event(&mut self, entry: u64, event: &str) {
        #[cfg(feature = "perf")]
        self.my_block_perf_counter
            .borrow_mut()
            .new_event(event, &entry);
    }

    fn perf_deregister(&mut self, entry: u64) {
        #[cfg(feature = "perf")]
        self.my_block_perf_counter
            .borrow_mut()
            .deregister_entry(&entry);
    }

    async fn worker(&mut self) -> Result<(), Error> {
        // This worker doesn't care about views and configs.
        // Its only job is to store and forward.
        // If it is my block, forward to {all other nodes, logserver and staging}.
        // It it is not my block, forward to {logserver and staging}.

        // Invariant: Anything that outputs from Block broadcaster is stored on disk.

        // Logserver and staging will take care of hash-chaining logic and everything else.
        tokio::select! {
            block = self.my_block_rx.recv() => {
                if block.is_none() {
                    return Err(Error::new(ErrorKind::BrokenPipe, "my_block_rx channel closed"));
                }
                let block = block.unwrap();
                let __n = block.0;
                // info!("Expecting {}", __n);

                let perf_entry = block.0;
                self.perf_register(perf_entry);
                let block = block.1.await;
                self.perf_add_event(perf_entry, "Retrieve prepared block");
                if block.is_err() {
                    error!("Failed to get block {} {:?}", __n, block);
                    return Ok(());
                }
                self.process_my_entry(block.unwrap()).await?;

                trace!("Processed block {}", __n);
            },

            msg = self.other_block_rx.recv() => {
                if msg.is_none() {
                    return Err(Error::new(ErrorKind::BrokenPipe, "other_block_rx channel closed"));
                }
                match msg.unwrap() {
                    BroadcasterMessage::Fork(fork) => {
                        #[cfg(not(feature = "dag"))]
                        self.process_other_entry(fork).await?;
                    }
                    #[cfg(feature = "dag")]
                    BroadcasterMessage::TipCut(tipcut) => {
                        self.process_other_entry(tipcut).await?;
                    }
                }
            },

            cmd = self.control_command_rx.recv() => {
                if cmd.is_none() {
                    return Err(Error::new(ErrorKind::BrokenPipe, "control_command_rx channel closed"));
                }
                // info!("Processing control command");
                self.handle_control_command(cmd.unwrap()).await?;
                // info!("Processed control command");
            }
        }

        Ok(())
    }

    fn get_everyone_except_me(&self) -> Vec<String> {
        let config = self.config.get();
        let me = &config.net_config.name;
        let mut node_list = config
            .consensus_config
            .node_list
            .iter()
            .filter(|e| *e != me)
            .map(|e| e.clone())
            .collect::<Vec<_>>();

        node_list.extend(
            config
                .consensus_config
                .learner_list
                .iter()
                .map(|e| e.clone()),
        );

        node_list
    }

    async fn handle_control_command(&mut self, cmd: BlockBroadcasterCommand) -> Result<(), Error> {
        match cmd {
            BlockBroadcasterCommand::UpdateCI(ci) => self.ci = ci,
            BlockBroadcasterCommand::NextAEForkPrefix(blocks) => {
                for block in blocks {
                    let block = block.await.unwrap().expect("Failed to get block");
                    self.fork_prefix_buffer.push(block);
                }
            }
        }

        Ok(())
    }

    async fn store_and_forward_internally(
        &mut self,
        entry: &BlockOrTipCut,
        ae_stats: AppendEntriesStats,
        this_is_final_block: bool,
    ) -> Result<(), Error> {
        let perf_entry = entry.n();

        // Store
        let storage_ack = match entry {
            BlockOrTipCut::Block(block) => self.storage.put_block(block).await,
            #[cfg(feature = "dag")]
            BlockOrTipCut::TipCut(tipcut) => self.storage.put_tipcut(tipcut).await,
        };
        self.perf_add_event(perf_entry, "Store block/tipcut");
        // info!("Stored {}", block.block.n);

        // Forward
        self.perf_add_event(perf_entry, "Forward block/tipcut to logserver");

        // info!("Sending {}", block.block.n);
        self.staging_tx
            .send(Proposal {
                entry: entry.clone(),
                storage_ack,
                ae_stats,
                this_is_final: this_is_final_block,
            })
            .await
            .unwrap();
        #[cfg(not(feature = "dag"))]
        // info!("Sent {}", block.block.n);
        self.perf_add_event(perf_entry, "Forward block/tipcut to staging");

        Ok(())
    }

    async fn process_my_entry(&mut self, entry: BlockOrTipCut) -> Result<(), Error> {
        debug!("Processing {}", entry.n());
        let perf_entry = entry.n();

        let (view, view_is_stable, config_num) =
            (entry.view(), entry.view_is_stable(), entry.config_num());

        // Leader-based: Build fork from prefix buffer + new block/tipcut
        let mut ae_fork = Vec::new();

        for e in self.fork_prefix_buffer.drain(..) {
            ae_fork.push(e);
        }
        ae_fork.push(entry.clone());

        if ae_fork.len() > 1 {
            trace!("AE: {:?}", ae_fork);
        }

        let _fork_size = ae_fork.len();
        let mut cnt = 0;
        for e in &ae_fork {
            cnt += 1;
            let this_is_final = cnt == _fork_size;
            self.store_and_forward_internally(
                &e,
                AppendEntriesStats {
                    view,
                    view_is_stable: e.view_is_stable(),
                    config_num,
                    sender: self.config.get().net_config.name.clone(),
                    ci: self.ci,
                },
                this_is_final,
            )
            .await?;
        }

        #[cfg(not(feature = "dag"))]
        if let BlockOrTipCut::Block(b) = entry {
            self.app_command_tx
                .send(AppCommand::NewRequestBatch(
                    b.n(),
                    view,
                    view_is_stable,
                    true,
                    b.tx_list.len(),
                    b.block_hash.clone(),
                ))
                .await
                .unwrap();
        }

        // Forward to other nodes. Involves copies and serialization so done last.
        let names = self.get_everyone_except_me();

        #[cfg(feature = "evil")]
        let names = self
            .maybe_act_evil(names, &ae_fork, view, view_is_stable, config_num)
            .await;

        self.broadcast_ae_fork(
            names,
            ae_fork,
            view,
            view_is_stable,
            config_num,
            Some(perf_entry),
        )
        .await;

        Ok(())
    }

    // async fn process_my_block(&mut self, block: CachedBlock) -> Result<(), Error> {
    //     debug!("Processing {}", block.block.n);
    //     let perf_entry = block.block.n;

    //     let (view, view_is_stable, config_num) = (
    //         block.block.view,
    //         block.block.view_is_stable,
    //         block.block.config_num,
    //     );

    //     // Leader-based: Build fork from prefix buffer + new block
    //     let mut ae_fork = Vec::new();

    //     for block in self.fork_prefix_buffer.drain(..) {
    //         ae_fork.push(block);
    //     }
    //     ae_fork.push(block.clone());

    //     if ae_fork.len() > 1 {
    //         trace!("AE: {:?}", ae_fork);
    //     }

    //     let _fork_size = ae_fork.len();
    //     let mut cnt = 0;
    //     for block in &ae_fork {
    //         cnt += 1;
    //         let this_is_final_block = cnt == _fork_size;
    //         self.store_and_forward_internally(
    //             &block,
    //             AppendEntriesStats {
    //                 view,
    //                 view_is_stable: block.block.view_is_stable,
    //                 config_num,
    //                 sender: self.config.get().net_config.name.clone(),
    //                 ci: self.ci,
    //             },
    //             this_is_final_block,
    //         )
    //         .await?;
    //     }

    //     // Forward to app for stats.
    //     self.app_command_tx
    //         .send(AppCommand::NewRequestBatch(
    //             block.block.n,
    //             view,
    //             view_is_stable,
    //             true,
    //             block.block.tx_list.len(),
    //             block.block_hash.clone(),
    //         ))
    //         .await
    //         .unwrap();

    //     // Forward to other nodes. Involves copies and serialization so done last.
    //     let names = self.get_everyone_except_me();

    //     #[cfg(feature = "evil")]
    //     let names = self
    //         .maybe_act_evil(names, &ae_fork, view, view_is_stable, config_num)
    //         .await;

    //     self.broadcast_ae_fork(
    //         names,
    //         ae_fork,
    //         view,
    //         view_is_stable,
    //         config_num,
    //         Some(perf_entry),
    //     )
    //     .await;

    //     Ok(())
    // }

    fn get_byzantine_broadcast_threshold(&self) -> usize {
        let config = self.config.get();
        let node_list_len = config.consensus_config.node_list.len();

        #[cfg(feature = "no_qc")]
        {
            let f = node_list_len / 2;
            return f;
        }

        #[cfg(feature = "platforms")]
        {
            if node_list_len <= config.consensus_config.liveness_u as usize {
                return 0;
            }
            let byzantine_threshold = node_list_len - config.consensus_config.liveness_u as usize;
            return byzantine_threshold - 1;
        }

        let f = node_list_len / 3;
        return 2 * f;
    }

    async fn process_other_entry(
        &mut self,
        #[cfg(not(feature = "dag"))] mut entries: MultipartFork,
        #[cfg(feature = "dag")] mut entries: MultipartTipCut,
    ) -> Result<(), Error> {
        let _entries = entries.await_all().await;
        // info!("Await all finished!");
        let num_parts = entries.remaining_parts;

        for entry in &_entries {
            if let Err(e) = entry {
                error!(
                    "This multipart fork is corrupted, I have no use for the remaining parts. {:?}",
                    e
                );
                let _ = self
                    .fork_receiver_command_tx
                    .send(ForkReceiverCommand::MultipartNack(num_parts))
                    .await;

                return Ok(());
            }
        }

        let (view, view_is_stable) = (entries.ae_stats.view, entries.ae_stats.view_is_stable);
        let _fork_size = _entries.len();
        let mut cnt = 0;
        for entry in _entries {
            cnt += 1;
            let this_is_final = cnt == _fork_size;

            #[cfg(not(feature = "dag"))]
            let entry = BlockOrTipCut::Block(entry.unwrap());
            #[cfg(feature = "dag")]
            let entry = BlockOrTipCut::TipCut(entry.unwrap());

            // info!("Processing {}", block.block.n);
            self.store_and_forward_internally(&entry, entries.ae_stats.clone(), this_is_final)
                .await?;

            // FIXME: Update for tipcuts
            // Forward to app for stats.
            // self.app_command_tx
            //     .send(AppCommand::NewRequestBatch(
            //         block.block.n,
            //         view,
            //         view_is_stable,
            //         false,
            //         block.block.tx_list.len(),
            //         block.block_hash.clone(),
            //     ))
            //     .await
            // .unwrap();
        }

        Ok(())
    }

    // #[cfg(feature = "dag")]
    // async fn process_other_tipcut(&mut self, tipcut: MultipartTipCut) -> Result<(), Error> {
    //     info!(
    //         "Processing TipCut with {} CARs from {} for view {} (ci={})",
    //         tipcut.tipcut.tipcut.tips.len(),
    //         tipcut.ae_stats.sender,
    //         tipcut.ae_stats.view,
    //         tipcut.ae_stats.ci
    //     );

    //     // Forward tip cut to staging for consensus voting
    //     // Staging will decide whether to vote for this tip cut
    //     self.staging_tx
    //         .send(StagingMessage::TipCut(TipCutProposal {
    //             tipcut: tipcut.tipcut,
    //             ae_stats: tipcut.ae_stats,
    //         }))
    //         .await
    //         .unwrap();

    //     debug!("Forwarded tip cut to staging for voting");

    //     Ok(())
    // }

    // /// Process and broadcast our own tip cut proposal (DAG mode only)
    // /// This is called when the local node (as leader) proposes a tip cut for consensus
    // #[cfg(feature = "dag")]
    // async fn process_my_tipcut(
    //     &mut self,
    //     tipcut_fork: Vec<CachedTipCut>,
    //     view: u64,
    //     view_is_stable: bool,
    //     config_num: u64,
    // ) -> Result<(), Error> {
    //     let total = tipcut_fork.len();
    //     info!(
    //         "Broadcasting my TipCutFork with {} tip cuts for view {} (ci={})",
    //         total, view, self.ci
    //     );

    //     // Forward each tip cut to staging (vote on last or all depending on staging policy)
    //     for tc in tipcut_fork.iter() {
    //         self.staging_tx
    //             .send(StagingMessage::TipCut(TipCutProposal {
    //                 tipcut: tc.clone(),
    //                 ae_stats: AppendEntriesStats {
    //                     view,
    //                     view_is_stable,
    //                     config_num,
    //                     sender: self.config.get().net_config.name.clone(),
    //                     ci: self.ci,
    //                 },
    //             }))
    //             .await
    //             .unwrap();
    //     }
    //     debug!("Forwarded my tip cut fork ({} cuts) to staging", total);

    //     // Broadcast entire fork
    //     let names = self.get_everyone_except_me();
    //     self.broadcast_ae_tipcut(names, tipcut_fork, view, view_is_stable, config_num)
    //         .await;
    //     Ok(())
    // }

    // FIXME: Update for tipcuts
    async fn maybe_act_evil(
        &mut self,
        names: Vec<String>,
        ae_fork: &Vec<CachedBlock>,
        view: u64,
        view_is_stable: bool,
        config_num: u64,
    ) -> Vec<String> {
        #[cfg(not(feature = "evil"))]
        return names;

        #[cfg(feature = "evil")]
        {
            let (should_be_evil, byz_start_block) = {
                let config = &self.config.get();
                let am_i_first_leader =
                    config.consensus_config.node_list[0] == config.net_config.name;

                let byz_start_block = config.evil_config.byzantine_start_block;
                let be_evil = config.evil_config.simulate_byzantine_behavior;

                (am_i_first_leader && be_evil, byz_start_block)
            };

            if !should_be_evil {
                return names;
            }

            if ae_fork.last().unwrap().block.n < byz_start_block {
                return names;
            }

            if let FutureHash::None = self.evil_last_hash {
                self.evil_last_hash =
                    FutureHash::Immediate(ae_fork.last().unwrap().block.parent.clone());
                info!(
                    "Equivocation starting on {}",
                    ae_fork.last().unwrap().block.n
                );
            }

            let parent_hash_rx = self.evil_last_hash.take();
            let must_sign = match &ae_fork.last().unwrap().block.sig {
                Some(crate::proto::consensus::proto_block::Sig::ProposerSig(_)) => true,
                _ => false,
            };

            let mut ae_fork = ae_fork.clone();
            let block = ae_fork.pop().unwrap();
            let mut block = block.block.clone();

            block.tx_list.push(ProtoTransaction {
                on_receive: None,
                on_crash_commit: None,
                on_byzantine_commit: None,
                is_reconfiguration: false,
                is_2pc: false,
            });

            trace!("Equivocating on block seq num {}", block.n);

            let (block, hash_rx, _hash_rx_2) = self
                .crypto
                .prepare_block(block, must_sign, parent_hash_rx)
                .await;
            self.evil_last_hash = FutureHash::Future(hash_rx);

            let block = block.await.unwrap();
            ae_fork.push(block);

            let partition_1_size = names.len() / 2;

            let (partition1, partition2) = names.split_at(partition_1_size);
            trace!(
                "Partition 1: {:?}, Partition 2: {:?}",
                partition1,
                partition2
            );

            self.broadcast_ae_fork(
                partition2.to_vec(),
                ae_fork,
                view,
                view_is_stable,
                config_num,
                None,
            )
            .await;

            // Equivocation logic: Add 1 extra dummy tx to the end of the last block.

            partition1.to_vec()
        }
    }

    async fn broadcast_ae_fork(
        &mut self,
        names: Vec<String>,
        mut ae_fork: Vec<BlockOrTipCut>,
        view: u64,
        view_is_stable: bool,
        config_num: u64,
        perf_entry: Option<u64>,
    ) {
        let (should_perf, perf_entry) = match perf_entry {
            Some(e) => (true, e),
            None => (false, 0),
        };

        #[cfg(not(feature = "dag"))]
        let append_entry = ProtoAppendEntries {
            entry: Some(crate::proto::consensus::proto_append_entries::Entry::Fork(
                ProtoFork {
                    serialized_blocks: ae_fork
                        .drain(..)
                        .map(|block| HalfSerializedBlock {
                            n: block.n(),
                            view: block.view(),
                            view_is_stable: block.view_is_stable(),
                            config_num: block.config_num(),
                            serialized_body: block.ser(),
                        })
                        .collect(),
                },
            )),
            commit_index: self.ci,
            view,
            view_is_stable,
            config_num,
            is_backfill_response: false,
        };
        #[cfg(feature = "dag")]
        let append_entry = ProtoAppendEntries {
            entry: Some(
                crate::proto::consensus::proto_append_entries::Entry::TipcutFork(ProtoTipCutFork {
                    serialized_tipcuts: ae_fork
                        .drain(..)
                        .map(|tipcut| HalfSerializedTipCut {
                            n: tipcut.n(),
                            view: tipcut.view(),
                            view_is_stable: tipcut.view_is_stable(),
                            config_num: tipcut.config_num(),
                            serialized_body: tipcut.ser(),
                        })
                        .collect(),
                }),
            ),
            commit_index: self.ci,
            view,
            view_is_stable,
            config_num,
            is_backfill_response: false,
        };

        // let data = bitcode::encode(&append_entry);
        let rpc = ProtoPayload {
            message: Some(crate::proto::rpc::proto_payload::Message::AppendEntries(
                append_entry,
            )),
        };
        let data = rpc.encode_to_vec();

        if should_perf {
            self.perf_add_event(perf_entry, "Serialize");
        }

        let sz = data.len();
        if !view_is_stable {
            info!("AE size: {} Broadcasting to {:?}", sz, names);
        }
        let data = PinnedMessage::from(data, sz, SenderType::Anon);
        let mut profile = LatencyProfile::new();
        let _res = PinnedClient::broadcast(
            &self.client,
            &names,
            &data,
            &mut profile,
            self.get_byzantine_broadcast_threshold(),
        )
        .await;

        if should_perf {
            self.perf_add_event(perf_entry, "Forward block to other nodes");
            self.perf_deregister(perf_entry);
        }
    }
}
