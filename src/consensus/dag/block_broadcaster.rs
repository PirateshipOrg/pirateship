/// DAG Block Broadcaster
///
/// This component handles the dissemination layer for DAG-based consensus.
/// Unlike the consensus-layer block_broadcaster, this component:
/// - Broadcasts individual blocks via AppendBlock messages
/// - Does NOT handle tip cut proposals (those go through consensus layer)
/// - Works with BlockReceiver for block validation and storage
/// - Operates independently of traditional fork-based consensus
///
/// Architecture:
/// ```
/// Worker Proposes Block
///     ↓
/// DAG BlockBroadcaster stores & broadcasts via AppendBlock
///     ↓
/// BlockReceiver validates & stores
///     ↓
/// LaneStaging acknowledges blocks, forms CARs
/// ```
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
    crypto::{CachedBlock, CryptoServiceConnector},
    proto::{
        consensus::{HalfSerializedBlock, ProtoAppendBlocks},
        rpc::ProtoPayload,
    },
    rpc::{client::PinnedClient, server::LatencyProfile, PinnedMessage, SenderType},
    utils::{
        channel::{Receiver, Sender},
        PerfCounter, StorageAck, StorageServiceConnector,
    },
};

use super::{
    super::app::AppCommand,
    block_receiver::{AppendBlockStats, BlockReceiverCommand, SingleBlock},
};

pub enum DagBlockBroadcasterCommand {
    UpdateCI(u64),
    /// Provide a lane prefix to be batched with the next locally proposed block
    /// Mirrors traditional broadcaster's NextAEForkPrefix behavior
    NextAppendBlocksPrefix(Vec<oneshot::Receiver<Result<CachedBlock, Error>>>),
}

pub struct DagBlockBroadcaster {
    config: AtomicConfig,
    crypto: CryptoServiceConnector,

    ci: u64,

    // Accumulates a lane prefix to batch with the next proposed block
    lane_prefix_buffer: Vec<CachedBlock>,

    // Input ports
    my_block_rx: Receiver<(u64, oneshot::Receiver<CachedBlock>)>,
    other_block_rx: Receiver<SingleBlock>,
    control_command_rx: Receiver<DagBlockBroadcasterCommand>,

    // Output ports
    storage: StorageServiceConnector,
    client: PinnedClient,
    lane_staging_tx: Sender<(
        CachedBlock,
        oneshot::Receiver<StorageAck>,
        AppendBlockStats,
        bool, /* this_is_final_block */
    )>,

    // Command ports
    block_receiver_command_tx: Sender<BlockReceiverCommand>,
    app_command_tx: Sender<AppCommand>,

    // Perf Counters
    my_block_perf_counter: RefCell<PerfCounter<u64>>,
}

impl DagBlockBroadcaster {
    pub fn new(
        config: AtomicConfig,
        client: PinnedClient,
        crypto: CryptoServiceConnector,
        my_block_rx: Receiver<(u64, oneshot::Receiver<CachedBlock>)>,
        other_block_rx: Receiver<SingleBlock>,
        control_command_rx: Receiver<DagBlockBroadcasterCommand>,
        storage: StorageServiceConnector,
        lane_staging_tx: Sender<(
            CachedBlock,
            oneshot::Receiver<StorageAck>,
            AppendBlockStats,
            bool,
        )>,
        block_receiver_command_tx: Sender<BlockReceiverCommand>,
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
            "DagBlockBroadcasterMyBlock",
            &my_block_event_order,
        ));

        Self {
            config,
            crypto,
            ci: 0,
            lane_prefix_buffer: Vec::new(),
            my_block_rx,
            other_block_rx,
            control_command_rx,
            storage,
            client,
            lane_staging_tx,
            block_receiver_command_tx,
            app_command_tx,
            my_block_perf_counter,
        }
    }

    pub async fn run(broadcaster: Arc<Mutex<Self>>) {
        let mut broadcaster = broadcaster.lock().await;

        let mut total_work = 0;
        loop {
            if let Err(_e) = broadcaster.worker().await {
                break;
            }

            total_work += 1;
            if total_work % 1000 == 0 {
                broadcaster.my_block_perf_counter.borrow().log_aggregate();
            }
        }

        info!("DAG Block Broadcaster worker exited.");
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
        // DAG dissemination layer worker
        // Handles individual block storage and broadcasting
        // Does NOT handle consensus proposals (forks/tipcuts)

        tokio::select! {
            block = self.my_block_rx.recv() => {
                if block.is_none() {
                    return Err(Error::new(ErrorKind::BrokenPipe, "my_block_rx channel closed"));
                }
                let block = block.unwrap();
                let __n = block.0;

                let perf_entry = block.0;
                self.perf_register(perf_entry);
                let block = block.1.await;
                self.perf_add_event(perf_entry, "Retrieve prepared block");
                if block.is_err() {
                    error!("Failed to get block {} {:?}", __n, block);
                    return Ok(());
                }
                self.process_my_block(block.unwrap()).await?;

                trace!("Processed block {}", __n);
            },

            block_vec = self.other_block_rx.recv() => {
                if block_vec.is_none() {
                    return Err(Error::new(ErrorKind::BrokenPipe, "other_block_rx channel closed"));
                }
                let blocks = block_vec.unwrap();
                self.process_other_single_block(blocks).await?;
            },

            cmd = self.control_command_rx.recv() => {
                if cmd.is_none() {
                    return Err(Error::new(ErrorKind::BrokenPipe, "control_command_rx channel closed"));
                }
                self.handle_control_command(cmd.unwrap()).await?;
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

    async fn handle_control_command(
        &mut self,
        cmd: DagBlockBroadcasterCommand,
    ) -> Result<(), Error> {
        match cmd {
            DagBlockBroadcasterCommand::UpdateCI(ci) => self.ci = ci,
            DagBlockBroadcasterCommand::NextAppendBlocksPrefix(blocks) => {
                for block_rx in blocks {
                    let block = block_rx.await.unwrap().expect("Failed to get block");
                    self.lane_prefix_buffer.push(block);
                }
            }
        }

        Ok(())
    }

    async fn store_and_forward_internally(
        &mut self,
        block: &CachedBlock,
        block_stats: AppendBlockStats,
        this_is_final_block: bool,
    ) -> Result<(), Error> {
        let perf_entry = block.block.n;

        // Store
        let storage_ack = self.storage.put_block(block).await;
        self.perf_add_event(perf_entry, "Store block");

        // Forward to staging (which is actually LaneStaging in DAG mode)
        self.perf_add_event(perf_entry, "Forward block to logserver");

        self.lane_staging_tx
            .send((block.clone(), storage_ack, block_stats, this_is_final_block))
            .await
            .unwrap();

        self.perf_add_event(perf_entry, "Forward block to staging");

        Ok(())
    }

    async fn process_my_block(&mut self, block: CachedBlock) -> Result<(), Error> {
        debug!("Processing my block {}", block.block.n);
        let perf_entry = block.block.n;

        let (view, view_is_stable, config_num) = (
            block.block.view,
            block.block.view_is_stable,
            block.block.config_num,
        );

        // Use own name as lane identifier
        let lane_id = self.config.get().net_config.name.clone();

        // Build a batched lane: prefix buffer + new block (mirrors traditional fork batching)
        let mut lane_batch: Vec<CachedBlock> = Vec::new();
        for b in self.lane_prefix_buffer.drain(..) {
            lane_batch.push(b);
        }
        lane_batch.push(block.clone());

        // Store and forward each block internally; mark only the last as final
        let total = lane_batch.len();
        for (idx, blk) in lane_batch.iter().enumerate() {
            let is_last = idx + 1 == total;
            self.store_and_forward_internally(
                blk,
                AppendBlockStats {
                    view,
                    view_is_stable: blk.block.view_is_stable,
                    config_num,
                    sender: self.config.get().net_config.name.clone(),
                    ci: self.ci,
                    lane_id: lane_id.clone(),
                },
                is_last,
            )
            .await?;
        }

        // Broadcast batched blocks to all other nodes in a single AppendBlocks message
        let names = self.get_everyone_except_me();
        self.broadcast_blocks(
            names,
            lane_batch,
            view,
            view_is_stable,
            config_num,
            Some(perf_entry),
        )
        .await;

        // Notify app for stats
        self.app_command_tx
            .send(AppCommand::NewRequestBatch(
                block.block.n,
                view,
                view_is_stable,
                true, // My block
                block.block.tx_list.len(),
                block.block_hash.clone(),
            ))
            .await
            .unwrap();

        Ok(())
    }

    async fn process_other_single_block(&mut self, block: SingleBlock) -> Result<(), Error> {
        let cached_block = match block.block_future.await {
            Ok(Ok(b)) => b,
            Ok(Err(e)) => {
                error!("Failed to verify block: {:?}", e);
                return Ok(());
            }
            Err(e) => {
                error!("Failed to receive block future: {:?}", e);
                return Ok(());
            }
        };

        let (view, view_is_stable) = (block.stats.view, block.stats.view_is_stable);

        // Store and forward the single block
        self.store_and_forward_internally(&cached_block, block.stats.clone(), true)
            .await?;

        // Forward to app for stats
        self.app_command_tx
            .send(AppCommand::NewRequestBatch(
                cached_block.block.n,
                view,
                view_is_stable,
                false, // Not my block
                cached_block.block.tx_list.len(),
                cached_block.block_hash.clone(),
            ))
            .await
            .unwrap();

        Ok(())
    }

    /// Broadcast a batch of blocks as a single AppendBlocks message
    async fn broadcast_blocks(
        &mut self,
        names: Vec<String>,
        mut blocks: Vec<CachedBlock>,
        view: u64,
        view_is_stable: bool,
        config_num: u64,
        perf_entry: Option<u64>,
    ) {
        let (should_perf, perf_entry) = match perf_entry {
            Some(e) => (true, e),
            None => (false, 0),
        };

        let serialized_blocks: Vec<HalfSerializedBlock> = blocks
            .drain(..)
            .map(|b| HalfSerializedBlock {
                n: b.block.n,
                view: b.block.view,
                view_is_stable: b.block.view_is_stable,
                config_num: b.block.config_num,
                serialized_body: b.block_ser.clone(),
            })
            .collect();

        let append_blocks = ProtoAppendBlocks {
            serialized_blocks,
            commit_index: self.ci,
            view,
            view_is_stable,
            config_num,
            is_backfill_response: false,
        };

        let rpc = ProtoPayload {
            message: Some(crate::proto::rpc::proto_payload::Message::AppendBlocks(
                append_blocks,
            )),
        };
        let data = rpc.encode_to_vec();

        if should_perf {
            self.perf_add_event(perf_entry, "Serialize");
        }

        let sz = data.len();
        if !view_is_stable {
            info!(
                "AppendBlocks batch size: {} Broadcasting to {:?}",
                sz, names
            );
        }
        let data = PinnedMessage::from(data, sz, SenderType::Anon);
        let mut profile = LatencyProfile::new();
        let _res = PinnedClient::broadcast(
            &self.client,
            &names,
            &data,
            &mut profile,
            self.get_car_broadcast_threshold(),
        )
        .await;

        if should_perf {
            self.perf_add_event(perf_entry, "Forward block to other nodes");
            self.perf_deregister(perf_entry);
        }
    }

    fn get_car_broadcast_threshold(&self) -> usize {
        let config = self.config.get();
        let node_list_len = config.consensus_config.node_list.len();

        // If using platforms, we need u+1 nodes to accept the CAR.
        #[cfg(feature = "platforms")]
        {
            if node_list_len <= config.consensus_config.liveness_u as usize {
                return 0;
            }
            let car_threshold = config.consensus_config.liveness_u as usize;
            return car_threshold + 1;
        }

        // Default: f+1
        let f = node_list_len / 3;
        return f + 1;
    }
}
