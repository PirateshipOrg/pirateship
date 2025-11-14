use std::cell::RefCell;
use std::{pin::Pin, sync::Arc, time::Duration};

use crate::crypto::{default_hash, FutureHash};
use crate::utils::channel::{Receiver, Sender};
use log::{debug, error, info, trace, warn};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::{oneshot, Mutex};

use crate::utils::PerfCounter;
use crate::{
    config::AtomicConfig,
    crypto::{CachedBlock, CryptoServiceConnector, HashType},
    proto::consensus::{
        DefferedSignature, ProtoBlock, ProtoForkValidation, ProtoQuorumCertificate,
    },
    utils::timer::ResettableTimer,
};

use super::batch_proposal::{MsgAckChanWithTag, RawBatch};

#[cfg(feature = "dag")]
use super::block_broadcaster::BlockBroadcasterCommand;
#[cfg(feature = "dag")]
use crate::proto::consensus::ProtoTipCut;

pub enum BlockSequencerControlCommand {
    NewUnstableView(u64 /* view num */, u64 /* config num */), // View changed to a new view, it is not stable, so don't propose new blocks.
    ViewStabilised(u64 /* view num */, u64 /* config num */), // View is stable now, if I am the leader in this view, propose new blocks.
    NewViewMessage(
        u64, /* view num */
        u64, /* config num */
        Vec<ProtoForkValidation>,
        HashType, /* new parent hash */
        u64,      /* new seq num */
    ), // Change view to unstable, use ProtoForkValidation to propose a new view message.
}

pub struct BlockSequencer {
    config: AtomicConfig,
    control_command_rx: Receiver<BlockSequencerControlCommand>,

    #[cfg(not(feature = "dag"))]
    batch_rx: Receiver<(RawBatch, Vec<MsgAckChanWithTag>)>,
    #[cfg(feature = "dag")]
    tipcut_rx: Receiver<ProtoTipCut>,

    signature_timer: Arc<Pin<Box<ResettableTimer>>>,

    qc_rx: UnboundedReceiver<ProtoQuorumCertificate>,
    current_qc_list: Vec<ProtoQuorumCertificate>,

    block_broadcaster_tx: Sender<(u64, oneshot::Receiver<CachedBlock>)>, // Last-ditch effort to parallelize hashing and signing of blocks, shouldn't matter.
    client_reply_tx: Sender<(oneshot::Receiver<HashType>, Vec<MsgAckChanWithTag>)>,

    crypto: CryptoServiceConnector,
    parent_hash_rx: FutureHash,
    seq_num: u64,
    view: u64,
    config_num: u64,
    view_is_stable: bool,
    force_sign_next_batch: bool,
    last_signed_seq_num: u64,

    perf_counter_signed: RefCell<PerfCounter<u64>>,
    perf_counter_unsigned: RefCell<PerfCounter<u64>>,

    __last_qc_n_seen: u64,
    __blocks_proposed_in_this_view: u64,

    // DAG mode fields
    #[cfg(feature = "dag")]
    block_broadcaster_command_tx: Sender<BlockBroadcasterCommand>,
}

impl BlockSequencer {
    pub fn new(
        config: AtomicConfig,
        control_command_rx: Receiver<BlockSequencerControlCommand>,
        #[cfg(not(feature = "dag"))] batch_rx: Receiver<(RawBatch, Vec<MsgAckChanWithTag>)>,
        #[cfg(feature = "dag")] tipcut_rx: Receiver<ProtoTipCut>,
        qc_rx: UnboundedReceiver<ProtoQuorumCertificate>,
        block_broadcaster_tx: Sender<(u64, oneshot::Receiver<CachedBlock>)>,
        client_reply_tx: Sender<(oneshot::Receiver<HashType>, Vec<MsgAckChanWithTag>)>,
        crypto: CryptoServiceConnector,
        #[cfg(feature = "dag")] block_broadcaster_command_tx: Sender<BlockBroadcasterCommand>,
    ) -> Self {
        let signature_timer = ResettableTimer::new(Duration::from_millis(
            config.get().consensus_config.signature_max_delay_ms,
        ));

        let event_order = vec![
            "Add QCs",
            "Create Block",
            "Send to Client Reply",
            "Send to Block Broadcaster",
        ];

        let perf_counter_signed =
            RefCell::new(PerfCounter::new("BlockSequencerSigned", &event_order));
        let perf_counter_unsigned =
            RefCell::new(PerfCounter::new("BlockSequencerUnsigned", &event_order));

        let mut ret = Self {
            config,
            control_command_rx,
            #[cfg(not(feature = "dag"))]
            batch_rx,
            #[cfg(feature = "dag")]
            tipcut_rx,
            signature_timer,
            qc_rx,
            current_qc_list: Vec::new(),
            block_broadcaster_tx,
            client_reply_tx,
            crypto,
            parent_hash_rx: FutureHash::None,
            seq_num: 0,
            view: 0,
            config_num: 0,
            view_is_stable: false,
            force_sign_next_batch: false,
            last_signed_seq_num: 0,
            perf_counter_signed,
            perf_counter_unsigned,
            __last_qc_n_seen: 0,
            __blocks_proposed_in_this_view: 0,
            #[cfg(feature = "dag")]
            block_broadcaster_command_tx,
        };

        #[cfg(not(feature = "view_change"))]
        {
            ret.view_is_stable = true;
            ret.view = 1;
            ret.config_num = 1;
        }

        ret
    }

    pub async fn run(block_maker: Arc<Mutex<Self>>) {
        let mut block_maker = block_maker.lock().await;
        let signature_timer_handle = block_maker.signature_timer.run().await;
        let chan_depth = block_maker.config.get().rpc_config.channel_depth;

        loop {
            if let Err(_) = block_maker.worker(chan_depth as usize).await {
                break;
            }

            if block_maker.seq_num % 1000 == 0 {
                block_maker.perf_counter_signed.borrow().log_aggregate();
                block_maker.perf_counter_unsigned.borrow().log_aggregate();
            }
        }

        signature_timer_handle.abort();
    }

    fn i_am_leader(&self) -> bool {
        let config = self.config.get();
        let leader = config.consensus_config.get_leader_for_view(self.view);
        leader == config.net_config.name
    }

    fn perf_register(&mut self, entry: u64) {
        #[cfg(feature = "perf")]
        {
            self.perf_counter_signed
                .borrow_mut()
                .register_new_entry(entry);
            self.perf_counter_unsigned
                .borrow_mut()
                .register_new_entry(entry);
        }
    }

    fn perf_fix_signature(&mut self, entry: u64, signed: bool) {
        #[cfg(feature = "perf")]
        if signed {
            self.perf_counter_unsigned
                .borrow_mut()
                .deregister_entry(&entry);
        } else {
            self.perf_counter_signed
                .borrow_mut()
                .deregister_entry(&entry);
        }
    }

    fn perf_add_event(&mut self, entry: u64, event: &str, signed: bool) {
        #[cfg(feature = "perf")]
        if signed {
            self.perf_counter_signed
                .borrow_mut()
                .new_event(event, &entry);
        } else {
            self.perf_counter_unsigned
                .borrow_mut()
                .new_event(event, &entry);
        }
    }

    fn perf_deregister(&mut self, entry: u64) {
        #[cfg(feature = "perf")]
        {
            self.perf_counter_unsigned
                .borrow_mut()
                .deregister_entry(&entry);
            self.perf_counter_signed
                .borrow_mut()
                .deregister_entry(&entry);
        }
    }

    async fn worker(&mut self, chan_depth: usize) -> Result<(), ()> {
        // DAG mode: sequence tip cuts for consensus layer
        #[cfg(feature = "dag")]
        {
            tokio::select! {
                biased;
                _tipcut = self.tipcut_rx.recv() => {
                    if let Some(tipcut) = _tipcut {
                        self.handle_new_tipcut(tipcut).await;
                    }
                },
                _cmd = self.control_command_rx.recv() => {
                    self.handle_control_command(_cmd).await;
                },
            }
            return Ok(());
        }

        // Traditional mode: sequence batches into blocks
        #[cfg(not(feature = "dag"))]
        {
            // The slow path needs 2-hop QCs to byz-commit.
            // If we assume the head of the chain is crash committed immediately (best case),
            // On average, need the 2-hop to happen within config.consensus_config.commit_index_gap_hard.
            // Otherwise, this will cause a view change.

            // So, we want to wait for QCs to appear if seq_num - last_qc_n_seen > commit_index_gap_hard / 2.
            // This limits the depth of pipeline (ie, max number of inflight blocks).

            let mut listen_for_new_batch = self.view_is_stable && self.i_am_leader();
            let mut blocked_for_qc_pass = false;

            #[cfg(not(feature = "no_qc"))]
            {
                // Is there a QC I can get?
                let mut qc_check_cond = self.qc_rx.len() > 0;
                #[cfg(feature = "no_pipeline")]
                {
                    qc_check_cond = qc_check_cond && self.current_qc_list.len() == 0;
                }
                if qc_check_cond {
                    let mut qc_buf = Vec::new();
                    self.qc_rx.recv_many(&mut qc_buf, self.qc_rx.len()).await;
                    self.add_qcs(qc_buf).await;
                }

                // let config = &self.config.get().consensus_config;
                // let hard_gap = config.commit_index_gap_hard;
                // let soft_gap = config.commit_index_gap_soft;

                // if !self.force_sign_next_batch && self.__blocks_proposed_in_this_view > soft_gap {
                //     listen_for_new_batch = listen_for_new_batch
                //     && (self.seq_num as i64 - self.__last_qc_n_seen as i64) < (hard_gap / 2) as i64;
                //     // This is to prevent the locking happen when the leader is new.

                //     blocked_for_qc_pass = true;
                // }
            }

            let mut qc_buf = Vec::new();

            if listen_for_new_batch {
                tokio::select! {
                    biased;
                    _ = self.qc_rx.recv_many(&mut qc_buf, chan_depth) => {
                        self.add_qcs(qc_buf).await;
                    }
                    _tick = self.signature_timer.wait() => {
                        self.force_sign_next_batch = true;
                    },
                    _batch_and_client_reply = self.batch_rx.recv() => {
                        if let Some(_) = _batch_and_client_reply {
                            self.__blocks_proposed_in_this_view += 1;
                            let (batch, client_reply) = _batch_and_client_reply.unwrap();
                            self.perf_register(self.seq_num + 1); // Projected seq num is used as entry id for perf
                            self.handle_new_batch(batch, client_reply, vec![], self.seq_num + 1).await;
                        }
                    },
                    _cmd = self.control_command_rx.recv() => {
                        self.handle_control_command(_cmd).await;
                    },
                }
            } else if blocked_for_qc_pass {
                tokio::select! {
                    biased;
                    _ = self.qc_rx.recv_many(&mut qc_buf, chan_depth) => {
                        self.add_qcs(qc_buf).await;
                    },
                    _tick = self.signature_timer.wait() => {
                        self.force_sign_next_batch = true;
                    },
                    _cmd = self.control_command_rx.recv() => {
                        self.handle_control_command(_cmd).await;
                    }

                    // I am not listening to new batch because I am blocked for a new QC.
                    // There is no need to cancel requests here.
                }
            } else {
                tokio::select! {
                    biased;
                    _ = self.qc_rx.recv_many(&mut qc_buf, chan_depth) => {
                        self.add_qcs(qc_buf).await;
                    }
                    _cmd = self.control_command_rx.recv() => {
                        self.handle_control_command(_cmd).await;
                    },
                    _batch_and_client_reply = self.batch_rx.recv() => {
                        if let Some(_) = _batch_and_client_reply {
                            let (_, client_reply) = _batch_and_client_reply.unwrap();
                            let (tx, rx) = oneshot::channel();
                            tx.send(vec![]).expect("Should be able to send hash");

                            self.client_reply_tx
                                .send((rx, client_reply))
                                .await
                                .expect("Should be able to send client_reply_tx");
                        }
                    },
                }
            }

            Ok(())
        } // end cfg(not(feature = "dag"))
    }

    async fn handle_new_batch(
        &mut self,
        batch: RawBatch,
        replies: Vec<MsgAckChanWithTag>,
        fork_validation: Vec<ProtoForkValidation>,
        perf_entry_id: u64,
    ) {
        self.seq_num += 1;
        let n = self.seq_num;

        let config = self.config.get();

        #[cfg(feature = "dynamic_sign")]
        let must_sign = self.force_sign_next_batch
            || (n - self.last_signed_seq_num) >= config.consensus_config.signature_max_delay_blocks
            || (self.i_am_leader() && !self.view_is_stable); // Always sign the NewView message.

        #[cfg(feature = "never_sign")]
        let must_sign = false;

        #[cfg(feature = "always_sign")]
        let must_sign = true;

        if must_sign {
            self.last_signed_seq_num = n;
            self.force_sign_next_batch = false;
        }

        self.perf_fix_signature(perf_entry_id, must_sign);

        // Invariant: Only signed blocks get QCs.
        let qc_list = if must_sign {
            self.current_qc_list.drain(..).collect()
        } else {
            Vec::new()
        };

        self.perf_add_event(perf_entry_id, "Add QCs", must_sign);

        let block = ProtoBlock {
            n,
            parent: Vec::new(),
            view: self.view,
            qc: qc_list,
            fork_validation,
            view_is_stable: self.view_is_stable,
            config_num: self.config_num,
            tx_list: batch,
            sig: Some(crate::proto::consensus::proto_block::Sig::NoSig(
                DefferedSignature {},
            )),
        };

        let parent_hash_rx = self.parent_hash_rx.take();
        self.perf_add_event(perf_entry_id, "Create Block", must_sign);

        let (block_rx, hash_rx, hash_rx2) = self
            .crypto
            .prepare_block(block, must_sign, parent_hash_rx)
            .await;
        self.parent_hash_rx = FutureHash::Future(hash_rx);

        self.client_reply_tx
            .send((hash_rx2, replies))
            .await
            .expect("Should be able to send client_reply_tx");
        self.perf_add_event(perf_entry_id, "Send to Client Reply", must_sign);

        self.block_broadcaster_tx
            .send((n, block_rx))
            .await
            .expect("Should be able to send block_broadcaster_tx");
        self.perf_add_event(perf_entry_id, "Send to Block Broadcaster", must_sign);

        self.perf_deregister(perf_entry_id);
        trace!("Sequenced: {}", n);
    }

    async fn add_qcs(&mut self, mut qcs: Vec<ProtoQuorumCertificate>) {
        for qc in qcs.drain(..) {
            // Invariant: All qc.view in self.current_qc_list == self.view
            if qc.view != self.view {
                continue;
            }

            if qc.n > self.__last_qc_n_seen {
                self.__last_qc_n_seen = qc.n;
            }

            self.current_qc_list.push(qc);
        }
    }

    async fn handle_control_command(&mut self, cmd: Option<BlockSequencerControlCommand>) {
        if cmd.is_none() {
            return;
        }
        let cmd = cmd.unwrap();

        match cmd {
            // Follow the changes, no questions asked!
            BlockSequencerControlCommand::NewUnstableView(v, c) => {
                self.view = v;
                self.config_num = c;
                self.view_is_stable = false;
                self.current_qc_list.retain(|e| e.view >= self.view);
                self.__blocks_proposed_in_this_view = 0;
                self.__last_qc_n_seen = self.seq_num;
            }
            BlockSequencerControlCommand::ViewStabilised(v, c) => {
                self.view = v;
                self.config_num = c;
                self.view_is_stable = true;
                self.current_qc_list.retain(|e| e.view >= self.view);
                self.__blocks_proposed_in_this_view = 0;
                self.__last_qc_n_seen = self.seq_num;
            }
            BlockSequencerControlCommand::NewViewMessage(
                v,
                c,
                fork_validation,
                new_parent_hash,
                new_seq_num,
            ) => {
                warn!(
                    "Request for new view message: view: {} config: {} new_seq_num: {}",
                    v, c, new_seq_num
                );
                self.view = v;
                self.config_num = c;
                self.view_is_stable = false;
                self.current_qc_list.retain(|e| e.view == self.view);

                self.__last_qc_n_seen = new_seq_num;
                self.__blocks_proposed_in_this_view = 0;

                // Rest is only applicable if I am the leader.
                if !self.i_am_leader() {
                    return;
                }

                self.seq_num = new_seq_num; // This may not be monotonic due to rollbacks.
                self.parent_hash_rx = FutureHash::Immediate(new_parent_hash);

                // Now the NEXT block (ie new_seq_num + 1) is going to be for NewView.
                self.handle_new_batch(RawBatch::new(), vec![], fork_validation, 0)
                    .await;
            }
        }
    }

    /// Handle a new tip cut in DAG mode.
    /// Compute digest using crypto service with pipelining support.
    /// This mirrors the prepare_block pipelining pattern for consistency.
    #[cfg(feature = "dag")]
    async fn handle_new_tipcut(&mut self, tipcut: ProtoTipCut) {
        trace!("Sequencing tip cut with {} tips", tipcut.tips.len());

        // Take parent hash for pipelining (like handle_new_batch does)
        let parent_hash_rx = self.parent_hash_rx.take();

        // Use crypto service to prepare tip cut with pipelining
        // The crypto worker will await the parent hash asynchronously,
        // allowing this tip cut to start processing before the previous one completes
        let (tipcut_rx, digest_rx, digest_rx2) =
            self.crypto.prepare_tipcut(tipcut, parent_hash_rx).await;

        // Store future digest for next tip cut (enables pipelining)
        self.parent_hash_rx = FutureHash::Future(digest_rx);

        // Send tip cut to block_broadcaster via command
        // The tipcut_rx will resolve when the crypto worker completes processing
        let tipcut_future = tipcut_rx;
        let digest_future = digest_rx2;

        // Spawn a task to send the command once the tip cut is ready
        let broadcaster_tx = self.block_broadcaster_command_tx.clone();
        let view = self.view;
        let view_is_stable = self.view_is_stable;
        let config_num = self.config_num;

        tokio::spawn(async move {
            // Await the prepared tip cut
            let tipcut = match tipcut_future.await {
                Ok(tc) => tc,
                Err(_) => {
                    error!("Failed to receive prepared tip cut from crypto service");
                    return;
                }
            };

            // Send to broadcaster
            let cmd =
                BlockBroadcasterCommand::BroadcastTipCut(tipcut, view, view_is_stable, config_num);

            if let Err(e) = broadcaster_tx.send(cmd).await {
                error!("Failed to send tip cut to block_broadcaster: {:?}", e);
            }

            trace!("Tip cut sequenced and sent to block_broadcaster");
        });
    }
}
