/// DAG Block Sequencer
///
/// This component sits between dag/batch_proposal and dag/block_broadcaster in the DAG dissemination layer.
/// Unlike the consensus-layer block_sequencer, this component:
/// - Does NOT handle quorum certificates (QCs) - those are consensus-layer concerns
/// - Does NOT handle view changes - DAG dissemination is view-agnostic
/// - Only focuses on sequencing batches into blocks for data dissemination
/// - Prepares blocks for storage in the lane-logserver (not traditional logserver)
/// - Provides proof of availability (via CARs) rather than consensus proofs
///
/// Architecture:
/// ```
/// dag/batch_proposal
///     ↓ (RawBatch)
/// dag/block_sequencer (sequences into blocks, computes hashes, signs)
///     ↓ (CachedBlock)
/// dag/block_broadcaster (distributes to all nodes)
///     ↓ (via AppendBlock RPC)
/// dag/block_receiver (validates and stores)
///     ↓
/// dag/lane_staging (creates CARs for proof of availability)
/// ```
///
/// Key Design:
/// - Maintains parent hash chain for integrity
/// - Signs blocks for authenticity
/// - No QCs needed - CARs provide proof of availability
/// - Operates independently of consensus views
/// - Blocks are stored in lanes (identified by sender name from RPC context)
use std::cell::RefCell;
use std::{pin::Pin, sync::Arc, time::Duration};

use crate::crypto::FutureHash;
use crate::utils::channel::{Receiver, Sender};
use log::{debug, info, trace};
use tokio::sync::{oneshot, Mutex};

use crate::utils::PerfCounter;
use crate::{
    config::AtomicConfig,
    crypto::{CachedBlock, CryptoServiceConnector, HashType},
    proto::consensus::{DefferedSignature, ProtoBlock},
    utils::timer::ResettableTimer,
};

use super::super::batch_proposal::{MsgAckChanWithTag, RawBatch};

/// Control commands for the DAG block sequencer
/// DAG dissemination layer doesn't need view change commands - it's view-agnostic
pub enum DagBlockSequencerCommand {
    // Currently no commands needed, but placeholder for future extensions
    // e.g., UpdateLane, PauseProposal, ResumeProposal, etc.
}

pub struct DagBlockSequencer {
    config: AtomicConfig,
    control_command_rx: Receiver<DagBlockSequencerCommand>,

    batch_rx: Receiver<(RawBatch, Vec<MsgAckChanWithTag>)>,

    signature_timer: Arc<Pin<Box<ResettableTimer>>>,

    dag_broadcaster_tx: Sender<(u64, oneshot::Receiver<CachedBlock>)>,
    client_reply_tx: Sender<(oneshot::Receiver<HashType>, Vec<MsgAckChanWithTag>)>,

    crypto: CryptoServiceConnector,
    parent_hash_rx: FutureHash,
    seq_num: u64,
    force_sign_next_batch: bool,
    last_signed_seq_num: u64,

    perf_counter_signed: RefCell<PerfCounter<u64>>,
    perf_counter_unsigned: RefCell<PerfCounter<u64>>,
}

impl DagBlockSequencer {
    pub fn new(
        config: AtomicConfig,
        control_command_rx: Receiver<DagBlockSequencerCommand>,
        batch_rx: Receiver<(RawBatch, Vec<MsgAckChanWithTag>)>,
        dag_broadcaster_tx: Sender<(u64, oneshot::Receiver<CachedBlock>)>,
        client_reply_tx: Sender<(oneshot::Receiver<HashType>, Vec<MsgAckChanWithTag>)>,
        crypto: CryptoServiceConnector,
    ) -> Self {
        let signature_timer = ResettableTimer::new(Duration::from_millis(
            config.get().consensus_config.signature_max_delay_ms,
        ));

        let event_order = vec![
            "Create Block",
            "Send to Client Reply",
            "Send to Block Broadcaster",
        ];

        let perf_counter_signed =
            RefCell::new(PerfCounter::new("DagBlockSequencerSigned", &event_order));
        let perf_counter_unsigned =
            RefCell::new(PerfCounter::new("DagBlockSequencerUnsigned", &event_order));

        Self {
            config,
            control_command_rx,
            batch_rx,
            signature_timer,
            dag_broadcaster_tx,
            client_reply_tx,
            crypto,
            parent_hash_rx: FutureHash::None,
            seq_num: 0,
            force_sign_next_batch: false,
            last_signed_seq_num: 0,
            perf_counter_signed,
            perf_counter_unsigned,
        }
    }

    pub async fn run(block_maker: Arc<Mutex<Self>>) {
        let mut block_maker = block_maker.lock().await;
        let signature_timer_handle = block_maker.signature_timer.run().await;

        info!("DAG Block Sequencer started");

        loop {
            if let Err(_) = block_maker.worker().await {
                break;
            }

            if block_maker.seq_num % 1000 == 0 {
                block_maker.perf_counter_signed.borrow().log_aggregate();
                block_maker.perf_counter_unsigned.borrow().log_aggregate();
            }
        }

        signature_timer_handle.abort();
        info!("DAG Block Sequencer exited");
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

    async fn worker(&mut self) -> Result<(), ()> {
        // DAG dissemination layer is much simpler than consensus layer:
        // - No view changes to handle
        // - No QCs to wait for
        // - Just sequence batches as they arrive
        // - Always ready to accept new batches

        tokio::select! {
            biased;
            _tick = self.signature_timer.wait() => {
                // Signature timer expired - force signing next batch
                self.force_sign_next_batch = true;
            },
            batch_and_client_reply = self.batch_rx.recv() => {
                if let Some((batch, client_reply)) = batch_and_client_reply {
                    let perf_entry = self.seq_num + 1; // Projected seq num for perf tracking
                    self.perf_register(perf_entry);
                    self.handle_new_batch(batch, client_reply, perf_entry).await;
                }
            },
            cmd = self.control_command_rx.recv() => {
                if cmd.is_some() {
                    self.handle_control_command(cmd.unwrap()).await;
                }
            },
        }

        Ok(())
    }

    async fn handle_new_batch(
        &mut self,
        batch: RawBatch,
        replies: Vec<MsgAckChanWithTag>,
        perf_entry_id: u64,
    ) {
        self.seq_num += 1;
        let n = self.seq_num;

        let config = self.config.get();

        // Determine if this block should be signed
        // In DAG mode, we typically sign all blocks for authenticity
        #[cfg(feature = "dynamic_sign")]
        let must_sign = self.force_sign_next_batch
            || (n - self.last_signed_seq_num) >= config.consensus_config.signature_max_delay_blocks;

        #[cfg(feature = "never_sign")]
        let must_sign = false;

        #[cfg(feature = "always_sign")]
        let must_sign = true;

        #[cfg(not(any(
            feature = "dynamic_sign",
            feature = "never_sign",
            feature = "always_sign"
        )))]
        let must_sign = true; // Default: always sign in DAG mode

        if must_sign {
            self.last_signed_seq_num = n;
            self.force_sign_next_batch = false;
        }

        self.perf_fix_signature(perf_entry_id, must_sign);

        // Create block for DAG dissemination
        // Key differences from consensus-layer blocks:
        // - No QCs (qc field is empty)
        // - No fork_validation
        // - view and config_num are fixed (DAG layer doesn't do view changes)
        // - view_is_stable is always true (no view change protocol)
        let block = ProtoBlock {
            n,
            parent: Vec::new(), // Will be filled in by crypto service with actual parent hash
            view: 1,            // DAG dissemination doesn't use views
            qc: Vec::new(), // No QCs in dissemination layer - CARs provide proof of availability
            fork_validation: Vec::new(), // No fork validation in dissemination layer
            view_is_stable: true, // Always stable in DAG dissemination
            config_num: 1,  // Fixed config in dissemination layer
            tx_list: batch,
            sig: Some(crate::proto::consensus::proto_block::Sig::NoSig(
                DefferedSignature {},
            )),
        };

        let parent_hash_rx = self.parent_hash_rx.take();
        self.perf_add_event(perf_entry_id, "Create DAG Block", must_sign);

        // Prepare block: compute hash, sign if needed, maintain parent chain
        let (block_rx, hash_rx, hash_rx2) = self
            .crypto
            .prepare_block(block, must_sign, parent_hash_rx)
            .await;

        // Store hash for next block's parent
        self.parent_hash_rx = FutureHash::Future(hash_rx);

        // Send hash to client reply handler
        self.client_reply_tx
            .send((hash_rx2, replies))
            .await
            .expect("Should be able to send to client_reply_tx");
        self.perf_add_event(perf_entry_id, "Send to Client Reply", must_sign);

        // Send block to broadcaster for dissemination
        self.dag_broadcaster_tx
            .send((n, block_rx))
            .await
            .expect("Should be able to send to dag_broadcaster_tx");
        self.perf_add_event(perf_entry_id, "Send to DAG Broadcaster", must_sign);

        self.perf_deregister(perf_entry_id);
        trace!("DAG Sequenced block {}", n);
    }

    async fn handle_control_command(&mut self, _cmd: DagBlockSequencerCommand) {
        // Placeholder for future control commands
        // DAG dissemination layer doesn't need view changes or other consensus control
    }
}
