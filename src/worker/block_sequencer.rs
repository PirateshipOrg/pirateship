use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use log::trace;
use tokio::sync::{oneshot, Mutex};

use crate::config::AtomicConfig;
use crate::consensus::batch_proposal::{MsgAckChanWithTag, RawBatch};
use crate::crypto::{CachedBlock, CryptoServiceConnector, FutureHash, HashType};
use crate::proto::consensus::{DefferedSignature, ProtoBlock};
use crate::utils::channel::{Receiver, Sender};
use crate::utils::timer::ResettableTimer;

pub struct BlockSequencer {
    config: AtomicConfig,
    crypto: CryptoServiceConnector,

    batch_rx: Receiver<(RawBatch, Vec<MsgAckChanWithTag>)>,
    block_broadcaster_tx: Sender<(u64, oneshot::Receiver<CachedBlock>)>,
    vote_register_tx: Sender<(u64, oneshot::Receiver<HashType>, Vec<MsgAckChanWithTag>)>,

    parent_hash_rx: FutureHash,
    seq_num: u64,

    signature_timer: Arc<Pin<Box<ResettableTimer>>>,
    force_sign_next_batch: bool,
    last_signed_seq_num: u64,
}

impl BlockSequencer {
    pub fn new(
        config: AtomicConfig,
        crypto: CryptoServiceConnector,
        batch_rx: Receiver<(RawBatch, Vec<MsgAckChanWithTag>)>,
        block_broadcaster_tx: Sender<(u64, oneshot::Receiver<CachedBlock>)>,
        vote_register_tx: Sender<(u64, oneshot::Receiver<HashType>, Vec<MsgAckChanWithTag>)>,
    ) -> Self {
        let signature_timer = ResettableTimer::new(Duration::from_millis(
            config.get().consensus_config.signature_max_delay_ms,
        ));

        Self {
            config,
            crypto,
            batch_rx,
            block_broadcaster_tx,
            vote_register_tx,
            parent_hash_rx: FutureHash::None,
            seq_num: 0,
            signature_timer,
            force_sign_next_batch: false,
            last_signed_seq_num: 0,
        }
    }

    pub async fn run(sequencer: Arc<Mutex<Self>>) {
        let mut seq = sequencer.lock().await;
        let timer_handle = seq.signature_timer.run().await;

        loop {
            if let Err(_) = seq.worker().await {
                break;
            }
        }

        timer_handle.abort();
    }

    async fn worker(&mut self) -> Result<(), ()> {
        tokio::select! {
            biased;
            _tick = self.signature_timer.wait() => {
                self.force_sign_next_batch = true;
            },
            batch = self.batch_rx.recv() => {
                if batch.is_none() {
                    return Err(());
                }
                let (raw_batch, reply_chans) = batch.unwrap();
                self.handle_new_batch(raw_batch, reply_chans).await;
            },
        }

        Ok(())
    }

    async fn handle_new_batch(
        &mut self,
        batch: RawBatch,
        replies: Vec<MsgAckChanWithTag>,
    ) {
        self.seq_num += 1;
        let n = self.seq_num;

        let config = self.config.get();

        let must_sign = self.force_sign_next_batch
            || (n - self.last_signed_seq_num)
                >= config.consensus_config.signature_max_delay_blocks;

        if must_sign {
            self.last_signed_seq_num = n;
            self.force_sign_next_batch = false;
        }

        let block = ProtoBlock {
            n,
            parent: Vec::new(),
            view: 1,
            qc: Vec::new(),
            fork_validation: Vec::new(),
            view_is_stable: true,
            config_num: 1,
            tx_list: batch,
            sig: Some(crate::proto::consensus::proto_block::Sig::NoSig(
                DefferedSignature {},
            )),
        };

        let parent_hash_rx = self.parent_hash_rx.take();

        let (block_rx, hash_rx, hash_rx2) = self
            .crypto
            .prepare_block(block, must_sign, parent_hash_rx)
            .await;
        self.parent_hash_rx = FutureHash::Future(hash_rx);

        self.vote_register_tx
            .send((n, hash_rx2, replies))
            .await
            .expect("vote_register_tx send failed");

        self.block_broadcaster_tx
            .send((n, block_rx))
            .await
            .expect("block_broadcaster_tx send failed");

        trace!("Worker sequenced block {}", n);
    }
}
