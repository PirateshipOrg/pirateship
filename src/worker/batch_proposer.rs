use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::io::{Error, ErrorKind};

use log::{info, warn};
use tokio::sync::Mutex;

use crate::config::AtomicConfig;
use crate::consensus::batch_proposal::{MsgAckChanWithTag, RawBatch, TxWithAckChanTag};
use crate::utils::channel::{Sender, Receiver};
use crate::utils::timer::ResettableTimer;

pub struct BatchProposer {
    config: AtomicConfig,

    rx: Receiver<TxWithAckChanTag>,
    block_maker_tx: Sender<(RawBatch, Vec<MsgAckChanWithTag>)>,

    current_raw_batch: Option<RawBatch>,
    current_reply_vec: Vec<MsgAckChanWithTag>,
    batch_timer: Arc<Pin<Box<ResettableTimer>>>,

    last_batch_proposed: Instant,
}

impl BatchProposer {
    pub fn new(
        config: AtomicConfig,
        rx: Receiver<TxWithAckChanTag>,
        block_maker_tx: Sender<(RawBatch, Vec<MsgAckChanWithTag>)>,
    ) -> Self {
        let batch_timer = ResettableTimer::new(
            Duration::from_millis(config.get().consensus_config.batch_max_delay_ms)
        );
        let max_batch_size = config.get().consensus_config.max_backlog_batch_size;

        Self {
            config,
            rx,
            block_maker_tx,
            current_raw_batch: Some(RawBatch::with_capacity(max_batch_size)),
            current_reply_vec: Vec::with_capacity(max_batch_size),
            batch_timer,
            last_batch_proposed: Instant::now(),
        }
    }

    pub async fn run(batch_proposer: Arc<Mutex<Self>>) {
        let mut bp = batch_proposer.lock().await;
        let timer_handle = bp.batch_timer.run().await;

        loop {
            if let Err(_) = bp.worker().await {
                break;
            }
        }

        timer_handle.abort();
    }

    async fn worker(&mut self) -> Result<(), Error> {
        let mut new_tx = None;
        let mut batch_timer_tick = false;

        tokio::select! {
            biased;
            _new_tx = self.rx.recv() => {
                new_tx = _new_tx;
            },
            _tick = self.batch_timer.wait() => {
                batch_timer_tick = _tick;
            }
        }

        if new_tx.is_none() && !batch_timer_tick {
            return Err(Error::new(ErrorKind::BrokenPipe, "Channels closed"));
        }

        if !batch_timer_tick {
            if self.last_batch_proposed.elapsed().as_millis() as u64
                >= self.config.get().consensus_config.batch_max_delay_ms
            {
                batch_timer_tick = true;
            }
        }

        if let Some(tx) = new_tx {
            let (tx_opt, ack_chan) = tx;
            if tx_opt.is_none() {
                warn!("Malformed transaction in worker batch proposer");
                return Ok(());
            }
            self.current_raw_batch.as_mut().unwrap().push(tx_opt.unwrap());
            self.current_reply_vec.push(ack_chan);
        }

        let max_batch_size = self.config.get().consensus_config.max_backlog_batch_size;
        let batch_len = self.current_raw_batch.as_ref().unwrap().len();

        if batch_len >= max_batch_size || batch_timer_tick {
            self.propose_new_batch().await;
        }

        Ok(())
    }

    async fn propose_new_batch(&mut self) {
        self.last_batch_proposed = Instant::now();
        let batch = self.current_raw_batch.take().unwrap();
        self.current_raw_batch = Some(RawBatch::with_capacity(
            self.config.get().consensus_config.max_backlog_batch_size,
        ));
        let reply_chans = self.current_reply_vec.drain(..).collect();
        let _ = self.block_maker_tx.send((batch, reply_chans)).await;
        self.batch_timer.reset();
    }
}
