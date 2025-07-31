use std::cell::RefCell;
use std::time::Instant;
use std::{io::Error, pin::Pin, sync::Arc, time::Duration};

use std::io::ErrorKind;
use log::warn;
use prost::Message as _;
use crate::config::NodeInfo;
use crate::proto::client::{ProtoClientReply, ProtoCurrentLeader};
use crate::proto::execution::ProtoTransactionResult;
use crate::rpc::server::LatencyProfile;
use crate::rpc::{PinnedMessage, SenderType};
use crate::utils::channel::{Sender, Receiver};
use crate::utils::PerfCounter;
use tokio::sync::{oneshot, Mutex};

use crate::{config::AtomicConfig, utils::timer::ResettableTimer, proto::execution::ProtoTransaction, rpc::server::MsgAckChan};

use super::client_reply::ClientReplyCommand;

pub type RawBatch = Vec<ProtoTransaction>;

pub type MsgAckChanWithTag = (MsgAckChan, u64 /* client tag */, SenderType /* client name */);
pub type TxWithAckChanTag = (Option<ProtoTransaction>, MsgAckChanWithTag);

pub type BatchProposerCommand = (
    bool /* true == make new batches, false == stop making new batches */,
    String /* Current leader */
);

pub struct BatchProposer {
    config: AtomicConfig,

    batch_proposer_rx: Receiver<TxWithAckChanTag>,
    block_maker_tx: Sender<(RawBatch, Vec<MsgAckChanWithTag>)>,

    reply_tx: Sender<ClientReplyCommand>,
    unlogged_tx: Sender<(ProtoTransaction, oneshot::Sender<ProtoTransactionResult>)>,

    current_raw_batch: Option<RawBatch>, // So that I can take()
    current_reply_vec: Vec<MsgAckChanWithTag>,
    batch_timer: Arc<Pin<Box<ResettableTimer>>>,

    perf_counter: RefCell<PerfCounter<usize>>,

    make_new_batches: bool,
    current_leader: String,

    cmd_rx: Receiver<BatchProposerCommand>,

    last_batch_proposed: Instant,
}

impl BatchProposer {
    pub fn new(
        config: AtomicConfig,
        batch_proposer_rx: Receiver<TxWithAckChanTag>,
        block_maker_tx: Sender<(RawBatch, Vec<MsgAckChanWithTag>)>,
        reply_tx: Sender<ClientReplyCommand>, unlogged_tx: Sender<(ProtoTransaction, oneshot::Sender<ProtoTransactionResult>)>,
        cmd_rx: Receiver<BatchProposerCommand>,
    ) -> Self {
        let batch_timer = ResettableTimer::new(
            Duration::from_millis(config.get().consensus_config.batch_max_delay_ms)
        );

        let max_batch_size = config.get().consensus_config.max_backlog_batch_size;

        let event_order = vec![
            "Add request to batch",
            "Propose batch"
        ];

        let perf_counter = RefCell::new(PerfCounter::new("BatchProposer", &event_order));

        #[allow(unused_mut)]
        let mut ret = Self {
            config,
            batch_proposer_rx, block_maker_tx,
            current_raw_batch: Some(RawBatch::with_capacity(max_batch_size)),
            batch_timer,
            current_reply_vec: Vec::with_capacity(max_batch_size),
            reply_tx, unlogged_tx,
            perf_counter,
            make_new_batches: false,
            current_leader: String::new(),
            cmd_rx,
            last_batch_proposed: Instant::now(),
        };

        #[cfg(not(feature = "view_change"))]
        {
            let leader = ret.config.get().consensus_config.get_leader_for_view(1);
            ret.make_new_batches = leader == ret.config.get().net_config.name;
            ret.current_leader = leader;
        }

        ret
    }

    pub async fn run(batch_proposer: Arc<Mutex<Self>>) {
        let mut batch_proposer = batch_proposer.lock().await;
        let batch_timer_handle = batch_proposer.batch_timer.run().await;

        let batch_size = batch_proposer.config.get().consensus_config.max_backlog_batch_size;
        let mut total_work = 0;
        loop {
            if let Err(_) = batch_proposer.worker(total_work).await {
                break;
            }

            total_work += 1;
            if total_work % (1000 * batch_size) == 0 {
                batch_proposer.perf_counter.borrow().log_aggregate();
            }

        }

        batch_timer_handle.abort();
    }

    fn perf_register_random(&mut self, _entry: usize) {
        #[cfg(not(feature = "perf"))]
        return;

        #[cfg(feature = "perf")]
        {
            let mut batch_size = self.config.get().consensus_config.max_backlog_batch_size;
            // Randomly decide whether to register the new entry with probability 1/batch_size (approx)
            // A random sample gives `true` with prob 1/2.
            // So for n tries 1/2^n <= 1/batch_size or n >= log2(batch_size)
            // log2(batch_size) is the number of bits needed to express batch_size.
            // So an approx way to calculate log2(batch_size) is to keep shifting right until batch_size is 0.
            let mut should_register = true;
            while batch_size > 0 {
                batch_size >>= 1;
                
                should_register = should_register && rand::random::<bool>();
            }
    
            if !should_register {
                return;
            }
            self.perf_counter.borrow_mut().register_new_entry(_entry);

        }
    }

    fn perf_add_event(&mut self, _entry: usize, _event: &str) {

        #[cfg(feature = "perf")]
        self.perf_counter.borrow_mut().new_event(_event, &_entry);
    }

    fn perf_event_and_deregister_all(&mut self, _event: &str) {
        #[cfg(feature = "perf")]
        {
            self.perf_counter.borrow_mut().new_event_for_all(_event);
            self.perf_counter.borrow_mut().deregister_all();
        }
    }

    async fn worker(&mut self, work_counter: usize) -> Result<(), Error> {
        let mut new_tx = None;
        let mut batch_timer_tick = false;
        
        tokio::select! {
            biased;
            _new_tx = self.batch_proposer_rx.recv() => {
                new_tx = _new_tx;
            },
            _cmd = self.cmd_rx.recv() => {
                let (make_new_batches, current_leader) = _cmd.unwrap();
                self.make_new_batches = make_new_batches;
                self.current_leader = current_leader;
                return Ok(());
            },
            _tick = self.batch_timer.wait() => {
                batch_timer_tick = _tick;
            }
        }

        if new_tx.is_none() && !batch_timer_tick {
            return Err(Error::new(
                ErrorKind::BrokenPipe, "Channels not working correctly"
            ));
        }

        if !batch_timer_tick {
            if self.last_batch_proposed.elapsed().as_millis() as u64 >= self.config.get().consensus_config.batch_max_delay_ms {
                batch_timer_tick = true;
            }
        }

        
        if new_tx.is_some() {
            // Filter read-only transactions that do not need to go through consensus.
            // Forward them directly to execution.
            new_tx = self.filter_unlogged_request(new_tx.unwrap()).await;
        }

        if new_tx.is_some() {

            if !self.i_am_leader() {
                self.reply_leader(new_tx.unwrap()).await;
                return Ok(());
            }

            self.perf_register_random(work_counter);

            let new_tx = new_tx.unwrap();
            if new_tx.0.is_none() {
                warn!("Malformed transaction");
                self.register_reply_malformed(new_tx.1).await;
                return Ok(());
            }

            let ack_chan = new_tx.1;
            let new_tx = new_tx.0.unwrap();

            self.current_raw_batch.as_mut().unwrap().push(new_tx);
            self.current_reply_vec.push(ack_chan);
            self.perf_add_event(work_counter, "Add request to batch");
        }

        let max_batch_size = self.config.get().consensus_config.max_backlog_batch_size;

        if self.current_raw_batch.as_ref().unwrap().len() >= max_batch_size || (self.make_new_batches && batch_timer_tick) {
            self.propose_new_batch().await;
        }

        Ok(())
    }

    async fn register_reply_malformed(&mut self, _ack_chan: MsgAckChanWithTag) {
        todo!()
    }

    async fn reply_leader(&mut self, new_tx: TxWithAckChanTag) { // TODO
        let (ack_chan, client_tag, _) = new_tx.1;
        let node_infos = NodeInfo {
            nodes: self.config.get().net_config.nodes.clone(),
        };
        let reply = ProtoClientReply {
            reply: Some(
                crate::proto::client::proto_client_reply::Reply::Leader(ProtoCurrentLeader {
                    name: self.current_leader.clone(),
                    serialized_node_infos: node_infos.serialize(),
                })
            ),
            client_tag
        };

        let reply_ser = reply.encode_to_vec();
        let _sz = reply_ser.len();
        let reply_msg = PinnedMessage::from(reply_ser, _sz, crate::rpc::SenderType::Anon);
        let latency_profile = LatencyProfile::new();
        
        let _ = ack_chan.send((reply_msg, latency_profile)).await;
    }

    async fn propose_new_batch(&mut self) {
        self.last_batch_proposed = Instant::now();
        let batch = self.current_raw_batch.take().unwrap();
        self.current_raw_batch = Some(RawBatch::with_capacity(
            self.config.get().consensus_config.max_backlog_batch_size
        ));
        let reply_chans = self.current_reply_vec.drain(..).collect();
        let _ = self.block_maker_tx.send((batch, reply_chans)).await;
        self.perf_event_and_deregister_all("Propose batch");
        self.batch_timer.reset();
    }


    fn i_am_leader(&self) -> bool {
        self.config.get().net_config.name == self.current_leader
    }

    /// None implies don't process the transaction forward!
    /// Either the transaction is malformed or it is a read-only transaction.
    async fn filter_unlogged_request(&mut self, tx: TxWithAckChanTag) -> Option<TxWithAckChanTag> {
        let (tx, ack_chan) = tx;
        let tx = tx.unwrap();
        
        if tx.on_receive.is_some() {
            if !(tx.on_crash_commit.is_none() && tx.on_byzantine_commit.is_none()) {
                warn!("Malformed transaction");
            }

            let (res_tx, res_rx) = oneshot::channel();

            let (is_probe, block_n, tx_n, is_audit) = self.is_probe_tx(&tx);

            if !is_probe {
                self.unlogged_tx.send((tx, res_tx)).await.unwrap();
                self.reply_tx.send(ClientReplyCommand::UnloggedRequestAck(res_rx, ack_chan)).await.unwrap();
            } else {
                self.reply_tx.send(ClientReplyCommand::ProbeRequestAck(block_n, tx_n, is_audit, ack_chan)).await.unwrap();
            }
                
            return None;
        }

        Some((Some(tx), ack_chan))

    }

    fn is_probe_tx(&self, tx: &ProtoTransaction) -> (bool, u64, u64, bool) { // Returns (is_probe, block_n, tx_n, is_audit)
        if tx.on_receive.is_none() {
            return (false, 0, 0, false);
        }

        if tx.on_receive.as_ref().unwrap().ops.len() != 1 {
            return (false, 0, 0, false);
        }

        let op = &tx.on_receive.as_ref().unwrap().ops[0];

        let is_audit = if op.op_type == crate::proto::execution::ProtoTransactionOpType::ProbeAudit as i32 {
            true
        } else if op.op_type == crate::proto::execution::ProtoTransactionOpType::ProbeCommit as i32 {
            false
        } else {
            return (false, 0, 0, false);
        };

        if op.operands.len() != 2 {
            return (false, 0, 0, false);
        }

        let block_n = op.operands[0].clone();
        let block_n = match block_n.as_slice().try_into() {
            Ok(arr) => u64::from_be_bytes(arr),
            Err(_) => return (false, 0, 0, false),
        };
        let tx_n = op.operands[1].clone();
        let tx_n = match tx_n.as_slice().try_into() {
            Ok(arr) => u64::from_be_bytes(arr),
            Err(_) => return (false, 0, 0, false),
        };

        (true, block_n, tx_n, is_audit)
    }

}