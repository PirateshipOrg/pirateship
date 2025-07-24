use std::{cell::RefCell, marker::PhantomData, pin::Pin, sync::Arc, time::Duration};

use hex::ToHex;
use log::{info, warn};
use serde::{de::DeserializeOwned, Serialize};
use tokio::sync::{oneshot, Mutex};

use crate::{config::AtomicConfig, consensus::issuer::IssuerCommand, crypto::{default_hash, CachedBlock, HashType}, proto::{client::ProtoByzResponse, execution::{ProtoTransaction, ProtoTransactionOp, ProtoTransactionResult}}, utils::{channel::{Receiver, Sender}, PerfCounter}};

use super::{client_reply::ClientReplyCommand, super::utils::timer::ResettableTimer};
#[cfg(feature = "channel_monitoring")]
use super::channel_monitor::ChannelMonitor;

pub type TransactionValidationResult = Result<(), String>;
pub type TxWithValidationAck = (ProtoTransactionOp, oneshot::Sender<TransactionValidationResult>);

pub enum AppCommand {
    NewRequestBatch(u64 /* block.n */, u64 /* view */, bool /* view_is_stable */, bool /* i_am_leader */, usize /* length of new batch of request */, HashType /* hash of the last block */),
    CrashCommit(Vec<CachedBlock> /* all blocks from old_ci + 1 to new_ci */),
    ByzCommit(Vec<CachedBlock> /* all blocks from old_bci + 1 to new_bci */),
    Rollback(u64 /* new last block */),
    #[cfg(feature = "policy_validation")]
    Validate(CachedBlock, oneshot::Sender<TransactionValidationResult>),
}

pub trait AppEngine {
    type State: std::fmt::Debug + std::fmt::Display + Clone + Serialize + DeserializeOwned + Send;

    fn new(config: AtomicConfig) -> Self;
    fn handle_crash_commit(&mut self, blocks: Vec<CachedBlock>) -> Vec<Vec<ProtoTransactionResult>>;
    fn handle_byz_commit(&mut self, blocks: Vec<CachedBlock>) -> Vec<Vec<ProtoByzResponse>>;
    fn handle_rollback(&mut self, new_last_block: u64);
    fn handle_unlogged_request(&mut self, request: ProtoTransaction) -> ProtoTransactionResult;
    #[cfg(feature = "policy_validation")]
    fn handle_validation(&mut self, tx: &ProtoTransactionOp) -> TransactionValidationResult;
    fn get_current_state(&self) -> Self::State;
}

struct LogStats {
    ci: u64,
    bci: u64,
    view: u64,
    i_am_leader: bool,
    view_is_stable: bool,
    last_n: u64,
    last_qc: u64,
    last_hash: HashType,
    total_requests: u64,
    total_crash_committed_txs: u64,
    total_byz_committed_txs: u64,
    total_unlogged_txs: u64,

    #[cfg(feature = "extra_2pc")]
    total_2pc_txs: u64,
}

impl LogStats {
    fn new() -> Self {
        #[allow(unused_mut)]
        let mut res = Self {
            ci: 0,
            bci: 0,
            view: 0,
            i_am_leader: false,
            view_is_stable: false,
            last_n: 0,
            last_qc: 0,
            last_hash: default_hash(),
            total_requests: 0,
            total_crash_committed_txs: 0,
            total_byz_committed_txs: 0,
            total_unlogged_txs: 0,

            #[cfg(feature = "extra_2pc")]
            total_2pc_txs: 0,
        };

        #[cfg(not(feature = "view_change"))]
        {
            res.view_is_stable = true;
            res.view = 1;
        }

        res
    }

    fn print(&self) {
        info!("fork.last = {}, fork.last_qc = {}, commit_index = {}, byz_commit_index = {}, pending_acks = {}, pending_qcs = {} num_crash_committed_txs = {}, num_byz_committed_txs = {}, fork.last_hash = {}, total_client_request = {}, view = {}, view_is_stable = {}, i_am_leader: {}",
            self.last_n,
            self.last_qc,
            self.ci,
            self.bci,
            self.total_requests - (self.total_crash_committed_txs + self.total_unlogged_txs),
            self.ci as i64 - self.bci as i64,
            self.total_crash_committed_txs,
            self.total_byz_committed_txs,
            self.last_hash.encode_hex::<String>(),
            self.total_requests,
            self.view,
            self.view_is_stable,
            self.i_am_leader
        );

        info!("Total unlogged txs: {}", self.total_unlogged_txs);

        #[cfg(feature = "extra_2pc")]
        {
            info!("Total 2PC txs: {}", self.total_2pc_txs);
        }
    }
}

pub struct Application<'a, E: AppEngine + Send + Sync + 'a> {
    _config: AtomicConfig,

    engine: E,
    stats: LogStats,

    staging_rx: Receiver<AppCommand>,
    unlogged_rx: Receiver<(ProtoTransaction, oneshot::Sender<ProtoTransactionResult>)>,
    
    #[cfg(feature = "extra_2pc")]
    twopc_tx: Sender<(ProtoTransaction, oneshot::Sender<ProtoTransactionResult>)>,

    client_reply_tx: Sender<ClientReplyCommand>,
    issuer_tx: Sender<IssuerCommand>,

    #[cfg(feature = "policy_validation")]
    validation_rx: Receiver<TxWithValidationAck>,

    checkpoint_timer: Arc<Pin<Box<ResettableTimer>>>,
    log_timer: Arc<Pin<Box<ResettableTimer>>>,

    perf_counter: RefCell<PerfCounter<u64>>,

    gc_tx: Sender<u64>,

    #[cfg(feature = "channel_monitoring")]
    channel_monitor: Arc<Mutex<ChannelMonitor>>,

    phantom: PhantomData<&'a E>,
}


impl<'a, E: AppEngine + Send + Sync + 'a> Application<'a, E> {
    pub fn new(
        config: AtomicConfig,
        staging_rx: Receiver<AppCommand>, unlogged_rx: Receiver<(ProtoTransaction, oneshot::Sender<ProtoTransactionResult>)>,
        client_reply_tx: Sender<ClientReplyCommand>, issuer_tx: Sender<IssuerCommand>, gc_tx: Sender<u64>,

        #[cfg(feature = "extra_2pc")]
        twopc_tx: Sender<(ProtoTransaction, oneshot::Sender<ProtoTransactionResult>)>,
        #[cfg(feature = "channel_monitoring")]
        channel_monitor: Arc<Mutex<ChannelMonitor>>,
        #[cfg(feature = "policy_validation")]
        validation_rx: Receiver<TxWithValidationAck>,
    ) -> Self {
        let checkpoint_timer = ResettableTimer::new(Duration::from_millis(config.get().app_config.checkpoint_interval_ms));
        let log_timer = ResettableTimer::new(Duration::from_millis(config.get().app_config.logger_stats_report_ms));
        let engine = E::new(config.clone());

        let event_order = vec![
            "Process Crash Committed Block",
            "Send Reply",
        ];
        let perf_counter = RefCell::new(PerfCounter::new("Application", &event_order));
        Self {
            _config: config,
            engine,
            stats: LogStats::new(),
            staging_rx,
            unlogged_rx,
            client_reply_tx,
            issuer_tx,
            checkpoint_timer,
            log_timer,
            perf_counter,
            gc_tx,

            #[cfg(feature = "extra_2pc")]
            twopc_tx,

            phantom: PhantomData,
            
            #[cfg(feature = "channel_monitoring")]
            channel_monitor: channel_monitor,
            #[cfg(feature = "policy_validation")]
            validation_rx,
        }
    }

    pub async fn run(application: Arc<Mutex<Self>>) {
        let mut application = application.lock().await;

        let log_timer_handle = application.log_timer.run().await;
        let checkpoint_timer_handle = application.checkpoint_timer.run().await;

        let mut last_perf_logged_ci = 0;
        while let Ok(_) = application.worker().await {
            if (application.stats.ci - last_perf_logged_ci) > 1000 {
                application.perf_counter.borrow().log_aggregate();
                last_perf_logged_ci = application.stats.ci;
            }
        }

        log_timer_handle.abort();
        checkpoint_timer_handle.abort();
    }

    async fn worker(&mut self) -> Result<(), ()> {
        #[cfg(not(feature = "policy_validation"))]
        tokio::select! {
            biased;
            cmd = self.staging_rx.recv() => {
                if cmd.is_none() {
                    return Err(());
                }
                self.handle_staging_command(cmd.unwrap()).await;
            },
            req = self.unlogged_rx.recv() => {
                if req.is_none() {
                    return Err(());
                }

                let (req, reply_tx) = req.unwrap();

                self.handle_unlogged_request(req, reply_tx).await;
            },
            _ = self.checkpoint_timer.wait() => {
                self.checkpoint().await;
            },
            _ = self.log_timer.wait() => {
                self.log_stats().await;
            }
        }
        #[cfg(feature = "policy_validation")]
        tokio::select! {
            biased;
            cmd = self.staging_rx.recv() => {
                if cmd.is_none() {
                    return Err(());
                }
                self.handle_staging_command(cmd.unwrap()).await;
            },
            req = self.unlogged_rx.recv() => {
                if req.is_none() {
                    return Err(());
                }

                let (req, reply_tx) = req.unwrap();

                self.handle_unlogged_request(req, reply_tx).await;
            },
            txwva = self.validation_rx.recv() => {
                if txwva.is_none() {
                    return Err(());
                }
                let (tx, reply_tx) = txwva.unwrap();
                let res = reply_tx.send(self.engine.handle_validation(&tx));
                if res.is_err() {
                    warn!("Validation reply channel closed, skipping validation for tx: {:?}\n{:?}", tx, res.err().unwrap());
                }
            },
            _ = self.checkpoint_timer.wait() => {
                self.checkpoint().await;
            },
            _ = self.log_timer.wait() => {
                self.log_stats().await;
            }
        }

        Ok(())
    }

    /// This is used to compute throughput.
    async fn log_stats(&mut self) {
        self.stats.print();
        
        // Log channel statistics
        #[cfg(feature = "channel_monitoring")]
        {
            let monitor = self.channel_monitor.lock().await;
            monitor.log_stats().await;
        }
    }

    async fn checkpoint(&mut self) {
        let state = self.engine.get_current_state();
        // TODO: Decide on checkpointing strategy

        info!("Current state checkpoint: {}", state);

        // It should be safe to garbage collect all bcied + executed blocks.
        // Since the application is single-threaded and self.bci is set inevitably during the execution,
        // it is safe to gc till self.bci.

        // However, if there is a view change, the policy is to send everything from self.bci onwards (inclusive of self.bci).
        // So we only GC till self.bci - 1.

        if self.stats.bci > 1 {
            self.gc_tx.send(self.stats.bci - 1).await.unwrap();
            let _ = self.issuer_tx.send(IssuerCommand::GC(self.stats.bci)).await;
        } 

    }

    async fn handle_unlogged_request(&mut self, request: ProtoTransaction, reply_tx: oneshot::Sender<ProtoTransactionResult>) {
        #[cfg(feature = "extra_2pc")]
        {
            if request.is_2pc {
                self.twopc_tx.send((request, reply_tx)).await.unwrap();
                self.stats.total_2pc_txs += 1;
                return;
            }
        }

        
        let result = self.engine.handle_unlogged_request(request);
        self.stats.total_requests += 1;
        self.stats.total_unlogged_txs += 1;

        reply_tx.send(result).unwrap();
    }

    fn perf_register(&mut self, entry: u64) {
        self.perf_counter.borrow_mut().register_new_entry(entry);
    }

    fn perf_deregister(&mut self, entry: u64) {
        self.perf_counter.borrow_mut().deregister_entry(&entry);
    }

    fn perf_add_event(&mut self, entry: u64, event: &str) {
        self.perf_counter.borrow_mut().new_event(event, &entry);
    }




    async fn handle_staging_command(&mut self, cmd: AppCommand) {
        match cmd {
            AppCommand::NewRequestBatch(n, view, view_is_stable, i_am_leader, length, last_hash) => {
                self.stats.last_n = n;
                self.stats.view = view;
                self.stats.view_is_stable = view_is_stable;
                self.stats.i_am_leader = i_am_leader;
                self.stats.last_hash = last_hash;

                self.stats.total_requests += length as u64;

                if self.stats.last_n % 1000 == 0 {
                    // This is necessary for manual sanity checks.
                    self.stats.print();
                }

                self.perf_register(n);
            },
            AppCommand::CrashCommit(blocks) => {
                let mut new_ci = self.stats.ci;
                let mut new_last_qc = self.stats.last_qc;
                let (block_hashes, block_ns) = blocks.iter().map(|block| {
                    if new_ci < block.block.n {
                        new_ci = block.block.n;
                    }

                    for qc in &block.block.qc {
                        if new_last_qc < qc.n {
                            new_last_qc = qc.n;
                        }
                    }
                    (block.block_hash.clone(), block.block.n)
                }).collect::<(Vec<_>, Vec<_>)>();

                let _ = self.issuer_tx.send(IssuerCommand::NewChunk(blocks.clone())).await;

                let results = self.engine.handle_crash_commit(blocks);
                
                for n in &block_ns {
                    self.perf_add_event(*n, "Process Crash Committed Block");
                }

                self.stats.total_crash_committed_txs += results.iter().map(|e| e.len() as u64).sum::<u64>();
                self.stats.ci = new_ci;
                self.stats.last_qc = new_last_qc;

                assert_eq!(block_hashes.len(), results.len());

                let block_ns_cp = block_ns.clone();
                let result_map = block_hashes.into_iter().zip( // (HashType, (u64, Vec<ProtoTransactionResult>)) ---> HashMap<HashType, (u64, Vec<ProtoTransactionResult>)>
                    block_ns.into_iter().zip(results.into_iter()) // (u64, Vec<ProtoTransactionResult>)
                ).collect();
                self.client_reply_tx.send(ClientReplyCommand::CrashCommitAck(result_map, new_last_qc)).await.unwrap();
                for n in block_ns_cp {
                    self.perf_add_event(n, "Send Reply");
                }
            },
            AppCommand::ByzCommit(blocks) => {
                let mut new_bci = self.stats.bci;
                let (block_hashes, block_ns) = blocks.iter().map(|block| {
                    if new_bci < block.block.n {
                        new_bci = block.block.n;
                    }
                    (block.block_hash.clone(), block.block.n)
                }).collect::<(Vec<_>, Vec<_>)>();
                let results = self.engine.handle_byz_commit(blocks);
                self.stats.total_byz_committed_txs += results.iter().map(|e| e.len() as u64).sum::<u64>();
                self.stats.bci = new_bci;

                assert_eq!(block_hashes.len(), results.len());

                let block_ns_cp = block_ns.clone();
                let result_map = block_hashes.into_iter().zip( // (HashType, (u64, Vec<ProtoByzResponse>)) ---> HashMap<HashType, (u64, Vec<ProtoTransactionResult>)>
                    block_ns.into_iter().zip(results.into_iter()) // (u64, Vec<ProtoByzResponse>)
                ).collect();
                self.client_reply_tx.send(ClientReplyCommand::ByzCommitAck(result_map)).await.unwrap();
                
                for n in block_ns_cp {
                    self.perf_deregister(n);
                }

            },
            AppCommand::Rollback(mut new_last_block) => {               
                if new_last_block <= self.stats.bci {
                    new_last_block = self.stats.bci + 1;
                }

                if self.stats.ci > new_last_block {
                    self.stats.ci = new_last_block;
                }

                if self.stats.last_n > new_last_block {
                    warn!("Rolling back to block {}", new_last_block);
                }

                self.stats.last_n = new_last_block;
                let _ = self.issuer_tx.send(IssuerCommand::Rollback(new_last_block)).await;
                self.engine.handle_rollback(new_last_block);
            }
            #[cfg(feature = "policy_validation")]
            AppCommand::Validate(block, reply_tx) => {
                for tx in &block.block.tx_list {
                    let Some(phase) = &tx.on_crash_commit else {
                        continue;
                    };
                    for op in &phase.ops {
                        let result = self.engine.handle_validation(op);
                        if result.is_err() {
                            reply_tx.send(result).unwrap();
                            return;
                        }
                    }
                }
                reply_tx.send(Ok(())).unwrap();
            }
        }
    }
}