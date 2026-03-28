use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::sync::Arc;

use log::info;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::config::AtomicConfig;
use crate::consensus::batch_proposal::TxWithAckChanTag;
use crate::crypto::HashType;
use crate::proto::consensus::ProtoWorkerBlockInfo;
use crate::proto::execution::{ProtoTransaction, ProtoTransactionOp, ProtoTransactionOpType, ProtoTransactionPhase};
use crate::rpc::client::PinnedClient;
use crate::rpc::server::LatencyProfile;
use crate::rpc::{PinnedMessage, SenderType};
use crate::utils::channel::{Receiver, Sender};

pub type Cut = HashMap<String, (u64, HashType)>;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CutSerialized {
    pub cut: Vec<(String, u64, HashType)>,
}

impl From<Cut> for CutSerialized {
    fn from(cut: Cut) -> Self {
        Self {
            cut: cut.iter().map(|(k, v)| (k.clone(), v.0, v.1.clone())).collect(),
        }
    }
}

pub struct WorkerHandler {
    config: AtomicConfig,
    client: PinnedClient,

    block_info_rx: Receiver<ProtoWorkerBlockInfo>,
    batch_proposer_tx: Sender<TxWithAckChanTag>,
    worker_acker_tx: Sender<(tokio::sync::mpsc::Receiver<(PinnedMessage, LatencyProfile)>, CutSerialized)>,

    __current_tag: u64,

    /// Latest block seen per worker: worker_name -> (block_n, block_hash)
    cut_seen: Cut,
    /// Latest block proposed per worker: worker_name -> (block_n, block_hash)
    cut_proposed: Cut,
}

impl WorkerHandler {
    pub fn new(
        config: AtomicConfig,
        client: PinnedClient,
        block_info_rx: Receiver<ProtoWorkerBlockInfo>,
        batch_proposer_tx: Sender<TxWithAckChanTag>,
        worker_acker_tx: Sender<(tokio::sync::mpsc::Receiver<(PinnedMessage, LatencyProfile)>, CutSerialized)>,
    ) -> Self {
        Self {
            config,
            client,
            block_info_rx,
            batch_proposer_tx,
            cut_seen: HashMap::new(),
            cut_proposed: HashMap::new(),
            worker_acker_tx,
            __current_tag: 0,
        }
    }

    pub async fn run(handler: Arc<Mutex<Self>>) {
        let mut wh = handler.lock().await;

        loop {
            if let Err(_) = wh.worker().await {
                break;
            }
        }

        info!("Worker handler exited.");
    }

    async fn worker(&mut self) -> Result<(), Error> {
        let incoming = self.block_info_rx.recv().await;
        if incoming.is_none() {
            return Err(Error::new(ErrorKind::BrokenPipe, "block_info_rx closed"));
        }
        let block_info = incoming.unwrap();
        self.handle_block_info(block_info).await
    }

    async fn handle_block_info(&mut self, block_info: ProtoWorkerBlockInfo) -> Result<(), Error> {
        let target = block_info.block_origin.clone();

        // Validate and record the block in cut_seen.
        match self.cut_seen.get(&target) {
            None => {
                // First block from this worker; block_n must be 0.
                assert!(
                    block_info.block_n == 1,
                    "First block from worker {} must have block_n=0, got {}",
                    target, block_info.block_n
                );
            }
            Some(&(prev_n, _)) => {
                assert!(
                    block_info.block_n == prev_n + 1,
                    "Expected block_n={} from worker {}, got {}",
                    prev_n + 1, target, block_info.block_n
                );
            }
        }
        self.cut_seen.insert(target.clone(), (block_info.block_n, block_info.block_hash.clone()));

        self.maybe_propose_cut().await;

        info!(
            "Received block info for block {} from {}",
            block_info.block_n, target
        );

        Ok(())
    }

    const BATCH_SIZE: usize = 10;
    async fn maybe_propose_cut(&mut self) {
        // How many pending blocks are there?
        let pending_blocks = self.cut_seen.keys()
            .map(|k|
                self.cut_seen.get(k).unwrap().0
                - self.cut_proposed.get(k).unwrap_or(&(0, HashType::default())).0
            )
            .sum::<u64>();

        let batch_size = Self::BATCH_SIZE;

        if pending_blocks > batch_size as u64 {
            self.do_propose_cut().await;
        }
    }

    async fn do_propose_cut(&mut self) {
        let cut = CutSerialized::from(self.cut_seen.clone());
        let cut_ser = bincode::serialize(&cut).unwrap();
        let cut_tx = ProtoTransaction {
            on_crash_commit: Some(ProtoTransactionPhase {
                ops: vec![ProtoTransactionOp {
                    op_type: ProtoTransactionOpType::Noop.into(),
                    operands: vec![cut_ser],
                }],
            }),
            on_byzantine_commit: None,
            is_reconfiguration: false,
            is_2pc: false,
            on_receive: None,
        };

        let (tx, ack_rx) = tokio::sync::mpsc::channel(1);
        self.__current_tag += 1;
        let current_tag = self.__current_tag;
        let tx_with_ack_chan_tag: TxWithAckChanTag = (Some(cut_tx), (tx, current_tag, SenderType::Anon));
        self.batch_proposer_tx.send(tx_with_ack_chan_tag).await.unwrap();

        self.worker_acker_tx.send((ack_rx, cut)).await.unwrap();
    }
}
