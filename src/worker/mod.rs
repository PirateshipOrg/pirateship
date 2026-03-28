pub mod batch_proposer;
mod block_sequencer;
mod block_broadcaster;
mod block_storage;
mod fork_receiver;
mod vote_sender;
pub mod vote_tracker;

use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::ops::Deref;
use std::pin::Pin;
use std::sync::Arc;

use batch_proposer::BatchProposer;
use block_broadcaster::BlockBroadcaster;
use block_sequencer::BlockSequencer;
use block_storage::BlockStorage;
use fork_receiver::ForkReceiver;
use log::{debug, info, warn};
use prost::Message;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use vote_sender::VoteSender;
use vote_tracker::VoteTracker;

use crate::config::{AtomicConfig, Config, StorageConfig};
use crate::consensus::batch_proposal::TxWithAckChanTag;
use crate::crypto::{AtomicKeyStore, CryptoService, KeyStore};
use crate::proto::consensus::{ProtoAppendEntries, ProtoWorkerVote};
use crate::proto::rpc::ProtoPayload;
use crate::rpc::client::Client;
use crate::rpc::server::{MsgAckChan, RespType, Server, ServerContextType};
use crate::rpc::{MessageRef, SenderType};
use crate::utils::channel::{make_channel, Sender};
use crate::utils::RocksDBStorageEngine;

pub struct WorkerServerContext {
    #[allow(dead_code)]
    config: AtomicConfig,
    keystore: AtomicKeyStore,
    batch_proposer_tx: Sender<TxWithAckChanTag>,
    incoming_block_txs: HashMap<String, Sender<(ProtoAppendEntries, SenderType)>>,
    vote_tx: Sender<ProtoWorkerVote>,
}

#[derive(Clone)]
pub struct PinnedWorkerServerContext(pub Arc<Pin<Box<WorkerServerContext>>>);

impl PinnedWorkerServerContext {
    pub fn new(
        config: AtomicConfig,
        keystore: AtomicKeyStore,
        batch_proposer_tx: Sender<TxWithAckChanTag>,
        incoming_block_txs: HashMap<String, Sender<(ProtoAppendEntries, SenderType)>>,
        vote_tx: Sender<ProtoWorkerVote>,
    ) -> Self {
        Self(Arc::new(Box::pin(WorkerServerContext {
            config,
            keystore,
            batch_proposer_tx,
            incoming_block_txs,
            vote_tx,
        })))
    }
}

impl Deref for PinnedWorkerServerContext {
    type Target = WorkerServerContext;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ServerContextType for PinnedWorkerServerContext {
    fn get_server_keys(&self) -> Arc<Box<KeyStore>> {
        self.keystore.get()
    }

    async fn handle_rpc(
        &self,
        m: MessageRef<'_>,
        ack_chan: MsgAckChan,
    ) -> Result<RespType, Error> {
        let sender = match m.2 {
            SenderType::Anon => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "unauthenticated message",
                ));
            }
            _sender @ SenderType::Auth(_, _) => _sender.clone(),
        };

        let body = match ProtoPayload::decode(&m.0.as_slice()[0..m.1]) {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    "Worker: parsing problem: {} ... Dropping connection",
                    e.to_string()
                );
                debug!("Original message: {:?} {:?}", &m.0, &m.1);
                return Err(Error::new(ErrorKind::InvalidData, e));
            }
        };

        let msg = match body.message {
            Some(m) => m,
            None => {
                warn!("Worker: nil message: {}", m.1);
                return Ok(RespType::NoResp);
            }
        };


        match msg {
            crate::proto::rpc::proto_payload::Message::ClientRequest(req) => {
                let client_tag = req.client_tag;
                self.batch_proposer_tx
                    .send((req.tx, (ack_chan, client_tag, sender)))
                    .await
                    .expect("batch_proposer_tx send error");
                return Ok(RespType::Resp);
            }
            crate::proto::rpc::proto_payload::Message::WorkerBlock(ae) => {
                let sender_name = sender.to_name_and_sub_id().0;
                if let Some(tx) = self.incoming_block_txs.get(&sender_name) {
                    tx.send((ae, sender))
                        .await
                        .expect("incoming_block_tx send error");
                } else {
                    warn!("Worker: received block from unknown sender: {}", sender_name);
                }
                return Ok(RespType::NoResp);
            }
            crate::proto::rpc::proto_payload::Message::WorkerVote(vote) => {
                self.vote_tx
                    .send(vote)
                    .await
                    .expect("vote_tx send error");
                return Ok(RespType::NoResp);
            }
            _ => {
                warn!("Worker: unexpected message type");
                return Ok(RespType::NoResp);
            }
        }
    }
}

pub struct WorkerNode {
    #[allow(dead_code)]
    config: AtomicConfig,
    #[allow(dead_code)]
    keystore: AtomicKeyStore,

    server: Arc<Server<PinnedWorkerServerContext>>,
    #[allow(dead_code)]
    crypto: CryptoService,

    batch_proposer: Arc<Mutex<BatchProposer>>,
    block_sequencer: Arc<Mutex<BlockSequencer>>,
    block_broadcaster: Arc<Mutex<BlockBroadcaster>>,
    fork_receivers: Vec<Arc<Mutex<ForkReceiver>>>,
    block_storage: Arc<Mutex<BlockStorage>>,
    vote_sender: Arc<Mutex<VoteSender>>,
    vote_tracker: Arc<Mutex<VoteTracker>>,
}

impl WorkerNode {
    pub fn new(config: Config) -> Self {
        let chan_depth = config.rpc_config.channel_depth as usize;
        let num_crypto_tasks = config.consensus_config.num_crypto_workers;

        let key_store = KeyStore::new(
            &config.rpc_config.allowed_keylist_path,
            &config.rpc_config.signing_priv_key_path,
        );
        let config = AtomicConfig::new(config);
        let keystore = AtomicKeyStore::new(key_store);

        let mut crypto = CryptoService::new(num_crypto_tasks, keystore.clone(), config.clone());
        crypto.run();

        let broadcaster_client = Client::new_atomic(
            config.clone(),
            keystore.clone(),
            false,
            0,
        );

        let (batch_proposer_tx, batch_proposer_rx) = make_channel(chan_depth);
        let (block_maker_tx, block_maker_rx) = make_channel(chan_depth);
        let (broadcaster_tx, broadcaster_rx) = make_channel(chan_depth);
        let (storage_tx, storage_rx) = make_channel(chan_depth);
        let (vote_sender_tx, vote_sender_rx) = make_channel(chan_depth);
        let (vote_register_tx, vote_register_rx) = make_channel(chan_depth);
        let (vote_tx, vote_rx) = make_channel(chan_depth);

        let my_name = config.get().net_config.name.clone();
        let learner_list: Vec<String> = config
            .get()
            .consensus_config
            .learner_list
            .iter()
            .filter(|n| *n != &my_name)
            .cloned()
            .collect();

        let mut incoming_block_txs: HashMap<String, Sender<(ProtoAppendEntries, SenderType)>> =
            HashMap::new();
        let mut fork_receivers: Vec<Arc<Mutex<ForkReceiver>>> = Vec::new();

        for learner in &learner_list {
            let (incoming_block_tx, incoming_block_rx) = make_channel(chan_depth);
            incoming_block_txs.insert(learner.clone(), incoming_block_tx);
            fork_receivers.push(Arc::new(Mutex::new(ForkReceiver::new(
                incoming_block_rx,
                storage_tx.clone(),
            ))));
        }

        let sequencer_crypto = crypto.get_connector();

        let ctx = PinnedWorkerServerContext::new(
            config.clone(),
            keystore.clone(),
            batch_proposer_tx,
            incoming_block_txs,
            vote_tx,
        );

        let batch_proposer = BatchProposer::new(
            config.clone(),
            batch_proposer_rx,
            block_maker_tx,
        );

        let block_sequencer = BlockSequencer::new(
            config.clone(),
            sequencer_crypto,
            block_maker_rx,
            broadcaster_tx,
            vote_register_tx,
        );

        let vote_sender_client = Client::new_atomic(
            config.clone(),
            keystore.clone(),
            false,
            0,
        );

        let block_broadcaster = BlockBroadcaster::new(
            config.clone(),
            broadcaster_client.into(),
            broadcaster_rx,
        );

        let storage_config = config.get().consensus_config.log_storage_config.clone();
        let storage_config = match storage_config {
            StorageConfig::RocksDB(config) => {
                let mut final_config = config.clone();
                final_config.db_path = format!("{}_worker", config.db_path);
                StorageConfig::RocksDB(final_config)
            }
            StorageConfig::FileStorage(_) => {
                panic!("File storage not supported!");
            }
        };
        let db = RocksDBStorageEngine::new(storage_config);

        let block_storage = BlockStorage::new(
            config.clone(),
            db,
            storage_rx,
            vote_sender_tx,
        );

        let vote_sender = VoteSender::new(
            vote_sender_client.into(),
            vote_sender_rx,
        );

        let vote_tracker = VoteTracker::new(
            config.clone(),
            vote_register_rx,
            vote_rx,
        );

        Self {
            config: config.clone(),
            keystore: keystore.clone(),
            server: Arc::new(Server::new_atomic(config.clone(), ctx, keystore.clone())),
            crypto,
            batch_proposer: Arc::new(Mutex::new(batch_proposer)),
            block_sequencer: Arc::new(Mutex::new(block_sequencer)),
            block_broadcaster: Arc::new(Mutex::new(block_broadcaster)),
            fork_receivers,
            block_storage: Arc::new(Mutex::new(block_storage)),
            vote_sender: Arc::new(Mutex::new(vote_sender)),
            vote_tracker: Arc::new(Mutex::new(vote_tracker)),
        }
    }

    pub async fn run(&mut self) -> JoinSet<()> {
        let server = self.server.clone();
        let batch_proposer = self.batch_proposer.clone();
        let block_sequencer = self.block_sequencer.clone();
        let block_broadcaster = self.block_broadcaster.clone();
        let fork_receivers = self.fork_receivers.clone();
        let block_storage = self.block_storage.clone();
        let vote_sender = self.vote_sender.clone();
        let vote_tracker = self.vote_tracker.clone();

        let mut handles = JoinSet::new();

        handles.spawn(async move {
            info!("Running server");
            let err = Server::<PinnedWorkerServerContext>::run(server).await;
            info!("Server error: {:?}", err);
            panic!("Server error: {:?}", err);
        });

        handles.spawn(async move {
            BatchProposer::run(batch_proposer).await;
        });

        handles.spawn(async move {
            BlockSequencer::run(block_sequencer).await;
        });

        handles.spawn(async move {
            BlockBroadcaster::run(block_broadcaster).await;
        });

        for fork_receiver in fork_receivers {
            handles.spawn(async move {
                ForkReceiver::run(fork_receiver).await;
            });
        }

        handles.spawn(async move {
            BlockStorage::run(block_storage).await;
        });

        handles.spawn(async move {
            VoteSender::run(vote_sender).await;
        });

        handles.spawn(async move {
            VoteTracker::run(vote_tracker).await;
        });

        handles
    }
}
