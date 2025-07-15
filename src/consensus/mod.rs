pub mod batch_proposal;
mod block_sequencer;
mod block_broadcaster;
mod staging;
pub mod fork_receiver;
pub mod app;
pub mod engines;
pub mod client_reply;
mod logserver;
mod pacemaker;
mod issuer;
pub mod extra_2pc;
#[cfg(feature = "channel_monitoring")]
mod channel_monitor;

// #[cfg(test)]
// mod tests;

use std::{io::{Error, ErrorKind}, ops::Deref, pin::Pin, sync::Arc};

use app::{AppEngine, Application};
use batch_proposal::{BatchProposer, TxWithAckChanTag};
use block_broadcaster::BlockBroadcaster;
use block_sequencer::BlockSequencer;
use client_reply::ClientReplyHandler;
use extra_2pc::TwoPCHandler;
use fork_receiver::{ForkReceiver, ForkReceiverCommand};
use log::{debug, info, warn};
use logserver::LogServer;
use issuer::Issuer;
use pacemaker::Pacemaker;
use prost::Message;
use staging::{Staging, VoteWithSender};
use tokio::{sync::{mpsc::unbounded_channel, Mutex}, task::JoinSet};
#[cfg(feature = "channel_monitoring")]
use channel_monitor::ChannelMonitor;
#[cfg(feature = "policy_validation")]
use crate::consensus::app::TxWithValidationAck;
use crate::{proto::{checkpoint::ProtoBackfillNack, consensus::{ProtoAppendEntries, ProtoViewChange}}, rpc::{client::Client, SenderType}, utils::{channel::{make_channel, Receiver, Sender}, RocksDBStorageEngine, StorageService}};

use crate::{config::{AtomicConfig, Config}, crypto::{AtomicKeyStore, CryptoService, KeyStore}, proto::rpc::ProtoPayload, rpc::{server::{MsgAckChan, RespType, Server, ServerContextType}, MessageRef}};

pub struct ConsensusServerContext {
    config: AtomicConfig,
    keystore: AtomicKeyStore,
    batch_proposal_tx: Sender<TxWithAckChanTag>,
    fork_receiver_tx: Sender<(ProtoAppendEntries, SenderType)>,
    fork_receiver_command_tx: Sender<ForkReceiverCommand>,
    vote_receiver_tx: Sender<VoteWithSender>,
    view_change_receiver_tx: Sender<(ProtoViewChange, SenderType)>,
    backfill_request_tx: Sender<ProtoBackfillNack>,
}


#[derive(Clone)]
pub struct PinnedConsensusServerContext(pub Arc<Pin<Box<ConsensusServerContext>>>);

impl PinnedConsensusServerContext {
    pub fn new(
        config: AtomicConfig, keystore: AtomicKeyStore,
        batch_proposal_tx: Sender<TxWithAckChanTag>,
        fork_receiver_tx: Sender<(ProtoAppendEntries, SenderType)>,
        fork_receiver_command_tx: Sender<ForkReceiverCommand>,
        vote_receiver_tx: Sender<VoteWithSender>,
        view_change_receiver_tx: Sender<(ProtoViewChange, SenderType)>,
        backfill_request_tx: Sender<ProtoBackfillNack>,
    ) -> Self {
        Self(Arc::new(Box::pin(ConsensusServerContext {
            config, keystore, batch_proposal_tx,
            fork_receiver_tx, fork_receiver_command_tx,
            vote_receiver_tx, view_change_receiver_tx,
            backfill_request_tx,
        })))
    }
}

impl Deref for PinnedConsensusServerContext {
    type Target = ConsensusServerContext;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}


impl ServerContextType for PinnedConsensusServerContext {
    fn get_server_keys(&self) -> std::sync::Arc<Box<crate::crypto::KeyStore>> {
        self.keystore.get()
    }

    async fn handle_rpc(&self, m: MessageRef<'_>, ack_chan: MsgAckChan) -> Result<RespType, Error> {
        let sender = match m.2 {
            crate::rpc::SenderType::Anon => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "unauthenticated message",
                )); // Anonymous replies shouldn't come here
            }
            _sender @ crate::rpc::SenderType::Auth(_, _) => _sender.clone()
        };
        let body = match ProtoPayload::decode(&m.0.as_slice()[0..m.1]) {
            Ok(b) => b,
            Err(e) => {
                warn!("Parsing problem: {} ... Dropping connection", e.to_string());
                debug!("Original message: {:?} {:?}", &m.0, &m.1);
                return Err(Error::new(ErrorKind::InvalidData, e));
            }
        };
    
        let msg = match body.message {
            Some(m) => m,
            None => {
                warn!("Nil message: {}", m.1);
                return Ok(RespType::NoResp);
            }
        };

        match msg {
            crate::proto::rpc::proto_payload::Message::ViewChange(proto_view_change) => {
                        self.view_change_receiver_tx.send((proto_view_change, sender)).await
                            .expect("Channel send error");
                        return Ok(RespType::NoResp);
                    },
            crate::proto::rpc::proto_payload::Message::AppendEntries(proto_append_entries) => {
                        // info!("Received append entries from {:?}. Size: {}", sender, proto_append_entries.encoded_len());
                        if proto_append_entries.is_backfill_response {
                            self.fork_receiver_command_tx.send(ForkReceiverCommand::UseBackfillResponse(proto_append_entries, sender)).await
                                .expect("Channel send error");
                        } else {
                            self.fork_receiver_tx.send((proto_append_entries, sender)).await
                                .expect("Channel send error");
                        }
                        return Ok(RespType::NoResp);
                    },
            crate::proto::rpc::proto_payload::Message::Vote(proto_vote) => {
                        self.vote_receiver_tx.send((sender, proto_vote)).await
                            .expect("Channel send error");
                        return Ok(RespType::NoResp);
                    },
            crate::proto::rpc::proto_payload::Message::ClientRequest(proto_client_request) => {
                        let client_tag = proto_client_request.client_tag;
                        self.batch_proposal_tx.send((proto_client_request.tx, (ack_chan, client_tag, sender))).await
                            .expect("Channel send error");

                        return Ok(RespType::Resp);
                    },
            crate::proto::rpc::proto_payload::Message::BackfillRequest(proto_back_fill_request) => {},
            crate::proto::rpc::proto_payload::Message::BackfillResponse(proto_back_fill_response) => {},
            crate::proto::rpc::proto_payload::Message::BackfillNack(proto_backfill_nack) => {
                        self.backfill_request_tx.send(proto_backfill_nack).await
                            .expect("Channel send error");
                        return Ok(RespType::NoResp);
            },
        }



        Ok(RespType::NoResp)
    }
}

pub struct ConsensusNode<E: AppEngine + Send + Sync + 'static> {
    config: AtomicConfig,
    keystore: AtomicKeyStore,

    server: Arc<Server<PinnedConsensusServerContext>>,
    storage: Arc<Mutex<StorageService<RocksDBStorageEngine>>>,
    crypto: CryptoService,


    /// This will be owned by the task that runs batch_proposer
    /// So the lock will be taken exactly ONCE and held forever.
    batch_proposer: Arc<Mutex<BatchProposer>>,
    block_sequencer: Arc<Mutex<BlockSequencer>>,
    block_broadcaster: Arc<Mutex<BlockBroadcaster>>,
    staging: Arc<Mutex<Staging>>,
    fork_receiver: Arc<Mutex<ForkReceiver>>,
    app: Arc<Mutex<Application<'static, E>>>,
    client_reply: Arc<Mutex<ClientReplyHandler>>,
    logserver: Arc<Mutex<LogServer>>,
    pacemaker: Arc<Mutex<Pacemaker>>,
    issuer: Arc<Mutex<Issuer>>,

    #[cfg(feature = "extra_2pc")]
    extra_2pc: Arc<Mutex<TwoPCHandler>>,

    #[cfg(feature = "channel_monitoring")]
    channel_monitor: Arc<Mutex<ChannelMonitor>>,


    /// TODO: When all wiring is done, this will be empty.
    __sink_handles: JoinSet<()>,


    /// Use this to feed transactions from within the same process.
    pub batch_proposer_tx: Sender<TxWithAckChanTag>,
}

impl<E: AppEngine + Send + Sync> ConsensusNode<E> {
    pub fn new(config: Config) -> Self {
        let (batch_proposer_tx, batch_proposer_rx) = make_channel(config.rpc_config.channel_depth as usize);
        #[cfg(feature = "policy_validation")]
        let (validator_tx, validator_rx) = make_channel(config.rpc_config.channel_depth as usize);
        Self::mew(config, batch_proposer_tx, batch_proposer_rx, 
            #[cfg(feature = "policy_validation")]
            validator_rx
        )
    }
    
    /// mew() must be called from within a Tokio context with channel passed in.
    /// This is new()'s cat brother.
    ///
    ///  /\_/\
    /// ( o.o )
    ///  > ^ < 
    pub fn mew(config: Config, batch_proposer_tx: Sender<TxWithAckChanTag>, batch_proposer_rx: Receiver<TxWithAckChanTag>,
        #[cfg(feature = "policy_validation")]
        validator_rx: Receiver<TxWithValidationAck>
    ) -> Self {
        let _chan_depth = config.rpc_config.channel_depth as usize;
        let _num_crypto_tasks = config.consensus_config.num_crypto_workers;

        let key_store = KeyStore::new(
            &config.rpc_config.allowed_keylist_path,
            &config.rpc_config.signing_priv_key_path,
        );
        let config = AtomicConfig::new(config);
        let keystore = AtomicKeyStore::new(key_store);
        let mut crypto = CryptoService::new(_num_crypto_tasks, keystore.clone(), config.clone());
        crypto.run();
        let storage_config = &config.get().consensus_config.log_storage_config;
        let storage = match storage_config {
            rocksdb_config @ crate::config::StorageConfig::RocksDB(_) => {
                let _db = RocksDBStorageEngine::new(rocksdb_config.clone());
                StorageService::new(_db, _chan_depth)
            },
            crate::config::StorageConfig::FileStorage(_) => {
                panic!("File storage not supported!");
            },
        };

        let client = Client::new_atomic(config.clone(), keystore.clone(), false, 0);
        let staging_client = Client::new_atomic(config.clone(), keystore.clone(), false, 0);
        let logserver_client = Client::new_atomic(config.clone(), keystore.clone(), false, 0);
        let pacemaker_client = Client::new_atomic(config.clone(), keystore.clone(), false, 0);
        let fork_receiver_client = Client::new_atomic(config.clone(), keystore.clone(), false, 0);

        #[cfg(feature = "extra_2pc")]
        let extra_2pc_client = Client::new_atomic(config.clone(), keystore.clone(), true, 50);

        // let (batch_proposer_tx, batch_proposer_rx) = make_channel(_chan_depth);
        let (batch_proposer_command_tx, batch_proposer_command_rx) = make_channel(_chan_depth);

        let (block_maker_tx, block_maker_rx) = make_channel(_chan_depth);
        let (control_command_tx, control_command_rx) = make_channel(_chan_depth);
        let (qc_tx, qc_rx) = unbounded_channel();
        let (block_broadcaster_tx, block_broadcaster_rx) = make_channel(_chan_depth);
        let (other_block_tx, other_block_rx) = make_channel(_chan_depth);
        let (client_reply_tx, client_reply_rx) = make_channel(_chan_depth);
        let (client_reply_command_tx, client_reply_command_rx) = make_channel(_chan_depth);
        let (broadcaster_control_command_tx, broadcaster_control_command_rx) = make_channel(_chan_depth);
        let (staging_tx, staging_rx) = make_channel(_chan_depth);
        let (logserver_tx, logserver_rx) = make_channel(_chan_depth);
        let (vote_tx, vote_rx) = make_channel(_chan_depth);
        let (view_change_tx, view_change_rx) = make_channel(_chan_depth);
        let (pacemaker_cmd_tx, pacemaker_cmd_rx) = make_channel(_chan_depth);
        let (pacemaker_cmd_tx2, pacemaker_cmd_rx2) = make_channel(_chan_depth);

        let (app_tx, app_rx) = make_channel(_chan_depth);
        let (fork_receiver_command_tx, fork_receiver_command_rx) = make_channel(_chan_depth);
        let (fork_tx, fork_rx) = make_channel(_chan_depth);
        let (unlogged_tx, unlogged_rx) = make_channel(_chan_depth);
        let (backfill_request_tx, backfill_request_rx) = make_channel(_chan_depth);
        let (gc_tx, gc_rx) = make_channel(_chan_depth);
        let (logserver_query_tx, logserver_query_rx) = make_channel(_chan_depth);
        let (issuer_tx, issuer_rx) = make_channel(_chan_depth);

        let block_maker_crypto = crypto.get_connector();
        let block_broadcaster_crypto = crypto.get_connector();
        let block_broadcaster_storage = storage.get_connector(block_broadcaster_crypto);
        let block_broadcaster_crypto2 = crypto.get_connector();
        let logserver_crypto = crypto.get_connector();
        let logserver_storage = storage.get_connector(logserver_crypto);
        let staging_crypto = crypto.get_connector();
        let fork_receiver_crypto = crypto.get_connector();
        let pacemaker_crypto = crypto.get_connector();

        #[cfg(feature = "extra_2pc")]
        let (extra_2pc_command_tx, extra_2pc_command_rx) = make_channel(10 * _chan_depth);
        #[cfg(feature = "extra_2pc")]
        let (extra_2pc_phase_message_tx, extra_2pc_phase_message_rx) = make_channel(10 * _chan_depth);
        #[cfg(feature = "extra_2pc")]
        let (extra_2pc_staging_tx, extra_2pc_staging_rx) = make_channel(10 * _chan_depth);

        let ctx = PinnedConsensusServerContext::new(config.clone(), keystore.clone(), batch_proposer_tx.clone(), fork_tx.clone(), fork_receiver_command_tx.clone(), vote_tx.clone(), view_change_tx.clone(), backfill_request_tx.clone());
        let batch_proposer = BatchProposer::new(config.clone(), batch_proposer_rx, block_maker_tx.clone(), client_reply_command_tx.clone(), unlogged_tx.clone(), batch_proposer_command_rx);
        let block_sequencer = BlockSequencer::new(config.clone(), control_command_rx, block_maker_rx, qc_rx, block_broadcaster_tx.clone(), client_reply_tx.clone(), block_maker_crypto);
        let block_broadcaster = BlockBroadcaster::new(config.clone(), client.into(), block_broadcaster_crypto2, block_broadcaster_rx, other_block_rx, broadcaster_control_command_rx, block_broadcaster_storage, staging_tx.clone(), fork_receiver_command_tx.clone(), app_tx.clone());
        let staging = Staging::new(config.clone(), staging_client.into(), staging_crypto, staging_rx, vote_rx, pacemaker_cmd_rx, pacemaker_cmd_tx2.clone(), client_reply_command_tx.clone(), app_tx.clone(), broadcaster_control_command_tx.clone(), control_command_tx.clone(), fork_receiver_command_tx.clone(), qc_tx, batch_proposer_command_tx.clone(), logserver_tx.clone(),
            #[cfg(feature = "extra_2pc")]
            extra_2pc_command_tx.clone(),

            #[cfg(feature = "extra_2pc")]
            extra_2pc_staging_rx,
        );
        let issuer = Issuer::new(config.clone(), issuer_rx, logserver_query_tx.clone());
        let fork_receiver = ForkReceiver::new(config.clone(), fork_receiver_crypto, fork_receiver_client.into(), fork_rx, fork_receiver_command_rx, other_block_tx.clone(), logserver_query_tx.clone());
        
        #[cfg(feature = "channel_monitoring")]
        let channel_monitor = {
            let mut channel_mon = ChannelMonitor::new(config.clone());
            channel_mon.register_sender("batch_proposer_command".to_string(), batch_proposer_command_tx.clone());
            channel_mon.register_sender("block_maker".to_string(), block_maker_tx.clone());
            channel_mon.register_sender("control_command".to_string(), control_command_tx.clone());
            channel_mon.register_sender("block_broadcaster".to_string(), block_broadcaster_tx.clone());
            channel_mon.register_sender("other_block".to_string(), other_block_tx.clone());
            channel_mon.register_sender("client_reply".to_string(), client_reply_tx.clone());
            channel_mon.register_sender("client_reply_command".to_string(), client_reply_command_tx.clone());
            channel_mon.register_sender("broadcaster_control_command".to_string(), broadcaster_control_command_tx.clone());
            channel_mon.register_sender("staging".to_string(), staging_tx.clone());
            channel_mon.register_sender("logserver".to_string(), logserver_tx.clone());
            channel_mon.register_sender("vote".to_string(), vote_tx.clone());
            channel_mon.register_sender("view_change".to_string(), view_change_tx.clone());
            channel_mon.register_sender("pacemaker_cmd".to_string(), pacemaker_cmd_tx.clone());
            channel_mon.register_sender("pacemaker_cmd2".to_string(), pacemaker_cmd_tx2.clone());
            channel_mon.register_sender("app".to_string(), app_tx.clone());
            channel_mon.register_sender("fork_receiver_command".to_string(), fork_receiver_command_tx.clone());
            channel_mon.register_sender("fork".to_string(), fork_tx.clone());
            channel_mon.register_sender("unlogged".to_string(), unlogged_tx.clone());
            channel_mon.register_sender("backfill_request".to_string(), backfill_request_tx.clone());
            channel_mon.register_sender("gc".to_string(), gc_tx.clone());
            channel_mon.register_sender("logserver_query".to_string(), logserver_query_tx.clone());
            channel_mon.register_sender("issuer".to_string(), issuer_tx.clone());
            
            #[cfg(feature = "extra_2pc")]
            {
                channel_mon.register_sender("extra_2pc_command".to_string(), extra_2pc_command_tx.clone());
                channel_mon.register_sender("extra_2pc_phase_message".to_string(), extra_2pc_phase_message_tx.clone());
                channel_mon.register_sender("extra_2pc_staging".to_string(), extra_2pc_staging_tx.clone());
            }

            Arc::new(Mutex::new(channel_mon))
        };

        let app = Application::new(config.clone(), app_rx, unlogged_rx, client_reply_command_tx, issuer_tx.clone(), gc_tx,

            #[cfg(feature = "extra_2pc")]
            extra_2pc_phase_message_tx,

            #[cfg(feature = "channel_monitoring")]
            channel_monitor.clone(),

            #[cfg(feature = "policy_validation")]
            validator_rx,
        );

        let client_reply = ClientReplyHandler::new(config.clone(), client_reply_rx, client_reply_command_rx, issuer_tx);
        let logserver = LogServer::new(config.clone(), logserver_client.into(), logserver_rx, backfill_request_rx, gc_rx, logserver_query_rx, logserver_storage);
        let pacemaker = Pacemaker::new(config.clone(), pacemaker_client.into(), pacemaker_crypto, view_change_rx, pacemaker_cmd_tx, pacemaker_cmd_rx2, logserver_query_tx);

        #[cfg(feature = "extra_2pc")]
        let extra_2pc = extra_2pc::TwoPCHandler::new(config.clone(), extra_2pc_client.into(), storage.get_connector(crypto.get_connector()), storage.get_connector(crypto.get_connector()), extra_2pc_command_rx, extra_2pc_phase_message_rx, extra_2pc_staging_tx);

        let mut handles = JoinSet::new();


        Self {
            config: config.clone(),
            keystore: keystore.clone(),
            server: Arc::new(Server::new_atomic(config.clone(), ctx, keystore.clone())),
            batch_proposer: Arc::new(Mutex::new(batch_proposer)),
            block_sequencer: Arc::new(Mutex::new(block_sequencer)),
            block_broadcaster: Arc::new(Mutex::new(block_broadcaster)),
            staging: Arc::new(Mutex::new(staging)),
            fork_receiver: Arc::new(Mutex::new(fork_receiver)),
            client_reply: Arc::new(Mutex::new(client_reply)),
            logserver: Arc::new(Mutex::new(logserver)),
            pacemaker: Arc::new(Mutex::new(pacemaker)),
            issuer: Arc::new(Mutex::new(issuer)),

            #[cfg(feature = "extra_2pc")]
            extra_2pc: Arc::new(Mutex::new(extra_2pc)),

            #[cfg(feature = "channel_monitoring")]
            channel_monitor,

            crypto,
            storage: Arc::new(Mutex::new(storage)),
            __sink_handles: handles,

            app: Arc::new(Mutex::new(app)),

            batch_proposer_tx,
        }
    }

    pub async fn run(&mut self) -> JoinSet<()> {
        let server = self.server.clone();
        let batch_proposer = self.batch_proposer.clone();
        let block_maker = self.block_sequencer.clone();
        let storage = self.storage.clone();
        let block_broadcaster = self.block_broadcaster.clone();
        let staging = self.staging.clone();
        let app = self.app.clone();
        let client_reply = self.client_reply.clone();
        let fork_receiver = self.fork_receiver.clone();
        let logserver = self.logserver.clone();
        let pacemaker = self.pacemaker.clone();
        let issuer = self.issuer.clone();

        let mut handles = JoinSet::new();

        handles.spawn(async move {
            let mut storage = storage.lock().await;
            storage.run().await;
        });

        handles.spawn(async move {
            let _ = Server::<PinnedConsensusServerContext>::run(server).await;
        });

        handles.spawn(async move {
            BatchProposer::run(batch_proposer).await;
        });

        handles.spawn(async move {
            BlockSequencer::run(block_maker).await;
        });

        handles.spawn(async move {
            BlockBroadcaster::run(block_broadcaster).await;
        });
    
        handles.spawn(async move {
            Staging::run(staging).await;
        });

        handles.spawn(async move {
            info!("Booting up application");
            Application::run(app).await;
        });

        handles.spawn(async move {
            ClientReplyHandler::run(client_reply).await;
        });

        handles.spawn(async move {
            ForkReceiver::run(fork_receiver).await;
        });

        handles.spawn(async move {
            LogServer::run(logserver).await;
        });

        handles.spawn(async move {
            Pacemaker::run(pacemaker).await;
        });

        handles.spawn(async move {
            Issuer::run(issuer).await;
        });

        #[cfg(feature = "extra_2pc")]
        {
            let extra_2pc = self.extra_2pc.clone();
            handles.spawn(async move {
                extra_2pc::TwoPCHandler::run(extra_2pc).await;
            });
        }
    
        handles
    }
}
