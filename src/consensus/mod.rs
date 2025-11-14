pub mod app;
pub mod batch_proposal;
mod block_broadcaster;
mod block_sequencer;
pub mod client_reply;
#[cfg(feature = "dag")]
mod dag;
pub mod engines;
pub mod extra_2pc;
pub mod fork_receiver;
mod logserver;
mod pacemaker;
mod staging;

// #[cfg(test)]
// mod tests;

use std::{
    io::{Error, ErrorKind},
    ops::Deref,
    pin::Pin,
    sync::Arc,
};

use crate::{
    consensus::batch_proposal::{MsgAckChanWithTag, RawBatch},
    proto::{
        checkpoint::ProtoBackfillNack,
        consensus::{ProtoAppendEntries, ProtoViewChange},
    },
    rpc::{client::Client, SenderType},
    utils::{
        channel::{make_channel, Receiver, Sender},
        RocksDBStorageEngine, StorageService,
    },
};

#[cfg(feature = "dag")]
use crate::{
    consensus::dag::{
        block_receiver::BlockReceiver, block_receiver::BlockReceiverCommand, lane_logserver,
        tip_cut_proposal,
    },
    proto::consensus::{
        ProtoAppendBlocks, ProtoBlockAck, ProtoBlockCar, ProtoExecutionResults, ProtoTipCut,
    },
};
use app::{AppEngine, Application};
use batch_proposal::{BatchProposer, TxWithAckChanTag};
use block_broadcaster::BlockBroadcaster;
use block_sequencer::BlockSequencer;
use client_reply::ClientReplyHandler;
use extra_2pc::TwoPCHandler;
use fork_receiver::{ForkReceiver, ForkReceiverCommand};
use log::{debug, info, warn};
use logserver::LogServer;
#[cfg(feature = "dag")]
use lz4_flex::block;
use pacemaker::Pacemaker;
use prost::Message;
use staging::{Staging, VoteWithSender};
use tokio::{
    sync::{mpsc::unbounded_channel, Mutex},
    task::JoinSet,
};

use crate::{
    config::{AtomicConfig, Config},
    crypto::{AtomicKeyStore, CryptoService, KeyStore},
    proto::rpc::ProtoPayload,
    rpc::{
        server::{MsgAckChan, RespType, Server, ServerContextType},
        MessageRef,
    },
};

pub struct ConsensusServerContext {
    config: AtomicConfig,
    keystore: AtomicKeyStore,
    batch_proposal_tx: Sender<TxWithAckChanTag>,
    fork_receiver_tx: Sender<(ProtoAppendEntries, SenderType)>,
    fork_receiver_command_tx: Sender<ForkReceiverCommand>,
    vote_receiver_tx: Sender<VoteWithSender>,
    view_change_receiver_tx: Sender<(ProtoViewChange, SenderType)>,
    backfill_request_tx: Sender<ProtoBackfillNack>,

    // DAG-specific channels
    #[cfg(feature = "dag")]
    block_receiver_tx: Sender<(ProtoAppendBlocks, SenderType)>,
    #[cfg(feature = "dag")]
    block_receiver_command_tx: Sender<BlockReceiverCommand>,
    #[cfg(feature = "dag")]
    block_ack_tx: Sender<(ProtoBlockAck, SenderType)>,
    #[cfg(feature = "dag")]
    car_tx: Sender<(ProtoBlockCar, SenderType)>,
    #[cfg(feature = "dag")]
    tipcut_proposal_tx: Sender<ProtoTipCut>,
    #[cfg(feature = "dag")]
    execution_results_tx: Sender<ProtoExecutionResults>,
}

#[derive(Clone)]
pub struct PinnedConsensusServerContext(pub Arc<Pin<Box<ConsensusServerContext>>>);

impl PinnedConsensusServerContext {
    pub fn new(
        config: AtomicConfig,
        keystore: AtomicKeyStore,
        batch_proposal_tx: Sender<TxWithAckChanTag>,
        fork_receiver_tx: Sender<(ProtoAppendEntries, SenderType)>,
        fork_receiver_command_tx: Sender<ForkReceiverCommand>,
        vote_receiver_tx: Sender<VoteWithSender>,
        view_change_receiver_tx: Sender<(ProtoViewChange, SenderType)>,
        backfill_request_tx: Sender<ProtoBackfillNack>,
        #[cfg(feature = "dag")] block_receiver_tx: Sender<(ProtoAppendBlocks, SenderType)>,
        #[cfg(feature = "dag")] block_receiver_command_tx: Sender<BlockReceiverCommand>,
        #[cfg(feature = "dag")] block_ack_tx: Sender<(ProtoBlockAck, SenderType)>,
        #[cfg(feature = "dag")] car_tx: Sender<(ProtoBlockCar, SenderType)>,
        #[cfg(feature = "dag")] tipcut_proposal_tx: Sender<ProtoTipCut>,
        #[cfg(feature = "dag")] execution_results_tx: Sender<ProtoExecutionResults>,
    ) -> Self {
        Self(Arc::new(Box::pin(ConsensusServerContext {
            config,
            keystore,
            batch_proposal_tx,
            fork_receiver_tx,
            fork_receiver_command_tx,
            vote_receiver_tx,
            view_change_receiver_tx,
            backfill_request_tx,
            #[cfg(feature = "dag")]
            block_receiver_tx,
            #[cfg(feature = "dag")]
            block_receiver_command_tx,
            #[cfg(feature = "dag")]
            block_ack_tx,
            #[cfg(feature = "dag")]
            car_tx,
            #[cfg(feature = "dag")]
            tipcut_proposal_tx,
            #[cfg(feature = "dag")]
            execution_results_tx,
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
            _sender @ crate::rpc::SenderType::Auth(_, _) => _sender.clone(),
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
            // View Change messages are routed to the ViewChange handler
            crate::proto::rpc::proto_payload::Message::ViewChange(proto_view_change) => {
                self.view_change_receiver_tx
                    .send((proto_view_change, sender))
                    .await
                    .expect("Channel send error");
                return Ok(RespType::NoResp);
            }
            // AppendEntries messages are routed to the ForkReceiver
            crate::proto::rpc::proto_payload::Message::AppendEntries(proto_append_entries) => {
                // info!("Received append entries from {:?}. Size: {}", sender, proto_append_entries.encoded_len());
                if proto_append_entries.is_backfill_response {
                    self.fork_receiver_command_tx
                        .send(ForkReceiverCommand::UseBackfillResponse(
                            proto_append_entries,
                            sender,
                        ))
                        .await
                        .expect("Channel send error");
                } else {
                    self.fork_receiver_tx
                        .send((proto_append_entries, sender))
                        .await
                        .expect("Channel send error");
                }
                return Ok(RespType::NoResp);
            }
            // AppendBlock messages are routed to the BlockReceiver in DAG-mode, otherwise ignored
            crate::proto::rpc::proto_payload::Message::AppendBlocks(proto_append_blocks) => {
                #[cfg(feature = "dag")]
                {
                    if proto_append_blocks.is_backfill_response {
                        // Extract sender name for lane identification
                        let (sender_name, _) = sender.to_name_and_sub_id();
                        warn!("Received is_backfill AppendBlocks message without AppendBlockLane wrapper from {}", sender_name);
                        return Ok(RespType::NoResp);
                    } else {
                        self.block_receiver_tx
                            .send((proto_append_blocks, sender))
                            .await
                            .expect("Channel send error");
                    }
                }

                #[cfg(not(feature = "dag"))]
                {
                    warn!("Received AppendBlock in non-DAG mode - ignoring");
                }
                return Ok(RespType::NoResp);
            }
            // AppendBlockLane messages are routed to the BlockReceiver in DAG-mode, otherwise ignored
            crate::proto::rpc::proto_payload::Message::AppendBlockLane(proto_append_block_lane) => {
                #[cfg(feature = "dag")]
                {
                    if proto_append_block_lane
                        .ab
                        .as_ref()
                        .map_or(false, |ab| ab.is_backfill_response)
                    {
                        self.block_receiver_command_tx
                            .send(BlockReceiverCommand::UseBackfillResponse(
                                proto_append_block_lane,
                                sender,
                            ))
                            .await
                            .expect("Channel send error");
                    } else {
                        warn!(
                            "Received AppendBlockLane without is_backfill set from {:?}. Size: {}",
                            sender,
                            proto_append_block_lane.encoded_len()
                        );
                        return Ok(RespType::NoResp);
                        // QUESTION: Should we handle these messages differently?
                        // self.block_receiver_tx
                        //     .send((proto_append_block_lane.ab.unwrap(), sender))
                        //     .await
                        //     .expect("Channel send error");
                    }
                }

                #[cfg(not(feature = "dag"))]
                {
                    warn!("Received AppendBlockLane in non-DAG mode - ignoring");
                }
                return Ok(RespType::NoResp);
            }
            // BlockAck messages are routed to the BlockAck handler in DAG-mode, otherwise ignored
            crate::proto::rpc::proto_payload::Message::BlockAck(proto_block_ack) => {
                #[cfg(feature = "dag")]
                {
                    self.block_ack_tx
                        .send((proto_block_ack, sender))
                        .await
                        .expect("Channel send error");
                }
                #[cfg(not(feature = "dag"))]
                {
                    warn!("Received BlockAck in non-DAG mode - ignoring");
                }
                return Ok(RespType::NoResp);
            }
            // BlockCAR messages are routed to the LaneStaging in DAG-mode, otherwise ignored
            crate::proto::rpc::proto_payload::Message::BlockCar(proto_block_car) => {
                #[cfg(feature = "dag")]
                {
                    // Forward to LaneStaging for CAR aggregation and tip cut formation
                    debug!(
                        "Received BlockCAR for block n={} from origin {}",
                        proto_block_car.n, proto_block_car.origin_node
                    );

                    self.car_tx
                        .send((proto_block_car, sender))
                        .await
                        .expect("Failed to send BlockCAR to LaneStaging");
                }
                #[cfg(not(feature = "dag"))]
                {
                    warn!("Received BlockCAR in leader mode - ignoring");
                }

                return Ok(RespType::NoResp);
            }
            // TipCut proposals are routed to the TipCutProposal handler in DAG-mode, otherwise ignored
            crate::proto::rpc::proto_payload::Message::TipCut(proto_tip_cut) => {
                #[cfg(feature = "dag")]
                {
                    self.tipcut_proposal_tx
                        .send(proto_tip_cut)
                        .await
                        .expect("Channel send error");
                }
                #[cfg(not(feature = "dag"))]
                {
                    warn!("Received TipCut in leader mode - ignoring");
                }
                return Ok(RespType::NoResp);
            }
            // ExecutionResults messages are forwarded to ClientReplyHandler in DAG-mode, otherwise ignored
            crate::proto::rpc::proto_payload::Message::ExecutionResults(
                proto_execution_results,
            ) => {
                #[cfg(feature = "dag")]
                {
                    // Forward to client reply handler to match with local reply channels
                    debug!("Received ExecutionResults for block hash {:?}, forwarding to ClientReplyHandler",
                           hex::encode(&proto_execution_results.block_hash));

                    self.execution_results_tx
                        .send(proto_execution_results)
                        .await
                        .expect("Failed to send execution results to ClientReplyHandler");
                }
                #[cfg(not(feature = "dag"))]
                {
                    warn!("Received ExecutionResults in non-DAG mode - ignoring");
                }
                return Ok(RespType::NoResp);
            }
            // Note: TipCut votes now use the regular Vote message (ProtoVote)
            // which supports voting for both Fork and TipCut via the digest field
            crate::proto::rpc::proto_payload::Message::Vote(proto_vote) => {
                self.vote_receiver_tx
                    .send((sender, proto_vote))
                    .await
                    .expect("Channel send error");
                return Ok(RespType::NoResp);
            }
            // Client Requests are routed to batch proposer
            // In DAG-mode, this is dag/batch_proposal::BatchProposer
            crate::proto::rpc::proto_payload::Message::ClientRequest(proto_client_request) => {
                let client_tag = proto_client_request.client_tag;
                self.batch_proposal_tx
                    .send((proto_client_request.tx, (ack_chan, client_tag, sender)))
                    .await
                    .expect("Channel send error");

                return Ok(RespType::Resp);
            }
            crate::proto::rpc::proto_payload::Message::BackfillRequest(proto_back_fill_request) => {
            }
            crate::proto::rpc::proto_payload::Message::BackfillResponse(
                proto_back_fill_response,
            ) => {}
            crate::proto::rpc::proto_payload::Message::BackfillNack(proto_backfill_nack) => {
                self.backfill_request_tx
                    .send(proto_backfill_nack)
                    .await
                    .expect("Channel send error");
                return Ok(RespType::NoResp);
            }
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

    // Traditional mode components
    #[cfg(not(feature = "dag"))]
    batch_proposer: Arc<Mutex<BatchProposer>>,
    // DAG mode components
    #[cfg(feature = "dag")]
    dag_batch_proposer: Arc<Mutex<dag::batch_proposal::BatchProposer>>,
    #[cfg(feature = "dag")]
    dag_block_sequencer: Arc<Mutex<dag::block_sequencer::DagBlockSequencer>>,
    #[cfg(feature = "dag")]
    dag_block_broadcaster: Arc<Mutex<dag::block_broadcaster::DagBlockBroadcaster>>,
    #[cfg(feature = "dag")]
    dag_block_receiver: Arc<Mutex<dag::block_receiver::BlockReceiver>>,
    #[cfg(feature = "dag")]
    dag_lane_staging: Arc<Mutex<dag::lane_staging::LaneStaging>>,
    #[cfg(feature = "dag")]
    dag_lane_logserver: Arc<Mutex<dag::lane_logserver::LaneLogServer>>,
    #[cfg(feature = "dag")]
    dag_tip_cut_proposal: Arc<Mutex<dag::tip_cut_proposal::TipCutProposal>>,

    // Shared components (used in both modes, but behavior may differ)
    block_sequencer: Arc<Mutex<BlockSequencer>>,
    block_broadcaster: Arc<Mutex<BlockBroadcaster>>,
    staging: Arc<Mutex<Staging>>,
    fork_receiver: Arc<Mutex<ForkReceiver>>,
    app: Arc<Mutex<Application<'static, E>>>,
    client_reply: Arc<Mutex<ClientReplyHandler>>,
    logserver: Arc<Mutex<LogServer>>,
    pacemaker: Arc<Mutex<Pacemaker>>,

    #[cfg(feature = "extra_2pc")]
    extra_2pc: Arc<Mutex<TwoPCHandler>>,

    /// TODO: When all wiring is done, this will be empty.
    __sink_handles: JoinSet<()>,

    /// Use this to feed transactions from within the same process.
    pub batch_proposer_tx: Sender<TxWithAckChanTag>,
}

impl<E: AppEngine + Send + Sync> ConsensusNode<E> {
    pub fn new(config: Config) -> Self {
        let (batch_proposer_tx, batch_proposer_rx) =
            make_channel(config.rpc_config.channel_depth as usize);
        Self::mew(config, batch_proposer_tx, batch_proposer_rx)
    }

    /// mew() must be called from within a Tokio context with channel passed in.
    /// This is new()'s cat brother.
    ///
    ///  /\_/\
    /// ( o.o )
    ///  > ^ <
    pub fn mew(
        config: Config,
        batch_proposer_tx: Sender<TxWithAckChanTag>,
        batch_proposer_rx: Receiver<TxWithAckChanTag>,
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
            }
            crate::config::StorageConfig::FileStorage(_) => {
                panic!("File storage not supported!");
            }
        };

        let client = Client::new_atomic(config.clone(), keystore.clone(), false, 0);
        let staging_client = Client::new_atomic(config.clone(), keystore.clone(), false, 0);
        let logserver_client = Client::new_atomic(config.clone(), keystore.clone(), false, 0);
        let pacemaker_client = Client::new_atomic(config.clone(), keystore.clone(), false, 0);
        let fork_receiver_client = Client::new_atomic(config.clone(), keystore.clone(), false, 0);
        #[cfg(feature = "dag")]
        let client_reply = Client::new_atomic(config.clone(), keystore.clone(), false, 0);
        #[cfg(feature = "dag")]
        let dag_block_receiver_client =
            Client::new_atomic(config.clone(), keystore.clone(), false, 0);
        #[cfg(feature = "dag")]
        let dag_block_broadcaster_client =
            Client::new_atomic(config.clone(), keystore.clone(), false, 0);
        #[cfg(feature = "dag")]
        let lane_logserver_client = Client::new_atomic(config.clone(), keystore.clone(), false, 0);
        #[cfg(feature = "dag")]
        let lane_staging_client = Client::new_atomic(config.clone(), keystore.clone(), false, 0);
        #[cfg(feature = "dag")]
        let dag_tip_cut_proposal_client =
            Client::new_atomic(config.clone(), keystore.clone(), false, 0);

        #[cfg(feature = "extra_2pc")]
        let extra_2pc_client = Client::new_atomic(config.clone(), keystore.clone(), true, 50);

        // Batch Proposer commands (dissemination - DAG or traditional)
        let (batch_proposer_command_tx, batch_proposer_command_rx) = make_channel(_chan_depth);
        // BlockSequencer channels (dissemination - traditional)
        #[cfg(not(feature = "dag"))]
        let (block_maker_tx, block_maker_rx) = make_channel(_chan_depth);
        let (control_command_tx, control_command_rx) = make_channel(_chan_depth);
        let (qc_tx, qc_rx) = unbounded_channel();
        // BlockBroadcaster channels (consensus)
        let (block_broadcaster_tx, block_broadcaster_rx) = make_channel(_chan_depth);
        let (other_block_tx, other_block_rx) = make_channel(_chan_depth);
        let (broadcaster_control_command_tx, broadcaster_control_command_rx) =
            make_channel(_chan_depth);
        // ClientReplyHandler channels (consensus)
        let (client_reply_tx, client_reply_rx) = make_channel(_chan_depth);
        let (client_reply_command_tx, client_reply_command_rx) = make_channel(_chan_depth);
        // Staging channels (consensus)
        let (staging_tx, staging_rx) = make_channel(_chan_depth);
        let (vote_tx, vote_rx) = make_channel(_chan_depth);
        let (view_change_tx, view_change_rx) = make_channel(_chan_depth);
        // LogServer channels (consensus)
        let (logserver_tx, logserver_rx) = make_channel(_chan_depth);
        let (logserver_query_tx, logserver_query_rx) = make_channel(_chan_depth);
        let (gc_tx, gc_rx) = make_channel(_chan_depth);
        // Pacemaker channels (both)
        let (pacemaker_cmd_tx, pacemaker_cmd_rx) = make_channel(_chan_depth);
        let (pacemaker_cmd_tx2, pacemaker_cmd_rx2) = make_channel(_chan_depth);
        // App Channels (consensus)
        let (app_tx, app_rx) = make_channel(_chan_depth);
        // ForkReceiver channels (consensus)
        let (fork_receiver_command_tx, fork_receiver_command_rx) = make_channel(_chan_depth);
        let (fork_tx, fork_rx) = make_channel(_chan_depth);
        let (unlogged_tx, unlogged_rx) = make_channel(_chan_depth);
        let (backfill_request_tx, backfill_request_rx) = make_channel(_chan_depth);

        // -- DAG-specific component channels --
        // NOTE: we use batch_proposal channels defined above
        // DAG Block Sequencer (dissemination - DAG)
        #[cfg(feature = "dag")]
        let (dag_block_sequencer_tx, dag_block_sequencer_rx) = make_channel(_chan_depth);
        #[cfg(feature = "dag")]
        let (dag_block_sequencer_control_command_tx, dag_block_sequencer_control_command_rx) =
            make_channel(_chan_depth);
        // DAG Block Receiver (dissemination - DAG)
        #[cfg(feature = "dag")]
        let (dag_block_receiver_tx, dag_block_receiver_rx) = make_channel(_chan_depth);
        #[cfg(feature = "dag")]
        let (dag_block_receiver_command_tx, dag_block_receiver_command_rx) =
            make_channel(_chan_depth);
        #[cfg(feature = "dag")]
        let (lane_backfill_request_tx, lane_backfill_request_rx) = make_channel(_chan_depth);
        // DAG Block Broadcaster (dissemination - DAG)
        #[cfg(feature = "dag")]
        let (dag_block_broadcaster_tx, dag_block_broadcaster_rx) = make_channel(_chan_depth);
        #[cfg(feature = "dag")]
        let (dag_other_block_tx, dag_other_block_rx) = make_channel(_chan_depth);
        #[cfg(feature = "dag")]
        let (dag_broadcaster_control_command_tx, dag_broadcaster_control_command_rx) =
            make_channel(_chan_depth);
        // DAG Lane Staging (dissemination - DAG)
        #[cfg(feature = "dag")]
        let (lane_staging_tx, lane_staging_rx) = make_channel(_chan_depth);
        #[cfg(feature = "dag")]
        let (dag_block_ack_tx, dag_block_ack_rx) = make_channel(_chan_depth);
        #[cfg(feature = "dag")]
        let (dag_car_tx, dag_car_rx) = make_channel(_chan_depth);
        #[cfg(feature = "dag")]
        let (lane_staging_query_tx, lane_staging_query_rx) = make_channel(_chan_depth);
        // DAG Lane LogServer (dissemination - DAG)
        #[cfg(feature = "dag")]
        let (lane_logserver_tx, lane_logserver_rx) = make_channel(_chan_depth);
        #[cfg(feature = "dag")]
        let (lane_logserver_query_tx, lane_logserver_query_rx) = make_channel(_chan_depth);
        #[cfg(feature = "dag")]
        let (lane_gc_tx, lane_gc_rx) = make_channel(_chan_depth);
        // DAG Tip Cut Proposal Handler (dissemination - DAG)
        #[cfg(feature = "dag")]
        let (tip_cut_proposal_tx, tip_cut_proposal_rx) = make_channel(_chan_depth);
        #[cfg(feature = "dag")]
        let (tip_cut_proposal_cmd_tx, tip_cut_proposal_cmd_rx) = make_channel(_chan_depth);
        #[cfg(feature = "dag")]
        let (block_broadcaster_command_tx, block_broadcaster_command_rx) =
            make_channel(_chan_depth);

        // DAG Execution Results handler (consensus - DAG)
        #[cfg(feature = "dag")]
        let (execution_results_tx, execution_results_rx) = make_channel(_chan_depth);

        // Crypto and Storage connectors
        let block_maker_crypto = crypto.get_connector();
        let block_broadcaster_crypto = crypto.get_connector();
        let block_broadcaster_storage = storage.get_connector(block_broadcaster_crypto);
        let block_broadcaster_crypto2 = crypto.get_connector();
        let logserver_crypto = crypto.get_connector();
        let logserver_storage = storage.get_connector(logserver_crypto);
        let staging_crypto = crypto.get_connector();
        let fork_receiver_crypto = crypto.get_connector();
        let pacemaker_crypto = crypto.get_connector();
        #[cfg(feature = "dag")]
        let dag_block_sequencer_crypto = crypto.get_connector();
        #[cfg(feature = "dag")]
        let dag_block_broadcaster_crypto = crypto.get_connector();
        #[cfg(feature = "dag")]
        let dag_block_broadcaster_storage = storage.get_connector(dag_block_broadcaster_crypto);
        #[cfg(feature = "dag")]
        let dag_block_broadcaster_crypto2 = crypto.get_connector();
        #[cfg(feature = "dag")]
        let dag_block_receiver_crypto = crypto.get_connector();
        #[cfg(feature = "dag")]
        let lane_staging_crypto = crypto.get_connector();
        #[cfg(feature = "dag")]
        let lane_logserver_crypto = crypto.get_connector();
        #[cfg(feature = "dag")]
        let lane_logserver_storage = storage.get_connector(lane_logserver_crypto);

        #[cfg(feature = "extra_2pc")]
        let (extra_2pc_command_tx, extra_2pc_command_rx) = make_channel(10 * _chan_depth);
        #[cfg(feature = "extra_2pc")]
        let (extra_2pc_phase_message_tx, extra_2pc_phase_message_rx) =
            make_channel(10 * _chan_depth);
        #[cfg(feature = "extra_2pc")]
        let (extra_2pc_staging_tx, extra_2pc_staging_rx) = make_channel(10 * _chan_depth);

        let ctx = PinnedConsensusServerContext::new(
            config.clone(),
            keystore.clone(),
            batch_proposer_tx.clone(),
            fork_tx,
            fork_receiver_command_tx.clone(),
            vote_tx,
            view_change_tx,
            backfill_request_tx,
            #[cfg(feature = "dag")]
            dag_block_receiver_tx.clone(),
            #[cfg(feature = "dag")]
            dag_block_receiver_command_tx.clone(),
            #[cfg(feature = "dag")]
            dag_block_ack_tx.clone(),
            #[cfg(feature = "dag")]
            dag_car_tx.clone(),
            #[cfg(feature = "dag")]
            tip_cut_proposal_tx.clone(),
            #[cfg(feature = "dag")]
            execution_results_tx.clone(),
        );

        // -- Instantiate DAG Dissemination Layer components first --
        // Dag Batch Proposer
        #[cfg(feature = "dag")]
        let batch_proposer = dag::batch_proposal::BatchProposer::new(
            config.clone(),
            batch_proposer_rx,
            dag_block_sequencer_tx.clone(),
            client_reply_command_tx.clone(),
            unlogged_tx,
            batch_proposer_command_rx,
        );

        // DAG Block Sequencer
        #[cfg(feature = "dag")]
        let dag_block_sequencer = dag::block_sequencer::DagBlockSequencer::new(
            config.clone(),
            dag_block_sequencer_control_command_rx,
            dag_block_sequencer_rx,
            dag_block_broadcaster_tx.clone(),
            client_reply_tx.clone(),
            dag_block_sequencer_crypto,
        );

        // DAG Block Broadcaster
        #[cfg(feature = "dag")]
        let dag_block_broadcaster = dag::block_broadcaster::DagBlockBroadcaster::new(
            config.clone(),
            dag_block_broadcaster_client.into(),
            dag_block_broadcaster_crypto2,
            dag_block_broadcaster_rx,
            dag_other_block_rx,
            dag_broadcaster_control_command_rx,
            dag_block_broadcaster_storage,
            lane_staging_tx,
            dag_block_receiver_command_tx.clone(),
            app_tx.clone(),
        );

        // DAG Block Receiver
        #[cfg(feature = "dag")]
        let block_receiver = dag::block_receiver::BlockReceiver::new(
            config.clone(),
            dag_block_receiver_crypto,
            dag_block_receiver_client.into(),
            dag_block_receiver_rx,
            dag_block_receiver_command_rx,
            dag_other_block_tx,
            lane_logserver_query_tx.clone(),
        );

        // DAG Lane Staging
        #[cfg(feature = "dag")]
        let lane_staging = dag::lane_staging::LaneStaging::new(
            config.clone(),
            lane_staging_client.into(),
            lane_staging_crypto,
            lane_staging_rx,
            dag_block_ack_rx,
            dag_car_rx,
            lane_staging_query_rx,
            client_reply_command_tx.clone(),
            lane_logserver_tx,
        );

        // DAG Lane LogServer
        #[cfg(feature = "dag")]
        let lane_logserver = dag::lane_logserver::LaneLogServer::new(
            config.clone(),
            lane_logserver_client.into(),
            lane_logserver_rx,
            lane_backfill_request_rx,
            lane_gc_rx,
            lane_logserver_query_rx,
            lane_logserver_storage,
        );

        // DAG Tip Cut Proposal Handler
        #[cfg(feature = "dag")]
        let tip_cut_proposal = dag::tip_cut_proposal::TipCutProposal::new(
            config.clone(),
            lane_staging_query_tx.clone(),
            tip_cut_proposal_tx.clone(), // to BlockSequencer
            tip_cut_proposal_cmd_rx,
        );

        // -- Instantiate Consensus components --
        // Traditional Batch Proposer
        #[cfg(not(feature = "dag"))]
        let batch_proposer = BatchProposer::new(
            config.clone(),
            batch_proposer_rx,
            block_maker_tx.clone(),
            client_reply_command_tx.clone(),
            unlogged_tx,
            batch_proposer_command_rx,
        );

        // Traditional Block Sequencer
        let block_sequencer = BlockSequencer::new(
            config.clone(),
            control_command_rx,
            #[cfg(not(feature = "dag"))]
            block_maker_rx,
            #[cfg(feature = "dag")]
            tip_cut_proposal_rx,
            qc_rx,
            block_broadcaster_tx.clone(),
            client_reply_tx.clone(),
            block_maker_crypto,
            #[cfg(feature = "dag")]
            block_broadcaster_command_tx.clone(),
        );

        // Block Broadcaster
        let block_broadcaster = BlockBroadcaster::new(
            config.clone(),
            client.into(),
            block_broadcaster_crypto2,
            block_broadcaster_rx,
            other_block_rx,
            broadcaster_control_command_rx,
            block_broadcaster_storage,
            staging_tx,
            fork_receiver_command_tx.clone(),
            app_tx.clone(),
        );
        let staging = Staging::new(
            config.clone(),
            staging_client.into(),
            staging_crypto,
            staging_rx,
            vote_rx,
            pacemaker_cmd_rx,
            pacemaker_cmd_tx2,
            client_reply_command_tx.clone(),
            app_tx,
            broadcaster_control_command_tx,
            control_command_tx,
            fork_receiver_command_tx,
            qc_tx,
            batch_proposer_command_tx,
            logserver_tx,
            #[cfg(feature = "extra_2pc")]
            extra_2pc_command_tx,
            #[cfg(feature = "extra_2pc")]
            extra_2pc_staging_rx,
        );
        let fork_receiver = ForkReceiver::new(
            config.clone(),
            fork_receiver_crypto,
            fork_receiver_client.into(),
            fork_rx,
            fork_receiver_command_rx,
            other_block_tx,
            logserver_query_tx.clone(),
        );
        let app = Application::new(
            config.clone(),
            app_rx,
            unlogged_rx,
            client_reply_command_tx,
            gc_tx,
            #[cfg(feature = "extra_2pc")]
            extra_2pc_phase_message_tx,
        );
        let client_reply = ClientReplyHandler::new(
            config.clone(),
            client_reply_rx,
            client_reply_command_rx,
            #[cfg(feature = "dag")]
            client_reply.into(),
            #[cfg(feature = "dag")]
            execution_results_rx,
        );
        let logserver = LogServer::new(
            config.clone(),
            logserver_client.into(),
            logserver_rx,
            backfill_request_rx,
            gc_rx,
            logserver_query_rx,
            logserver_storage,
        );
        let pacemaker = Pacemaker::new(
            config.clone(),
            pacemaker_client.into(),
            pacemaker_crypto,
            view_change_rx,
            pacemaker_cmd_tx,
            pacemaker_cmd_rx2,
            logserver_query_tx,
        );

        #[cfg(feature = "extra_2pc")]
        let extra_2pc = extra_2pc::TwoPCHandler::new(
            config.clone(),
            extra_2pc_client.into(),
            storage.get_connector(crypto.get_connector()),
            storage.get_connector(crypto.get_connector()),
            extra_2pc_command_rx,
            extra_2pc_phase_message_rx,
            extra_2pc_staging_tx,
        );

        let mut handles = JoinSet::new();

        Self {
            config: config.clone(),
            keystore: keystore.clone(),
            server: Arc::new(Server::new_atomic(config.clone(), ctx, keystore.clone())),
            #[cfg(feature = "dag")]
            dag_batch_proposer: Arc::new(Mutex::new(batch_proposer)),
            #[cfg(feature = "dag")]
            dag_block_sequencer: Arc::new(Mutex::new(dag_block_sequencer)),
            #[cfg(feature = "dag")]
            dag_block_broadcaster: Arc::new(Mutex::new(dag_block_broadcaster)),
            #[cfg(feature = "dag")]
            dag_block_receiver: Arc::new(Mutex::new(block_receiver)),
            #[cfg(feature = "dag")]
            dag_lane_staging: Arc::new(Mutex::new(lane_staging)),
            #[cfg(feature = "dag")]
            dag_lane_logserver: Arc::new(Mutex::new(lane_logserver)),
            #[cfg(feature = "dag")]
            dag_tip_cut_proposal: Arc::new(Mutex::new(tip_cut_proposal)),
            #[cfg(not(feature = "dag"))]
            batch_proposer: Arc::new(Mutex::new(batch_proposer)),
            block_sequencer: Arc::new(Mutex::new(block_sequencer)),
            block_broadcaster: Arc::new(Mutex::new(block_broadcaster)),
            staging: Arc::new(Mutex::new(staging)),
            fork_receiver: Arc::new(Mutex::new(fork_receiver)),
            client_reply: Arc::new(Mutex::new(client_reply)),
            logserver: Arc::new(Mutex::new(logserver)),
            pacemaker: Arc::new(Mutex::new(pacemaker)),

            #[cfg(feature = "extra_2pc")]
            extra_2pc: Arc::new(Mutex::new(extra_2pc)),

            crypto,
            storage: Arc::new(Mutex::new(storage)),
            __sink_handles: handles,

            app: Arc::new(Mutex::new(app)),

            batch_proposer_tx,
        }
    }

    pub async fn run(&mut self) -> JoinSet<()> {
        let server = self.server.clone();
        let storage = self.storage.clone();

        // Shared components
        let block_broadcaster = self.block_broadcaster.clone();
        let staging = self.staging.clone();
        let fork_receiver = self.fork_receiver.clone();
        let app = self.app.clone();
        let client_reply = self.client_reply.clone();
        let logserver = self.logserver.clone();
        let pacemaker = self.pacemaker.clone();

        let mut handles = JoinSet::new();

        // Storage service
        handles.spawn(async move {
            let mut storage = storage.lock().await;
            storage.run().await;
        });

        // RPC server
        handles.spawn(async move {
            let _ = Server::<PinnedConsensusServerContext>::run(server).await;
        });

        // Batch proposer - DAG or traditional (only component not shared)
        #[cfg(feature = "dag")]
        {
            let dag_batch_proposer = self.dag_batch_proposer.clone();
            handles.spawn(async move {
                info!("Starting DAG BatchProposer");
                dag::batch_proposal::BatchProposer::run(dag_batch_proposer).await;
            });
        }
        #[cfg(not(feature = "dag"))]
        {
            let batch_proposer = self.batch_proposer.clone();
            handles.spawn(async move {
                BatchProposer::run(batch_proposer).await;
            });
        }

        // Block sequencer - used in both modes (handles forks in traditional, tip cuts in DAG)
        let block_sequencer = self.block_sequencer.clone();
        handles.spawn(async move {
            #[cfg(feature = "dag")]
            info!("Starting BlockSequencer (for tip cuts)");
            #[cfg(not(feature = "dag"))]
            info!("Starting BlockSequencer");
            BlockSequencer::run(block_sequencer).await;
        });

        // DAG-specific dissemination layer components
        #[cfg(feature = "dag")]
        {
            let dag_block_sequencer = self.dag_block_sequencer.clone();
            let dag_block_broadcaster = self.dag_block_broadcaster.clone();
            let dag_block_receiver = self.dag_block_receiver.clone();
            let dag_lane_staging = self.dag_lane_staging.clone();
            let dag_lane_logserver = self.dag_lane_logserver.clone();
            let dag_tip_cut_proposal = self.dag_tip_cut_proposal.clone();

            handles.spawn(async move {
                info!("Starting DAG BlockSequencer");
                dag::block_sequencer::DagBlockSequencer::run(dag_block_sequencer).await;
            });

            handles.spawn(async move {
                info!("Starting DAG BlockBroadcaster");
                dag::block_broadcaster::DagBlockBroadcaster::run(dag_block_broadcaster).await;
            });

            handles.spawn(async move {
                info!("Starting DAG BlockReceiver");
                dag::block_receiver::BlockReceiver::run(dag_block_receiver).await;
            });

            handles.spawn(async move {
                info!("Starting DAG LaneStaging");
                dag::lane_staging::LaneStaging::run(dag_lane_staging).await;
            });

            handles.spawn(async move {
                info!("Starting DAG LaneLogServer");
                dag::lane_logserver::LaneLogServer::run(dag_lane_logserver).await;
            });

            handles.spawn(async move {
                info!("Starting DAG TipCutProposal");
                dag::tip_cut_proposal::TipCutProposal::run(dag_tip_cut_proposal).await;
            });
        }

        // Shared consensus components (handle forks in traditional mode, tip cuts in DAG mode)
        handles.spawn(async move {
            #[cfg(feature = "dag")]
            info!("Starting BlockBroadcaster (for tip cuts)");
            #[cfg(not(feature = "dag"))]
            info!("Starting BlockBroadcaster");
            BlockBroadcaster::run(block_broadcaster).await;
        });

        handles.spawn(async move {
            #[cfg(feature = "dag")]
            info!("Starting ForkReceiver (for tip cuts)");
            #[cfg(not(feature = "dag"))]
            info!("Starting ForkReceiver");
            ForkReceiver::run(fork_receiver).await;
        });

        handles.spawn(async move {
            #[cfg(feature = "dag")]
            info!("Starting Staging (for tip cuts)");
            #[cfg(not(feature = "dag"))]
            info!("Starting Staging");
            Staging::run(staging).await;
        });

        handles.spawn(async move {
            #[cfg(feature = "dag")]
            info!("Starting LogServer (for tip cuts)");
            #[cfg(not(feature = "dag"))]
            info!("Starting LogServer");
            LogServer::run(logserver).await;
        });

        handles.spawn(async move {
            info!("Starting Pacemaker");
            Pacemaker::run(pacemaker).await;
        });

        // Execution and client response components
        handles.spawn(async move {
            info!("Booting up Application");
            Application::run(app).await;
        });

        handles.spawn(async move {
            #[cfg(feature = "dag")]
            info!("Starting ClientReplyHandler");
            ClientReplyHandler::run(client_reply).await;
        });

        #[cfg(feature = "extra_2pc")]
        {
            let extra_2pc = self.extra_2pc.clone();
            handles.spawn(async move {
                #[cfg(feature = "dag")]
                info!("Starting Extra2PC Handler");
                extra_2pc::TwoPCHandler::run(extra_2pc).await;
            });
        }

        handles
    }
}
