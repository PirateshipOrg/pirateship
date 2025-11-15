use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use log::{debug, info, trace, warn};
use prost::Message as _;
use tokio::{
    sync::{oneshot, Mutex},
    task::JoinSet,
};

use crate::{
    config::{AtomicConfig, NodeInfo},
    crypto::HashType,
    proto::{
        client::{ProtoByzResponse, ProtoClientReply, ProtoTransactionReceipt, ProtoTryAgain},
        execution::ProtoTransactionResult,
    },
    rpc::{server::LatencyProfile, PinnedMessage, SenderType},
    utils::channel::Receiver,
};

#[cfg(feature = "dag")]
use crate::rpc::client::PinnedClient;

use super::batch_proposal::MsgAckChanWithTag;

pub enum ClientReplyCommand {
    CancelAllRequests,
    StopCancelling,
    CrashCommitAck(HashMap<HashType, (u64, Vec<ProtoTransactionResult>)>),
    #[cfg(feature = "dag")]
    CrashCommitAckWithOrigins(
        HashMap<HashType, (u64, Vec<ProtoTransactionResult>, String)>, /* hash -> (block_n, results, origin_node) */
    ),
    ByzCommitAck(HashMap<HashType, (u64, Vec<ProtoByzResponse>)>),
    #[cfg(feature = "dag")]
    ByzCommitAckWithOrigins(
        HashMap<HashType, (u64, Vec<ProtoByzResponse>, String)>, /* hash -> (block_n, responses, origin_node) */
    ),
    UnloggedRequestAck(oneshot::Receiver<ProtoTransactionResult>, MsgAckChanWithTag),
    ProbeRequestAck(u64 /* block_n */, MsgAckChanWithTag),
}

enum ReplyProcessorCommand {
    CrashCommit(
        u64, /* block_n */
        u64, /* tx_n */
        HashType,
        ProtoTransactionResult, /* result */
        MsgAckChanWithTag,
        Vec<ProtoByzResponse>,
    ),
    Unlogged(oneshot::Receiver<ProtoTransactionResult>, MsgAckChanWithTag),
    Probe(u64 /* block_n */, Vec<MsgAckChanWithTag>),
}
pub struct ClientReplyHandler {
    config: AtomicConfig,

    batch_rx: Receiver<(oneshot::Receiver<HashType>, Vec<MsgAckChanWithTag>)>,
    reply_command_rx: Receiver<ClientReplyCommand>,

    #[cfg(feature = "dag")]
    client: PinnedClient,
    #[cfg(feature = "dag")]
    execution_results_rx: Receiver<crate::proto::consensus::ProtoExecutionResults>,
    #[cfg(feature = "dag")]
    byz_results_rx: Receiver<crate::proto::consensus::ProtoByzResults>,

    reply_map: HashMap<HashType, Vec<MsgAckChanWithTag>>,
    byz_reply_map: HashMap<HashType, Vec<(u64, SenderType)>>,

    crash_commit_reply_buf: HashMap<HashType, (u64, Vec<ProtoTransactionResult>)>,
    byz_commit_reply_buf: HashMap<HashType, (u64, Vec<ProtoByzResponse>)>,

    byz_response_store: HashMap<SenderType /* Sender */, Vec<ProtoByzResponse>>,

    reply_processors: JoinSet<()>,
    reply_processor_queue: (
        async_channel::Sender<ReplyProcessorCommand>,
        async_channel::Receiver<ReplyProcessorCommand>,
    ),

    probe_buffer: BTreeMap<u64 /* block_n */, Vec<MsgAckChanWithTag>>,
    acked_bci: u64,

    must_cancel: bool,
}

impl ClientReplyHandler {
    pub fn new(
        config: AtomicConfig,
        batch_rx: Receiver<(oneshot::Receiver<HashType>, Vec<MsgAckChanWithTag>)>,
        reply_command_rx: Receiver<ClientReplyCommand>,
        #[cfg(feature = "dag")] client: PinnedClient,
        #[cfg(feature = "dag")] execution_results_rx: Receiver<
            crate::proto::consensus::ProtoExecutionResults,
        >,
        #[cfg(feature = "dag")] byz_results_rx: Receiver<crate::proto::consensus::ProtoByzResults>,
    ) -> Self {
        let _chan_depth = config.get().rpc_config.channel_depth as usize;
        Self {
            config,
            batch_rx,
            reply_command_rx,
            #[cfg(feature = "dag")]
            client,
            #[cfg(feature = "dag")]
            execution_results_rx,
            #[cfg(feature = "dag")]
            byz_results_rx,
            reply_map: HashMap::new(),
            byz_reply_map: HashMap::new(),
            crash_commit_reply_buf: HashMap::new(),
            byz_commit_reply_buf: HashMap::new(),
            reply_processors: JoinSet::new(),
            reply_processor_queue: async_channel::unbounded(),
            byz_response_store: HashMap::new(),
            probe_buffer: BTreeMap::new(),
            acked_bci: 0,
            must_cancel: false,
        }
    }

    pub async fn run(client_reply_handler: Arc<Mutex<Self>>) {
        let mut client_reply_handler = client_reply_handler.lock().await;
        for _ in 0..100 {
            let rx = client_reply_handler.reply_processor_queue.1.clone();
            client_reply_handler.reply_processors.spawn(async move {
                while let Ok(cmd) = rx.recv().await {
                    match cmd {
                        ReplyProcessorCommand::CrashCommit(
                            block_n,
                            tx_n,
                            hsh,
                            reply,
                            (reply_chan, client_tag, _),
                            byz_responses,
                        ) => {
                            let reply = ProtoClientReply {
                                reply: Some(
                                    crate::proto::client::proto_client_reply::Reply::Receipt(
                                        ProtoTransactionReceipt {
                                            req_digest: hsh,
                                            block_n,
                                            tx_n,
                                            results: Some(reply),
                                            await_byz_response: true,
                                            byz_responses,
                                        },
                                    ),
                                ),
                                client_tag,
                            };

                            let reply_ser = reply.encode_to_vec();
                            let _sz = reply_ser.len();
                            let reply_msg =
                                PinnedMessage::from(reply_ser, _sz, crate::rpc::SenderType::Anon);
                            let latency_profile = LatencyProfile::new();

                            let _ = reply_chan.send((reply_msg, latency_profile)).await;
                        }
                        ReplyProcessorCommand::Unlogged(res_rx, (reply_chan, tag, _sender)) => {
                            let reply = res_rx.await.unwrap();
                            let reply = ProtoClientReply {
                                reply: Some(
                                    crate::proto::client::proto_client_reply::Reply::Receipt(
                                        ProtoTransactionReceipt {
                                            req_digest: vec![],
                                            block_n: 0,
                                            tx_n: 0,
                                            results: Some(reply),
                                            await_byz_response: false,
                                            byz_responses: vec![],
                                        },
                                    ),
                                ),
                                client_tag: tag,
                            };

                            let reply_ser = reply.encode_to_vec();
                            let _sz = reply_ser.len();
                            let reply_msg =
                                PinnedMessage::from(reply_ser, _sz, crate::rpc::SenderType::Anon);
                            let latency_profile = LatencyProfile::new();

                            let _ = reply_chan.send((reply_msg, latency_profile)).await;
                        }

                        ReplyProcessorCommand::Probe(block_n, reply_vec) => {
                            let reply = ProtoClientReply {
                                reply: Some(
                                    crate::proto::client::proto_client_reply::Reply::Receipt(
                                        ProtoTransactionReceipt {
                                            req_digest: vec![],
                                            block_n,
                                            tx_n: 0,
                                            results: None,
                                            await_byz_response: false,
                                            byz_responses: vec![],
                                        },
                                    ),
                                ),
                                client_tag: 0, // TODO: this should be a real tag; but currently probe is not done over the network so we are ok.
                            };

                            let reply_ser = reply.encode_to_vec();
                            let _sz = reply_ser.len();
                            let reply_msg =
                                PinnedMessage::from(reply_ser, _sz, crate::rpc::SenderType::Anon);

                            for (reply_chan, _tag, _sender) in reply_vec {
                                let latency_profile = LatencyProfile::new();

                                let _ = reply_chan.send((reply_msg.clone(), latency_profile)).await;
                            }
                        }
                    }
                }
            });
        }

        loop {
            if let Err(_) = client_reply_handler.worker().await {
                break;
            }
        }
    }

    async fn worker(&mut self) -> Result<(), ()> {
        #[cfg(feature = "dag")]
        {
            tokio::select! {
                batch = self.batch_rx.recv() => {
                    if batch.is_none() {
                        return Ok(());
                    }

                    let (batch_hash_chan, mut reply_vec) = batch.unwrap();
                    let batch_hash = batch_hash_chan.await.unwrap();

                    if batch_hash.is_empty() || self.must_cancel {
                        // This is called when !listen_on_new_batch
                        // This must be cancelled.
                        if reply_vec.len() > 0 {
                            info!("Clearing out queued replies of size {}", reply_vec.len());
                            let node_infos = NodeInfo {
                                nodes: self.config.get().net_config.nodes.clone()
                            };
                            for (chan, tag, _) in reply_vec.drain(..) {
                                let reply = Self::get_try_again_message(tag, &node_infos);
                                let reply_ser = reply.encode_to_vec();
                                let _sz = reply_ser.len();
                                let reply_msg = PinnedMessage::from(reply_ser, _sz, crate::rpc::SenderType::Anon);
                                let _ = chan.send((reply_msg, LatencyProfile::new())).await;
                            }
                        }
                        return Ok(());
                    }

                    self.byz_reply_map.insert(batch_hash.clone(), reply_vec.iter().map(|(_, client_tag, sender)| (*client_tag, sender.clone())).collect());
                    self.reply_map.insert(batch_hash.clone(), reply_vec);

                    self.maybe_clear_reply_buf(batch_hash).await;
                },
                cmd = self.reply_command_rx.recv() => {
                    if cmd.is_none() {
                        return Ok(());
                    }

                    let cmd = cmd.unwrap();

                    self.handle_reply_command(cmd).await;
                },
                // Execution results for DAG mode only
                execution_results = self.execution_results_rx.recv() => {
                    if execution_results.is_none() {
                        return Ok(());
                    }

                    let results = execution_results.unwrap();
                    self.handle_forwarded_results(results).await;
                },
                // Byz results for DAG mode only
                byz_results = self.byz_results_rx.recv() => {
                    if byz_results.is_none() {
                        return Ok(());
                    }

                    let byz = byz_results.unwrap();
                    self.handle_forwarded_byz_results(byz).await;
                },
            }
        }

        #[cfg(not(feature = "dag"))]
        {
            tokio::select! {
                batch = self.batch_rx.recv() => {
                    if batch.is_none() {
                        return Ok(());
                    }

                    let (batch_hash_chan, mut reply_vec) = batch.unwrap();
                    let batch_hash = batch_hash_chan.await.unwrap();

                    if batch_hash.is_empty() || self.must_cancel {
                        // This is called when !listen_on_new_batch
                        // This must be cancelled.
                        if reply_vec.len() > 0 {
                            info!("Clearing out queued replies of size {}", reply_vec.len());
                            let node_infos = NodeInfo {
                                nodes: self.config.get().net_config.nodes.clone()
                            };
                            for (chan, tag, _) in reply_vec.drain(..) {
                                let reply = Self::get_try_again_message(tag, &node_infos);
                                let reply_ser = reply.encode_to_vec();
                                let _sz = reply_ser.len();
                                let reply_msg = PinnedMessage::from(reply_ser, _sz, crate::rpc::SenderType::Anon);
                                let _ = chan.send((reply_msg, LatencyProfile::new())).await;
                            }
                        }
                        return Ok(());
                    }

                    self.byz_reply_map.insert(batch_hash.clone(), reply_vec.iter().map(|(_, client_tag, sender)| (*client_tag, sender.clone())).collect());
                    self.reply_map.insert(batch_hash.clone(), reply_vec);

                    self.maybe_clear_reply_buf(batch_hash).await;
                },
                cmd = self.reply_command_rx.recv() => {
                    if cmd.is_none() {
                        return Ok(());
                    }

                    let cmd = cmd.unwrap();

                    self.handle_reply_command(cmd).await;
                },
            }
        }

        {
            tokio::select! {
                batch = self.batch_rx.recv() => {
                    if batch.is_none() {
                        return Ok(());
                    }

                    let (batch_hash_chan, mut reply_vec) = batch.unwrap();
                    let batch_hash = batch_hash_chan.await.unwrap();

                    if batch_hash.is_empty() || self.must_cancel {
                        // This is called when !listen_on_new_batch
                        // This must be cancelled.
                        if reply_vec.len() > 0 {
                            info!("Clearing out queued replies of size {}", reply_vec.len());
                            let node_infos = NodeInfo {
                                nodes: self.config.get().net_config.nodes.clone()
                            };
                            for (chan, tag, _) in reply_vec.drain(..) {
                                let reply = Self::get_try_again_message(tag, &node_infos);
                                let reply_ser = reply.encode_to_vec();
                                let _sz = reply_ser.len();
                                let reply_msg = PinnedMessage::from(reply_ser, _sz, crate::rpc::SenderType::Anon);
                                let _ = chan.send((reply_msg, LatencyProfile::new())).await;
                            }
                        }
                        return Ok(());
                    }

                    self.byz_reply_map.insert(batch_hash.clone(), reply_vec.iter().map(|(_, client_tag, sender)| (*client_tag, sender.clone())).collect());
                    self.reply_map.insert(batch_hash.clone(), reply_vec);

                    self.maybe_clear_reply_buf(batch_hash).await;
                },
                cmd = self.reply_command_rx.recv() => {
                    if cmd.is_none() {
                        return Ok(());
                    }

                    let cmd = cmd.unwrap();

                    self.handle_reply_command(cmd).await;
                },
            }
        }
        Ok(())
    }

    async fn do_crash_commit_reply(
        &mut self,
        reply_sender_vec: Vec<MsgAckChanWithTag>,
        hash: HashType,
        n: u64,
        reply_vec: Vec<ProtoTransactionResult>,
    ) {
        assert_eq!(reply_sender_vec.len(), reply_vec.len());
        for (tx_n, ((reply_chan, client_tag, sender), reply)) in reply_sender_vec
            .into_iter()
            .zip(reply_vec.into_iter())
            .enumerate()
        {
            let byz_responses = self.byz_response_store.remove(&sender).unwrap_or_default();

            self.reply_processor_queue
                .0
                .send(ReplyProcessorCommand::CrashCommit(
                    n,
                    tx_n as u64,
                    hash.clone(),
                    reply,
                    (reply_chan, client_tag, sender),
                    byz_responses,
                ))
                .await
                .unwrap();
        }
    }

    async fn do_byz_commit_reply(
        &mut self,
        reply_sender_vec: Vec<(u64, SenderType)>,
        _hash: HashType,
        n: u64,
        reply_vec: Vec<ProtoByzResponse>,
    ) {
        assert_eq!(reply_sender_vec.len(), reply_vec.len());
        for (_tx_n, ((client_tag, sender), mut reply)) in reply_sender_vec
            .into_iter()
            .zip(reply_vec.into_iter())
            .enumerate()
        {
            reply.client_tag = client_tag;
            match self.byz_response_store.get_mut(&sender) {
                Some(byz_responses) => {
                    byz_responses.push(reply);
                }
                None => {
                    self.byz_response_store.insert(sender, vec![reply]);
                }
            }
        }

        if n > self.acked_bci {
            self.acked_bci = n;
        }

        self.maybe_clear_probe_buf().await;
    }

    async fn handle_reply_command(&mut self, cmd: ClientReplyCommand) {
        match cmd {
            ClientReplyCommand::CancelAllRequests => {
                let node_infos = NodeInfo {
                    nodes: self.config.get().net_config.nodes.clone(),
                };
                for (_, mut vec) in self.reply_map.drain() {
                    for (chan, tag, _) in vec.drain(..) {
                        let reply = Self::get_try_again_message(tag, &node_infos);
                        let reply_ser = reply.encode_to_vec();
                        let _sz = reply_ser.len();
                        let reply_msg =
                            PinnedMessage::from(reply_ser, _sz, crate::rpc::SenderType::Anon);
                        let _ = chan.send((reply_msg, LatencyProfile::new())).await;
                    }
                }

                self.must_cancel = true;
            }
            ClientReplyCommand::CrashCommitAck(crash_commit_ack) => {
                for (hash, (n, reply_vec)) in crash_commit_ack {
                    if let Some(reply_sender_vec) = self.reply_map.remove(&hash) {
                        self.do_crash_commit_reply(reply_sender_vec, hash, n, reply_vec)
                            .await;
                    } else {
                        // We received the reply before the request. Store it for later.
                        self.crash_commit_reply_buf.insert(hash, (n, reply_vec));
                    }
                }
            }
            ClientReplyCommand::ByzCommitAck(byz_commit_ack) => {
                for (hash, (n, reply_vec)) in byz_commit_ack {
                    if let Some(reply_sender_vec) = self.byz_reply_map.remove(&hash) {
                        self.do_byz_commit_reply(reply_sender_vec, hash, n, reply_vec)
                            .await;
                    } else {
                        self.byz_commit_reply_buf.insert(hash, (n, reply_vec));
                    }
                }
            }
            ClientReplyCommand::StopCancelling => {
                self.must_cancel = false;
            }
            ClientReplyCommand::UnloggedRequestAck(res_rx, sender) => {
                let reply_chan = sender.0;
                let client_tag = sender.1;
                let sender = sender.2;
                self.reply_processor_queue
                    .0
                    .send(ReplyProcessorCommand::Unlogged(
                        res_rx,
                        (reply_chan, client_tag, sender),
                    ))
                    .await
                    .unwrap();
            }
            ClientReplyCommand::ProbeRequestAck(block_n, sender) => {
                if let Some(vec) = self.probe_buffer.get_mut(&block_n) {
                    vec.push(sender);
                } else {
                    self.probe_buffer.insert(block_n, vec![sender]);
                }

                self.maybe_clear_probe_buf().await;
            }
            #[cfg(feature = "dag")]
            ClientReplyCommand::CrashCommitAckWithOrigins(crash_commit_ack_with_origins) => {
                self.handle_crash_commit_ack_with_origins(crash_commit_ack_with_origins)
                    .await;
            }
            #[cfg(feature = "dag")]
            ClientReplyCommand::ByzCommitAckWithOrigins(byz_commit_ack_with_origins) => {
                self.handle_byz_commit_ack_with_origins(byz_commit_ack_with_origins)
                    .await;
            }
        }
    }

    async fn maybe_clear_probe_buf(&mut self) {
        let mut remove_vec = vec![];

        self.probe_buffer.retain(|block_n, reply_vec| {
            if *block_n <= self.acked_bci {
                trace!(
                    "Clearing probe tx buffer of size {} for block {}",
                    reply_vec.len(),
                    block_n
                );

                remove_vec.push((*block_n, reply_vec.drain(..).collect::<Vec<_>>()));
                false
            } else {
                true
            }
        });

        for (block_n, reply_vec) in remove_vec {
            self.reply_processor_queue
                .0
                .send(ReplyProcessorCommand::Probe(block_n, reply_vec))
                .await
                .unwrap();
        }
    }

    fn get_try_again_message(client_tag: u64, node_infos: &NodeInfo) -> ProtoClientReply {
        ProtoClientReply {
            reply: Some(crate::proto::client::proto_client_reply::Reply::TryAgain(
                ProtoTryAgain {
                    serialized_node_infos: node_infos.serialize(),
                },
            )),
            client_tag,
        }
    }

    async fn maybe_clear_reply_buf(&mut self, batch_hash: HashType) {
        // Byz register must happen first. Otherwise when crash commit piggybacks the byz commit reply, it will be too late.
        if let Some((n, reply_vec)) = self.byz_commit_reply_buf.remove(&batch_hash) {
            if let Some(reply_sender_vec) = self.byz_reply_map.remove(&batch_hash) {
                self.do_byz_commit_reply(reply_sender_vec, batch_hash.clone(), n, reply_vec)
                    .await;
            }
        }

        if let Some((n, reply_vec)) = self.crash_commit_reply_buf.remove(&batch_hash) {
            if let Some(reply_sender_vec) = self.reply_map.remove(&batch_hash) {
                self.do_crash_commit_reply(reply_sender_vec, batch_hash.clone(), n, reply_vec)
                    .await;
            }
        }
    }

    /// Handle crash commit acknowledgment with origin nodes (DAG mode)
    /// For each result, check if it originated from this node or needs forwarding
    #[cfg(feature = "dag")]
    async fn handle_crash_commit_ack_with_origins(
        &mut self,
        crash_commit_ack_with_origins: HashMap<
            HashType,
            (u64, Vec<ProtoTransactionResult>, String),
        >,
    ) {
        let my_name = self.config.get().net_config.name.clone();

        for (hash, (n, reply_vec, origin_node)) in crash_commit_ack_with_origins {
            if origin_node == my_name {
                // This result originated from this node - handle locally
                if let Some(reply_sender_vec) = self.reply_map.remove(&hash) {
                    self.do_crash_commit_reply(reply_sender_vec, hash, n, reply_vec)
                        .await;
                } else {
                    // Store for later if request hasn't arrived yet
                    self.crash_commit_reply_buf.insert(hash, (n, reply_vec));
                }
            } else {
                // Forward to origin node
                self.forward_results_to_origin(hash, n, reply_vec, origin_node)
                    .await;
            }
        }
    }

    /// Handle byzantine commit acknowledgment with origin nodes (DAG mode)
    /// For each result, check if it originated from this node or needs forwarding
    #[cfg(feature = "dag")]
    async fn handle_byz_commit_ack_with_origins(
        &mut self,
        byz_commit_ack_with_origins: HashMap<HashType, (u64, Vec<ProtoByzResponse>, String)>,
    ) {
        use crate::proto::consensus::ProtoByzResults;
        use crate::proto::rpc::proto_payload;

        let my_name = self.config.get().net_config.name.clone();

        for (hash, (n, reply_vec, origin_node)) in byz_commit_ack_with_origins {
            if origin_node == my_name {
                // This result originated from this node - handle locally
                if let Some(reply_sender_vec) = self.byz_reply_map.remove(&hash) {
                    self.do_byz_commit_reply(reply_sender_vec, hash, n, reply_vec)
                        .await;
                } else {
                    // Store for later if request hasn't arrived yet
                    self.byz_commit_reply_buf.insert(hash, (n, reply_vec));
                }
            } else {
                // Forward to origin node (convert ProtoByzResponse to ProtoTransactionResult)
                // Forward byzantine responses to origin node to attach locally to receipts
                let byz_results = ProtoByzResults {
                    block_hash: hash.clone(),
                    block_n: n,
                    responses: reply_vec.clone(),
                    origin_node: origin_node.clone(),
                };
                let payload = crate::proto::rpc::ProtoPayload {
                    message: Some(proto_payload::Message::ByzResults(byz_results)),
                };

                let buf = payload.encode_to_vec();
                let sz = buf.len();

                if let Err(e) = PinnedClient::send(
                    &self.client,
                    &origin_node,
                    crate::rpc::MessageRef(&buf, sz, &SenderType::Anon),
                )
                .await
                {
                    warn!(
                        "Failed to forward byz responses to origin node {}: {:?}",
                        origin_node, e
                    );
                }
            }
        }
    }

    /// Forward execution results to the origin node via RPC
    #[cfg(feature = "dag")]
    async fn forward_results_to_origin(
        &mut self,
        block_hash: HashType,
        block_n: u64,
        results: Vec<ProtoTransactionResult>,
        origin_node: String,
    ) {
        debug!(
            "Forwarding execution results for block {} (hash={:?}) to origin node {}",
            block_n,
            hex::encode(&block_hash),
            origin_node
        );

        let execution_results = crate::proto::consensus::ProtoExecutionResults {
            block_hash,
            results,
            origin_node: origin_node.clone(),
            block_n,
        };

        let payload = crate::proto::rpc::ProtoPayload {
            message: Some(crate::proto::rpc::proto_payload::Message::ExecutionResults(
                execution_results,
            )),
        };

        // Serialize once and keep buffer alive across await
        let buf = payload.encode_to_vec();
        let sz = buf.len();

        // Send to origin node - failures are acceptable (node may have crashed)
        if let Err(e) = PinnedClient::send(
            &self.client,
            &origin_node,
            crate::rpc::MessageRef(&buf, sz, &SenderType::Anon),
        )
        .await
        {
            warn!(
                "Failed to forward execution results to origin node {}: {:?}",
                origin_node, e
            );
        }
    }

    /// Handle execution results forwarded from another node (DAG mode)
    /// This is called when receiving ProtoExecutionResults via RPC
    #[cfg(feature = "dag")]
    async fn handle_forwarded_results(
        &mut self,
        results: crate::proto::consensus::ProtoExecutionResults,
    ) {
        debug!(
            "Handling forwarded execution results for block {} (hash={:?})",
            results.block_n,
            hex::encode(&results.block_hash)
        );

        // Match results with local reply channels
        if let Some(reply_sender_vec) = self.reply_map.remove(&results.block_hash) {
            self.do_crash_commit_reply(
                reply_sender_vec,
                results.block_hash.clone(),
                results.block_n,
                results.results.clone(),
            )
            .await;
        } else {
            debug!(
                "No local reply channels found for forwarded results (block_hash={:?})",
                hex::encode(&results.block_hash)
            );
        }
    }

    /// Handle byzantine results forwarded from another node (DAG mode)
    /// This is called when receiving ProtoByzResults via RPC
    #[cfg(feature = "dag")]
    async fn handle_forwarded_byz_results(
        &mut self,
        byz: crate::proto::consensus::ProtoByzResults,
    ) {
        debug!(
            "Handling forwarded byz results for block {} (hash={:?}) count={}",
            byz.block_n,
            hex::encode(&byz.block_hash),
            byz.responses.len()
        );

        let block_hash = byz.block_hash.clone();
        let block_n = byz.block_n;
        let responses = byz.responses.clone();

        // If we already have byz_reply_map entry, apply immediately
        if let Some(reply_sender_vec) = self.byz_reply_map.remove(&block_hash) {
            self.do_byz_commit_reply(
                reply_sender_vec,
                block_hash.clone(),
                block_n,
                responses.clone(),
            )
            .await;
        } else {
            // Otherwise, buffer for later
            self.byz_commit_reply_buf
                .insert(block_hash.clone(), (block_n, responses.clone()));
        }

        // Update progress for probes
        if block_n > self.acked_bci {
            self.acked_bci = block_n;
        }
        self.maybe_clear_probe_buf().await;
    }
}
