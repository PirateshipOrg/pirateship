use std::{collections::{BTreeMap, HashMap}, sync::Arc};

use log::{error, info, trace};
use prost::Message as _;
use tokio::{sync::{oneshot, Mutex}, task::JoinSet};

use crate::{config::{AtomicConfig, NodeInfo}, consensus::issuer::{IssuerCommand, ProofChain}, crypto::{HashType, MerkleInclusionProof}, proto::{client::{ProtoAuditReceipt, ProtoByzResponse, ProtoClientReply, ProtoCommitReceipt, ProtoTransactionReceipt, ProtoTryAgain, ProtoUnloggedReceipt}, execution::ProtoTransactionResult, rpc::ProtoPayload}, rpc::{server::LatencyProfile, PinnedMessage, SenderType}, utils::channel::{make_channel, Receiver, Sender}};

use super::batch_proposal::MsgAckChanWithTag;

pub enum ClientReplyCommand {
    CancelAllRequests,
    StopCancelling,
    CrashCommitAck(HashMap<HashType, (u64, Vec<ProtoTransactionResult>)>),
    ByzCommitAck(HashMap<HashType, (u64, Vec<ProtoByzResponse>)>),
    UnloggedRequestAck(oneshot::Receiver<ProtoTransactionResult>, MsgAckChanWithTag),
    ProbeRequestAck(u64 /* block_n */, u64 /* tx_n */, MsgAckChanWithTag),
}

enum ReplyProcessorCommand {
    CrashCommit(u64 /* block_n */, u64 /* tx_n */, HashType, ProtoTransactionResult /* result */, MsgAckChanWithTag, Vec<ProtoByzResponse>, ProofChain, MerkleInclusionProof),
    ByzCommit(u64 /* block_n */, u64 /* tx_n */, ProtoTransactionResult /* result */, MsgAckChanWithTag),
    Unlogged(oneshot::Receiver<ProtoTransactionResult>, MsgAckChanWithTag),
    Probe(u64 /* block_n */, ProofChain, Vec<(MsgAckChanWithTag, u64 /* tx_n */, MerkleInclusionProof)>),
}
pub struct ClientReplyHandler {
    config: AtomicConfig,

    batch_rx: Receiver<(oneshot::Receiver<HashType>, Vec<MsgAckChanWithTag>)>,
    reply_command_rx: Receiver<ClientReplyCommand>,
    issuer_tx: Sender<IssuerCommand>,

    reply_map: HashMap<HashType, Vec<MsgAckChanWithTag>>,
    byz_reply_map: HashMap<HashType, Vec<(u64, SenderType)>>,

    crash_commit_reply_buf: HashMap<HashType, (u64, Vec<ProtoTransactionResult>)>,
    byz_commit_reply_buf: HashMap<HashType, (u64, Vec<ProtoByzResponse>)>,

    byz_response_store: HashMap<SenderType /* Sender */, Vec<ProtoByzResponse>>,

    reply_processors: JoinSet<()>,
    reply_processor_queue: (async_channel::Sender<ReplyProcessorCommand>, async_channel::Receiver<ReplyProcessorCommand>),

    probe_buffer: BTreeMap<u64 /* block_n */, Vec<(MsgAckChanWithTag, u64 /* tx_n */)>>,
    acked_bci: u64,

    must_cancel: bool,
}

impl ClientReplyHandler {
    pub fn new(
        config: AtomicConfig,
        batch_rx: Receiver<(oneshot::Receiver<HashType>, Vec<MsgAckChanWithTag>)>,
        reply_command_rx: Receiver<ClientReplyCommand>,
        issuer_tx: Sender<IssuerCommand>,
    ) -> Self {
        let _chan_depth = config.get().rpc_config.channel_depth as usize;
        Self {
            config,
            batch_rx,
            reply_command_rx,
            issuer_tx,
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
                        ReplyProcessorCommand::CrashCommit(block_n, tx_n, hsh, reply, (reply_chan, client_tag, _), byz_responses, proof_chain, inclusion_proof) => {
                            let reply = ProtoClientReply {
                                reply: Some(
                                    crate::proto::client::proto_client_reply::Reply::Receipt(
                                        ProtoTransactionReceipt {
                                            receipt: Some(crate::proto::client::proto_transaction_receipt::Receipt::CommitReceipt(
                                                ProtoCommitReceipt {
                                                    req_digest: hsh,
                                                    block_n,
                                                    tx_n,
                                                    results: Some(reply),
                                                    chain: proof_chain,
                                                    proof: inclusion_proof.as_vec(),
                                                }
                                            )),
                                            byz_responses,
                                        },
                                )),
                                client_tag
                            };
                
                            let reply_ser = reply.encode_to_vec();
                            let _sz = reply_ser.len();
                            let reply_msg = PinnedMessage::from(reply_ser, _sz, crate::rpc::SenderType::Anon);
                            let latency_profile = LatencyProfile::new();
                            
                            let _ = reply_chan.send((reply_msg, latency_profile)).await;
                        },
                        ReplyProcessorCommand::ByzCommit(_, _, result, sender) => {

                        },

                        ReplyProcessorCommand::Unlogged(res_rx, (reply_chan, tag, sender)) => {
                            let reply = res_rx.await.unwrap();
                            let reply = ProtoClientReply {
                                reply: Some(
                                    crate::proto::client::proto_client_reply::Reply::Receipt(
                                        ProtoTransactionReceipt {
                                            receipt: Some(crate::proto::client::proto_transaction_receipt::Receipt::UnloggedReceipt(
                                                ProtoUnloggedReceipt {
                                                    results: Some(reply),
                                                }
                                            )),
                                            byz_responses: vec![],
                                        }
                                    ),
                                ),
                                client_tag: tag,
                            };


                            let reply_ser = reply.encode_to_vec();
                            let _sz = reply_ser.len();
                            let reply_msg = PinnedMessage::from(reply_ser, _sz, crate::rpc::SenderType::Anon);
                            let latency_profile = LatencyProfile::new();
                            
                            let _ = reply_chan.send((reply_msg, latency_profile)).await;
                        },

                        ReplyProcessorCommand::Probe(_block_n, proof_chain, reply_vec) => {
                            for ((reply_chan, client_tag, _sender), _tx_n, inclusion_proof) in reply_vec {
                                let latency_profile = LatencyProfile::new();
                                let reply = ProtoClientReply {
                                    reply: Some(
                                        crate::proto::client::proto_client_reply::Reply::Receipt(
                                            ProtoTransactionReceipt {
                                                receipt: Some(crate::proto::client::proto_transaction_receipt::Receipt::AuditReceipt(
                                                    ProtoAuditReceipt {
                                                        chain: proof_chain.clone(),
                                                        proof: inclusion_proof.as_vec(),
                                                    }
                                                )),
                                                byz_responses: vec![],
                                            },
                                        ),
                                    ),
                                    client_tag,
                                };
                                let reply_ser = reply.encode_to_vec();
                                let _sz = reply_ser.len();
                                let reply_msg = PinnedMessage::from(reply_ser, _sz, crate::rpc::SenderType::Anon);
                                
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
        Ok(())
    }

    async fn do_crash_commit_reply(&mut self, reply_sender_vec: Vec<MsgAckChanWithTag>, hash: HashType, n: u64, reply_vec: Vec<ProtoTransactionResult>) {
        let (tx, rx) = oneshot::channel();
        self.issuer_tx.send(IssuerCommand::IssueCommitReceipt(n,  (0..reply_vec.len()).map(|i| i as u64).collect(), tx)).await.unwrap();
        let builder = rx.await.unwrap().unwrap_or_else(|| {
            error!("Failed to build commit receipt for block {}", n);
            crate::consensus::issuer::ReceiptBuilder {
                chain: vec![],
                proofs: vec![MerkleInclusionProof::default(); reply_vec.len()],
            }
        });
        assert_eq!(reply_sender_vec.len(), reply_vec.len());
        assert_eq!(reply_sender_vec.len(), builder.proofs.len());
        for (tx_n, (((reply_chan, client_tag, sender), reply), proof)) in reply_sender_vec.into_iter().zip(reply_vec.into_iter()).zip(builder.proofs).enumerate() {
            let byz_responses = self.byz_response_store.remove(&sender).unwrap_or_default();

            self.reply_processor_queue.0.send(ReplyProcessorCommand::CrashCommit(n, tx_n as u64, hash.clone(), reply, (reply_chan, client_tag, sender), byz_responses, builder.chain.clone(), proof)).await.unwrap();
        }
    }

    async fn do_byz_commit_reply(&mut self, reply_sender_vec: Vec<(u64, SenderType)>, hash: HashType, n: u64, reply_vec: Vec<ProtoByzResponse>) {
        assert_eq!(reply_sender_vec.len(), reply_vec.len());
        for (tx_n, ((client_tag, sender), mut reply)) in reply_sender_vec.into_iter().zip(reply_vec.into_iter()).enumerate() {
            reply.client_tag = client_tag;
            match self.byz_response_store.get_mut(&sender) {
                Some(byz_responses) => {
                    byz_responses.push(reply);
                },
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
                    nodes: self.config.get().net_config.nodes.clone()
                };
                for (_, mut vec) in self.reply_map.drain() {
                    for (chan, tag, _) in vec.drain(..) {
                        let reply = Self::get_try_again_message(tag, &node_infos);
                        let reply_ser = reply.encode_to_vec();
                        let _sz = reply_ser.len();
                        let reply_msg = PinnedMessage::from(reply_ser, _sz, crate::rpc::SenderType::Anon);
                        let _ = chan.send((reply_msg, LatencyProfile::new())).await;
                    }
                }

                self.must_cancel = true;
                
            },
            ClientReplyCommand::CrashCommitAck(crash_commit_ack) => {
                for (hash, (n, reply_vec)) in crash_commit_ack {
                    if let Some(reply_sender_vec) = self.reply_map.remove(&hash) {
                        self.do_crash_commit_reply(reply_sender_vec, hash, n, reply_vec).await;
                    } else {
                        // We received the reply before the request. Store it for later.
                        self.crash_commit_reply_buf.insert(hash, (n, reply_vec));
                    }
                }
            },
            ClientReplyCommand::ByzCommitAck(byz_commit_ack) => {
                for (hash, (n, reply_vec)) in byz_commit_ack {
                    if let Some(reply_sender_vec) = self.byz_reply_map.remove(&hash) {
                        self.do_byz_commit_reply(reply_sender_vec, hash, n, reply_vec).await;
                    } else {
                        self.byz_commit_reply_buf.insert(hash, (n, reply_vec));
                    }
                }
            },
            ClientReplyCommand::StopCancelling => {
                self.must_cancel = false;
            },
            ClientReplyCommand::UnloggedRequestAck(res_rx, sender) => {
                let reply_chan = sender.0;
                let client_tag = sender.1;
                let sender = sender.2;
                self.reply_processor_queue.0.send(ReplyProcessorCommand::Unlogged(res_rx, (reply_chan, client_tag, sender))).await.unwrap();
            },
            ClientReplyCommand::ProbeRequestAck(block_n, tx_n, sender) => {
                if let Some(vec) = self.probe_buffer.get_mut(&block_n) {
                    vec.push((sender, tx_n));
                } else {
                    self.probe_buffer.insert(block_n, vec![(sender, tx_n)]);
                }

                self.maybe_clear_probe_buf().await;
            },
        }
    }

    async fn maybe_clear_probe_buf(&mut self) {
        let mut remove_vec = vec![];
        
        self.probe_buffer.retain(|block_n, reply_vec| {
            if *block_n <= self.acked_bci {
                trace!("Clearing probe tx buffer of size {} for block {}", reply_vec.len(), block_n);

                remove_vec.push((*block_n, reply_vec.drain(..).collect::<Vec<_>>()));
                false
            } else {
                true
            }
        });

        for (block_n, reply_vec) in remove_vec {
            let (tx, rx) = oneshot::channel();
            self.issuer_tx.send(IssuerCommand::IssueAuditReceipt(block_n, reply_vec.iter().map(|(_, tx_n)| *tx_n).collect(), tx)).await.unwrap();
            let Some(builder) = rx.await.unwrap() else {
                error!("Failed to build audit receipt for block {}", block_n);
                continue;
            };
            assert_eq!(reply_vec.len(), builder.proofs.len());
            self.reply_processor_queue.0.send(ReplyProcessorCommand::Probe(block_n, builder.chain, reply_vec.into_iter().zip(builder.proofs).map(|((sender, tx_n), proof)| (sender, tx_n, proof)).collect())).await.unwrap();
        }
    }

    fn get_try_again_message(client_tag: u64, node_infos: &NodeInfo) -> ProtoClientReply {
        ProtoClientReply {
            reply: Some(
                crate::proto::client::proto_client_reply::Reply::TryAgain(ProtoTryAgain {
                    serialized_node_infos: node_infos.serialize(),
                }),
            ),
            client_tag,
        }
    }

    async fn maybe_clear_reply_buf(&mut self, batch_hash: HashType) {
        // Byz register must happen first. Otherwise when crash commit piggybacks the byz commit reply, it will be too late.
        if let Some((n, reply_vec)) = self.byz_commit_reply_buf.remove(&batch_hash) {
            if let Some(reply_sender_vec) = self.byz_reply_map.remove(&batch_hash) {
                self.do_byz_commit_reply(reply_sender_vec, batch_hash.clone(), n, reply_vec).await;
            }
        }

        if let Some((n, reply_vec)) = self.crash_commit_reply_buf.remove(&batch_hash) {
            if let Some(reply_sender_vec) = self.reply_map.remove(&batch_hash) {
                self.do_crash_commit_reply(reply_sender_vec, batch_hash.clone(), n, reply_vec).await;
            }
        }

    }
}

