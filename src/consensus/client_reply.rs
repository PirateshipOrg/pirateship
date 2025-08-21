use std::{collections::HashMap, sync::Arc};

#[allow(unused_imports)]
use log::{error, info, trace};
use prost::Message as _;
use tokio::{sync::{oneshot, Mutex}, task::JoinSet};

use crate::{config::{AtomicConfig, NodeInfo}, crypto::HashType, proto::{client::{ProtoByzResponse, ProtoClientReply, ProtoTransactionResponse, ProtoTryAgain}, execution::ProtoTransactionResult}, rpc::{server::LatencyProfile, PinnedMessage, SenderType}, utils::channel::Receiver};

use super::batch_proposal::MsgAckChanWithTag;

#[cfg(feature = "receipts")]
use crate::{
    consensus::issuer::{IssuerCommand, ProofChain},
    crypto::MerkleInclusionProof,
    proto::client::ProtoTransactionReceipt,
    proto::consensus::ProtoQuorumCertificate,
    utils::channel::Sender,
};
#[cfg(feature = "receipts")]
use std::collections::BTreeMap;


pub enum ClientReplyCommand {
    CancelAllRequests,
    StopCancelling,
    CrashCommitAck(HashMap<HashType, (u64, Vec<ProtoTransactionResult>)>),
    ByzCommitAck(HashMap<HashType, (u64, Vec<ProtoByzResponse>)>, u64 /* last_qc */),
    UnloggedRequestAck(oneshot::Receiver<ProtoTransactionResult>, MsgAckChanWithTag),
    ProbeRequestAck(u64 /* block_n */, u64 /* tx_n */, bool /* is_audit */, MsgAckChanWithTag),
}

#[allow(dead_code)]
enum ReplyProcessorCommand {
    CrashCommit(u64 /* block_n */, u64 /* tx_n */, HashType, ProtoTransactionResult /* result */, MsgAckChanWithTag, Vec<ProtoByzResponse>),
    ByzCommit(u64 /* block_n */, u64 /* tx_n */, ProtoTransactionResult /* result */, MsgAckChanWithTag),
    Unlogged(oneshot::Receiver<ProtoTransactionResult>, MsgAckChanWithTag),
    #[cfg(feature = "receipts")]
    Probe(bool /* is_audit */, u64 /* block_n */, ProofChain, Vec<ProtoQuorumCertificate>, Vec<(MsgAckChanWithTag, u64 /* tx_n */, MerkleInclusionProof)>),
}
pub struct ClientReplyHandler {
    config: AtomicConfig,

    batch_rx: Receiver<(oneshot::Receiver<HashType>, Vec<MsgAckChanWithTag>)>,
    reply_command_rx: Receiver<ClientReplyCommand>,
    #[cfg(feature = "receipts")]
    issuer_tx: Sender<IssuerCommand>,

    reply_map: HashMap<HashType, Vec<MsgAckChanWithTag>>,
    byz_reply_map: HashMap<HashType, Vec<(u64, SenderType)>>,

    crash_commit_reply_buf: HashMap<HashType, (u64, Vec<ProtoTransactionResult>)>,
    byz_commit_reply_buf: HashMap<HashType, (u64, Vec<ProtoByzResponse>)>,

    byz_response_store: HashMap<SenderType /* Sender */, Vec<ProtoByzResponse>>,

    reply_processors: JoinSet<()>,
    reply_processor_queue: (async_channel::Sender<ReplyProcessorCommand>, async_channel::Receiver<ReplyProcessorCommand>),

    #[cfg(feature = "receipts")]
    probe_audit_buffer: BTreeMap<u64 /* block_n */, Vec<(MsgAckChanWithTag, u64 /* tx_n */)>>,
    #[cfg(feature = "receipts")]
    probe_commit_buffer: BTreeMap<u64 /* block_n */, Vec<(MsgAckChanWithTag, u64 /* tx_n */)>>,
    acked_bci: u64,
    last_qc: u64,

    must_cancel: bool,
}

impl ClientReplyHandler {
    pub fn new(
        config: AtomicConfig,
        batch_rx: Receiver<(oneshot::Receiver<HashType>, Vec<MsgAckChanWithTag>)>,
        reply_command_rx: Receiver<ClientReplyCommand>,
        #[cfg(feature = "receipts")]
        issuer_tx: Sender<IssuerCommand>,
    ) -> Self {
        let _chan_depth = config.get().rpc_config.channel_depth as usize;
        Self {
            config,
            batch_rx,
            reply_command_rx,
            #[cfg(feature = "receipts")]
            issuer_tx,
            reply_map: HashMap::new(),
            byz_reply_map: HashMap::new(),
            crash_commit_reply_buf: HashMap::new(),
            byz_commit_reply_buf: HashMap::new(),
            reply_processors: JoinSet::new(),
            reply_processor_queue: async_channel::unbounded(),
            byz_response_store: HashMap::new(),
            #[cfg(feature = "receipts")]
            probe_audit_buffer: BTreeMap::new(),
            #[cfg(feature = "receipts")]
            probe_commit_buffer: BTreeMap::new(),
            acked_bci: 0,
            last_qc: 0,
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
                        ReplyProcessorCommand::CrashCommit(block_n, tx_n, hsh, reply, (reply_chan, client_tag, _), byz_responses) => {
                            let reply = ProtoClientReply {
                                reply: Some(
                                   crate::proto::client::proto_client_reply::Reply::Response(
                                     ProtoTransactionResponse {
                                            req_digest: hsh,
                                            block_n,
                                            tx_n,
                                            results: Some(reply),
                                            byz_responses,
                                     }
                                )),
                                client_tag
                            };
                
                            let reply_ser = reply.encode_to_vec();
                            let _sz = reply_ser.len();
                            let reply_msg = PinnedMessage::from(reply_ser, _sz, crate::rpc::SenderType::Anon);
                            let latency_profile = LatencyProfile::new();
                            
                            let _ = reply_chan.send((reply_msg, latency_profile)).await;
                        },
                        ReplyProcessorCommand::ByzCommit(_, _, _result, _sender) => {

                        },

                        ReplyProcessorCommand::Unlogged(res_rx, (reply_chan, tag, _sender)) => {
                            let results = res_rx.await.unwrap();
                            let reply = ProtoClientReply {
                                reply: Some(
                                   crate::proto::client::proto_client_reply::Reply::Response(
                                     ProtoTransactionResponse {
                                            req_digest: vec![],
                                            block_n: 0,
                                            tx_n: 0,
                                            results: Some(results),
                                            byz_responses: vec![],
                                     }
                                )),
                                client_tag: tag,
                            };

                            let reply_ser = reply.encode_to_vec();
                            let _sz = reply_ser.len();
                            let reply_msg = PinnedMessage::from(reply_ser, _sz, crate::rpc::SenderType::Anon);
                            let latency_profile = LatencyProfile::new();
                            
                            let _ = reply_chan.send((reply_msg, latency_profile)).await;
                        },

                        #[cfg(feature = "receipts")]
                        ReplyProcessorCommand::Probe(is_audit, _block_n, proof_chain, qcs, reply_vec) => {
                            for ((reply_chan, client_tag, _sender), _tx_n, inclusion_proof) in reply_vec {
                                let latency_profile = LatencyProfile::new();
                                let reply = ProtoClientReply {
                                    reply: Some(
                                        // this is just syntax sugar for the proto. both are chains, qcs, a proof, but the chain validation should be different (1 vs 2 QCs/fastQC)
                                        if is_audit { 
                                            crate::proto::client::proto_client_reply::Reply::AuditReceipt(
                                                ProtoTransactionReceipt {
                                                    chain: proof_chain.clone(),
                                                    proof: inclusion_proof.as_vec(),
                                                    qcs: qcs.clone(),
                                                }
                                            )
                                        } else {
                                            crate::proto::client::proto_client_reply::Reply::CommitReceipt(
                                                ProtoTransactionReceipt {
                                                    chain: proof_chain.clone(),
                                                    proof: inclusion_proof.as_vec(),
                                                    qcs: qcs.clone(),
                                                }
                                            )
                                        }
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
        assert_eq!(reply_sender_vec.len(), reply_vec.len());
        for (tx_n, ((reply_chan, client_tag, sender), reply)) in reply_sender_vec.into_iter().zip(reply_vec.into_iter()).enumerate() {
            let byz_responses = self.byz_response_store.remove(&sender).unwrap_or_default();
            
            self.reply_processor_queue.0.send(ReplyProcessorCommand::CrashCommit(n, tx_n as u64, hash.clone(), reply, (reply_chan, client_tag, sender), byz_responses)).await.unwrap();
        }

        #[cfg(feature = "receipts")]
        self.maybe_clear_probe_buf().await;
    }

    async fn do_byz_commit_reply(&mut self, reply_sender_vec: Vec<(u64, SenderType)>, _hash: HashType, n: u64, reply_vec: Vec<ProtoByzResponse>) {
        assert_eq!(reply_sender_vec.len(), reply_vec.len());
        for (_tx_n, ((client_tag, sender), mut reply)) in reply_sender_vec.into_iter().zip(reply_vec.into_iter()).enumerate() {
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

        #[cfg(feature = "receipts")]
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
            ClientReplyCommand::ByzCommitAck(byz_commit_ack, qc) => {
                if qc > self.last_qc {
                    self.last_qc = qc;
                }
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
            #[cfg(feature = "receipts")]
            ClientReplyCommand::ProbeRequestAck(block_n, tx_n, is_audit, sender) => {
                let buffer = if is_audit {
                    &mut self.probe_audit_buffer
                } else {
                    &mut self.probe_commit_buffer
                };
                if let Some(vec) = buffer.get_mut(&block_n) {
                    vec.push((sender, tx_n));
                } else {
                    buffer.insert(block_n, vec![(sender, tx_n)]);
                }

                self.maybe_clear_probe_buf().await;
            },
            #[cfg(not(feature = "receipts"))]
            ClientReplyCommand::ProbeRequestAck(_block_n, _tx_n, _is_audit, _sender) => {
                // no-op for now if receipts are disabled
                // ideally error back
            }
        }
    }

    #[cfg(feature = "receipts")]
    async fn maybe_clear_probe_buf(&mut self) {
        let mut ready_for_audit_receipt = vec![];
        let mut ready_for_commit_receipt = vec![];
        
        self.probe_audit_buffer.retain(|block_n, reply_vec| {
            if *block_n <= self.acked_bci {
                trace!("Clearing probe audit tx buffer of size {} for block {}", reply_vec.len(), block_n);
                ready_for_audit_receipt.push((*block_n, reply_vec.drain(..).collect::<Vec<_>>()));
                false
            } else {
                true
            }
        });

        self.probe_commit_buffer.retain(|block_n, reply_vec| {
            if *block_n <= self.last_qc {
                trace!("Clearing probe commit tx buffer of size {} for block {}", reply_vec.len(), block_n);
                ready_for_commit_receipt.push((*block_n, reply_vec.drain(..).collect::<Vec<_>>()));
                false
            } else {
                true
            }
        });

        for (block_n, reply_vec) in ready_for_audit_receipt {
            #[cfg(not(feature = "dummy_receipts"))] {
                let (tx, rx) = oneshot::channel();
                self.issuer_tx.send(IssuerCommand::IssueAuditReceipt(block_n, reply_vec.iter().map(|(_, tx_n)| *tx_n).collect(), tx)).await.unwrap();
                let Some(builder) = rx.await.unwrap() else {
                    error!("Failed to build audit receipt for block {}", block_n);
                    continue;
                };
                assert_eq!(reply_vec.len(), builder.proofs.len());
                self.reply_processor_queue.0.send(ReplyProcessorCommand::Probe(true, block_n, builder.chain, builder.qcs, reply_vec.into_iter().zip(builder.proofs).map(|((sender, tx_n), proof)| (sender, tx_n, proof)).collect())).await.unwrap();
            }
            #[cfg(feature = "dummy_receipts")] {
                let builder = crate::consensus::issuer::ReceiptBuilder {
                    chain: vec![],
                    proofs: reply_vec.iter().map(|_| MerkleInclusionProof::default()).collect(),
                    qcs: vec![],
                };
                assert_eq!(reply_vec.len(), builder.proofs.len());
                self.reply_processor_queue.0.send(ReplyProcessorCommand::Probe(true, block_n, builder.chain, builder.qcs, reply_vec.into_iter().zip(builder.proofs).map(|((sender, tx_n), proof)| (sender, tx_n, proof)).collect())).await.unwrap();
            }
        }

        for (block_n, reply_vec) in ready_for_commit_receipt {
            #[cfg(not(feature = "dummy_receipts"))] {
                let (tx, rx) = oneshot::channel();
                self.issuer_tx.send(IssuerCommand::IssueCommitReceipt(block_n, reply_vec.iter().map(|(_, tx_n)| *tx_n).collect(), tx)).await.unwrap();
                let Some(builder) = rx.await.unwrap() else {
                    error!("Failed to build commit receipt for block {}", block_n);
                    continue;
                };
                assert_eq!(reply_vec.len(), builder.proofs.len());
                self.reply_processor_queue.0.send(ReplyProcessorCommand::Probe(false, block_n, builder.chain, builder.qcs, reply_vec.into_iter().zip(builder.proofs).map(|((sender, tx_n), proof)| (sender, tx_n, proof)).collect())).await.unwrap();
            }
            #[cfg(feature = "dummy_receipts")] {
                let builder = crate::consensus::issuer::ReceiptBuilder {
                    chain: vec![],
                    proofs: reply_vec.iter().map(|_| MerkleInclusionProof::default()).collect(),
                    qcs: vec![],
                };
                assert_eq!(reply_vec.len(), builder.proofs.len());
                self.reply_processor_queue.0.send(ReplyProcessorCommand::Probe(false, block_n, builder.chain, builder.qcs, reply_vec.into_iter().zip(builder.proofs).map(|((sender, tx_n), proof)| (sender, tx_n, proof)).collect())).await.unwrap();
            }
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

