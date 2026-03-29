use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use log::{info, trace};
use prost::Message as _;
use tokio::sync::{oneshot, Mutex};
use tokio::time::{self, Interval};

use crate::config::AtomicConfig;
use crate::consensus::batch_proposal::MsgAckChanWithTag;
use crate::crypto::HashType;
use crate::proto::client::{ProtoByzResponse, ProtoClientReply, ProtoTransactionReceipt};
use crate::proto::consensus::ProtoWorkerVote;
use crate::rpc::server::LatencyProfile;
use crate::rpc::{PinnedMessage, SenderType};
use crate::utils::channel::Receiver;

struct PendingBlock {
    block_n: u64,
    voters: HashSet<String>,
    ack_chans: Option<Vec<MsgAckChanWithTag>>,
}

pub struct VoteTracker {
    #[allow(dead_code)]
    config: AtomicConfig,

    register_rx: Receiver<(u64, oneshot::Receiver<HashType>, Vec<MsgAckChanWithTag>)>,
    vote_rx: Receiver<ProtoWorkerVote>,

    pending: HashMap<HashType, PendingBlock>,
    threshold: usize,
    node_names: HashSet<String>,
    worker_names: HashSet<String>,

    total_blocks_acked: u64,
    total_txns_acked: u64,
    total_txns_byz_committed: u64,
    log_timer: Interval,

    pending_byz_responses: HashMap<(u64 /* block_n */, SenderType), Vec<ProtoByzResponse>>,
}

impl VoteTracker {
    pub fn new(
        config: AtomicConfig,
        register_rx: Receiver<(u64, oneshot::Receiver<HashType>, Vec<MsgAckChanWithTag>)>,
        vote_rx: Receiver<ProtoWorkerVote>,
    ) -> Self {
        let threshold = config.get().consensus_config.liveness_u as usize + 1;
        let node_names = config.get().consensus_config.node_list.clone().into_iter().collect();
        let worker_names = config.get().consensus_config.learner_list.clone().into_iter().collect();

        let log_interval = Duration::from_millis(config.get().app_config.logger_stats_report_ms as u64);
        Self {
            config,
            register_rx,
            vote_rx,
            pending: HashMap::new(),
            threshold,
            total_blocks_acked: 0,
            total_txns_acked: 0,
            total_txns_byz_committed: 0,
            log_timer: time::interval(log_interval),
            node_names,
            worker_names,
            pending_byz_responses: HashMap::new(),
        }
    }

    pub async fn run(tracker: Arc<Mutex<Self>>) {
        let mut vt = tracker.lock().await;

        loop {
            if let Err(_) = vt.worker().await {
                break;
            }
        }

        info!("Worker vote tracker exited.");
    }

    async fn worker(&mut self) -> Result<(), ()> {
        tokio::select! {
            reg = self.register_rx.recv() => {
                if reg.is_none() {
                    return Err(());
                }
                let (block_n, hash_rx, ack_chans) = reg.unwrap();
                self.handle_register(block_n, hash_rx, ack_chans).await;
            },
            vote = self.vote_rx.recv() => {
                if vote.is_none() {
                    return Err(());
                }
                self.handle_vote(vote.unwrap()).await;
            },
            _ = self.log_timer.tick() => {
                info!("total_blocks_acked = {}, total_txns_acked = {}, total_txns_byz_committed = {}",
                    self.total_blocks_acked,
                    self.total_txns_acked,
                    self.total_txns_byz_committed
                );
            },
        }

        Ok(())
    }

    async fn handle_register(
        &mut self,
        block_n: u64,
        hash_rx: oneshot::Receiver<HashType>,
        ack_chans: Vec<MsgAckChanWithTag>,
    ) {
        let hash = match hash_rx.await {
            Ok(h) => h,
            Err(_) => return,
        };

        let entry = self.pending.entry(hash.clone()).or_insert_with(|| PendingBlock {
            block_n,
            voters: HashSet::new(),
            ack_chans: None,
        });

        for (i, (_, client_tag, sender)) in ack_chans.iter().enumerate() {
            self.pending_byz_responses.entry((block_n, sender.clone())).or_insert_with(|| Vec::new()).push(ProtoByzResponse {
                block_n,
                tx_n: i as u64,
                client_tag: *client_tag,
            });
        }

        entry.voters.insert(self.config.get().net_config.name.clone()); // Vote for myself
        entry.ack_chans = Some(ack_chans);



        self.maybe_ack(&hash, 0).await;
    }

    async fn handle_vote(&mut self, vote: ProtoWorkerVote) {
        let voter = vote.voter.clone();
        let vote_n = vote.block_n;

        let eligible_hashes: Vec<HashType> = self
            .pending
            .iter()
            .filter(|(_, entry)| entry.block_n <= vote_n)
            .map(|(hash, _)| hash.clone())
            .collect();

        for hash in &eligible_hashes {
            if let Some(entry) = self.pending.get_mut(hash) {
                entry.voters.insert(voter.clone());
            }
        }

        for hash in eligible_hashes {
            self.maybe_ack(&hash, vote.byz_block_n).await;
        }
    }

    async fn maybe_ack(&mut self, hash: &HashType, byz_block_n: u64) {
        if byz_block_n == 0 {
            return;
        }
        
        let should_ack = {
            if let Some(entry) = self.pending.get(hash) {
                let worker_votes = entry.voters.iter().filter(|v| self.worker_names.contains(*v)).count();
                let has_node_vote = entry.voters.iter().any(|v| self.node_names.contains(v));
                worker_votes >= self.threshold && entry.ack_chans.is_some()
                && has_node_vote
            } else {
                false
            }
        };

        if !should_ack {
            return;
        }


        let entry = self.pending.remove(hash).unwrap();
        let ack_chans = entry.ack_chans.unwrap();

        self.total_blocks_acked += 1;
        self.total_txns_acked += ack_chans.len() as u64;

        trace!(
            "Vote threshold reached for block {}, acking {} clients",
            hex::encode(hash), ack_chans.len()
        );

        for (i, (reply_chan, client_tag, sender)) in ack_chans.into_iter().enumerate() {
            let byz_responses = self.pending_byz_responses.iter()
                .filter(|((n, _sender), _)| *n <= byz_block_n && *_sender == sender)
                .map(|((n,  _sender), byz_responses)| (*n, byz_responses.clone()))
                .collect::<HashMap<u64, Vec<ProtoByzResponse>>>();

            byz_responses.keys().for_each(|n| {
                self.pending_byz_responses.remove(&(*n, sender.clone()));
            });

            let byz_responses = byz_responses.values().flatten().cloned().collect::<Vec<ProtoByzResponse>>();
            self.total_txns_byz_committed += byz_responses.len() as u64;


            let reply = ProtoClientReply {
                reply: Some(crate::proto::client::proto_client_reply::Reply::Receipt(
                    ProtoTransactionReceipt {
                        req_digest: hash.clone(),
                        block_n: entry.block_n,
                        tx_n: i as u64,
                        results: None,
                        await_byz_response: true,
                        byz_responses,
                    },
                )),
                client_tag,
            };

            let reply_ser = reply.encode_to_vec();
            let sz = reply_ser.len();
            let reply_msg = PinnedMessage::from(reply_ser, sz, crate::rpc::SenderType::Anon);
            let latency_profile = LatencyProfile::new();

            let _ = reply_chan.send((reply_msg, latency_profile)).await;
        }
    }
}
