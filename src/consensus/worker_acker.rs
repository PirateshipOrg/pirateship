use std::collections::{BTreeMap, HashMap};
use std::io::{Error, ErrorKind};
use std::sync::Arc;

use log::{info, trace, warn};
use prost::Message;
use tokio::sync::Mutex;

use crate::config::AtomicConfig;
use crate::consensus::worker_handler::Cut;
use crate::crypto::default_hash;
use crate::proto::client::ProtoClientReply;
use crate::proto::consensus::ProtoWorkerVote;
use crate::proto::rpc::ProtoPayload;
use crate::rpc::client::PinnedClient;
use crate::rpc::server::LatencyProfile;
use crate::rpc::{PinnedMessage, SenderType};
use crate::utils::channel::Receiver;

use super::worker_handler::CutSerialized;

pub struct WorkerAcker {
    config: AtomicConfig,
    client: PinnedClient,
    worker_acker_rx: Receiver<(tokio::sync::mpsc::Receiver<(PinnedMessage, LatencyProfile)>, CutSerialized)>,
    byz_commit_pending: BTreeMap<u64 /* client tag */, CutSerialized>,
    byz_committed_cut: Cut,
}

impl WorkerAcker {
    pub fn new(
        config: AtomicConfig,
        client: PinnedClient,
        worker_acker_rx: Receiver<(tokio::sync::mpsc::Receiver<(PinnedMessage, LatencyProfile)>, CutSerialized)>,
    ) -> Self {
        Self { config, client, worker_acker_rx, byz_commit_pending: BTreeMap::new(), byz_committed_cut: HashMap::new() }
    }

    pub async fn run(acker: Arc<Mutex<Self>>) {
        let mut wa = acker.lock().await;
        loop {
            if let Err(_) = wa.worker().await {
                break;
            }
        }
        info!("Worker acker exited.");
    }

    async fn worker(&mut self) -> Result<(), Error> {
        let incoming = self.worker_acker_rx.recv().await;
        if incoming.is_none() {
            return Err(Error::new(ErrorKind::BrokenPipe, "worker_acker_rx closed"));
        }
        let (mut ack_rx, cut) = incoming.unwrap();

        // Wait for the cut to be committed before sending votes.
        let res = ack_rx.recv().await;
        let msg = res.unwrap().0;
        let sz = msg.as_ref().1;
        let resp = ProtoClientReply::decode(&msg.as_ref().0.as_slice()[..sz]);
        if resp.is_err() {
            // We need to try again.
            panic!("Failed to receive response from consensus: {:?}", resp.err());
        }

        let resp = resp.unwrap();

        match resp.reply {
            Some(crate::proto::client::proto_client_reply::Reply::Receipt(receipt)) => {
                self.byz_commit_pending.insert(resp.client_tag, cut.clone());

                for byz_resp in receipt.byz_responses.iter() {
                    let Some(byz_cut) = self.byz_commit_pending.remove(&byz_resp.client_tag) else {
                        continue;
                    };

                    for (worker_name, block_n, block_hash) in &byz_cut.cut {
                        let entry = self.byz_committed_cut.entry(worker_name.clone()).or_insert((0, default_hash()));
                        if *block_n > entry.0 {
                            entry.0 = *block_n;
                            entry.1 = block_hash.clone();
                        }
                    }
                }
            },
            _ => {
                panic!("Unexpected response from consensus: {:?}", resp.reply);
            }
        }



        let my_name = self.config.get().net_config.name.clone();

        trace!("Sending votes for cut to workers: {:?}",
            cut.cut.iter().map(|(w, b, _)| format!("{}: {}", *w, *b)).collect::<Vec<String>>().join(", "));

        for (worker_name, block_n, block_hash) in &cut.cut {
            let byz_block_n = self.byz_committed_cut.get(worker_name).map(|(n, _)| *n).unwrap_or(0);
            let vote = ProtoWorkerVote {
                block_hash: block_hash.clone(),
                block_n: *block_n,
                voter: my_name.clone(),
                byz_block_n,
            };

            let rpc = ProtoPayload {
                message: Some(crate::proto::rpc::proto_payload::Message::WorkerVote(vote)),
            };
            let data = rpc.encode_to_vec();
            let sz = data.len();
            let msg = PinnedMessage::from(data, sz, SenderType::Anon);

            if let Err(e) = PinnedClient::send(&self.client, worker_name, msg.as_ref()).await {
                warn!("Failed to send worker vote to {}: {}", worker_name, e);
            }
        }

        Ok(())
    }
}
