use std::io::{Error, ErrorKind};
use std::sync::Arc;

use log::{info, warn};
use prost::Message;
use tokio::sync::Mutex;

use crate::config::AtomicConfig;
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
}

impl WorkerAcker {
    pub fn new(
        config: AtomicConfig,
        client: PinnedClient,
        worker_acker_rx: Receiver<(tokio::sync::mpsc::Receiver<(PinnedMessage, LatencyProfile)>, CutSerialized)>,
    ) -> Self {
        Self { config, client, worker_acker_rx }
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
        let _ = ack_rx.recv().await;

        let my_name = self.config.get().net_config.name.clone();

        info!("Sending votes for cut to workers: {:?}",
            cut.cut.iter().map(|(w, b, _)| format!("{}: {}", *w, *b)).collect::<Vec<String>>().join(", "));

        for (worker_name, block_n, block_hash) in &cut.cut {
            let vote = ProtoWorkerVote {
                block_hash: block_hash.clone(),
                block_n: *block_n,
                voter: my_name.clone(),
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
