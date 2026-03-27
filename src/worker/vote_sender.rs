use std::io::{Error, ErrorKind};
use std::sync::Arc;

use log::{info, trace, warn};
use prost::Message;
use tokio::sync::Mutex;

use crate::proto::consensus::ProtoWorkerVote;
use crate::proto::rpc::ProtoPayload;
use crate::rpc::client::PinnedClient;
use crate::rpc::{PinnedMessage, SenderType};
use crate::utils::channel::Receiver;

pub struct VoteSender {
    client: PinnedClient,

    vote_rx: Receiver<(ProtoWorkerVote, String)>,
}

impl VoteSender {
    pub fn new(
        client: PinnedClient,
        vote_rx: Receiver<(ProtoWorkerVote, String)>,
    ) -> Self {
        Self {
            client,
            vote_rx,
        }
    }

    pub async fn run(vote_sender: Arc<Mutex<Self>>) {
        let mut vs = vote_sender.lock().await;

        loop {
            if let Err(_) = vs.worker().await {
                break;
            }
        }

        info!("Worker vote sender exited.");
    }

    async fn worker(&mut self) -> Result<(), Error> {
        let incoming = self.vote_rx.recv().await;
        if incoming.is_none() {
            return Err(Error::new(ErrorKind::BrokenPipe, "vote_rx closed"));
        }
        let (vote, target) = incoming.unwrap();
        self.send_vote(vote, target).await
    }

    async fn send_vote(&mut self, vote: ProtoWorkerVote, target: String) -> Result<(), Error> {
        trace!("Sending vote for block {} to {}", vote.block_n, target);

        let rpc = ProtoPayload {
            message: Some(crate::proto::rpc::proto_payload::Message::WorkerVote(vote)),
        };
        let data = rpc.encode_to_vec();
        let sz = data.len();
        let data = PinnedMessage::from(data, sz, SenderType::Anon);

        if let Err(e) = PinnedClient::send(&self.client, &target, data.as_ref()).await {
            warn!("Failed to send vote to {}: {}", target, e);
        }

        Ok(())
    }
}
