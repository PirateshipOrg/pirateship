use std::io::{Error, ErrorKind};
use std::sync::Arc;

use log::{info, trace, warn};
use prost::Message;
use tokio::sync::Mutex;

use crate::config::AtomicConfig;
use crate::proto::consensus::{ProtoWorkerBlockInfo, ProtoWorkerVote};
use crate::proto::rpc::ProtoPayload;
use crate::rpc::client::PinnedClient;
use crate::rpc::{PinnedMessage, SenderType};
use crate::utils::channel::Receiver;

pub struct WorkerHandler {
    config: AtomicConfig,
    client: PinnedClient,

    block_info_rx: Receiver<ProtoWorkerBlockInfo>,
}

impl WorkerHandler {
    pub fn new(
        config: AtomicConfig,
        client: PinnedClient,
        block_info_rx: Receiver<ProtoWorkerBlockInfo>,
    ) -> Self {
        Self {
            config,
            client,
            block_info_rx,
        }
    }

    pub async fn run(handler: Arc<Mutex<Self>>) {
        let mut wh = handler.lock().await;

        loop {
            if let Err(_) = wh.worker().await {
                break;
            }
        }

        info!("Worker handler exited.");
    }

    async fn worker(&mut self) -> Result<(), Error> {
        let incoming = self.block_info_rx.recv().await;
        if incoming.is_none() {
            return Err(Error::new(ErrorKind::BrokenPipe, "block_info_rx closed"));
        }
        let block_info = incoming.unwrap();
        self.handle_block_info(block_info).await
    }

    async fn handle_block_info(&mut self, block_info: ProtoWorkerBlockInfo) -> Result<(), Error> {
        let my_name = self.config.get().net_config.name.clone();
        let target = block_info.block_origin.clone();

        info!(
            "Received block info for block {} from {}, sending vote",
            block_info.block_n, target
        );

        let vote = ProtoWorkerVote {
            block_hash: block_info.block_hash,
            block_n: block_info.block_n,
            voter: my_name,
        };

        let rpc = ProtoPayload {
            message: Some(crate::proto::rpc::proto_payload::Message::WorkerVote(vote)),
        };
        let data = rpc.encode_to_vec();
        let sz = data.len();
        let data = PinnedMessage::from(data, sz, SenderType::Anon);

        if let Err(e) = PinnedClient::send(&self.client, &target, data.as_ref()).await {
            warn!("Failed to send worker vote to {}: {}", target, e);
        }

        Ok(())
    }
}
