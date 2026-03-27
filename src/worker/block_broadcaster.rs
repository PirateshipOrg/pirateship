use std::io::{Error, ErrorKind};
use std::sync::Arc;

use log::{error, info, trace};
use prost::Message;
use tokio::sync::{oneshot, Mutex};

use crate::config::AtomicConfig;
use crate::crypto::CachedBlock;
use crate::proto::consensus::{HalfSerializedBlock, ProtoAppendEntries, ProtoFork};
use crate::proto::rpc::ProtoPayload;
use crate::rpc::client::PinnedClient;
use crate::rpc::server::LatencyProfile;
use crate::rpc::{PinnedMessage, SenderType};
use crate::utils::channel::Receiver;

pub struct BlockBroadcaster {
    config: AtomicConfig,
    client: PinnedClient,

    my_block_rx: Receiver<(u64, oneshot::Receiver<CachedBlock>)>,
}

impl BlockBroadcaster {
    pub fn new(
        config: AtomicConfig,
        client: PinnedClient,
        my_block_rx: Receiver<(u64, oneshot::Receiver<CachedBlock>)>,
    ) -> Self {
        Self {
            config,
            client,
            my_block_rx,
        }
    }

    pub async fn run(broadcaster: Arc<Mutex<Self>>) {
        let mut bb = broadcaster.lock().await;

        loop {
            if let Err(_) = bb.worker().await {
                break;
            }
        }

        info!("Worker block broadcaster exited.");
    }

    fn get_everyone_except_me(&self) -> Vec<String> {
        let config = self.config.get();
        let me = &config.net_config.name;
        config
            .consensus_config
            .learner_list
            .iter()
            .filter(|e| *e != me)
            .cloned()
            .collect()
    }

    async fn worker(&mut self) -> Result<(), Error> {
        let block = self.my_block_rx.recv().await;
        if block.is_none() {
            return Err(Error::new(ErrorKind::BrokenPipe, "my_block_rx closed"));
        }
        let (n, block_rx) = block.unwrap();
        let block = block_rx.await;
        if block.is_err() {
            error!("Failed to get block {}: {:?}", n, block);
            return Ok(());
        }
        self.broadcast_my_block(block.unwrap()).await?;

        Ok(())
    }

    async fn broadcast_my_block(&mut self, block: CachedBlock) -> Result<(), Error> {
        let names = self.get_everyone_except_me();

        let ae = ProtoAppendEntries {
            fork: Some(ProtoFork {
                serialized_blocks: vec![HalfSerializedBlock {
                    n: block.block.n,
                    view: block.block.view,
                    view_is_stable: block.block.view_is_stable,
                    config_num: block.block.config_num,
                    serialized_body: block.block_ser.clone(),
                }],
            }),
            commit_index: 0,
            view: 1,
            view_is_stable: true,
            config_num: 1,
            is_backfill_response: false,
        };

        let rpc = ProtoPayload {
            message: Some(crate::proto::rpc::proto_payload::Message::WorkerBlock(ae)),
        };
        let data = rpc.encode_to_vec();
        let sz = data.len();
        let data = PinnedMessage::from(data, sz, SenderType::Anon);
        let mut profile = LatencyProfile::new();
        trace!("Broadcasting block {} to {}", block.block.n, names.join(", "));
        let _ = PinnedClient::broadcast(
            &self.client,
            &names,
            &data,
            &mut profile,
            0,
        )
        .await;

        trace!("Worker broadcast block {}", block.block.n);
        Ok(())
    }

}
