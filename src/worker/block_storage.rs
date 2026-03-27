use std::io::{Error, ErrorKind};
use std::sync::Arc;

use log::{info, trace, warn};
use tokio::sync::Mutex;

use crate::config::AtomicConfig;
use crate::crypto::hash_proto_block_ser;
use crate::proto::consensus::ProtoWorkerVote;
use crate::utils::channel::{Receiver, Sender};
use crate::utils::RocksDBStorageEngine;
use crate::utils::StorageEngine;

pub struct BlockStorage {
    config: AtomicConfig,
    db: RocksDBStorageEngine,

    block_rx: Receiver<(Vec<u8>, u64, String)>,
    vote_sender_tx: Sender<(ProtoWorkerVote, String)>,
}

impl BlockStorage {
    pub fn new(
        config: AtomicConfig,
        db: RocksDBStorageEngine,
        block_rx: Receiver<(Vec<u8>, u64, String)>,
        vote_sender_tx: Sender<(ProtoWorkerVote, String)>,
    ) -> Self {
        Self {
            config,
            db,
            block_rx,
            vote_sender_tx,
        }
    }

    pub async fn run(storage: Arc<Mutex<Self>>) {
        let mut bs = storage.lock().await;
        bs.db.init();

        loop {
            if let Err(_) = bs.worker().await {
                break;
            }
        }

        bs.db.destroy();
        info!("Worker block storage exited.");
    }

    async fn worker(&mut self) -> Result<(), Error> {
        let incoming = self.block_rx.recv().await;
        if incoming.is_none() {
            return Err(Error::new(ErrorKind::BrokenPipe, "block_rx closed"));
        }
        let (serialized_body, block_n, sender_name) = incoming.unwrap();
        self.handle_block(serialized_body, block_n, sender_name).await
    }

    async fn handle_block(
        &mut self,
        serialized_body: Vec<u8>,
        block_n: u64,
        sender_name: String,
    ) -> Result<(), Error> {
        let block_hash = hash_proto_block_ser(&serialized_body);

        if let Err(e) = self.db.put_block(&serialized_body, &block_hash) {
            warn!("Failed to store block {}: {}", block_n, e);
        }

        trace!("Stored block {} (hash={})", block_n, hex::encode(&block_hash));

        let vote = ProtoWorkerVote {
            block_hash,
            block_n,
            voter: self.config.get().net_config.name.clone(),
        };

        self.vote_sender_tx
            .send((vote, sender_name))
            .await
            .expect("vote_sender_tx send error");

        Ok(())
    }
}
