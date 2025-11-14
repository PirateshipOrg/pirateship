use std::{marker::PhantomData, sync::Arc};

use log::{error, info};
use serde::{Serialize, de::DeserializeOwned};
use tokio::sync::Mutex;

use crate::{config::AtomicConfig, crypto::hash, rpc::client::PinnedClient, utils::{StorageServiceConnector, channel::Receiver}};

pub struct CheckpointHandler<S> {
    config: AtomicConfig,
    checkpoint_rx: Receiver<(u64 /* bci */, S /* state */)>,
    storage: StorageServiceConnector,
    client: PinnedClient,
    phantom: PhantomData<S>,
}

impl<S> CheckpointHandler<S> 
where S: Serialize + DeserializeOwned,
{
    pub fn new(config: AtomicConfig, checkpoint_rx: Receiver<(u64 /* bci */, S /* state */)>, storage: StorageServiceConnector, client: PinnedClient) -> Self {
        Self {
            config,
            checkpoint_rx,
            storage,
            client,
            phantom: PhantomData,
        }
    }

    pub async fn run(checkpoint_handler: Arc<Mutex<Self>>) {
        let mut checkpoint_handler = checkpoint_handler.lock().await;
        while let Some((bci, state)) = checkpoint_handler.checkpoint_rx.recv().await {
            checkpoint_handler.handle_checkpoint(bci, state).await;
        }
    }

    async fn handle_checkpoint(&mut self, bci: u64, state: S) {
        let Ok(state_ser) = bincode::serialize(&state) else {
            error!("Failed to serialize state at bci {}", bci);
            return;
        };

        let state_digest = hash(&state_ser);
        let checkpoint_storage_key = format!("checkpoint:{}", hex::encode(state_digest));

        self.storage.put_raw(checkpoint_storage_key.clone(), state_ser).await;

        info!("Checkpoint at bci {} saved to storage with key {}", bci, checkpoint_storage_key);
    }
}