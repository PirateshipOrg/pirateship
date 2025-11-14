use std::{collections::HashMap, marker::PhantomData, sync::Arc};

use indexmap::IndexMap;
use log::{error, info};
use serde::{Serialize, de::DeserializeOwned};
use tokio::sync::Mutex;

use crate::{config::AtomicConfig, crypto::{AtomicKeyStore, HashType, hash}, proto::{checkpoint::{ProtoCheckpointCertificate, ProtoCheckpointVote}, consensus::ProtoNameWithSignature}, rpc::client::PinnedClient, utils::{StorageServiceConnector, channel::Receiver}};


type CheckpointWithBci<S> = (u64, S);

struct PendingCheckpoint {
    digest: HashType,
    vote_set: HashMap<String, ProtoCheckpointVote>,
}

impl PendingCheckpoint {
    fn new(digest: HashType) -> Self {
        Self {
            digest,
            vote_set: HashMap::new(),
        }
    }

    fn add_vote(&mut self, vote: ProtoCheckpointVote) -> usize {
        self.vote_set.insert(vote.sender.clone(), vote);
        self.vote_set.len()
    }
}

pub struct CheckpointHandler<S> {
    config: AtomicConfig,
    keystore: AtomicKeyStore,
    checkpoint_rx: Receiver<(u64 /* bci */, S /* state */)>,
    storage: StorageServiceConnector,
    client: PinnedClient,
    phantom: PhantomData<S>,

    pending_checkpoints: IndexMap<u64, PendingCheckpoint>,
    last_stable_checkpoint: Option<ProtoCheckpointCertificate>,
}

impl<S> CheckpointHandler<S> 
where S: Serialize + DeserializeOwned,
{
    pub fn new(config: AtomicConfig, keystore: AtomicKeyStore, checkpoint_rx: Receiver<(u64 /* bci */, S /* state */)>, storage: StorageServiceConnector, client: PinnedClient) -> Self {
        Self {
            config,
            keystore,
            checkpoint_rx,
            storage,
            client,
            phantom: PhantomData,
            pending_checkpoints: IndexMap::new(),
            last_stable_checkpoint: None,
        }
    }

    pub async fn run(checkpoint_handler: Arc<Mutex<Self>>) {
        let mut checkpoint_handler = checkpoint_handler.lock().await;
        while let Some((bci, state)) = checkpoint_handler.checkpoint_rx.recv().await {
            checkpoint_handler.handle_checkpoint(bci, state).await;
        }
    }

    async fn handle_checkpoint(&mut self, bci: u64, state: S) {
        let checkpoint_with_bci: CheckpointWithBci<S> = (bci, state);
        let Ok(state_ser) = bincode::serialize(&checkpoint_with_bci) else {
            error!("Failed to serialize state at bci {}", bci);
            return;
        };

        let state_digest = hash(&state_ser);
        let checkpoint_storage_key = format!("checkpoint:{}", hex::encode(&state_digest));

        self.storage.put_raw(checkpoint_storage_key.clone(), state_ser).await;

        info!("Checkpoint at bci {} saved to storage with key {}", bci, checkpoint_storage_key);
        self.pending_checkpoints.insert(bci, PendingCheckpoint::new(state_digest.clone()));


        let sig = self.keystore.get().sign(state_digest.clone().as_slice()).to_vec();

        let my_vote = ProtoCheckpointVote {
            digest: state_digest,
            bci,
            sender: self.config.get().net_config.name.clone(),
            sig,
        };

        let vote_count = self.pending_checkpoints.get_mut(&bci).unwrap().add_vote(my_vote);

        if vote_count >= self.get_threshold() {
            self.stabilize_checkpoint(bci).await;
        }

    }

    fn get_threshold(&self) -> usize {
        let config = self.config.get();
        let n = config.consensus_config.node_list.len();
        let u = config.consensus_config.liveness_u as usize;
        n - u
    }

    async fn stabilize_checkpoint(&mut self, bci: u64) {
        let checkpoint = self.pending_checkpoints.swap_remove(&bci).unwrap();
        let certificate = ProtoCheckpointCertificate {
            digest: checkpoint.digest,
            bci,
            sigs: checkpoint.vote_set.values().map(|vote| ProtoNameWithSignature {
                name: vote.sender.clone(),
                sig: vote.sig.clone(),
            }).collect(),
        };
        self.last_stable_checkpoint = Some(certificate);
    }
}