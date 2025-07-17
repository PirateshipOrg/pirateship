use std::{collections::VecDeque, ops::{Deref, DerefMut}, sync::Arc};

use ed25519_dalek::{Signer, SigningKey, SIGNATURE_LENGTH};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use tokio::{sync::Mutex, sync::oneshot};

use crate::{config::AtomicConfig, crypto::{default_hash, AtomicKeyStore, FutureHash, HashType, Sha, DIGEST_LENGTH}, rpc::SenderType, utils::channel::{Receiver, Sender}};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum PRLogEntryContent {
    Send {
        receiver: SenderType,
        message: Vec<u8>,
    },
    Recv {
        sender: SenderType,
        sender_seq_num: u64,
        message: Vec<u8>,
    },
}

impl PRLogEntryContent {
    pub fn hash(&self) -> HashType {
        let mut hasher = Sha::new();
        hasher.update(&bincode::serialize(self).unwrap());
        hasher.finalize().to_vec()
    }
}

pub struct PRLogEntry {
    pub seq_num: u64,
    pub parent_hash: HashType,
    pub content: PRLogEntryContent,
    __cached_hash: HashType,
    __cached_signature: [u8; SIGNATURE_LENGTH],
}

impl PRLogEntry {
    pub async fn new(seq_num: u64, parent_hash: FutureHash, content: PRLogEntryContent, signing_key: &SigningKey) -> Self {
        let mut hasher = Sha::new();
        hasher.update(&seq_num.to_le_bytes());
        hasher.update(content.hash());

        let parent_hash = match parent_hash {
            FutureHash::None => panic!("Parent hash cannot be None"),
            FutureHash::Immediate(val) => val,
            FutureHash::Future(receiver) => {
                receiver.await.unwrap()
            },
            FutureHash::FutureResult(receiver) => {
                receiver.await.unwrap().unwrap()
            },
        };
        hasher.update(&parent_hash);
        let __cached_hash = hasher.finalize().to_vec();


        let mut buf = vec![0u8; size_of::<u64>() + DIGEST_LENGTH];
        buf[..size_of::<u64>()].copy_from_slice(&seq_num.to_le_bytes());
        buf[size_of::<u64>()..].copy_from_slice(&__cached_hash);
        let __cached_signature = signing_key
            .sign(&buf)
            .to_bytes();

        Self { seq_num, parent_hash, content, __cached_hash, __cached_signature }
    }

    pub fn hash(&self) -> HashType {
        return self.__cached_hash.clone();
    }
}

pub struct CachedPRLogEntry(Arc<Box<PRLogEntry>>);

impl Deref for CachedPRLogEntry {
    type Target = PRLogEntry;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

type ContentWithSeqNum = (u64, FutureHash, PRLogEntryContent, oneshot::Sender<HashType>);

pub struct PRLogSequencer {
    config: AtomicConfig,
    keystore: AtomicKeyStore,

    seq_num: u64,
    parent_hash: FutureHash,

    log_entry_rx: Receiver<PRLogEntryContent>,
    log_broadcaster_tx: Sender<CachedPRLogEntry>,

    content_with_seq_num_tx: async_channel::Sender<ContentWithSeqNum>,
    content_with_seq_num_rx: async_channel::Receiver<ContentWithSeqNum>,
}

impl PRLogSequencer {
    pub fn new(config: AtomicConfig, keystore: AtomicKeyStore, log_entry_rx: Receiver<PRLogEntryContent>, log_broadcaster_tx: Sender<CachedPRLogEntry>) -> Self {
        let (content_with_seq_num_tx, content_with_seq_num_rx) = async_channel::bounded(config.get().rpc_config.channel_depth as usize);
        
        Self {
            config, keystore,
            log_entry_rx, log_broadcaster_tx,
            seq_num: 0, parent_hash: FutureHash::Immediate(default_hash()),
            content_with_seq_num_tx, content_with_seq_num_rx
        }
    }

    pub async fn run(pr_log_sequencer: Arc<Mutex<Self>>) -> Result<(), ()> {
        let mut pr_log_sequencer = pr_log_sequencer.lock().await;

        let signing_key = pr_log_sequencer.keystore.get().get_privkey().clone();

        let num_crypto_workers = pr_log_sequencer.config.get().consensus_config.num_crypto_workers;
        for _i in 0..num_crypto_workers {
            let content_with_seq_num_rx = pr_log_sequencer.content_with_seq_num_rx.clone();
            let log_broadcaster_tx = pr_log_sequencer.log_broadcaster_tx.clone();

            tokio::spawn(Self::crypto_worker(content_with_seq_num_rx, log_broadcaster_tx, signing_key.clone()));
        }

        loop {
            pr_log_sequencer.worker().await?;
        }
    }

    async fn worker(&mut self) -> Result<(), ()> {
        tokio::select! {
            Some(log_entry_content) = self.log_entry_rx.recv() => {
                self.handle_log_entry_content(log_entry_content).await?;
            }
        }
        Ok(())
    }

    async fn handle_log_entry_content(&mut self, log_entry_content: PRLogEntryContent) -> Result<(), ()> {
        self.seq_num += 1;
        let parent_hash = self.parent_hash.take();
        let (hash_tx, hash_rx) = oneshot::channel();
        let content_with_seq_num = (self.seq_num, parent_hash, log_entry_content, hash_tx);
        self.content_with_seq_num_tx.send(content_with_seq_num).await.unwrap();
        self.parent_hash = FutureHash::Future(hash_rx);
        Ok(())
    }

    async fn crypto_worker(content_with_seq_num_rx: async_channel::Receiver<ContentWithSeqNum>, log_broadcaster_tx: Sender<CachedPRLogEntry>, signing_key: SigningKey) {
        while let Ok((seq_num, parent_hash, content, hash_tx)) = content_with_seq_num_rx.recv().await {
            let log_entry = PRLogEntry::new(seq_num, parent_hash, content, &signing_key).await;
            let log_entry_hash = log_entry.hash();
            hash_tx.send(log_entry_hash).unwrap();
            log_broadcaster_tx.send(CachedPRLogEntry(Arc::new(Box::new(log_entry)))).await.unwrap();
        }
    }
}



