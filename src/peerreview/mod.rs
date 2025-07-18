use std::{collections::{HashMap, VecDeque}, ops::Deref, sync::Arc};

use ed25519_dalek::{Signer, SigningKey, SIGNATURE_LENGTH};
use log::error;
use prost::Message as _;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use tokio::{sync::Mutex, sync::oneshot};
use crate::{proto::{peerreview::{proto_peer_review_log_entry_content, ProtoPeerReviewLogEntry, ProtoPeerReviewLogEntryContent, ProtoPeerReviewLogEntryContentRecv, ProtoPeerReviewLogEntryContentSend}, rpc::{proto_payload, ProtoPayload}}, rpc::{server::LatencyProfile, MessageRef, PinnedMessage}};

use rand::prelude::*;
use rand_chacha::ChaCha8Rng;

use crate::{config::{AtomicConfig, ConsensusConfig}, crypto::{default_hash, hash, AtomicKeyStore, FutureHash, HashType, Sha, DIGEST_LENGTH}, rpc::{client::PinnedClient, SenderType}, utils::channel::{Receiver, Sender}};

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

        // ^ Must be done before the parent hash is awaited below. v

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

    pub fn to_proto(&self) -> ProtoPeerReviewLogEntry {
        ProtoPeerReviewLogEntry {
            seq_num: self.seq_num,
            parent_hash: self.parent_hash.to_vec(),
            content: Some(ProtoPeerReviewLogEntryContent { content: Some(
                match &self.content {
                    PRLogEntryContent::Send { receiver, message } => {
                        proto_peer_review_log_entry_content::Content::Send(
                            ProtoPeerReviewLogEntryContentSend { receiver: receiver.to_name_and_sub_id().0, message: message.clone() }
                        )
                    }
                    PRLogEntryContent::Recv { sender, sender_seq_num, message } => {
                        proto_peer_review_log_entry_content::Content::Recv(
                            ProtoPeerReviewLogEntryContentRecv { sender: sender.to_name_and_sub_id().0, sender_seq_num: *sender_seq_num, message: message.clone() }
                        )
                    }
                }
            ) }),
            signature: self.__cached_signature.to_vec(),
        }
    }

    pub fn from_proto(proto_pr_log_entry: ProtoPeerReviewLogEntry) -> Self {
        let content = match proto_pr_log_entry.content.unwrap().content.unwrap() {
            proto_peer_review_log_entry_content::Content::Send(proto_pr_log_entry_content_send) => {
                PRLogEntryContent::Send {
                    receiver: SenderType::Auth(proto_pr_log_entry_content_send.receiver, 0),
                    message: proto_pr_log_entry_content_send.message,
                }
            }
            proto_peer_review_log_entry_content::Content::Recv(proto_pr_log_entry_content_recv) => {
                PRLogEntryContent::Recv {
                    sender: SenderType::Auth(proto_pr_log_entry_content_recv.sender, 0),
                    sender_seq_num: proto_pr_log_entry_content_recv.sender_seq_num,
                    message: proto_pr_log_entry_content_recv.message,
                }
            }
        };


        let mut ret = Self {
            seq_num: proto_pr_log_entry.seq_num,
            parent_hash: proto_pr_log_entry.parent_hash.try_into().unwrap(),
            content,
            __cached_hash: default_hash(),
            __cached_signature: proto_pr_log_entry.signature.try_into().unwrap(),
        };

        // This follows the same logic as PRLogEntry::new
        let mut hasher = Sha::new();
        hasher.update(&ret.seq_num.to_le_bytes());
        hasher.update(ret.content.hash());
        hasher.update(&ret.parent_hash);
        let __cached_hash = hasher.finalize().to_vec();
        ret.__cached_hash = __cached_hash;

        ret
    }
}

#[derive(Clone)]
pub struct CachedPRLogEntry(Arc<Box<PRLogEntry>>);

impl Deref for CachedPRLogEntry {
    type Target = PRLogEntry;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

type ContentWithSeqNum = (u64, FutureHash, PRLogEntryContent, oneshot::Sender<HashType>, oneshot::Sender<CachedPRLogEntry>);

pub struct PRLogSequencer {
    config: AtomicConfig,
    keystore: AtomicKeyStore,

    seq_num: u64,
    parent_hash: FutureHash,

    log_entry_rx: Receiver<PRLogEntryContent>,
    log_broadcaster_tx: Sender<oneshot::Receiver<CachedPRLogEntry>>,

    content_with_seq_num_tx: async_channel::Sender<ContentWithSeqNum>,
    content_with_seq_num_rx: async_channel::Receiver<ContentWithSeqNum>,
}

impl PRLogSequencer {
    pub fn new(config: AtomicConfig, keystore: AtomicKeyStore, log_entry_rx: Receiver<PRLogEntryContent>, log_broadcaster_tx: Sender<oneshot::Receiver<CachedPRLogEntry>>) -> Self {
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

            tokio::spawn(Self::crypto_worker(content_with_seq_num_rx, signing_key.clone()));
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
        let (block_tx, block_rx) = oneshot::channel();
        let content_with_seq_num = (self.seq_num, parent_hash, log_entry_content, hash_tx, block_tx);
        self.content_with_seq_num_tx.send(content_with_seq_num).await.unwrap();
        self.parent_hash = FutureHash::Future(hash_rx);
        self.log_broadcaster_tx.send(block_rx).await.unwrap();
        Ok(())
    }

    /// These crypto workers are isolated from the crypto workers for the main protocol.
    /// They only process PeerReview Log Entries.
    /// But the logic is the same.
    async fn crypto_worker(content_with_seq_num_rx: async_channel::Receiver<ContentWithSeqNum>, signing_key: SigningKey) {
        while let Ok((seq_num, parent_hash, content, hash_tx, block_tx)) = content_with_seq_num_rx.recv().await {
            let log_entry = PRLogEntry::new(seq_num, parent_hash, content, &signing_key).await;
            let log_entry_hash = log_entry.hash();
            let _ = hash_tx.send(log_entry_hash);
            let _ = block_tx.send(CachedPRLogEntry(Arc::new(Box::new(log_entry))));
        }
    }
}


impl ConsensusConfig {
    /// Deterministic pseudo-random way to generate the witness list:
    /// 1. Remove the name from the node_list
    /// 2. Sort the rest of the names.
    /// 3. Seed the random number generator with the name.
    /// 4. Sample (rsafe + 1) names from all names.
    /// rsafe + 1 = N - 2 * u
    pub fn get_witness_list(&self, name: &String) -> Vec<String> {
        let seed = hash(name.as_bytes());
        
        let mut rng = ChaCha8Rng::from_seed(seed.try_into().unwrap());
        let mut witness_list = self.node_list.clone();
        witness_list.retain(|x| x != name);
        witness_list.sort();

        let witness_count = self.node_list.len() - 2 * self.liveness_u as usize;

        witness_list.iter()
            .choose_multiple(&mut rng, witness_count)
            .into_iter()
            .map(|x| x.clone())
            .collect()
    }
}

pub struct PRLogBroadcaster {
    config: AtomicConfig,
    client: PinnedClient,
    witness_list: Vec<String>,

    log_broadcaster_rx: Receiver<oneshot::Receiver<CachedPRLogEntry>>,
}

impl PRLogBroadcaster {
    pub fn new(config: AtomicConfig, client: PinnedClient, log_broadcaster_rx: Receiver<oneshot::Receiver<CachedPRLogEntry>>) -> Self {
        let my_name = &config.get().net_config.name;
        let witness_list = config.get().consensus_config.get_witness_list(my_name);
        Self { config, client, witness_list, log_broadcaster_rx }
    }

    pub async fn run(pr_log_broadcaster: Arc<Mutex<Self>>) -> Result<(), ()> {
        let mut pr_log_broadcaster = pr_log_broadcaster.lock().await;

        loop {
            pr_log_broadcaster.worker().await?;
        }
    }

    async fn worker(&mut self) -> Result<(), ()> {
        if let Some(log_entry) = self.log_broadcaster_rx.recv().await {
            self.handle_log_entry(log_entry).await?;
        } else {
            return Err(());
        }

        Ok(())
    }

    async fn handle_log_entry(&mut self, log_entry: oneshot::Receiver<CachedPRLogEntry>) -> Result<(), ()> {
        let log_entry = log_entry.await.map_err(|_| ())?;

        let log_entry_proto = log_entry.to_proto();
        let payload = ProtoPayload {
            message: Some(proto_payload::Message::PrLogEntry(log_entry_proto))
        };

        let buf = payload.encode_to_vec();
        let sz = buf.len();

        let sender_type = SenderType::Anon;
        let message = PinnedMessage::from(buf, sz, sender_type);

        let _ = PinnedClient::broadcast(
            &self.client,
            &self.witness_list,
            &message,
            &mut LatencyProfile::new(),
            self.witness_list.len(),
        ).await;

        Ok(())
    }
}

pub struct PRLogReceiver {
    config: AtomicConfig,
    logs: HashMap<SenderType, VecDeque<PRLogEntry>>,

    log_entry_rx: Receiver<(SenderType, ProtoPeerReviewLogEntry)>,
}

impl PRLogReceiver {
    pub fn new(config: AtomicConfig, log_entry_rx: Receiver<(SenderType, ProtoPeerReviewLogEntry)>) -> Self {
        Self { config, logs: HashMap::new(), log_entry_rx }
    }

    pub async fn run(pr_log_receiver: Arc<Mutex<Self>>) -> Result<(), ()> {
        let mut pr_log_receiver = pr_log_receiver.lock().await;

        loop {
            pr_log_receiver.worker().await?;
        }
    }

    async fn worker(&mut self) -> Result<(), ()> {
        if let Some((sender_type, proto_pr_log_entry)) = self.log_entry_rx.recv().await {
            self.handle_log_entry(sender_type, proto_pr_log_entry).await?;
        } else {
            return Err(());
        }

        self.check_log_consistency().await?;

        Ok(())
    }

    async fn handle_log_entry(&mut self, sender: SenderType, proto_pr_log_entry: ProtoPeerReviewLogEntry) -> Result<(), ()> {  
        let log_entry = PRLogEntry::from_proto(proto_pr_log_entry);

        let _name = sender.to_name_and_sub_id().0;

        let log_entry_map = self.logs.entry(sender).or_insert(VecDeque::new());
        let last_n = if log_entry_map.len() > 0 {
            log_entry_map.back().unwrap().seq_num
        } else {
            0
        };
        
        if log_entry.seq_num != last_n + 1 {
            error!("PR Log Continuity Violation for {}: Expected seq_num {} but got {}", _name, last_n + 1, log_entry.seq_num);
            return Err(());
        }

        log_entry_map.push_back(log_entry);

        Ok(())
    }

    async fn check_log_consistency(&mut self) -> Result<(), ()> {
        // This is the most important part of the protocol.
        // Ensure that all the logs received are consistent with the underlying protocol.
        // TODO: Find all the invariants that must be satisfied.
        
        Ok(())
    }
}