use std::{collections::{BTreeMap, HashMap, HashSet}, sync::Arc, time::Duration};
use log::{error, info, trace};
use prost::Message as _;
use rand::{SeedableRng as _, seq::IteratorRandom};
use rand_chacha::ChaCha20Rng;
use tokio::{sync::Mutex, task::JoinSet};

use crate::{config::AtomicConfig, crypto::{HashType, default_hash, hash}, proto::{consensus::{ProtoVoteWitness, ProtoWitness, proto_witness::Body}, rpc::ProtoPayload}, rpc::{PinnedMessage, SenderType, client::PinnedClient, server::LatencyProfile}, utils::{channel::{Receiver, Sender, make_channel}, timer::ResettableTimer}};

pub struct WitnessReceiver {
    config: AtomicConfig,
    client: PinnedClient,
    witness_set_map: HashMap<String, Vec<String>>, // sender -> list of witness sets.
    my_audit_responsibility: HashSet<String>, // list of nodes that I am responsible for auditing.
    witness_rx: Receiver<ProtoWitness>,
    witness_audit_txs: HashMap<String, Sender<ProtoWitness>>, // If the load is too high, might split the responsibility into multiple tasks.

    handles: JoinSet<()>,
}


struct AuditorState {
    sender: String,
    block_hashes: BTreeMap<u64 /* block n */, HashType>,
    votes: HashMap<String /* sender */, BTreeMap<u64, HashType>>,
}

impl AuditorState {
    pub fn new(sender: String) -> Self {
        Self { sender, block_hashes: BTreeMap::new(), votes: HashMap::new() }
    }

    fn display_hash(hash: &HashType) -> String {
        hex::encode(hash.as_slice()).get(..5).unwrap().to_string()
    }

    pub fn log_stats(&mut self) {
        let (last_block_n, last_block_hash) = match self.block_hashes.last_entry() {
            Some(entry) => (*entry.key(), Self::display_hash(entry.get())),
            None => (0, Self::display_hash(&default_hash())),
        };

        let mut vote_last = HashMap::new();
        for (sender, votes) in self.votes.iter_mut() {
            let last_vote = match votes.last_entry() {
                Some(entry) => (*entry.key(), Self::display_hash(entry.get())),
                None => (0, Self::display_hash(&default_hash())),
            };
            vote_last.insert(sender.clone(), last_vote);
        }

        let vote_stat_str = vote_last.iter().map(|(sender, (n, hash))| format!("{}: {} -> {}", sender, n, hash)).collect::<Vec<_>>().join(", ");

        info!("Auditor stats for node: {}, last block: {} -> {}, last vote: {}", self.sender, last_block_n, last_block_hash, vote_stat_str);        
    }

    pub fn process_witness(&mut self, witness: ProtoWitness) {
        match witness.body {
            Some(Body::BlockWitness(block_witness)) => {
                if self.block_hashes.contains_key(&block_witness.n) {
                    let old_hash = self.block_hashes.get(&block_witness.n).unwrap();
                    if old_hash != &block_witness.block_hash {
                        error!("Block hash mismatch for block n: {}, old hash: {}, new hash: {}", block_witness.n, Self::display_hash(old_hash), Self::display_hash(&block_witness.block_hash));
                    }
                }

                for (_, vote_buffer) in self.votes.iter() {
                    if vote_buffer.contains_key(&block_witness.n) {
                        let old_hash = vote_buffer.get(&block_witness.n).unwrap();
                        if old_hash != &block_witness.block_hash {
                            error!("Vote hash mismatch for block n: {}, old hash: {}, new hash: {}", block_witness.n, Self::display_hash(old_hash), Self::display_hash(&block_witness.block_hash));
                        } else {
                            trace!("Vote hash matches block hash for vote n: {} and sender: {}", block_witness.n, witness.sender);
                        }
                    }
                }
                self.block_hashes.insert(block_witness.n, block_witness.block_hash.clone());
            }
            Some(Body::VoteWitness(vote_witness)) => {
                let entry = self.votes.entry(witness.sender.clone()).or_insert_with(BTreeMap::new);
                if entry.contains_key(&vote_witness.n) {
                    let old_hash = entry.get(&vote_witness.n).unwrap();
                    if old_hash != &vote_witness.block_hash {
                        error!("Vote hash mismatch for vote n: {} and sender: {}, old hash: {}, new hash: {}", vote_witness.n, witness.sender, Self::display_hash(old_hash), Self::display_hash(&vote_witness.block_hash));
                    }
                }
                if self.block_hashes.contains_key(&vote_witness.n) {
                    let block_hash = self.block_hashes.get(&vote_witness.n).unwrap();
                    if block_hash != &vote_witness.block_hash {
                        error!("Block hash mismatch for vote n: {} and sender: {}, block hash: {}, vote hash: {}", vote_witness.n, witness.sender, Self::display_hash(block_hash), Self::display_hash(&vote_witness.block_hash));
                    } else {
                        trace!("Vote hash matches block hash for vote n: {} and sender: {}", vote_witness.n, witness.sender);
                    }
                }
                entry.insert(vote_witness.n, vote_witness.block_hash.clone());
            }
            None => {
                error!("Witness has no body!");
            }
        }
    }
}


impl WitnessReceiver {
    pub fn find_witness_set_map(mut node_list: Vec<String>, r_plus_one: usize) -> HashMap<String, Vec<String>> {
        let mut res = HashMap::new();

        let mut load_on_each_node: HashMap<String, usize> = HashMap::new();
        let max_load = r_plus_one;

        node_list.sort();


        for node in &node_list {
            // Randomly select r_plus_one nodes from the list.
            // Exclude the current node from the list.
            // Seed the RNG with the node's name.

            let _node_list = node_list.iter()
                .filter_map(|n| {
                    if n.eq(node) { 
                        None 
                    } else if *load_on_each_node.get(n).unwrap_or(&0) >= max_load {
                        None
                    } else { 
                        Some(n.clone())
                    }
                })
                .collect::<Vec<_>>();

            let seed: [u8; 32] = hash(node.as_bytes())[..32].try_into().unwrap();
            let mut rng = ChaCha20Rng::from_seed(seed);
            let witness_set = _node_list.iter()
                .choose_multiple(&mut rng, r_plus_one)
                .into_iter()
                .map(|n| n.clone())
                .collect::<Vec<_>>();
            for n in witness_set.iter() {
                *load_on_each_node.entry(n.clone()).or_insert(0) += 1;
            }

            res.insert(node.clone(), witness_set);
        }

        trace!("Witness set map: {:?}", res);

        res    
    }

    fn find_my_audit_responsibility(name: &String, witness_set_map: &HashMap<String, Vec<String>>) -> HashSet<String> {
        let mut res = HashSet::new();

        for (sender, witness_set) in witness_set_map.iter() {
            if witness_set.contains(name) {
                res.insert(sender.clone());
            }
        }

        res
    }

    
    pub fn new(config: AtomicConfig, client: PinnedClient, witness_rx: Receiver<ProtoWitness>) -> Self {
        let _config = config.get();
        let node_list = _config.consensus_config.node_list.clone();
        let r_plus_one = _config.consensus_config.node_list.len() - 2 * (_config.consensus_config.liveness_u as usize);
        let witness_set_map = Self::find_witness_set_map(node_list, r_plus_one);
        let my_audit_responsibility = Self::find_my_audit_responsibility(&_config.net_config.name, &witness_set_map);
        let handles = JoinSet::new();
        let witness_audit_txs = HashMap::new();
        Self { config, client, witness_set_map, my_audit_responsibility, witness_rx, witness_audit_txs, handles }
    }

    pub async fn run(witness_receiver: Arc<Mutex<Self>>) {
        let mut witness_receiver = witness_receiver.lock().await;
        let _chan_depth = witness_receiver.config.get().rpc_config.channel_depth as usize;

        let _audit_responsibility = witness_receiver.my_audit_responsibility.clone();
        trace!("Audit responsibility: {:?} Witness set map: {:?}", _audit_responsibility, witness_receiver.witness_set_map);

        // Auditing threads.
        // for node in _audit_responsibility.iter() {
        for _ in 0..1 { // TODO: Handle load-balancing logic.
            let (witness_audit_tx, witness_audit_rx) = make_channel(_chan_depth);
            witness_receiver.witness_audit_txs.insert("*".to_string(), witness_audit_tx);
            // let _node = node.clone();
            let log_timeout = witness_receiver.config.get().app_config.logger_stats_report_ms;
            let log_timer = ResettableTimer::new(Duration::from_millis(log_timeout));
            log_timer.run().await;
            witness_receiver.handles.spawn(async move {
                info!("Auditing task for node");
                let mut state = AuditorState::new("*".to_string());
                loop {
                    tokio::select! {
                        _ = log_timer.wait() => {
                            state.log_stats();
                        }
                        witness = witness_audit_rx.recv() => {
                            if let Some(witness) = witness {
                                state.process_witness(witness);
                            }
                        }
                    }
                }
            });
        }


        // Forward to other witness thread.
        let (witness_forward_tx, witness_forward_rx) = make_channel::<ProtoWitness>(_chan_depth);
        let _witness_set_map = witness_receiver.witness_set_map.clone();
        let _client = witness_receiver.client.clone();
        witness_receiver.handles.spawn(async move {
            while let Some(witness) = witness_forward_rx.recv().await {
                // Broadcast this witness to the witness set of the sender.
                let witness_set = _witness_set_map.get(&witness.sender).unwrap();

                let payload = ProtoPayload {
                    message: Some(crate::proto::rpc::proto_payload::Message::Witness(witness)),
                };
                let buf = payload.encode_to_vec();

                let sz = buf.len();
                let msg = PinnedMessage::from(buf, sz, SenderType::Anon);

                let mut profile = LatencyProfile::new();
                let _res = PinnedClient::broadcast(&_client, witness_set, &msg, &mut profile, 0).await;
            }
        });

        while let Some(witness) = witness_receiver.witness_rx.recv().await {
            witness_receiver.maybe_forward_witness(&witness, &witness_forward_tx).await;
            witness_receiver.maybe_audit_witness(witness).await;
        }
    }

    async fn maybe_forward_witness(&mut self, witness: &ProtoWitness, witness_forward_tx: &Sender<ProtoWitness>) {
        let Some(body) = witness.body.as_ref() else {
            return;
        };

        let Body::BlockWitness(block_witness) = body else {
            return;
        };

        let sender = witness.sender.clone();

        // Decompose the vote qc into a vector of votes and create a witness for each vote.
        for qc in block_witness.qc.iter() {
            for sig in qc.sig.iter() {
                let vote_witness = ProtoVoteWitness {
                    block_hash: qc.digest.clone(),
                    vote_sig: sig.sig.clone(),
                    n: qc.n,
                };

                let witness = ProtoWitness {
                    sender: sig.name.clone(),
                    receiver: sender.clone(),
                    body: Some(Body::VoteWitness(vote_witness)),
                };

                witness_forward_tx.send(witness).await.unwrap();
            }
        }

    }

    async fn maybe_audit_witness(&mut self, witness: ProtoWitness) {
        for (_, witness_audit_tx) in self.witness_audit_txs.iter() {
            // TODO: Handle load-balancing logic.
            witness_audit_tx.send(witness.clone()).await.unwrap();
        }
    }

}