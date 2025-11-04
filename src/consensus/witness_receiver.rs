use std::{collections::{HashMap, HashSet}, sync::Arc};
use prost::Message as _;
use rand::{Rng as _, SeedableRng as _};
use rand_chacha::ChaCha20Rng;
use tokio::{sync::Mutex, task::JoinSet};

use crate::{config::AtomicConfig, crypto::hash, proto::{consensus::{ProtoVoteWitness, ProtoWitness, proto_witness::Body}, rpc::ProtoPayload}, rpc::{PinnedMessage, SenderType, client::PinnedClient, server::LatencyProfile}, utils::channel::{Receiver, Sender, make_channel}};

pub struct WitnessReceiver {
    config: AtomicConfig,
    client: PinnedClient,
    witness_set_map: HashMap<String, Vec<String>>, // sender -> list of witness sets.
    my_audit_responsibility: HashSet<String>, // list of nodes that I am responsible for auditing.
    witness_rx: Receiver<ProtoWitness>,
    witness_audit_txs: HashMap<String, Sender<ProtoWitness>>,

    handles: JoinSet<()>,
}

impl WitnessReceiver {
    pub fn find_witness_set_map(node_list: &Vec<String>, r_plus_one: usize) -> HashMap<String, Vec<String>> {
        let mut res = HashMap::new();


        for node in node_list {
            // Randomly select r_plus_one nodes from the list.
            // Exclude the current node from the list.
            // Seed the RNG with the node's name.

            let _node_list = node_list.iter()
                .filter_map(|n| if n.eq(node) { None } else { Some(n.clone()) })
                .collect::<Vec<_>>();

            let seed: [u8; 32] = hash(node.as_bytes())[..32].try_into().unwrap();
            let rng = ChaCha20Rng::from_seed(seed);
            let witness_set_idxs = rng.sample_iter(&rand::distributions::Uniform::new(0, _node_list.len())).take(r_plus_one).collect::<Vec<usize>>();
            let witness_set = witness_set_idxs.iter().map(|idx| _node_list[*idx].clone()).collect();

            res.insert(node.clone(), witness_set);
        }

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
        let witness_set_map = Self::find_witness_set_map(&node_list, r_plus_one);
        let my_audit_responsibility = Self::find_my_audit_responsibility(&_config.net_config.name, &witness_set_map);
        let handles = JoinSet::new();
        let witness_audit_txs = HashMap::new();
        Self { config, client, witness_set_map, my_audit_responsibility, witness_rx, witness_audit_txs, handles }
    }

    pub async fn run(witness_receiver: Arc<Mutex<Self>>) {
        let mut witness_receiver = witness_receiver.lock().await;
        let _chan_depth = witness_receiver.config.get().rpc_config.channel_depth as usize;

        let _audit_responsibility = witness_receiver.my_audit_responsibility.clone();

        // Auditing threads.
        for node in _audit_responsibility.iter() {
            let (witness_audit_tx, witness_audit_rx) = make_channel(_chan_depth);
            witness_receiver.witness_audit_txs.insert(node.clone(), witness_audit_tx);
            witness_receiver.handles.spawn(async move {
                while let Some(_witness) = witness_audit_rx.recv().await {
                    // TODO: Audit this witness.
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

        let n = block_witness.n;
        let sender = witness.sender.clone();

        // Decompose the vote qc into a vector of votes and create a witness for each vote.
        for qc in block_witness.qc.iter() {
            for sig in qc.sig.iter() {
                let vote_witness = ProtoVoteWitness {
                    block_hash: qc.digest.clone(),
                    vote_sig: sig.sig.clone(),
                    n,
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
        if !self.witness_audit_txs.contains_key(&witness.sender) {
            return;
        }

        let witness_audit_tx = self.witness_audit_txs.get(&witness.sender).unwrap();
        witness_audit_tx.send(witness).await.unwrap();
    }

}