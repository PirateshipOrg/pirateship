use std::{collections::HashMap, sync::Arc};

use rand::{Rng as _, SeedableRng as _};
use rand_chacha::ChaCha20Rng;
use tokio::sync::Mutex;

use crate::{config::AtomicConfig, crypto::hash, proto::consensus::ProtoWitness, utils::channel::Receiver};

pub struct WitnessReceiver {
    config: AtomicConfig,
    witness_set_map: HashMap<String, Vec<String>>, // sender -> list of witness sets.
    my_audit_responsibility: Vec<String>, // list of nodes that I am responsible for auditing.
    witness_rx: Receiver<ProtoWitness>,
}

impl WitnessReceiver {
    fn find_witness_set_map(node_list: &Vec<String>, r_plus_one: usize) -> HashMap<String, Vec<String>> {
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

    fn find_my_audit_responsibility(name: &String, witness_set_map: &HashMap<String, Vec<String>>) -> Vec<String> {
        let mut res = Vec::new();

        for (sender, witness_set) in witness_set_map.iter() {
            if witness_set.contains(name) {
                res.push(sender.clone());
            }
        }

        res
    }

    
    pub fn new(config: AtomicConfig, witness_rx: Receiver<ProtoWitness>) -> Self {
        let _config = config.get();
        let node_list = _config.consensus_config.node_list.clone();
        let r_plus_one = _config.consensus_config.node_list.len() - 2 * (_config.consensus_config.liveness_u as usize);
        let witness_set_map = Self::find_witness_set_map(&node_list, r_plus_one);
        let my_audit_responsibility = Self::find_my_audit_responsibility(&_config.net_config.name, &witness_set_map);
        Self { config, witness_set_map, my_audit_responsibility, witness_rx }
    }

    pub async fn run(witness_receiver: Arc<Mutex<Self>>) {
        let mut witness_receiver = witness_receiver.lock().await;
        
    }
}