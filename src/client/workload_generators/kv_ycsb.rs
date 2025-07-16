use log::info;
use rand::distributions::{Uniform, WeightedIndex};
use rand_chacha::ChaCha20Rng;
use rand::prelude::*;
use zipf::ZipfDistribution;

use crate::{config::KVReadWriteYCSB, proto::execution::{ProtoTransaction, ProtoTransactionOp, ProtoTransactionOpType, ProtoTransactionPhase, ProtoTransactionResult}};

use super::{PerWorkerWorkloadGenerator, WorkloadUnit, Executor};

/// This is enough for YCSB-A, B, C
#[derive(Clone)]
enum TxOpType {
    Read,
    Update,
}

#[derive(Clone)]
enum TxPhaseType {
    Crash,
    Byz
}

/// This version of YCSB is directly adapted from the original paper: https://courses.cs.duke.edu/fall13/cps296.4/838-CloudPapers/ycsb.pdf
/// YCSB-A, B and C only deal with read and update operations,
/// With record to be updated selected using Zipfian distribution.
/// Records are virtually identified with a key of the format `user<num>`.
/// I choose num from a Zipfian distribution, I clip the chosen value so that it falls within the number of keys I have specified in config.
/// I add an offset of 1_000_000, so the keys have more or less same size in bytes.
/// Finally for each field, we deal with kv pairs of the form `user<num>:field<fieldnum> --> random val`.
/// All fields for a key are read or updated together.
/// 
/// If the config.load_phase is set, the client will force exit after the load phase completes.
/// For load phase, it is advised to run with num_clients = 1.
/// Once the load phase finishes, the run phase (with config.load_phase = false) can be run with however many num_clients as needed.
/// Load phase can be used for warmup, make sure to remove the load phase time from throughput calculations.
pub struct KVReadWriteYCSBGenerator { 
    config: KVReadWriteYCSB,
    rng: ChaCha20Rng,

    read_write_weights: [(TxOpType, i32); 2],
    read_write_dist: WeightedIndex<i32>,

    crash_byz_weights: [(TxPhaseType, i32); 2],
    crash_byz_dist: WeightedIndex<i32>,

    key_selection_dist: ZipfDistribution,

    val_gen_dist: Uniform<u8>,
    
    last_request_type: TxOpType,
    load_phase_cnt: usize,
    total_clients: usize,
}

impl KVReadWriteYCSBGenerator {
    pub fn new(config: &KVReadWriteYCSB, client_idx: usize, total_clients: usize) -> KVReadWriteYCSBGenerator {
        let rng = ChaCha20Rng::from_entropy();

        let read_write_weights = [
            (TxOpType::Read, (config.read_ratio * 1000.0) as i32),
            (TxOpType::Update, ((1.0 - config.read_ratio) * 1000.0) as i32),
        ];
        for item in &read_write_weights {
            if item.1 < 0 || item.1 > 1000 {
                panic!("Invalid config");
            }
        }

        let crash_byz_weights = [
            (TxPhaseType::Byz, (config.byz_commit_ratio * 1000.0) as i32),
            (TxPhaseType::Crash, ((1.0 - config.byz_commit_ratio) * 1000.0) as i32),
        ];
        for item in &crash_byz_weights {
            if item.1 < 0 || item.1 > 1000 {
                panic!("Invalid config");
            }
        }

        let read_write_dist = WeightedIndex::new(read_write_weights.iter().map(|(_, weight)| weight)).unwrap();
        let crash_byz_dist = WeightedIndex::new(crash_byz_weights.iter().map(|(_, weight)| weight)).unwrap();
        
        let key_selection_dist = ZipfDistribution::new(config.num_keys, config.zipf_exponent).unwrap();
        
        let val_gen_dist = Uniform::new('a' as u8, 'z' as u8);
        KVReadWriteYCSBGenerator {
            config: config.clone(),
            rng,
            read_write_dist,
            read_write_weights,
            crash_byz_dist,
            crash_byz_weights,
            key_selection_dist,
            val_gen_dist,
            last_request_type: TxOpType::Read,
            load_phase_cnt: client_idx,
            total_clients
        }
    
    }

    fn get_key_str_from_num(&self, num: usize) -> String {
        format!("user{}", num)
    }

    fn get_field_str_from_num(&self, num: usize) -> String {
        format!(":field{}", num)
    }

    fn get_next_val(&mut self) -> Vec<u8> {
        (0..self.config.val_size)
            .map(|_| self.val_gen_dist.sample(&mut self.rng))
            .collect()
    }

    fn transform_key_num(&self, key_num: usize) -> usize {
        let mut key_num = key_num;
        if key_num >= self.config.num_keys {
            key_num = self.config.num_keys - 1;
        }

        key_num += 1_000_000;

        key_num
    }

    fn get_next_key(&mut self) -> String {
        let key_num = self.key_selection_dist.sample(&mut self.rng);
        let key_num = self.transform_key_num(key_num);

        self.get_key_str_from_num(key_num)
    }

    fn load_phase_next(&mut self) -> WorkloadUnit {
        // Write Transaction with the next key to be loaded.
        // Always write on crash commit

        let key = self.get_key_str_from_num(self.transform_key_num(self.load_phase_cnt));
        self.load_phase_cnt += self.total_clients;

        let mut ops = Vec::new();
        for i in 0..self.config.num_fields {
            let key = key.clone() + &self.get_field_str_from_num(i);
            let val = self.get_next_val();

            ops.push(ProtoTransactionOp {
                op_type: ProtoTransactionOpType::Write.into(),
                operands: vec![key.into_bytes(), val]
            });
            
        }

        self.last_request_type = TxOpType::Update;

        WorkloadUnit {
            tx: ProtoTransaction {
                on_receive: None,
                on_crash_commit: Some(ProtoTransactionPhase {
                    ops,
                }),
                on_byzantine_commit: None,
                is_reconfiguration: false,
                is_2pc: false,
            },
            executor: Executor::Leader
        }
    }

    fn read_next(&mut self) -> ProtoTransactionPhase {
        let key = self.get_next_key();
        let mut ops = Vec::new();
        for i in 0..self.config.num_fields {
            let key = key.clone() + &self.get_field_str_from_num(i);
            ops.push(ProtoTransactionOp {
                op_type: ProtoTransactionOpType::Read.into(),
                operands: vec![key.into_bytes()]
            });
        }

        ProtoTransactionPhase{ ops }
    }

    fn update_next(&mut self) -> ProtoTransactionPhase {
        let key = self.get_next_key();
        let mut ops = Vec::new();
        for i in 0..self.config.num_fields {
            let key = key.clone() + &self.get_field_str_from_num(i);
            let val = self.get_next_val();

            ops.push(ProtoTransactionOp {
                op_type: ProtoTransactionOpType::Write.into(),
                operands: vec![key.into_bytes(), val]
            });
            
        }
        ProtoTransactionPhase{ ops }
    }

    fn read_crash_next(&mut self) -> ProtoTransaction {
        let ops = self.read_next();
        ProtoTransaction {
            on_receive: None,
            on_crash_commit: Some(ops),
            on_byzantine_commit: None,
            is_reconfiguration: false,
            is_2pc: false,
        }
    }

    fn read_byz_next(&mut self) -> ProtoTransaction {
        let ops = self.read_next();
        ProtoTransaction {
            on_receive: None,
            on_crash_commit: None,
            on_byzantine_commit: Some(ops),
            is_reconfiguration: false,
            is_2pc: false,
        }
    }

    fn read_unlogged_next(&mut self) -> ProtoTransaction {
        let ops = self.read_next();
        ProtoTransaction {
            on_receive: Some(ops),
            on_crash_commit: None,
            on_byzantine_commit: None,
            is_reconfiguration: false,
            is_2pc: false,
        }
    }

    fn update_crash_next(&mut self) -> ProtoTransaction {
        let ops = self.update_next();
        ProtoTransaction {
            on_receive: None,
            on_crash_commit: Some(ops),
            on_byzantine_commit: None,
            is_reconfiguration: false,
            is_2pc: false,
        }
    }

    fn update_byz_next(&mut self) -> ProtoTransaction {
        let ops = self.update_next();
        ProtoTransaction {
            on_receive: None,
            on_crash_commit: None,
            on_byzantine_commit: Some(ops),
            is_reconfiguration: false,
            is_2pc: false,
        }
    }

    fn run_phase_next(&mut self) -> WorkloadUnit {
        let next_op = self.read_write_weights[self.read_write_dist.sample(&mut self.rng)].0.clone();

        let tx = match next_op {
            TxOpType::Read => {
                self.last_request_type = TxOpType::Read;
                if self.config.linearizable_reads {
                    let crash_or_byz = &self.crash_byz_weights[self.crash_byz_dist.sample(&mut self.rng)].0;
                    match crash_or_byz {
                        TxPhaseType::Crash => self.read_crash_next(),
                        TxPhaseType::Byz => self.read_byz_next(),
                    }
                } else {
                    self.read_unlogged_next()
                }

            },
            TxOpType::Update => {
                self.last_request_type = TxOpType::Update;
                let crash_or_byz = &self.crash_byz_weights[self.crash_byz_dist.sample(&mut self.rng)].0;
                    match crash_or_byz {
                        TxPhaseType::Crash => self.update_crash_next(),
                        TxPhaseType::Byz => self.update_byz_next(),
                    }
            },
        };

        let executor = match next_op {
            TxOpType::Read => {
                if self.config.linearizable_reads {
                    Executor::Leader
                } else {
                    Executor::Any
                }
            },
            TxOpType::Update => Executor::Leader,
        };

        WorkloadUnit {
            tx, executor
        }

    }
}

impl PerWorkerWorkloadGenerator for KVReadWriteYCSBGenerator {
    fn next(&mut self) -> WorkloadUnit {
        if self.config.load_phase && self.load_phase_cnt < self.config.num_keys {
            return self.load_phase_next();
        } else {
            return self.run_phase_next();
        }
    }
    
    fn check_result(&mut self, result: &Option<ProtoTransactionResult>) -> bool {
        if let TxOpType::Read = self.last_request_type {
            if result.is_none() || result.as_ref().unwrap().result.len() != self.config.num_fields {
                return false;
            }

            for res in &result.as_ref().unwrap().result {
                if res.values.len() == 0 || res.values[0].len() != self.config.val_size {
                    return false;
                }
            }
            
            return true;
        }

        if self.config.load_phase && self.load_phase_cnt >= self.config.num_keys {
            info!("End of Load phase");
            self.config.load_phase = false;
        }

        true

    }
}