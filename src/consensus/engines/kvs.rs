// use std::collections::{BTreeMap, HashMap};
use hashbrown::HashMap;
use rustls::crypto::hash::Hash;
use std::fmt::Display;

use log::{error, info, trace, warn};
use serde::{Serialize, Deserialize};

use crate::{config::AtomicConfig, consensus::app::AppEngine};

use crate::proto::execution::{
    ProtoTransaction, ProtoTransactionPhase, ProtoTransactionOp, ProtoTransactionOpType,
    ProtoTransactionResult, ProtoTransactionOpResult,
};

use crate::proto::client::{ProtoByzResponse,};

use crate::proto::consensus::{
    ProtoBlock, ProtoQuorumCertificate, ProtoForkValidation, ProtoVote, ProtoSignatureArrayEntry,
    ProtoNameWithSignature, proto_block::Sig, DefferedSignature,
};

#[derive(std::fmt:: Debug, Clone, Serialize, Deserialize)]
pub struct KVSState {
    pub ci_state: HashMap<Vec<u8>, Vec<(u64, Vec<u8>) /* versions */>>,
    pub bci_state: HashMap<Vec<u8>, Vec<u8>>,
}

impl Display for KVSState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ci_state size: {}, bci_state size: {}", self.ci_state.len(), self.bci_state.len())
    }
}

pub struct KVSAppEngine {
    config: AtomicConfig,
    pub last_ci: u64,
    pub last_bci: u64,
    quit_signal: bool,
    state: KVSState,
    
}

impl AppEngine for KVSAppEngine {
    type State = KVSState;

    fn new(config: AtomicConfig) -> Self {
        Self {
            config,
            last_ci: 0,
            last_bci: 0,
            quit_signal: false,
            state: KVSState {
                ci_state: HashMap::new(),
                bci_state: HashMap::new(),
            },
        }
    }

    fn handle_crash_commit(&mut self, blocks: Vec<crate::crypto::CachedBlock>) -> Vec<Vec<crate::proto::execution::ProtoTransactionResult>> {
        // iterate through eac txn in each block
        // see if that txn on_crash_commit is not none
        //     iterate through all ops in order, see ops in protobuf
        //     for every op you have a result
        //     each txn gives a txn result. Transaction has many ops, prototransaction has many op results
            //if op type is write --> add to ci_state, if read dont add to ci_state

        //the return value is a list of lists containing transaction results for each block
        let mut block_count = 0;
        let mut txn_count = 0;

        let mut final_result: Vec<Vec<ProtoTransactionResult>> = Vec::new();

        for block in blocks.iter() {
            let proto_block: &ProtoBlock = &block.block;
            self.last_ci = proto_block.n;
            let mut block_result: Vec<ProtoTransactionResult> = Vec::new();
            for tx in proto_block.tx_list.iter() {
                let mut txn_result = ProtoTransactionResult {
                    result: Vec::new(),
                };
                let ops = match &tx.on_crash_commit {
                    Some(ops) => &ops.ops,
                    None => {
                        block_result.push(txn_result);
                        continue;
                    },
                };

                for op in ops.iter() {
                    
                    if let Some(op_type) = ProtoTransactionOpType::from_i32(op.op_type) {
                        if op_type == ProtoTransactionOpType::Write {
                            if op.operands.len() != 2 {
                                continue;
                            }
                            let key = &op.operands[0];
                            let val: &Vec<u8> = &op.operands[1];
                            if self.state.ci_state.contains_key(key) {
                                self.state.ci_state.get_mut(key).unwrap().push((proto_block.n, val.clone()));
                            } else {
                                self.state.ci_state.insert(key.clone(), vec![(proto_block.n, val.clone())]);
                            }
                            txn_result.result.push(ProtoTransactionOpResult {
                                success: true,
                                values: vec![],
                            });
                        } else if op_type == ProtoTransactionOpType::Read {
                            if op.operands.len() != 1 {
                                continue;
                            }
                            let key: &Vec<u8> = &op.operands[0];
                            let result = self.read(key);
                            // let result = Some(vec![0xde, 0xad, 0xbe, 0xef]);
                            if let Some(value) = result {
                                txn_result.result.push(ProtoTransactionOpResult {
                                    success: true,
                                    values: vec![value],
                                });
                            }
                        } else if op_type == ProtoTransactionOpType::Increment { // [key, incr_val, Optional check_val]
                            if op.operands.len() != 1 && op.operands.len() != 2 && op.operands.len() != 3 {
                                continue;
                            }

                            // Read increment value (default 1)
                            let incr_val = if op.operands.len() == 2 {
                                let incr_val = &op.operands[1];
                                if let Ok(arr) = incr_val.as_slice().try_into() {
                                    i64::from_be_bytes(arr)
                                } else {
                                    1
                                }
                            } else {
                                1
                            };

                            // Read counter
                            let key: &Vec<u8> = &op.operands[0];
                            let result = self.read(key);
                            let mut result = if result.is_none() {
                                0
                            } else {
                                let result = result.unwrap();
                                i64::from_be_bytes(result.as_slice().try_into().unwrap())
                            };

                            let must_increment = if op.operands.len() == 3 {
                                let check_val_buf = &op.operands[2];
                                if let Ok(arr) = check_val_buf.as_slice().try_into() {
                                    let check_val = i64::from_be_bytes(arr);
                                    result == check_val
                                } else {
                                    true // garbage input
                                }
                            } else {
                                true
                            };

                            // Perform op

                            if must_increment {
                                result += incr_val;
                            }

                            // Write back
                            let val = result.to_be_bytes().to_vec();

                            if self.state.ci_state.contains_key(key) {
                                self.state.ci_state.get_mut(key).unwrap().push((proto_block.n, val.clone()));
                            } else {
                                self.state.ci_state.insert(key.clone(), vec![(proto_block.n, val.clone())]);
                            }

                            // Return incremented value
                            txn_result.result.push(ProtoTransactionOpResult {
                                success: true,
                                values: vec![val],
                            });

                        } else if op_type == ProtoTransactionOpType::Cas { // [key1, swap_val1, compare_val1, key2, swap_val2, compare_val2, ...]                            
                            if op.operands.len() % 3 != 0 {
                                continue;
                            }

                            struct CasOp {
                                key: Vec<u8>,
                                swap_val: Vec<u8>,
                                compare_val: Vec<u8>,
                            }

                            let mut cas_ops = Vec::new();
                            let mut read_vals = Vec::new();
                            for i in (0..op.operands.len()).step_by(3) {
                                cas_ops.push(CasOp {
                                    key: op.operands[i].clone(),
                                    swap_val: op.operands[i + 1].clone(),
                                    compare_val: op.operands[i + 2].clone(),
                                });
                            }

                            for op in cas_ops.iter() {
                                // Read compare value
                                let key: &Vec<u8> = &op.key;
                                let result = self.read(key);
                                if result.is_none() {
                                    read_vals.push(vec![]);
                                } else {
                                    read_vals.push(result.unwrap());
                                }
                            }

                            let mut must_operate = true;
                            for i in 0..cas_ops.len() {
                                if !read_vals[i].eq(&cas_ops[i].compare_val) {
                                    must_operate = false;
                                    break;
                                }
                            }


                            if must_operate {
                                // Write back
                                for op in cas_ops.iter() {
                                    let key = &op.key;
                                    let val = &op.swap_val;
                                    if self.state.ci_state.contains_key(key) {
                                        self.state.ci_state.get_mut(key).unwrap().push((proto_block.n, val.clone()));
                                    } else {
                                        self.state.ci_state.insert(key.clone(), vec![(proto_block.n, val.clone())]);
                                    }
                                }
                            }
                            txn_result.result.push(ProtoTransactionOpResult {
                                success: must_operate,
                                values: read_vals,
                            });

                        }
                    } else {
                        warn!("Invalid operation type: {}", op.op_type);
                        continue;
                    }

                    
                }
                block_result.push(txn_result);
                //test
                txn_count += 1;
            }
            final_result.push(block_result);

            //test
            block_count += 1;
        }
        trace!("block count:{}", block_count);
        trace!("transaction count{}", txn_count);
        return final_result;
    }


                

    fn handle_byz_commit(&mut self, blocks: Vec<crate::crypto::CachedBlock>) -> Vec<Vec<ProtoByzResponse>> {
        let mut block_count = 0;
        let mut txn_count: i32 = 0;

        let mut final_result: Vec<Vec<ProtoByzResponse>> = Vec::new();

        for block in blocks.iter() {
            let proto_block: &ProtoBlock = &block.block;
            self.last_bci = proto_block.n;
            let mut block_result: Vec<ProtoByzResponse> = Vec::new(); 

            for (tx_n, tx) in proto_block.tx_list.iter().enumerate() {
                let mut byz_result = ProtoByzResponse {
                    block_n: proto_block.n,
                    tx_n: tx_n as u64,
                    client_tag: 0,
                };
                let ops: &_ = match &tx.on_byzantine_commit{
                    Some(ops) => &ops.ops,
                    None => {
                        block_result.push(byz_result);
                        continue;
                    },
                };

                for op in ops.iter() {
                    if op.operands.len() != 2 {
                        continue;
                    }
                    if let Some(op_type) = ProtoTransactionOpType::from_i32(op.op_type) {
                        if op_type == ProtoTransactionOpType::Write {
                            let key = &op.operands[0];
                            let val = &op.operands[1];
                            self.state.bci_state.insert(key.clone(), val.clone());
                        }
                    } else {
                        warn!("Invalid operation type: {}", op.op_type);
                        continue;
                    }
                }
                block_result.push(byz_result);
                //test
                txn_count += 1;
            }
            final_result.push(block_result);
            //test
            block_count += 1;
        }

        // Then move all Byz committed entries from ci_state to bci_state.
        for (key, val_versions) in self.state.ci_state.iter_mut() {
            for (pos, val) in &(*val_versions) {
                if *pos <= self.last_bci {
                    self.state.bci_state.insert(key.clone(), val.clone());
                }
            }

            val_versions.retain(|v| v.0 > self.last_bci);
        }
        self.state.ci_state.retain(|_, v| v.len() > 0);
        trace!("block count:{}", block_count);
        trace!("transaction count{}", txn_count);
        final_result
    }

    fn handle_rollback(&mut self, rolled_back_blocks: u64) {
        //roll back ci_state to rolled_back_blocks (block.n)
        for (_k, v) in self.state.ci_state.iter_mut() {
            v.retain(|(pos, _)| *pos <= rolled_back_blocks);
        }

        self.state.ci_state.retain(|_, v| v.len() > 0);
    }

    fn handle_unlogged_request(&mut self, request: crate::proto::execution::ProtoTransaction) -> crate::proto::execution::ProtoTransactionResult {
        let mut txn_result = ProtoTransactionResult {
            result: Vec::new(),
        };

        let ops: &_ = match &request.on_receive {
            Some(ops) => &ops.ops,
            None => return txn_result,
        };

        for op in ops {
            if op.operands.len() != 1 {
                continue;
            }
            let mut op_result = ProtoTransactionOpResult {
                success: false, 
                values: vec![],
            };
            let key = &op.operands[0];
            let result = self.read(key);
            if let Some(value) = result {
                op_result.success = true;
                op_result.values = vec![value];
            }
            txn_result.result.push(op_result);
        }
        return txn_result;
    }

    fn get_current_state(&self) -> Self::State {
        return self.state.clone();
    }

    
}

impl KVSAppEngine {
    fn read(&self, key: &Vec<u8>) -> Option<Vec<u8>> {
        //same search logic from old kvs.rs
        let ci_res = self.state.ci_state.get(key);
        if let Some(v) = ci_res {
            // Invariant: v is sorted by ci
            // Invariant: v.len() > 0
            let res = &v.last().unwrap().1;
            return Some(res.clone());
        } else {
            //check bci_state
        }
        
        let bci_res = self.state.bci_state.get(key);
        if let Some(v) = bci_res {
            return Some(v.clone());
        } else {
            return None;
        }
    }
}