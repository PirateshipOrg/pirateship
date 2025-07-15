use hashbrown::HashMap;
use std::fmt::Display;

use log::{error, trace, warn};
use serde::{Deserialize, Serialize};

#[cfg(feature = "policy_validation")]
use rquickjs::{Context, Function, Object, Runtime, Value};

use crate::{config::AtomicConfig, consensus::app::AppEngine};

use crate::proto::execution::{
    ProtoTransactionOpResult, ProtoTransactionOpType, ProtoTransactionResult,
};

use crate::proto::client::ProtoByzResponse;

use crate::proto::consensus::ProtoBlock;

#[derive(std::fmt:: Debug, Clone, Serialize, Deserialize)]
pub struct SCITTState {
    pub crash_committed_claims: HashMap<TXID, Vec<(u64, Vec<u8>) /* versions */>>,
    pub byz_committed_claims: HashMap<TXID, Vec<u8>>,
    pub crash_committed_policies: Vec<Vec<u8>>,
    pub byz_committed_policies: Vec<Vec<u8>>,
}

impl Display for SCITTState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ci_state size: {}, bci_state size: {}",
            self.crash_committed_claims.len(),
            self.byz_committed_claims.len()
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct TXID {
    pub block_n: u64,
    pub tx_idx: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub enum SCITTWriteType {
    Claim,
    Policy,
}

impl SCITTWriteType {
    pub fn from_slice(slice: &[u8]) -> Self {
        if slice == b"C" {
            SCITTWriteType::Claim
        } else if slice == b"P" {
            SCITTWriteType::Policy
        } else {
            panic!("Invalid SCITTWriteType slice");
        }
    }
    pub fn to_slice(&self) -> &[u8] {
        match self {
            SCITTWriteType::Claim => b"C",
            SCITTWriteType::Policy => b"P",
        }
    }
}

impl TXID {
    const DELIMITER: char = ':';
    pub fn new(block_n: u64, tx_idx: usize) -> Self {
        Self { block_n, tx_idx }
    }
    pub fn to_vec(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.block_n.to_be_bytes());
        v.extend_from_slice(&self.tx_idx.to_be_bytes());
        v
    }
    pub fn from_vec(v: &[u8]) -> Option<Self> {
        if v.len() < 16 {
            return None; // 8 bytes for u64 + 8 bytes for usize
        }
        let block_n = u64::from_be_bytes(v[0..8].try_into().ok()?);
        let tx_idx = usize::from_be_bytes(v[8..16].try_into().ok()?);
        Some(Self { block_n, tx_idx })
    }
    pub fn to_string(&self) -> String {
        format!("{}{}{}", self.block_n, Self::DELIMITER, self.tx_idx)
    }
    pub fn from_string(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(Self::DELIMITER).collect();
        if parts.len() != 2 {
            return None;
        }
        let block_n = parts[0].parse::<u64>().ok()?;
        let tx_idx = parts[1].parse::<usize>().ok()?;
        Some(Self { block_n, tx_idx })
    }
}

#[cfg(feature = "policy_validation")]
thread_local! {
    pub static JS_RUNTIME: Runtime = Runtime::new().unwrap();
}

pub struct SCITTAppEngine {
    config: AtomicConfig,
    pub last_ci: u64,
    pub last_bci: u64,
    state: SCITTState,
}

impl AppEngine for SCITTAppEngine {
    type State = SCITTState;

    fn new(config: AtomicConfig) -> Self {
        Self {
            config,
            last_ci: 0,
            last_bci: 0,
            state: SCITTState {
                crash_committed_claims: HashMap::new(),
                byz_committed_claims: HashMap::new(),
                crash_committed_policies: Vec::new(),
                byz_committed_policies: Vec::new(),
            },
        }
    }

    fn handle_crash_commit(
        &mut self,
        blocks: Vec<crate::crypto::CachedBlock>,
    ) -> Vec<Vec<crate::proto::execution::ProtoTransactionResult>> {
        let mut block_count = 0;
        let mut txn_count = 0;

        let mut final_result: Vec<Vec<ProtoTransactionResult>> = Vec::new();

        for block in blocks.iter() {
            let proto_block: &ProtoBlock = &block.block;
            self.last_ci = proto_block.n;
            let mut block_result: Vec<ProtoTransactionResult> = Vec::new();
            for tx in proto_block.tx_list.iter() {
                let mut txn_result = ProtoTransactionResult { result: Vec::new() };
                let ops = match &tx.on_crash_commit {
                    Some(ops) => &ops.ops,
                    None => {
                        block_result.push(txn_result);
                        continue;
                    }
                };

                for (i, op) in ops.iter().enumerate() {
                    if let Some(op_type) = ProtoTransactionOpType::from_i32(op.op_type) {
                        if op_type == ProtoTransactionOpType::Write {
                            if op.operands.len() != 2 {
                                continue;
                            }

                            match SCITTWriteType::from_slice(&op.operands[0]) {
                                SCITTWriteType::Claim => {
                                    let claim: &Vec<u8> = &op.operands[1];
                                    let txid = TXID::new(proto_block.n, i);
                                    if self.state.crash_committed_claims.contains_key(&txid) {
                                        error!(
                                            "Invalid ledger write: {} already exists",
                                            txid.to_string()
                                        );
                                    } else {
                                        self.state.crash_committed_claims.insert(
                                            txid.clone(),
                                            vec![(proto_block.n, claim.clone())],
                                        );
                                    }
                                    txn_result.result.push(ProtoTransactionOpResult {
                                        success: true,
                                        values: vec![txid.to_string().into_bytes()],
                                    });
                                }
                                SCITTWriteType::Policy => {
                                    let policy = &op.operands[1];

                                    self.state.crash_committed_policies.push(policy.clone());

                                    txn_result.result.push(ProtoTransactionOpResult {
                                        success: true,
                                        values: vec![],
                                    });
                                }
                            }
                        } else if op_type == ProtoTransactionOpType::Read {
                            if op.operands.len() != 1 {
                                continue;
                            }
                            let key = TXID::from_vec(&op.operands[0]);
                            let mut result = None;
                            if let Some(txid) = key {
                                result = self.read(&txid);
                            }
                            if let Some(value) = result {
                                txn_result.result.push(ProtoTransactionOpResult {
                                    success: true,
                                    values: vec![value],
                                });
                            }
                        } else if op_type == ProtoTransactionOpType::Scan {
                            if op.operands.len() != 2 {
                                continue;
                            }
                            let from = TXID::from_vec(&op.operands[0]);
                            let to = TXID::from_vec(&op.operands[1]);

                            let scan_result = self.scan(&from, &to);
                            if let Some(scan_result) = scan_result {
                                txn_result.result.push(ProtoTransactionOpResult {
                                    success: true,
                                    values: scan_result,
                                });
                            }
                        } else {
                            warn!("Invalid operation type: {}", op.op_type);
                            continue;
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

    fn handle_byz_commit(
        &mut self,
        blocks: Vec<crate::crypto::CachedBlock>,
    ) -> Vec<Vec<ProtoByzResponse>> {
        let mut block_count = 0;
        let mut txn_count: i32 = 0;

        let mut final_result: Vec<Vec<ProtoByzResponse>> = Vec::new();

        for block in blocks.iter() {
            let proto_block: &ProtoBlock = &block.block;
            self.last_bci = proto_block.n;
            let mut block_result: Vec<ProtoByzResponse> = Vec::new();

            for (tx_n, tx) in proto_block.tx_list.iter().enumerate() {
                let byz_result = ProtoByzResponse {
                    block_n: proto_block.n,
                    tx_n: tx_n as u64,
                    client_tag: 0,
                };
                let ops: &_ = match &tx.on_byzantine_commit {
                    Some(ops) => &ops.ops,
                    None => {
                        block_result.push(byz_result);
                        continue;
                    }
                };

                for op in ops.iter() {
                    if op.operands.len() != 2 {
                        continue;
                    }
                    if let Some(op_type) = ProtoTransactionOpType::from_i32(op.op_type) {
                        if op_type == ProtoTransactionOpType::Write {
                            let key = TXID {
                                block_n: proto_block.n,
                                tx_idx: tx_n,
                            };
                            let val = &op.operands[1];
                            self.state.byz_committed_claims.insert(key, val.clone());
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
        for (key, val_versions) in self.state.crash_committed_claims.iter_mut() {
            for (pos, val) in &(*val_versions) {
                if *pos <= self.last_bci {
                    self.state
                        .byz_committed_claims
                        .insert(key.clone(), val.clone());
                }
            }

            val_versions.retain(|v| v.0 > self.last_bci);
        }
        self.state.crash_committed_claims.retain(|_, v| v.len() > 0);
        trace!("block count:{}", block_count);
        trace!("transaction count{}", txn_count);
        final_result
    }

    fn handle_rollback(&mut self, rolled_back_blocks: u64) {
        //roll back ci_state to rolled_back_blocks (block.n)
        for (_k, v) in self.state.crash_committed_claims.iter_mut() {
            v.retain(|(pos, _)| *pos <= rolled_back_blocks);
        }

        self.state.crash_committed_claims.retain(|_, v| v.len() > 0);
    }

    fn handle_unlogged_request(
        &mut self,
        request: crate::proto::execution::ProtoTransaction,
    ) -> crate::proto::execution::ProtoTransactionResult {
        let mut txn_result = ProtoTransactionResult { result: Vec::new() };

        let ops: &_ = match &request.on_receive {
            Some(ops) => &ops.ops,
            None => return txn_result,
        };

        for op in ops {
            if let Some(op_type) = ProtoTransactionOpType::from_i32(op.op_type) {
                if op_type == ProtoTransactionOpType::Read {
                    if op.operands.len() != 1 {
                        continue;
                    }
                    let mut op_result = ProtoTransactionOpResult {
                        success: false,
                        values: vec![],
                    };
                    let key = TXID::from_vec(&op.operands[0]);
                    let mut result = None;
                    if let Some(txid) = key {
                        result = self.read(&txid);
                    }
                    if let Some(value) = result {
                        op_result.success = true;
                        op_result.values = vec![value];
                    }
                    txn_result.result.push(op_result);
                } else if op_type == ProtoTransactionOpType::Scan {
                    if op.operands.len() != 2 {
                        continue;
                    }
                    let mut op_result = ProtoTransactionOpResult {
                        success: false,
                        values: vec![],
                    };
                    let from = TXID::from_vec(&op.operands[0]);
                    let to = TXID::from_vec(&op.operands[1]);
                    let scan_result = self.scan(&from, &to);
                    if let Some(scan_result) = scan_result {
                        op_result.success = true;
                        op_result.values = scan_result;
                    }
                    txn_result.result.push(op_result);
                } else {
                    warn!("Invalid operation type: {}", op_type.as_str_name());
                }
            }
        }

        return txn_result;
    }

    #[cfg(feature = "policy_validation")]
    fn handle_validation(
        &mut self,
        tx: crate::proto::execution::ProtoTransaction,
    ) -> crate::consensus::app::TransactionValidationResult {
        let policy = self.state.crash_committed_policies.last();
        let Some(policy) = policy else {
            return Err("No policy found".to_string());
        };
        let issuer = ""; // FIXME
        JS_RUNTIME.with(|runtime| Self::validate_policy(runtime, policy, issuer))
    }

    fn get_current_state(&self) -> Self::State {
        return self.state.clone();
    }
}

impl SCITTAppEngine {
    fn read(&self, key: &TXID) -> Option<Vec<u8>> {
        //same search logic from old kvs.rs
        let ci_res = self.state.crash_committed_claims.get(key);
        if let Some(v) = ci_res {
            // Invariant: v is sorted by ci
            // Invariant: v.len() > 0
            let res = &v.last().unwrap().1;
            return Some(res.clone());
        } else {
            //check bci_state
        }

        let bci_res = self.state.byz_committed_claims.get(key);
        if let Some(v) = bci_res {
            return Some(v.clone());
        } else {
            return None;
        }
    }

    fn scan(&self, from: &Option<TXID>, to: &Option<TXID>) -> Option<Vec<Vec<u8>>> {
        if let (Some(from), Some(to)) = (from, to) {
            let mut scan_result = Vec::new();
            for (key, versions) in self.state.crash_committed_claims.iter() {
                if key.block_n >= from.block_n && key.block_n <= to.block_n {
                    for (pos, _) in versions {
                        if *pos >= from.block_n && *pos <= to.block_n {
                            scan_result.push(key.to_vec());
                        }
                    }
                }
            }
            for (key, _) in self.state.byz_committed_claims.iter() {
                if key.block_n >= from.block_n && key.block_n <= to.block_n {
                    scan_result.push(key.to_vec());
                }
            }
            Some(scan_result)
        } else {
            None
        }
    }

    #[cfg(feature = "policy_validation")]
    fn validate_policy(runtime: &Runtime, policy: &[u8], issuer: &str) -> Result<(), String> {
        let ctx = Context::full(runtime).unwrap();
        ctx.with(|ctx| {
            match ctx.eval::<(), _>(policy) {
                Ok(_) => {}
                Err(e) => return Err(format!("Failed to load script: {}", e)),
            }
            let arg = Object::new(ctx.clone()).unwrap();
            arg.set("issuer", issuer).unwrap();
            let globals = ctx.globals();
            let apply_fn: Function = globals.get("apply").unwrap();
            let result: Result<Value, _> = apply_fn.call((arg,));
            match result {
                Ok(value) => match value.type_of() {
                    rquickjs::Type::Bool => {
                        if value.as_bool().unwrap() {
                            Ok(())
                        } else {
                            Err("Policy validation failed".to_string())
                        }
                    }
                    rquickjs::Type::String => Err(value.as_string().unwrap().to_string().unwrap()),
                    _ => Err("Unexpected return type".to_string()),
                },
                Err(e) => Err(format!("Failed to call function 'apply': {}", e)),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_txid_encode_decode() {
        let txid = TXID::new(420, 69);
        let encoded = txid.to_vec();
        let decoded = TXID::from_vec(&encoded).unwrap();
        assert_eq!(txid, decoded);
    }
}
