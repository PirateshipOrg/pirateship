use hashbrown::HashMap;
use std::fmt::Display;

use log::{error, trace};
use serde::{Deserialize, Serialize};

#[cfg(feature = "policy_validation")]
use rquickjs::{
    Array, CatchResultExt, CaughtError, Context, Ctx, Function, Object, Runtime, Type, Value,
};

#[cfg(feature = "policy_validation")]
use scitt_cose::{validate_scitt_cose_signed_statement, CBORType, COSEHeaders, ProtectedHeader};

#[cfg(feature = "policy_validation")]
use base64::engine::{general_purpose, Engine};

use crate::{
    config::AtomicConfig,
    consensus::{
        app::AppEngine,
        engines::TXID,
    },
    proto::{
        client::ProtoByzResponse,
        consensus::ProtoBlock,
        execution::{
            ProtoTransactionOpResult, ProtoTransactionOpType, ProtoTransactionResult,
        },
    },
    utils::unwrap_tx_list,
};

#[derive(std::fmt:: Debug, Clone, Serialize, Deserialize)]
pub struct SCITTState {
    pub crash_committed_claims: HashMap<TXID, Vec<u8>>,
    pub byz_committed_claims: HashMap<TXID, Vec<u8>>,
    pub speculative_policies: Vec<(TXID, Vec<u8>)>,
    pub crash_committed_policies: Vec<(TXID, Vec<u8>)>,
    pub byz_committed_policies: Vec<(TXID, Vec<u8>)>,
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

#[cfg(feature = "policy_validation")]
thread_local! {
    pub static JS_RUNTIME: Runtime = Runtime::new().unwrap();
}

pub struct SCITTAppEngine {
    _config: AtomicConfig,
    pub last_ci: u64,
    pub last_bci: u64,
    state: SCITTState,
}

impl AppEngine for SCITTAppEngine {
    type State = SCITTState;

    fn new(config: AtomicConfig) -> Self {
        Self {
            _config: config,
            last_ci: 0,
            last_bci: 0,
            state: SCITTState {
                crash_committed_claims: HashMap::new(),
                byz_committed_claims: HashMap::new(),
                speculative_policies: Vec::new(),
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
            for (i, tx) in unwrap_tx_list(&proto_block).iter().enumerate() {
                let mut txn_result = ProtoTransactionResult { result: Vec::new() };
                let ops = match &tx.on_crash_commit {
                    Some(ops) => &ops.ops,
                    None => {
                        block_result.push(txn_result);
                        continue;
                    }
                };

                let op = &ops[0]; // TODO: guarantee we actually have a single op?

                if let Some(op_type) = ProtoTransactionOpType::try_from(op.op_type).ok() {
                    if op_type == ProtoTransactionOpType::Write {
                        if op.operands.len() != 2 {
                            continue;
                        }

                        let txid = TXID::new(proto_block.n, i);
                        match SCITTWriteType::from_slice(&op.operands[0]) {
                            SCITTWriteType::Claim => {
                                let claim: &Vec<u8> = &op.operands[1];
                                if self.state.crash_committed_claims.contains_key(&txid) {
                                    error!(
                                        "Invalid ledger write: {} already exists",
                                        txid.to_string()
                                    );
                                } else {
                                    self.state
                                        .crash_committed_claims
                                        .insert(txid.clone(), claim.clone());
                                }
                                txn_result.result.push(ProtoTransactionOpResult {
                                    success: true,
                                    values: vec![txid.to_string().into_bytes()],
                                });
                            }
                            SCITTWriteType::Policy => {
                                let policy = &op.operands[1];

                                self.state.crash_committed_policies.push((txid.clone(), policy.clone()));

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

            for (tx_n, tx) in unwrap_tx_list(&proto_block).iter().enumerate() {
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
                    error!("Not expected: {} {}", op.op_type, block.block.n);
                    if op.operands.len() != 2 {
                        continue;
                    }
                    if let Some(op_type) = ProtoTransactionOpType::try_from(op.op_type).ok() {
                        if op_type == ProtoTransactionOpType::Write {
                            let key = TXID {
                                block_n: proto_block.n,
                                tx_idx: tx_n,
                            };
                            let val = &op.operands[1];
                            self.state.byz_committed_claims.insert(key, val.clone());
                        }
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
        for (txid, claim) in self.state.crash_committed_claims.iter_mut() {
            if txid.block_n <= self.last_bci {
                self.state
                    .byz_committed_claims
                    .insert(txid.clone(), claim.clone());
            }
        }
        self.state.crash_committed_claims.retain(|v, _| v.block_n > self.last_bci);
        for (version, policy) in self.state.crash_committed_policies.iter() {
            if version.block_n <= self.last_bci {
                self.state.byz_committed_policies.push((version.clone(), policy.clone()));
            }
        }
        self.state.crash_committed_policies.retain(|(v, _)| v.block_n > self.last_bci);
        trace!("block count:{}", block_count);
        trace!("transaction count{}", txn_count);
        final_result
    }

    fn handle_rollback(&mut self, rolled_back_blocks: u64) {
        //roll back ci_state to rolled_back_blocks (block.n)
        self.state.crash_committed_claims.retain(|v, _| v.block_n <= rolled_back_blocks);
        self.state.crash_committed_policies.retain(|(v, _)| v.block_n <= rolled_back_blocks);
        self.state.speculative_policies.clear();
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
            if let Some(op_type) = ProtoTransactionOpType::try_from(op.op_type).ok() {
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
                }
            }
        }

        return txn_result;
    }

    #[cfg(feature = "policy_validation")]
    fn handle_validation(
        &self,
        tx_op: &crate::proto::execution::ProtoTransactionOp,
        txid: TXID,
    ) -> crate::consensus::app::TransactionValidationResult {
        #[cfg(feature = "null_validation")]
        return Ok(());

        if tx_op.operands.len() != 2 {
            error!(
                "Invalid operation operands length: {}",
                tx_op.operands.len()
            );
            return Err("Invalid operation operands length".to_string());
        }

        let op_type = SCITTWriteType::from_slice(&tx_op.operands[0]);
        let argument = &tx_op.operands[1];

        if op_type == SCITTWriteType::Policy {
            if let Err(err) = JS_RUNTIME.with(|runtime| validate_policy(runtime, argument)) {
                return Err(err);
            }
            return Ok(None);
        }

        let headers: COSEHeaders = match validate_scitt_cose_signed_statement(argument) {
            Ok(headers) => headers,
            Err(err) => {
                return Err(err);
            }
        };

        let Some(versioned_policy) = self.get_current_policy(&txid) else {
            return Err("No currently active policy found".to_string());
        };

        if let Err(err) = JS_RUNTIME.with(|runtime| apply_policy_to_claim(runtime, &versioned_policy.1, &headers.phdr)) {
            return Err(err);
        }
        return Ok(Some((txid, versioned_policy.0.clone())));
        
        
    }

    #[cfg(feature = "concurrent_validation")]
    fn handle_post_validation(&self, readsets: Vec<crate::consensus::app::ReadSet>) -> crate::consensus::app::PostValidationResult {
        #[cfg(feature = "null_validation")]
        return Ok(());

        for (reader, policy_version) in readsets {
            if let Some(versioned_policy) = self.get_current_policy(&reader) {
                let current_policy_version = &versioned_policy.0;
                if !current_policy_version.eq(&policy_version) {
                    return Err(format!("Policy version mismatch {:?} {:?}", current_policy_version, policy_version));
                }
            } else {
                panic!("No current policy found for reader: {:?}", reader);
            }
        }
        Ok(())
    }

    fn get_current_state(&self) -> Self::State {
        return self.state.clone();
    }
}

impl SCITTAppEngine {
    fn read(&self, key: &TXID) -> Option<Vec<u8>> {
        if let Some(claim) = self.state.crash_committed_claims.get(key) {
            return Some(claim.clone());
        } else if let Some(claim) = self.state.byz_committed_claims.get(key) {
            return Some(claim.clone());
        } else {
            return None;
        }
    }

    fn scan(&self, from: &Option<TXID>, to: &Option<TXID>) -> Option<Vec<Vec<u8>>> {
        if let (Some(from), Some(to)) = (from, to) {
            let mut scan_result = Vec::new();
            for (txid, _claim) in self.state.crash_committed_claims.iter() {
                if txid.block_n >= from.block_n && txid.block_n <= to.block_n {
                    scan_result.push(txid.to_vec());
                }
            }
            for (txid, _claim) in self.state.byz_committed_claims.iter() {
                if txid.block_n >= from.block_n && txid.block_n <= to.block_n {
                    scan_result.push(txid.to_vec());
                }
            }
            Some(scan_result)
        } else {
            None
        }
    }

    #[cfg(feature = "policy_validation")]
    fn get_current_policy(&self, reader: &TXID) -> Option<&(TXID, Vec<u8>)> {
        for versioned_policy in self.state.speculative_policies.iter().rev() {
            let version = &versioned_policy.0;
            if version.block_n <= reader.block_n || (version.block_n == reader.block_n && version.tx_idx <= reader.tx_idx) {
                return Some(versioned_policy);
            }
        }
        if let Some(versioned_policy) = self.state.crash_committed_policies.last() {
            Some(versioned_policy)
        } else if let Some(policy) = self.state.byz_committed_policies.last() {
                Some(policy)
        } else {
            None
        }
    }
}

#[cfg(feature = "policy_validation")]
pub fn apply_policy_to_claim(
    runtime: &Runtime,
    policy: &[u8],
    phdr: &ProtectedHeader,
) -> Result<(), String> {
    let ctx = Context::full(runtime).unwrap();
    ctx.with::<_, Result<(), String>>(|ctx| {
        if let Err(err) = ctx.eval::<(), _>(policy).catch(&ctx) {
            match err {
                CaughtError::Error(error) => {
                    return Err(format!("Runtime error loading policy: {}", error));
                }
                CaughtError::Exception(exception) => {
                    return Err(format!("Exception loading policy: {}", exception));
                }
                CaughtError::Value(value) => {
                    return Err(format!("Value error loading policy: {:?}", value));
                }
            }
        }

        let phdr_arg = match protected_header_to_js_val(&ctx, &phdr) {
            Ok(arg) => arg,
            Err(_) => return Err("Failed to convert ProtectedHeader to JS value".to_string()),
        };

        let globals = ctx.globals();
        let apply_fn: Function = globals.get("apply").unwrap();
        let result: Result<Value, _> = apply_fn.call((phdr_arg,));
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

#[cfg(feature = "policy_validation")]
fn protected_header_to_js_val<'a>(
    ctx: &Ctx<'a>,
    phdr: &ProtectedHeader,
) -> Result<Object<'a>, rquickjs::Error> {
    let obj = Object::new(ctx.clone())?;
    if let Some(alg) = phdr.alg {
        obj.set("alg", alg)?;
    }

    if let Some(crit) = &phdr.crit {
        let crit_array = Array::new(ctx.clone())?;
        for (i, e) in crit.iter().enumerate() {
            match e {
                CBORType::Int(val) => {
                    crit_array.set(i, *val as i64)?;
                }
                CBORType::Text(val) => {
                    crit_array.set(i, val.as_str())?;
                }
            }
        }
        obj.set("crit", crit_array)?;
    }

    if let Some(kid) = &phdr.kid {
        obj.set("kid", kid.as_str())?;
    }

    if let Some(feed) = &phdr.feed {
        obj.set("feed", feed.as_str())?;
    }

    if let Some(cty) = &phdr.cty {
        obj.set("cty", cty)?;
    }

    if let Some(x5chain) = &phdr.x5chain {
        let x5_array = Array::new(ctx.clone())?;
        for (i, der_cert) in x5chain.iter().enumerate() {
            let pem = format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
                general_purpose::STANDARD.encode(der_cert)
            );
            x5_array.set(i, pem)?;
        }
        obj.set("x5chain", x5_array)?;
    }

    if let Some(cwt) = &phdr.cwt {
        let cwt_obj = Object::new(ctx.clone())?;
        if let Some(iss) = &cwt.iss {
            cwt_obj.set("iss", iss.as_str())?;
        }
        if let Some(sub) = &cwt.sub {
            cwt_obj.set("sub", sub.as_str())?;
        }
        if let Some(iat) = cwt.iat {
            cwt_obj.set("iat", iat as i64)?;
        }
        if let Some(svn) = cwt.svn {
            cwt_obj.set("svn", svn as i64)?;
        }

        obj.set("cwt", cwt_obj)?;
    }

    Ok(obj)
}

#[cfg(feature = "policy_validation")]
pub fn validate_policy(runtime: &Runtime, policy: &[u8]) -> Result<(), String> {
    let ctx = Context::full(runtime).unwrap();
    ctx.with::<_, Result<(), String>>(|ctx| {
        if let Err(err) = ctx.eval::<(), _>(policy).catch(&ctx) {
            match err {
                CaughtError::Error(error) => {
                    return Err(format!("Runtime error loading policy: {}", error));
                }
                CaughtError::Exception(exception) => {
                    return Err(format!("Exception loading policy: {}", exception));
                }
                CaughtError::Value(value) => {
                    return Err(format!("Value error loading policy: {:?}", value));
                }
            }
        }
        let globals = ctx.globals();
        let apply_fn: Function = match globals.get("apply") {
            Ok(func) => func,
            Err(_) => return Err("No 'apply' function found in policy".to_string()),
        };
        // IDKW but sometimes it tends to return a constructor (not a function) but it works anyway
        if apply_fn.type_of() != Type::Function && apply_fn.type_of() != Type::Constructor {
            return Err("'apply' is not a function".to_string());
        }
        Ok(())
    })
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
