use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use pft::{consensus::engines::scitt::SCITTWriteType, proto::execution::{ProtoTransaction, ProtoTransactionOp, ProtoTransactionOpType, ProtoTransactionPhase}};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum JsonTransactionOpType {
    Noop,
    Read,
    Write,
    Increment,
    Cas,
    Scan,
    AddLearner,
    UpgradeFullNode,
    DelLearner,
    DowngradeFullNode,
    Custom,
    ProbeCommit,
    ProbeAudit,
}

impl From<JsonTransactionOpType> for ProtoTransactionOpType {
    fn from(json_op: JsonTransactionOpType) -> Self {
        match json_op {
            JsonTransactionOpType::Noop => ProtoTransactionOpType::Noop,
            JsonTransactionOpType::Read => ProtoTransactionOpType::Read,
            JsonTransactionOpType::Write => ProtoTransactionOpType::Write,
            JsonTransactionOpType::Increment => ProtoTransactionOpType::Increment,
            JsonTransactionOpType::Cas => ProtoTransactionOpType::Cas,
            JsonTransactionOpType::Scan => ProtoTransactionOpType::Scan,
            JsonTransactionOpType::AddLearner => ProtoTransactionOpType::AddLearner,
            JsonTransactionOpType::UpgradeFullNode => ProtoTransactionOpType::UpgradeFullNode,
            JsonTransactionOpType::DelLearner => ProtoTransactionOpType::DelLearner,
            JsonTransactionOpType::DowngradeFullNode => ProtoTransactionOpType::DowngradeFullNode,
            JsonTransactionOpType::Custom => ProtoTransactionOpType::Custom,
            JsonTransactionOpType::ProbeCommit => ProtoTransactionOpType::ProbeCommit,
            JsonTransactionOpType::ProbeAudit => ProtoTransactionOpType::ProbeAudit,
        }
    }
}

impl From<ProtoTransactionOpType> for JsonTransactionOpType {
    fn from(proto_op: ProtoTransactionOpType) -> Self {
        match proto_op {
            ProtoTransactionOpType::Noop => JsonTransactionOpType::Noop,
            ProtoTransactionOpType::Read => JsonTransactionOpType::Read,
            ProtoTransactionOpType::Write => JsonTransactionOpType::Write,
            ProtoTransactionOpType::Increment => JsonTransactionOpType::Increment,
            ProtoTransactionOpType::Cas => JsonTransactionOpType::Cas,
            ProtoTransactionOpType::Scan => JsonTransactionOpType::Scan,
            ProtoTransactionOpType::AddLearner => JsonTransactionOpType::AddLearner,
            ProtoTransactionOpType::UpgradeFullNode => JsonTransactionOpType::UpgradeFullNode,
            ProtoTransactionOpType::DelLearner => JsonTransactionOpType::DelLearner,
            ProtoTransactionOpType::DowngradeFullNode => JsonTransactionOpType::DowngradeFullNode,
            ProtoTransactionOpType::Custom => JsonTransactionOpType::Custom,
            ProtoTransactionOpType::ProbeCommit => JsonTransactionOpType::ProbeCommit,
            ProtoTransactionOpType::ProbeAudit => JsonTransactionOpType::ProbeAudit,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JsonOperand {
    SCITTWriteType(String),
    FilePath(String),
    Bytes(String),
}

#[allow(unused)]
impl JsonOperand {
    pub fn resolve(&self) -> Result<Vec<u8>, String> {
        match self {
            JsonOperand::SCITTWriteType(scitt_type) => {
                if scitt_type.eq("Claim") {
                    Ok(SCITTWriteType::Claim.to_slice().to_vec())
                } else if scitt_type.eq("Policy") {
                    Ok(SCITTWriteType::Policy.to_slice().to_vec())
                } else {
                    Err(format!("Unknown SCITT write type: {}", scitt_type))
                }
            }
            JsonOperand::FilePath(path_str) => {
                if Path::new(path_str).exists() {
                    fs::read(path_str)
                        .map_err(|e| format!("Failed to read file '{}': {}", path_str, e))
                } else {
                    Err(format!("File '{}' does not exist", path_str))
                }
            }
            JsonOperand::Bytes(base64_str) => {
                use base64::{Engine as _, engine::general_purpose};
                general_purpose::STANDARD
                    .decode(base64_str)
                    .map_err(|e| format!("Failed to decode base64: {}", e))
            }
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        use base64::{Engine as _, engine::general_purpose};
        JsonOperand::Bytes(general_purpose::STANDARD.encode(bytes))
    }

    pub fn from_file_path(path: &str) -> Self {
        JsonOperand::FilePath(path.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonTransactionOp {
    pub op_type: JsonTransactionOpType,
    pub operands: Vec<JsonOperand>,
}

impl JsonTransactionOp {
    pub fn to_proto(&self) -> Result<ProtoTransactionOp, String> {
        let operands: Result<Vec<Vec<u8>>, String> = self.operands
            .iter()
            .map(|op| op.resolve())
            .collect();

        let op_type: ProtoTransactionOpType = self.op_type.clone().into();
        Ok(ProtoTransactionOp {
            op_type: op_type as i32,
            operands: operands?,
        })
    }

    pub fn from_proto(proto_op: &ProtoTransactionOp) -> Self {
        let op_type = ProtoTransactionOpType::try_from(proto_op.op_type)
            .unwrap_or(ProtoTransactionOpType::Noop)
            .into();
        
        let operands = proto_op.operands
            .iter()
            .map(|bytes| JsonOperand::from_bytes(bytes))
            .collect();

        JsonTransactionOp {
            op_type,
            operands,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonTransactionPhase {
    pub ops: Vec<JsonTransactionOp>,
}

impl JsonTransactionPhase {
    pub fn to_proto(&self) -> Result<ProtoTransactionPhase, String> {
        let ops: Result<Vec<ProtoTransactionOp>, String> = self.ops
            .iter()
            .map(|op| op.to_proto())
            .collect();

        Ok(ProtoTransactionPhase {
            ops: ops?,
        })
    }

    pub fn from_proto(proto_phase: &ProtoTransactionPhase) -> Self {
        let ops = proto_phase.ops
            .iter()
            .map(JsonTransactionOp::from_proto)
            .collect();

        JsonTransactionPhase { ops }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonTransaction {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_receive: Option<JsonTransactionPhase>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_crash_commit: Option<JsonTransactionPhase>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_byzantine_commit: Option<JsonTransactionPhase>,
    pub is_reconfiguration: bool,
    pub is_2pc: bool,
}

#[allow(unused)]
impl JsonTransaction {
    pub fn to_proto(&self) -> Result<ProtoTransaction, String> {
        let on_receive = if let Some(phase) = &self.on_receive {
            Some(phase.to_proto()?)
        } else {
            None
        };

        let on_crash_commit = if let Some(phase) = &self.on_crash_commit {
            Some(phase.to_proto()?)
        } else {
            None
        };

        let on_byzantine_commit = if let Some(phase) = &self.on_byzantine_commit {
            Some(phase.to_proto()?)
        } else {
            None
        };

        Ok(ProtoTransaction {
            on_receive,
            on_crash_commit,
            on_byzantine_commit,
            is_reconfiguration: self.is_reconfiguration,
            is_2pc: self.is_2pc,
        })
    }

    pub fn from_proto(proto_tx: &ProtoTransaction) -> Self {
        let on_receive = proto_tx.on_receive
            .as_ref()
            .map(JsonTransactionPhase::from_proto);

        let on_crash_commit = proto_tx.on_crash_commit
            .as_ref()
            .map(JsonTransactionPhase::from_proto);

        let on_byzantine_commit = proto_tx.on_byzantine_commit
            .as_ref()
            .map(JsonTransactionPhase::from_proto);

        JsonTransaction {
            on_receive,
            on_crash_commit,
            on_byzantine_commit,
            is_reconfiguration: proto_tx.is_reconfiguration,
            is_2pc: proto_tx.is_2pc,
        }
    }

    pub fn from_json_file(path: &str) -> Result<Self, String> {
        let json_str = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read JSON file '{}': {}", path, e))?;
        
        serde_json::from_str(&json_str)
            .map_err(|e| format!("Failed to parse JSON: {}", e))
    }

    pub fn to_json_file(&self, path: &str) -> Result<(), String> {
        let json_str = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize to JSON: {}", e))?;
        
        fs::write(path, json_str)
            .map_err(|e| format!("Failed to write JSON file '{}': {}", path, e))
    }

    pub fn get_referenced_files(&self) -> Vec<String> {
        let mut files = Vec::new();
        
        if let Some(phase) = &self.on_receive {
            files.extend(get_files_from_phase(phase));
        }
        if let Some(phase) = &self.on_crash_commit {
            files.extend(get_files_from_phase(phase));
        }
        if let Some(phase) = &self.on_byzantine_commit {
            files.extend(get_files_from_phase(phase));
        }
        
        files
    }

    pub fn validate_files(&self) -> Result<(), String> {
        for file_path in self.get_referenced_files() {
            if !Path::new(&file_path).exists() {
                return Err(format!("Referenced file '{}' does not exist", file_path));
            }
        }
        Ok(())
    }
}

fn get_files_from_phase(phase: &JsonTransactionPhase) -> Vec<String> {
    let mut files = Vec::new();
    for op in &phase.ops {
        for operand in &op.operands {
            match operand {
                JsonOperand::SCITTWriteType(_) => {}
                JsonOperand::FilePath(path_str) => {
                    files.push(path_str.clone());
                }
                JsonOperand::Bytes(_) => {} 
            }
        }
    }
    files
}