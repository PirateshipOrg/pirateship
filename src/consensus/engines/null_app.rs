use serde::{Serialize, Deserialize};

use crate::{consensus::app::AppEngine, proto::{client::ProtoByzResponse, execution::{ProtoTransactionOpResult, ProtoTransactionPhase, ProtoTransactionResult}}};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NullApp;

impl std::fmt::Display for NullApp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NullApp")
    }
}

impl AppEngine for NullApp {
    type State = Self;

    fn new(_config: crate::config::AtomicConfig) -> Self {
        Self{}
    }

    fn handle_crash_commit(&mut self, blocks: Vec<crate::crypto::CachedBlock>) -> Vec<Vec<crate::proto::execution::ProtoTransactionResult>> {
        blocks.iter().map(|block| {
            block.block.tx_list.iter().map(|tx| {
                ProtoTransactionResult {
                    result: tx.on_crash_commit.as_ref().unwrap_or(&ProtoTransactionPhase::default())
                        .ops.iter().map(|_| ProtoTransactionOpResult {
                            success: true,
                            values: vec![],
                        }).collect(),
                }
            }).collect()
        }).collect()
    }

    fn handle_byz_commit(&mut self, blocks: Vec<crate::crypto::CachedBlock>) -> Vec<Vec<crate::proto::client::ProtoByzResponse>> {
        blocks.iter().map(|block| {
            block.block.tx_list.iter().enumerate().map(|(tx_n, _tx)| {
                ProtoByzResponse {
                    block_n: block.block.n,
                    tx_n: tx_n as u64,
                    client_tag: 0,          // This will be filled in by the client_reply_handler
                }
            }).collect()
        }).collect()
    }

    fn handle_rollback(&mut self, _num_rolled_back_blocks: u64) {
        // Nothing to do
    }

    fn handle_unlogged_request(&mut self, request: crate::proto::execution::ProtoTransaction) -> crate::proto::execution::ProtoTransactionResult {
        ProtoTransactionResult {
            result: request.on_receive.as_ref().unwrap_or(&ProtoTransactionPhase::default())
                .ops.iter().map(|_| ProtoTransactionOpResult {
                    success: true,
                    values: vec![],
                }).collect(),
        }
    }

    #[cfg(feature = "policy_validation")]
    fn handle_validation(&mut self, _tx: &crate::proto::execution::ProtoTransactionOp) -> crate::consensus::app::TransactionValidationResult {
        Ok(())
    }

    fn get_current_state(&self) -> Self::State {
        self.clone()
    }
}

