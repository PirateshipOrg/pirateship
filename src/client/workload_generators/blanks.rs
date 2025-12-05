use rand::{thread_rng, Rng};

use crate::proto::execution::{ProtoTransaction, ProtoTransactionOp, ProtoTransactionPhase, ProtoTransactionResult};

use super::{PerWorkerWorkloadGenerator, WorkloadUnit, Executor};

pub struct BlankWorkloadGenerator { }

impl PerWorkerWorkloadGenerator for BlankWorkloadGenerator {
    fn next(&mut self) -> WorkloadUnit {
        // Sample 512 byte random payload
        let mut payload = vec![2u8; 512];
        // {
        //     let mut rng = thread_rng();
        //     rng.fill(&mut payload[..]);
        // }
        let payload = vec![2u8; 512];
        WorkloadUnit {
            tx: ProtoTransaction{
                on_receive: None,
                on_crash_commit: Some(ProtoTransactionPhase {
                    ops: vec![ProtoTransactionOp {
                        op_type: crate::proto::execution::ProtoTransactionOpType::Noop.into(),
                        operands: vec![payload],
                        // operands: vec![vec![2u8; 0]],
                    }; 1],
                }),
                on_byzantine_commit: None,
                is_reconfiguration: false,
                is_2pc: false,
            },
            executor: Executor::Leader
        }
    }
    
    fn check_result(&mut self, _result: &Option<ProtoTransactionResult>) -> bool {
        true
    }
}