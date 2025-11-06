use crate::proto::execution::{
    ProtoTransaction, ProtoTransactionOp, ProtoTransactionOpType, ProtoTransactionPhase,
    ProtoTransactionResult,
};

use super::{Executor, PerWorkerWorkloadGenerator, WorkloadUnit};

pub struct MockSQLGenerator {
    pub query_num: usize,
}

impl MockSQLGenerator {
    pub fn new() -> Self {
        Self { query_num: 0 }
    }
}

impl PerWorkerWorkloadGenerator for MockSQLGenerator {
    fn next(&mut self) -> WorkloadUnit {
        let query = match self.query_num {
            0 => String::from("CREATE TABLE foo(id INT PRIMARY KEY, num INT);"),
            1 => String::from("INSERT INTO foo VALUES (1, 1);"),
            n => match n % 2 {
                0 => format!("UPDATE foo SET num = num + 1;"),
                1 => format!("SELECT * FROM foo;"),
                _ => panic!("Unreachable"),
            },
        };
        self.query_num += 1;

        let query_vec = query.as_bytes().to_vec();
        WorkloadUnit {
            tx: ProtoTransaction {
                on_receive: None,
                on_crash_commit: Some(ProtoTransactionPhase {
                    ops: vec![ProtoTransactionOp {
                        op_type: ProtoTransactionOpType::Custom.into(),
                        operands: vec![query_vec],
                    }],
                }),
                on_byzantine_commit: None,
                is_reconfiguration: false,
                is_2pc: false,
            },
            executor: Executor::Leader,
        }
    }

    fn check_result(&mut self, _result: &Option<ProtoTransactionResult>) -> bool {
        true
    }
}
