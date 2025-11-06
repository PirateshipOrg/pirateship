use crate::proto::execution::{ProtoTransaction, ProtoTransactionResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum Executor {
    Leader = 1,
    Any = 2,
}

pub struct WorkloadUnit {
    pub tx: ProtoTransaction,
    pub executor: Executor,
}

pub trait PerWorkerWorkloadGenerator: Send {
    fn next(&mut self) -> WorkloadUnit;
    fn check_result(&mut self, result: &Option<ProtoTransactionResult>) -> bool;
}

mod blanks;
pub use blanks::*;

mod kv_uniform;
pub use kv_uniform::*;

mod kv_ycsb;
pub use kv_ycsb::*;

mod mocksql;
pub use mocksql::*;
