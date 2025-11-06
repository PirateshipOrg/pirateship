use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, Copy)]
pub struct KVReadWriteUniform {
    pub num_keys: usize,
    pub val_size: usize,
    pub read_ratio: f64,
    pub write_byz_commit_ratio: f64,
}

/// We are only going to support YCSB-A, B and C.
/// These don't need the Latest distribution and are only updates/reads, so distributions need not be re-calculated.
#[derive(Serialize, Deserialize, Clone, Debug, Copy)]
pub struct KVReadWriteYCSB {
    pub read_ratio: f64,
    pub linearizable_reads: bool, // Reads go through consensus.
    pub byz_commit_ratio: f64,
    pub val_size: usize,
    pub num_fields: usize,
    pub num_keys: usize,
    pub zipf_exponent: f64,
    pub load_phase: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum RequestConfig {
    Blanks,
    KVReadWriteUniform(KVReadWriteUniform),
    KVReadWriteYCSB(KVReadWriteYCSB),
    MockSQL(),
}
