use serde::{Deserialize, Serialize};

pub mod null_app;
pub mod kvs;
pub mod scitt;

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct TXID {
    pub block_n: u64,
    pub tx_idx: usize,
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