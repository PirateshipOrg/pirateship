use std::{collections::VecDeque, sync::Arc};

use log::warn;
use tokio::sync::{oneshot, Mutex};

use crate::{
    config::AtomicConfig,
    consensus::logserver::LogServerQuery,
    crypto::{CachedBlock, MerkleInclusionProof},
    proto::consensus::ProtoBlock,
    utils::channel::{make_channel, Receiver, Sender},
};

pub type ProofChain = Vec<ProtoBlock>;
pub struct ReceiptBuilder {
    // The chain of blocks from the requested block to the subsequent auditQC
    pub chain: ProofChain,
    // Inclusion proofs for each requested transaction *in the same order as the request*
    pub proofs: Vec<MerkleInclusionProof>,
}

pub enum IssuerCommand {
    /// Request chain, auditQCs and inclusion proofs for a set of transactions in a block
    IssueAuditReceipt(u64, Vec<u64>, oneshot::Sender<Option<ReceiptBuilder>>),
    /// Request chain, single auditQC and inclusion proof
    IssueCommitReceipt(u64, Vec<u64>, oneshot::Sender<Option<ReceiptBuilder>>),
    /// Once a chunk of block is added, cache them for future inclusion proofs
    NewChunk(Vec<CachedBlock>),
    /// Drop tail of cached blocks
    Rollback(u64),
    /// Garbage collect cached blocks (at most) up to the current bci
    GC(u64),
}

const MIN_CACHED_BLOCKS: usize = 1000;
pub struct Issuer {
    config: AtomicConfig,

    issuer_rx: Receiver<IssuerCommand>,
    logserver_tx: Sender<LogServerQuery>,

    cached_blocks: VecDeque<CachedBlock>,
}

impl Issuer {
    pub fn new(
        config: AtomicConfig,
        issuer_rx: Receiver<IssuerCommand>,
        logserver_tx: Sender<LogServerQuery>,
    ) -> Self {
        Issuer {
            config,
            issuer_rx,
            logserver_tx,
            cached_blocks: VecDeque::with_capacity(MIN_CACHED_BLOCKS),
        }
    }

    pub async fn run(issuer: Arc<Mutex<Self>>) {
        let mut issuer = issuer.lock().await;
        loop {
            if let Err(_) = issuer.worker().await {
                break;
            }
        }
    }

    async fn worker(&mut self) -> Result<(), ()> {
        tokio::select! {
            biased;
            cmd = self.issuer_rx.recv() => {
                match cmd {
                    Some(IssuerCommand::IssueAuditReceipt(block_n, tx_n_list, reply_tx)) => {
                        self.generate_receipt_builder(block_n, tx_n_list, reply_tx, 2).await;
                    },
                    Some(IssuerCommand::IssueCommitReceipt(block_n, tx_n_list, reply_tx)) => {
                        self.generate_receipt_builder(block_n, tx_n_list, reply_tx, 1).await;
                    },
                    Some(IssuerCommand::NewChunk(cached_blocks)) => {
                        self.handle_new_chunk(cached_blocks).await;
                    },
                    Some(IssuerCommand::Rollback(block_n)) => {
                        self.handle_rollback(block_n).await;
                    },
                    Some(IssuerCommand::GC(bci)) => {
                        self.handle_gc(bci).await;
                    },
                    None => {
                        // Channel closed
                        return Err(());
                    }
                }
            },
        }

        Ok(())
    }

    async fn find_block(&mut self, block_n: u64) -> Option<usize> {
        if self.cached_blocks.is_empty() {
            return None;
        }
        let head = self.cached_blocks.front().unwrap().block.n;
        if head <= block_n {
            let index = (block_n - head) as usize;
            if self.cached_blocks.len() <= index {
                return None; // maybe we rolled it back?
            }
            return Some(index);
        }

        let (tx, rx) = make_channel(1);
        self.logserver_tx.send(LogServerQuery::GetChunk(block_n, head, tx)).await.unwrap();
        let chunk = rx.recv().await.unwrap();

        if chunk.is_empty() {
            return None; // logserver does not have the necessary ledger chunk to build this receipt (?)
        }

        assert!(self.cached_blocks.back().map_or(true, |f| f.block.n > chunk.last().unwrap().block.n), "Block number {} is greater than requested {}", chunk.last().unwrap().block.n, head);
        for b in chunk.into_iter().rev() {
            self.cached_blocks.push_front(b);
        }

        Some(0)
    }

    fn byzantine_fast_path_threshold(&self) -> usize {
        self.config.get().consensus_config.node_list.len()
    }

    async fn generate_receipt_builder(
        &mut self,
        block_n: u64,
        txs: Vec<u64>,
        reply: oneshot::Sender<Option<ReceiptBuilder>>,
        n_qcs: usize,
    ) {
        let mut chain = Vec::new();

        let Some(index) = self.find_block(block_n).await else {
            let _ = reply.send(None);
            return;
        };

        let block = &self.cached_blocks[index];

        let mut qcs = 0;
        for b in self.cached_blocks.iter().skip(index) {
            chain.push(b.block.clone());
            if !b.block.qc.is_empty() {
                if b.block.qc.len() >= self.byzantine_fast_path_threshold() {
                    break; // we have enough QCs to prove the block committed or audited
                }
                qcs += 1;
            }
            if qcs >= n_qcs {
                break; // we have enough QCs to prove the block
            }
        }

        if txs.is_empty() {
            // No transactions requested, just return the chain and empty proofs
            let _ = reply.send(Some(ReceiptBuilder {
                chain,
                proofs: vec![],
            }));
            return;
        }

        assert!(block.block.n == block_n, "Block number mismatch: expected {}, got {}", block_n, block.block.n);
        let proofs = txs
            .iter()
            .map(|&tx| block.merkle_tree.generate_inclusion_proof(tx as usize))
            .collect();

        let _ = reply.send(Some(ReceiptBuilder { chain, proofs }));
    }

    async fn handle_new_chunk(&mut self, blocks: Vec<CachedBlock>) {
        for block in blocks {
            if self.cached_blocks.back().map_or(true, |b| b.block.n == block.block.n - 1) {
                self.cached_blocks.push_back(block);
            } else {
                warn!("Received a block that is not sequentially next: expected {}, got {}", self.cached_blocks.back().map_or(0, |b| b.block.n + 1), block.block.n);
                break;
            }
        }
    }

    async fn handle_rollback(&mut self, block_n: u64) {
        if let Some(index) = self.find_block(block_n).await {
            self.cached_blocks.truncate(index + 1);
        } else {
            self.cached_blocks.clear();
        }
    }

    async fn handle_gc(&mut self, bci: u64) {
        // Doing this for now. Maybe we can just use a sliding window and not worry about GC
        let bci_cbi = self.find_block(bci).await;
        if self.cached_blocks.len() - bci_cbi.unwrap_or(0) > MIN_CACHED_BLOCKS {
            self.cached_blocks.drain(0..bci_cbi.unwrap_or(0));
        } else {
            self.cached_blocks.drain(0..self.cached_blocks.len() - MIN_CACHED_BLOCKS);
        }
    }
}
