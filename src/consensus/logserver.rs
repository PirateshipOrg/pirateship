#![allow(unused_imports)]
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::Arc,
};

use log::{error, info, trace, warn};
#[cfg(not(feature = "dag"))]
use prost::Message as _;
use tokio::sync::{oneshot, Mutex};

#[cfg(feature = "dag")]
use crate::crypto::CachedTipCut;
use crate::{
    config::AtomicConfig,
    crypto::CachedBlock,
    proto::{
        checkpoint::{proto_backfill_nack::Origin, ProtoBackfillNack, ProtoBlockHint},
        consensus::{HalfSerializedBlock, ProtoAppendEntries, ProtoFork, ProtoViewChange},
        rpc::{proto_payload::Message, ProtoPayload},
    },
    rpc::{client::PinnedClient, MessageRef},
    utils::{
        channel::{Receiver, Sender},
        StorageServiceConnector,
    },
};

/// Deletes older blocks in favor of newer ones.
/// If the cache is full, and the block being put() has a lower n than the oldest block in the cache,
/// it is a Noop.
/// Since reading GC blocks always forms the pattern of (read parent hash) -> (fetch block) -> (read parent hash) -> ...
/// There is no need to adjust the position of the block in the cache.
struct ReadCache {
    #[cfg(not(feature = "dag"))]
    cache: BTreeMap<u64, CachedBlock>,
    #[cfg(feature = "dag")]
    cache: BTreeMap<u64, CachedTipCut>,
    working_set_size: usize,
}

impl ReadCache {
    pub fn new(working_set_size: usize) -> Self {
        if working_set_size == 0 {
            panic!("Working set size cannot be 0");
        }
        ReadCache {
            cache: BTreeMap::new(),
            working_set_size,
        }
    }

    /// Return vals:
    /// - Ok(block) if the block is in the cache.
    /// - Err(block) block with the least n higher than the requested block, if the block is not in the cache.
    /// - Err(None) if the cache is just empty.
    #[cfg(not(feature = "dag"))]
    pub fn get(&mut self, n: u64) -> Result<CachedBlock, Option<CachedBlock>> {
        if self.cache.is_empty() {
            return Err(None);
        }

        let block = self.cache.get(&n).cloned();
        if let Some(block) = block {
            return Ok(block);
        }

        let next_block = match self.cache.range(n..).next() {
            Some((_, block)) => block.clone(),
            None => {
                return Err(None);
            }
        };
        Err(Some(next_block))
    }

    #[cfg(not(feature = "dag"))]
    pub fn put(&mut self, block: CachedBlock) {
        if self.cache.len() >= self.working_set_size
            && block.block.n < *self.cache.first_entry().unwrap().key()
        {
            // Don't put this in the cache.
            return;
        }
        if self.cache.len() >= self.working_set_size {
            self.cache.first_entry().unwrap().remove();
        }

        self.cache.insert(block.block.n, block);
    }

    #[cfg(feature = "dag")]
    pub fn get(&mut self, n: u64) -> Result<CachedTipCut, Option<CachedTipCut>> {
        if self.cache.is_empty() {
            return Err(None);
        }

        let tc = self.cache.get(&n).cloned();
        if let Some(tc) = tc {
            return Ok(tc);
        }

        let next_tc = match self.cache.range(n..).next() {
            Some((_, tc)) => tc.clone(),
            None => {
                return Err(None);
            }
        };
        Err(Some(next_tc))
    }

    #[cfg(feature = "dag")]
    pub fn put(&mut self, tipcut: CachedTipCut) {
        if self.cache.len() >= self.working_set_size
            && tipcut.tipcut.n < *self.cache.first_entry().unwrap().key()
        {
            return;
        }
        if self.cache.len() >= self.working_set_size {
            self.cache.first_entry().unwrap().remove();
        }

        self.cache.insert(tipcut.tipcut.n, tipcut);
    }
}

pub enum LogServerQuery {
    CheckHash(
        u64,     /* block.n */
        Vec<u8>, /* block_hash */
        Sender<bool>,
    ),
    GetHints(
        u64, /* last needed block.n */
        Sender<Vec<ProtoBlockHint>>,
    ),
}

pub enum LogServerCommand {
    NewBlock(CachedBlock),
    Rollback(u64),
    UpdateBCI(u64),
    #[cfg(feature = "dag")]
    NewTipCut(CachedTipCut),
}

pub struct LogServer {
    config: AtomicConfig,
    client: PinnedClient,
    bci: u64,

    logserver_rx: Receiver<LogServerCommand>,
    backfill_request_rx: Receiver<ProtoBackfillNack>,
    gc_rx: Receiver<u64>,

    query_rx: Receiver<LogServerQuery>,

    storage: StorageServiceConnector,
    #[cfg(not(feature = "dag"))]
    log: VecDeque<CachedBlock>,
    #[cfg(feature = "dag")]
    log: VecDeque<CachedTipCut>,

    /// LFU read cache for GCed blocks or tip cuts (DAG).
    read_cache: ReadCache,
}

const LOGSERVER_READ_CACHE_WSS: usize = 100;

impl LogServer {
    pub fn new(
        config: AtomicConfig,
        client: PinnedClient,
        logserver_rx: Receiver<LogServerCommand>,
        backfill_request_rx: Receiver<ProtoBackfillNack>,
        gc_rx: Receiver<u64>,
        query_rx: Receiver<LogServerQuery>,
        storage: StorageServiceConnector,
    ) -> Self {
        LogServer {
            config,
            client,
            logserver_rx,
            backfill_request_rx,
            gc_rx,
            query_rx,
            storage,
            log: VecDeque::new(),
            read_cache: ReadCache::new(LOGSERVER_READ_CACHE_WSS),
            bci: 0,
        }
    }

    pub async fn run(logserver: Arc<Mutex<Self>>) {
        let mut logserver = logserver.lock().await;
        loop {
            if let Err(_) = logserver.worker().await {
                break;
            }
        }
    }

    async fn worker(&mut self) -> Result<(), ()> {
        tokio::select! {
            biased;
            cmd = self.logserver_rx.recv() => {
                match cmd {
                    Some(LogServerCommand::NewBlock(block)) => {
                        trace!("Received block {}", block.block.n);
                        self.handle_new_block(block).await;
                    },
                    Some(LogServerCommand::Rollback(n)) => {
                        trace!("Rolling back to block {}", n);
                        self.handle_rollback(n).await;
                    },
                    Some(LogServerCommand::UpdateBCI(n)) => {
                        trace!("Updating BCI to {}", n);
                        self.bci = n;
                    },
                    #[cfg(feature = "dag")]
                    Some(LogServerCommand::NewTipCut(tipcut)) => {
                        trace!("Received tip cut with {} CARs", tipcut.tipcut.tips.len());
                        self.handle_new_tipcut(tipcut).await;
                    },
                    None => {
                        error!("LogServerCommand channel closed");
                        return Err(());
                    }
                }
            },

            gc_req = self.gc_rx.recv() => {
                if let Some(gc_req) = gc_req {
                    #[cfg(not(feature = "dag"))]
                    self.log.retain(|block| block.block.n > gc_req);
                    #[cfg(feature = "dag")]
                    {
                        // Retain tip cuts with sequence greater than GC request
                        self.log.retain(|tipcut| tipcut.tipcut.n > gc_req);
                        // Optionally adjust read cache here (not strictly necessary on GC)
                    }
                }
            },

            backfill_req = self.backfill_request_rx.recv() => {
                if let Some(backfill_req) = backfill_req {
                    self.respond_backfill(backfill_req).await?;
                }
            },

            query = self.query_rx.recv() => {
                if let Some(query) = query {
                    self.handle_query(query).await;
                }
            }
        }

        Ok(())
    }

    #[cfg(not(feature = "dag"))]
    async fn get_block(&mut self, n: u64) -> Option<CachedBlock> {
        let last_n = self.log.back()?.block.n;
        if n == 0 || n > last_n {
            return None;
        }

        let first_n = self.log.front()?.block.n;
        if n < first_n {
            return self.get_gced_block(n).await;
        }

        let block_idx = self.log.binary_search_by(|e| e.block.n.cmp(&n)).ok()?;
        let block = self.log[block_idx].clone();

        Some(block)
    }

    #[cfg(not(feature = "dag"))]
    async fn get_gced_block(&mut self, n: u64) -> Option<CachedBlock> {
        let first_n = self.log.front()?.block.n;
        if n >= first_n {
            return None; // The block is not GCed.
        }

        // Search in the read cache.
        let starting_point = match self.read_cache.get(n) {
            Ok(block) => {
                return Some(block);
            }
            Err(Some(block)) => block,
            Err(None) => {
                // Get the first block in the log.
                self.log.front()?.clone()
            }
        };

        // Fetch the block from the storage.
        let mut ret = starting_point;
        while ret.block.n > n {
            let parent_hash = &ret.block.parent;
            let block = self
                .storage
                .get_block(parent_hash)
                .await
                .expect("Failed to get block from storage");
            self.read_cache.put(block.clone());
            ret = block;
        }

        Some(ret)
    }

    #[cfg(not(feature = "dag"))]
    async fn respond_backfill(&mut self, backfill_req: ProtoBackfillNack) -> Result<(), ()> {
        let sender = backfill_req.reply_name;

        // Extract hints - traditional mode uses 'blocks', ignore DAG 'lanes'
        let hints = match backfill_req.hints {
            Some(crate::proto::checkpoint::proto_backfill_nack::Hints::Blocks(wrapper)) => {
                wrapper.hints
            }
            Some(crate::proto::checkpoint::proto_backfill_nack::Hints::Lane(_)) => {
                // DAG mode backfill - not handled by traditional logserver
                warn!("Received DAG-style backfill request (lanes) in traditional mode - ignoring");
                return Ok(());
            }
            None => {
                warn!("Backfill request has no hints");
                return Ok(());
            }
        };

        let existing_fork = match &backfill_req.origin {
            Some(Origin::Ae(ae)) => match &ae.entry {
                Some(crate::proto::consensus::proto_append_entries::Entry::Fork(fork)) => fork,
                _ => {
                    warn!("Malformed request - no fork in AppendEntries");
                    return Ok(());
                }
            },

            Some(Origin::Vc(vc)) => match vc.fork.as_ref() {
                Some(crate::proto::consensus::proto_view_change::Fork::F(fork)) => fork,
                _ => {
                    warn!("Malformed request");
                    return Ok(());
                }
            },

            Some(Origin::Abl(_)) => {
                // DAG mode backfill - not handled by traditional logserver
                warn!("Received DAG-style backfill request (AppendBlockLane) in traditional mode - ignoring");
                return Ok(());
            }

            None => {
                warn!("Malformed request");
                return Ok(());
            }
        };

        let last_n = match existing_fork.serialized_blocks.last() {
            Some(block) => block.n,
            None => match self.log.back() {
                Some(block) => block.block.n,
                None => 0,
            },
        };

        let first_n = backfill_req.last_index_needed;

        let new_fork = self.fill_fork(first_n, last_n, hints).await;

        let payload = match backfill_req.origin.unwrap() {
            Origin::Ae(ae) => ProtoPayload {
                message: Some(Message::AppendEntries(ProtoAppendEntries {
                    entry: Some(crate::proto::consensus::proto_append_entries::Entry::Fork(
                        new_fork,
                    )),
                    is_backfill_response: true,
                    ..ae
                })),
            },

            Origin::Vc(vc) => ProtoPayload {
                message: Some(Message::ViewChange(ProtoViewChange {
                    fork: Some(crate::proto::consensus::proto_view_change::Fork::F(
                        new_fork,
                    )),
                    ..vc
                })),
            },

            Origin::Abl(_) => {
                // This case should have been filtered out earlier
                // If we reach here, there's a logic error
                error!(
                    "DAG-style backfill request reached traditional logserver payload construction"
                );
                return Ok(());
            }
        };

        // Send the payload to the sender.
        let buf = payload.encode_to_vec();

        let _ = PinnedClient::send(
            &self.client,
            &sender,
            MessageRef(&buf, buf.len(), &crate::rpc::SenderType::Anon),
        )
        .await;

        Ok(())
    }

    #[cfg(feature = "dag")]
    async fn respond_backfill(&mut self, _backfill_req: ProtoBackfillNack) -> Result<(), ()> {
        // DAG backfill: interpret hints as tip cut sequence numbers
        let Some(hints_wrapper) = _backfill_req.hints.as_ref() else {
            return Ok(());
        };
        let sender = _backfill_req.reply_name.clone();
        // Currently reuse Blocks hints (sequence + digest) for tip cuts until dedicated hint type exists
        let hints: Vec<ProtoBlockHint> = match hints_wrapper {
            crate::proto::checkpoint::proto_backfill_nack::Hints::Blocks(wrapper) => {
                wrapper.hints.clone()
            }
            crate::proto::checkpoint::proto_backfill_nack::Hints::Lane(_) => {
                // Lane hints not supported in tip cut mode yet
                warn!("Lane hints unsupported for tip cut backfill");
                return Ok(());
            }
        };

        // Determine first requested n and last available
        let first_n = _backfill_req.last_index_needed;
        let last_n = self.log.back().map(|tc| tc.tipcut.n).unwrap_or(0);
        if last_n == 0 || first_n > last_n {
            return Ok(());
        }

        let fork = self.fill_tipcut_fork(first_n, last_n, hints).await;
        // Derive view/config from origin AE or VC if present
        let (view, view_is_stable, config_num, commit_index) = match _backfill_req.origin.as_ref() {
            Some(Origin::Ae(ae)) => (ae.view, ae.view_is_stable, ae.config_num, ae.commit_index),
            Some(Origin::Vc(vc)) => {
                // View change doesn't carry commit index or stability flag directly
                (vc.view, false, vc.config_num, 0)
            }
            Some(Origin::Abl(abl)) => {
                if let Some(ab) = abl.ab.as_ref() {
                    (ab.view, ab.view_is_stable, ab.config_num, ab.commit_index)
                } else {
                    (0, false, 0, 0)
                }
            }
            None => (0, false, 0, 0),
        };
        let ae_msg = ProtoAppendEntries {
            entry: Some(crate::proto::consensus::proto_append_entries::Entry::TipcutFork(fork)),
            commit_index,
            view,
            view_is_stable,
            config_num,
            is_backfill_response: true,
        };
        let payload = ProtoPayload {
            message: Some(Message::AppendEntries(ae_msg)),
        };
        #[cfg(not(feature = "dag"))]
        use prost::Message as _;
        let buf = <ProtoPayload as prost::Message>::encode_to_vec(&payload);
        let _ = PinnedClient::send(
            &self.client,
            &sender,
            MessageRef(&buf, buf.len(), &crate::rpc::SenderType::Anon),
        )
        .await;
        Ok(())
    }

    /// Returns a fork that contains blocks from `first_n` to `last_n` (both inclusive).
    /// During the process, if one of my blocks matches in hints, we stop.
    #[cfg(not(feature = "dag"))]
    async fn fill_fork(
        &mut self,
        first_n: u64,
        last_n: u64,
        mut hints: Vec<ProtoBlockHint>,
    ) -> ProtoFork {
        if last_n < first_n {
            panic!("Invalid range");
        }

        let hint_map = hints
            .drain(..)
            .map(|hint| (hint.block_n, hint.digest))
            .collect::<HashMap<_, _>>();

        let mut fork_queue = VecDeque::with_capacity((last_n - first_n + 1) as usize);

        for i in (first_n..=last_n).rev() {
            let block = match self.get_block(i).await {
                Some(block) => block,
                None => {
                    warn!("Block {} not found", i);
                    break;
                }
            };

            let hint = hint_map.get(&i);
            if let Some(hint) = hint {
                if hint.eq(&block.block_hash) {
                    break;
                }
            }

            fork_queue.push_front(block);
        }

        ProtoFork {
            serialized_blocks: fork_queue
                .into_iter()
                .map(|block| HalfSerializedBlock {
                    n: block.block.n,
                    view: block.block.view,
                    view_is_stable: block.block.view_is_stable,
                    config_num: block.block.config_num,
                    serialized_body: block.block_ser.clone(),
                })
                .collect(),
        }
    }

    #[cfg(not(feature = "dag"))]
    async fn handle_query(&mut self, query: LogServerQuery) {
        match query {
            LogServerQuery::CheckHash(n, hsh, sender) => {
                if n == 0 {
                    sender.send(true).await.unwrap();
                    return;
                }

                let block = match self.get_block(n).await {
                    Some(block) => block,
                    None => {
                        error!(
                            "Block {} not found, last_n seen: {}",
                            n,
                            self.log.back().map_or(0, |block| block.block.n)
                        );
                        sender.send(false).await.unwrap();
                        return;
                    }
                };

                sender.send(block.block_hash.eq(&hsh)).await.unwrap();
            }
            LogServerQuery::GetHints(last_needed_n, sender) => {
                // Starting from last_needed_n,
                // Include last_needed_n, last_needed_n + 1000, last_needed_n + 2000, ..., until last_needed_n + 10000,
                // Then include last_needed_n + 10000, last_needed_n + 20000, ..., until last_needed_n + 100000,
                // and so on until we reach last_n. Also include the last_n.

                const JUMP_START: u64 = 1000;
                const JUMP_MULTIPLIER: u64 = 10;

                let mut hints = Vec::new();

                let last_n = self.log.back().map_or(0, |block| block.block.n);
                let mut curr_n = last_needed_n;
                let mut curr_jump = JUMP_START;
                let mut curr_jump_used_for = 0;

                if curr_n == 0 {
                    curr_n = 1;
                }

                while curr_n < last_n {
                    let block = match self.get_block(curr_n).await {
                        Some(block) => block,
                        None => {
                            break;
                        }
                    };
                    hints.push(ProtoBlockHint {
                        block_n: block.block.n,
                        digest: block.block_hash.clone(),
                    });

                    curr_n += curr_jump;
                    curr_jump_used_for += 1;
                    if curr_jump_used_for >= JUMP_MULTIPLIER {
                        curr_jump *= JUMP_MULTIPLIER;
                        curr_jump_used_for = 0;
                    }
                }

                // Also add last_n.
                if last_n > 0 {
                    let block = match self.get_block(last_n).await {
                        Some(block) => block,
                        None => {
                            // This should never happen.
                            panic!("Block {} not found", last_n);
                        }
                    };
                    hints.push(ProtoBlockHint {
                        block_n: block.block.n,
                        digest: block.block_hash.clone(),
                    });
                }

                let len = hints.len();

                let res = sender.send(hints).await;
                info!("Sent hints size {}, result = {:?}", len, res);
            }
        }
    }

    #[cfg(feature = "dag")]
    async fn handle_query(&mut self, query: LogServerQuery) {
        match query {
            LogServerQuery::CheckHash(_, _, sender) => {
                // Not supported in DAG mode (uses tip cut hashes instead)
                let _ = sender.send(false).await;
            }
            LogServerQuery::GetHints(_, sender) => {
                // Hints logic for DAG blocks not yet implemented
                let _ = sender.send(Vec::new()).await;
            }
        }
    }

    /// Invariant: Log is continuous, increasing seq num and maintains hash chain continuity
    #[cfg(not(feature = "dag"))]
    async fn handle_new_block(&mut self, block: CachedBlock) {
        let last_n = self.log.back().map_or(0, |block| block.block.n);
        if block.block.n != last_n + 1 {
            error!(
                "Block {} is not the next block, last_n: {}",
                block.block.n, last_n
            );
            return;
        }

        if last_n > 0 && !block.block.parent.eq(&self.log.back().unwrap().block_hash) {
            error!("Parent hash mismatch for block {}", block.block.n);
            return;
        }

        self.log.push_back(block);
    }

    #[cfg(feature = "dag")]
    async fn handle_new_block(&mut self, _block: CachedBlock) {
        warn!("Ignoring traditional block in DAG mode logserver");
    }

    #[cfg(not(feature = "dag"))]
    async fn handle_rollback(&mut self, mut n: u64) {
        if n <= self.bci {
            n = self.bci + 1;
        }

        self.log.retain(|block| block.block.n <= n);

        // Clean up read cache.
        self.read_cache.cache.retain(|k, _| *k <= n);
    }

    #[cfg(feature = "dag")]
    async fn handle_rollback(&mut self, mut n: u64) {
        if n <= self.bci {
            n = self.bci + 1;
        }

        // Retain tip cuts up to n (inclusive).
        self.log.retain(|tipcut| tipcut.tipcut.n <= n);
        // Clean up tip cut read cache
        self.read_cache.cache.retain(|k, _| *k <= n);
    }

    #[cfg(feature = "dag")]
    async fn handle_new_tipcut(&mut self, tipcut: CachedTipCut) {
        // In DAG mode, store tip cuts instead of blocks
        info!(
            "Storing tip cut with {} CARs (digest: {:?})",
            tipcut.tipcut.tips.len(),
            hex::encode(&tipcut.tipcut_hash[..8])
        );

        // Verify parent relationship if not the first tip cut
        if !self.log.is_empty() {
            let last_tipcut = self.log.back().unwrap();
            if tipcut.tipcut.parent != last_tipcut.tipcut_hash {
                error!(
                    "Tip cut parent mismatch: expected {:?}, got {:?}",
                    hex::encode(&last_tipcut.tipcut_hash[..8]),
                    hex::encode(&tipcut.tipcut.parent[..8])
                );
                return;
            }
        } else {
            // First tip cut should have genesis parent (all zeros)
            if !tipcut.tipcut.parent.iter().all(|&b| b == 0) {
                error!("First tip cut should have genesis parent");
                return;
            }
        }

        // Persist before pushing to in-memory log
        let _ = self.storage.put_tipcut(&tipcut).await;
        self.log.push_back(tipcut);
    }

    #[cfg(feature = "dag")]
    async fn get_tipcut(&mut self, n: u64) -> Option<CachedTipCut> {
        let last_n = self.log.back()?.tipcut.n;
        if n == 0 || n > last_n {
            return None;
        }
        let first_n = self.log.front()?.tipcut.n;
        if n < first_n {
            return self.get_gced_tipcut(n).await;
        }
        // sequential n assumed; perform binary search by index offset
        let idx = (n - first_n) as usize;
        if idx < self.log.len() {
            Some(self.log[idx].clone())
        } else {
            None
        }
    }

    #[cfg(feature = "dag")]
    async fn get_gced_tipcut(&mut self, n: u64) -> Option<CachedTipCut> {
        let first_n = self.log.front()?.tipcut.n;
        if n >= first_n {
            return None;
        }

        // Search in the read cache first.
        let starting_point = match self.read_cache.get(n) {
            Ok(tc) => {
                return Some(tc);
            }
            Err(Some(tc)) => tc,
            Err(None) => {
                // fall back to first in-memory tip cut
                self.log.front()?.clone()
            }
        };

        // Fetch previous tip cuts from storage until we reach n
        let mut ret = starting_point;
        while ret.tipcut.n > n {
            let parent_hash = &ret.tipcut.parent;
            let tc = self.storage.get_tipcut(parent_hash).await.ok()?;
            self.read_cache.put(tc.clone());
            ret = tc;
        }
        Some(ret)
    }

    #[cfg(feature = "dag")]
    async fn fill_tipcut_fork(
        &mut self,
        first_n: u64,
        last_n: u64,
        mut hints: Vec<ProtoBlockHint>,
    ) -> crate::proto::consensus::ProtoTipCutFork {
        use crate::proto::consensus::HalfSerializedTipCut;
        if last_n < first_n {
            return crate::proto::consensus::ProtoTipCutFork {
                serialized_tipcuts: vec![],
            };
        }
        // Map hints for early stop (block hints repurposed for tip cuts for now)
        let hint_map = hints
            .drain(..)
            .map(|h| (h.block_n, h.digest))
            .collect::<std::collections::HashMap<_, _>>();
        let mut queue = VecDeque::new();
        for i in (first_n..=last_n).rev() {
            let tc = match self.get_tipcut(i).await {
                Some(v) => v,
                None => {
                    warn!("TipCut {} not found", i);
                    break;
                }
            };
            if let Some(digest) = hint_map.get(&i) {
                if digest.eq(&tc.tipcut_hash) {
                    break;
                }
            }
            queue.push_front(tc);
        }
        crate::proto::consensus::ProtoTipCutFork {
            serialized_tipcuts: queue
                .into_iter()
                .map(|tc| HalfSerializedTipCut {
                    n: tc.tipcut.n,
                    view: tc.tipcut.view,
                    view_is_stable: tc.tipcut.view_is_stable,
                    config_num: tc.tipcut.config_num,
                    serialized_body: tc.tipcut_ser.clone(),
                })
                .collect(),
        }
    }
}
