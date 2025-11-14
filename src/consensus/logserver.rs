use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::Arc,
};

use log::{error, info, trace, warn};
use prost::Message as _;
use tokio::sync::{oneshot, Mutex};

use crate::{
    config::AtomicConfig,
    crypto::CachedBlock,
    proto::{
        checkpoint::{proto_backfill_nack::Origin, ProtoBackfillNack, ProtoBlockHint},
        consensus::{
            HalfSerializedBlock, ProtoAppendEntries, ProtoFork, ProtoTipCut, ProtoViewChange,
        },
        rpc::{proto_payload::Message, ProtoPayload},
    },
    rpc::{client::PinnedClient, MessageRef, PinnedMessage},
    utils::{
        channel::{Receiver, Sender},
        get_parent_hash_in_proto_block_ser, StorageServiceConnector,
    },
};

/// Deletes older blocks in favor of newer ones.
/// If the cache is full, and the block being put() has a lower n than the oldest block in the cache,
/// it is a Noop.
/// Since reading GC blocks always forms the pattern of (read parent hash) -> (fetch block) -> (read parent hash) -> ...
/// There is no need to adjust the position of the block in the cache.
struct ReadCache {
    cache: BTreeMap<u64, CachedBlock>,
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
    NewTipCut(ProtoTipCut),
    #[cfg(feature = "dag")]
    GetLastTipCutDigest(oneshot::Sender<Option<Vec<u8>>>),
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
    log: VecDeque<CachedBlock>,

    /// LFU read cache for GCed blocks.
    read_cache: ReadCache,

    /// DAG mode: chain of tip cuts instead of blocks
    #[cfg(feature = "dag")]
    tipcut_log: VecDeque<ProtoTipCut>,
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
            #[cfg(feature = "dag")]
            tipcut_log: VecDeque::new(),
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
                        trace!("Received tip cut with {} CARs", tipcut.tips.len());
                        self.handle_new_tipcut(tipcut).await;
                    },
                    #[cfg(feature = "dag")]
                    Some(LogServerCommand::GetLastTipCutDigest(reply_tx)) => {
                        let digest = self.tipcut_log.back().map(|tc| tc.digest.clone());
                        let _ = reply_tx.send(digest);
                    },
                    None => {
                        error!("LogServerCommand channel closed");
                        return Err(());
                    }
                }
            },

            gc_req = self.gc_rx.recv() => {
                if let Some(gc_req) = gc_req {
                    self.log.retain(|block| block.block.n > gc_req);
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
                Some(fork) => fork,
                None => {
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
                    fork: Some(new_fork),
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

    /// Returns a fork that contains blocks from `first_n` to `last_n` (both inclusive).
    /// During the process, if one of my blocks matches in hints, we stop.
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

    /// Invariant: Log is continuous, increasing seq num and maintains hash chain continuity
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

    async fn handle_rollback(&mut self, mut n: u64) {
        if n <= self.bci {
            n = self.bci + 1;
        }

        self.log.retain(|block| block.block.n <= n);

        // Clean up read cache.
        self.read_cache.cache.retain(|k, _| *k <= n);
    }

    #[cfg(feature = "dag")]
    async fn handle_new_tipcut(&mut self, tipcut: ProtoTipCut) {
        // In DAG mode, store tip cuts instead of blocks
        info!(
            "Storing tip cut with {} CARs (digest: {:?})",
            tipcut.tips.len(),
            hex::encode(&tipcut.digest[..8])
        );

        // Verify parent relationship if not the first tip cut
        if !self.tipcut_log.is_empty() {
            let last_tipcut = self.tipcut_log.back().unwrap();
            if tipcut.parent != last_tipcut.digest {
                error!(
                    "Tip cut parent mismatch: expected {:?}, got {:?}",
                    hex::encode(&last_tipcut.digest[..8]),
                    hex::encode(&tipcut.parent[..8])
                );
                return;
            }
        } else {
            // First tip cut should have genesis parent (all zeros)
            if !tipcut.parent.iter().all(|&b| b == 0) {
                error!("First tip cut should have genesis parent");
                return;
            }
        }

        self.tipcut_log.push_back(tipcut);
    }
}
