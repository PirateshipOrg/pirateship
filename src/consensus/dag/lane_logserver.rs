/// Lane LogServer for DAG consensus protocol.
/// Maintains per-lane logs of blocks, handles backfill requests, and serves block queries.
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    hint,
    sync::Arc,
};

use futures::SinkExt;
use log::{error, info, trace, warn};
use prost::Message as _;
use tokio::sync::Mutex;

use crate::{
    config::AtomicConfig,
    crypto::CachedBlock,
    proto::{
        checkpoint::{
            proto_backfill_nack::Origin, ProtoBackfillNack, ProtoBlockHint, ProtoLaneBlockHints,
        },
        consensus::{HalfSerializedBlock, ProtoAppendBlock},
        rpc::{proto_payload::Message, ProtoPayload},
    },
    rpc::{client::PinnedClient, MessageRef},
    utils::{
        channel::{Receiver, Sender},
        StorageServiceConnector,
    },
};

/// LRU read cache for GCed blocks per lane.
/// Deletes older blocks in favor of newer ones.
/// If the cache is full, and the block being put() has a lower n than the oldest block in the cache,
/// it is a Noop.
/// Since reading GC blocks always forms the pattern of (read parent hash) -> (fetch block) -> (read parent hash) -> ...
/// There is no need to adjust the position of the block in the cache.
struct LaneReadCache {
    cache: BTreeMap<u64, CachedBlock>,
    working_set_size: usize,
}

impl LaneReadCache {
    pub fn new(working_set_size: usize) -> Self {
        if working_set_size == 0 {
            panic!("Working set size cannot be 0");
        }
        LaneReadCache {
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

pub enum LaneLogServerQuery {
    CheckHash(
        String,  /* lane_id */
        u64,     /* block.n */
        Vec<u8>, /* block_hash */
        Sender<bool>,
    ),
    GetHints(
        String,                      /* lane_id */
        u64,                         /* last needed block.n */
        Sender<ProtoLaneBlockHints>, /* lane_id, vec<BlockHints> */
    ),
    /// Get a specific block from a lane
    GetBlock(
        String, /* lane_id */
        u64,    /* block.n */
        Sender<Option<CachedBlock>>,
    ),
}

pub enum LaneLogServerCommand {
    NewBlock(String /* lane_id */, CachedBlock),
    Rollback(String /* lane_id (sender name) */, u64),
    UpdateBCI(u64),
}

pub struct LaneLogServer {
    config: AtomicConfig,
    client: PinnedClient,
    bci: u64,

    lane_logserver_rx: Receiver<LaneLogServerCommand>,
    backfill_request_rx: Receiver<ProtoBackfillNack>,
    lane_gc_rx: Receiver<u64>,

    query_rx: Receiver<LaneLogServerQuery>,

    storage: StorageServiceConnector,

    /// Map from lane_id (sender name) to their lane (chain of blocks)
    lanes: HashMap<String, VecDeque<CachedBlock>>,

    /// Read cache per lane for GCed blocks.
    read_caches: HashMap<String, LaneReadCache>,
}

const LOGSERVER_READ_CACHE_WSS: usize = 100;

impl LaneLogServer {
    pub fn new(
        config: AtomicConfig,
        client: PinnedClient,
        lane_logserver_rx: Receiver<LaneLogServerCommand>,
        backfill_request_rx: Receiver<ProtoBackfillNack>,
        lane_gc_rx: Receiver<u64>,
        query_rx: Receiver<LaneLogServerQuery>,
        storage: StorageServiceConnector,
    ) -> Self {
        LaneLogServer {
            config,
            client,
            lane_logserver_rx,
            backfill_request_rx,
            lane_gc_rx,
            query_rx,
            storage,
            lanes: HashMap::new(),
            read_caches: HashMap::new(),
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
            cmd = self.lane_logserver_rx.recv() => {
                match cmd {
                    Some(LaneLogServerCommand::NewBlock(lane_id, block)) => {
                        trace!("Received block {} for lane {}", block.block.n, lane_id);
                        self.handle_new_block(lane_id, block).await;
                    },
                    Some(LaneLogServerCommand::Rollback(lane_id, n)) => {
                        trace!("Rolling back lane {} to block {}", lane_id, n);
                        self.handle_rollback(lane_id, n).await;
                    },
                    Some(LaneLogServerCommand::UpdateBCI(n)) => {
                        trace!("Updating BCI to {}", n);
                        self.bci = n;
                    },
                    None => {
                        error!("LaneLogServerCommand channel closed");
                        return Err(());
                    }
                }
            },

            gc_req = self.lane_gc_rx.recv() => {
                if let Some(gc_req) = gc_req {
                    // GC all lanes
                    for lane in self.lanes.values_mut() {
                        lane.retain(|block| block.block.n > gc_req);
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

    /// Get block from lane at index n.
    async fn get_block(&mut self, lane_id: &String, n: u64) -> Option<CachedBlock> {
        let lane = self.lanes.get(lane_id)?;
        let last_n = lane.back()?.block.n;

        if n == 0 || n > last_n {
            return None;
        }

        let first_n = lane.front()?.block.n;
        if n < first_n {
            return self.get_gced_block(lane_id, n).await;
        }

        let block_idx = lane.binary_search_by(|e| e.block.n.cmp(&n)).ok()?;
        let block = lane[block_idx].clone();

        Some(block)
    }

    /// Get GC'ed block from lane at index n.
    async fn get_gced_block(&mut self, lane_id: &String, n: u64) -> Option<CachedBlock> {
        let lane = self.lanes.get(lane_id)?;
        let first_n = lane.front()?.block.n;
        if n >= first_n {
            return None; // The block is not GCed.
        }

        // Get or create read cache for this lane
        let read_cache = self
            .read_caches
            .entry(lane_id.clone())
            .or_insert_with(|| LaneReadCache::new(LOGSERVER_READ_CACHE_WSS));

        // Search in the read cache.
        let starting_point = match read_cache.get(n) {
            Ok(block) => {
                return Some(block);
            }
            Err(Some(block)) => block,
            Err(None) => {
                // Get the first block in the lane.
                lane.front()?.clone()
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

            // Update cache for this lane
            if let Some(cache) = self.read_caches.get_mut(lane_id) {
                cache.put(block.clone());
            }
            ret = block;
        }

        Some(ret)
    }

    /// Respond to a lane backfill request
    async fn respond_backfill(&mut self, backfill_req: ProtoBackfillNack) -> Result<(), ()> {
        let sender = backfill_req.reply_name;

        // Extract hints from wrapper
        let lane_hint = match backfill_req.hints {
            Some(crate::proto::checkpoint::proto_backfill_nack::Hints::Blocks(_)) => {
                warn!("Received block hints for DAG backfill, LaneLogserver requires Lane hints");
                return Ok(());
            }
            Some(crate::proto::checkpoint::proto_backfill_nack::Hints::Lane(lane)) => lane,
            None => {
                warn!("Backfill request has no hints");
                return Ok(());
            }
        };

        // Handle different origin types
        match &backfill_req.origin {
            Some(Origin::Abl(abl)) => {
                // AppendBlockLane is the proper DAG mode path
                self.respond_backfill_abl(sender, abl, lane_hint, backfill_req.last_index_needed)
                    .await
            }

            Some(Origin::Ae(ae)) => {
                // LaneLogserver doesn't handle AE backfill
                warn!(
                    "Received AE backfill request in LaneLogserver (DAG only component) - ignoring"
                );
                return Ok(());
            }

            Some(Origin::Vc(_vc)) => {
                // ViewChange backfill not supported in DAG mode
                warn!("Malformed Request");
                Ok(())
            }

            None => {
                warn!("Malformed backfill request - no origin");
                Ok(())
            }
        }
    }

    /// Handle backfill for AppendBlockLane (DAG mode)
    async fn respond_backfill_abl(
        &mut self,
        sender: String,
        abl: &crate::proto::consensus::ProtoAppendBlockLane,
        hints: ProtoLaneBlockHints,
        last_index_needed: u64,
    ) -> Result<(), ()> {
        // Extract lane_id and AppendBlock from the request
        let lane_id = hints.name.clone();
        let ab = match &abl.ab {
            Some(ab) => ab,
            None => {
                warn!("Malformed AppendBlockLane request - no AppendBlock");
                return Ok(());
            }
        };

        // The requesting node has a block at some index and needs earlier blocks
        // Extract the block_n from the AppendBlock request
        let requester_block_n = match &ab.block {
            Some(block) => block.n,
            None => ab.commit_index, // Fallback to commit_index if no block
        };

        let first_n = last_index_needed;
        let last_n = requester_block_n;

        // Get the requested block from this lane
        let requested_blocks = self.fill_lane(&lane_id, first_n, last_n, hints).await;

        // Construct response as AppendBlockLane
        let payload = if !requested_blocks.is_empty() {
            ProtoPayload {
                message: Some(Message::AppendBlockLane(
                    crate::proto::consensus::ProtoAppendBlockLane {
                        name: lane_id,
                        ab: ProtoAppendBlocks {
                            serialized_blocks: requested_blocks,
                            commit_index: ab.commit_index,
                            view: ab.view,
                            view_is_stable: ab.view_is_stable,
                            config_num: ab.config_num,
                        },
                    },
                )),
            }
        } else {
            warn!(
                "Could not find requested blocks for backfill in lane {}",
                lane_id
            );
            return Ok(());
        };

        // Send the payload to the sender
        let buf = payload.encode_to_vec();
        let _ = PinnedClient::send(
            &self.client,
            &sender,
            MessageRef(&buf, buf.len(), &crate::rpc::SenderType::Anon),
        )
        .await;

        Ok(())
    }

    /// Get blocks from lane in range [first_n, last_n].
    /// If we see a block that matches a hint, we stop and return the blocks up to that point.
    async fn fill_lane(
        &mut self,
        lane_id: &String,
        first_n: u64,
        last_n: u64,
        mut hints: Vec<ProtoBlockHint>,
    ) -> Vec<HalfSerializedBlock> {
        if last_n < first_n {
            // QUESTION: Is panic correct here? logserver panics in this case...
            panic!("Invalid range: last_n ({}) < first_n ({})", last_n, first_n);
        }

        let hint_map = hints
            .drain(..)
            .map(|hint| (hint.block_n, hint.digest))
            .collect::<HashMap<_, _>>();

        let mut lane_queue = VecDequeue::with_capacity((last_n - first_n + 1) as usize);
        for i in (first_n..=last_n) {
            let block = match self.get_block(lane_id, i).await {
                Some(block) => block,
                None => {
                    warn!("Block {} not found in lane {}", i, lane_id);
                    continue;
                }
            };

            let hint = hint_map.get(&i);
            if let Some(hint) = hint {
                if hint.eq(&block.block_hash) {
                    // This block matches, requester already has it, skip
                    break;
                }
            }

            lane_queue.push_back(HalfSerializedBlock {
                n: block.block.n,
                view: block.block.view,
                view_is_stable: block.block.view_is_stable,
                config_num: block.block.config_num,
                serialized_body: block.block_ser.clone(),
            });
        }
    }

    /// Handle incoming queries:
    /// - CheckHash
    /// - GetHints
    /// - GetBlock
    async fn handle_query(&mut self, query: LaneLogServerQuery) {
        match query {
            LaneLogServerQuery::CheckHash(proposer_sig, n, hsh, sender) => {
                if n == 0 {
                    sender.send(true).await.unwrap();
                    return;
                }

                let block = match self.get_block(&proposer_sig, n).await {
                    Some(block) => block,
                    None => {
                        let lane = self.lanes.get(&proposer_sig);
                        let last_n_in_lane = lane.and_then(|l| l.back()).map_or(0, |b| b.block.n);
                        error!(
                            "Block {} not found in lane {:?}, last_n seen: {}",
                            n, proposer_sig, last_n_in_lane
                        );
                        sender.send(false).await.unwrap();
                        return;
                    }
                };

                sender.send(block.block_hash.eq(&hsh)).await.unwrap();
            }
            LaneLogServerQuery::GetHints(proposer_sig, last_needed_n, sender) => {
                // Starting from last_needed_n,
                // Include last_needed_n, last_needed_n + 1000, last_needed_n + 2000, ..., until last_needed_n + 10000,
                // Then include last_needed_n + 10000, last_needed_n + 20000, ..., until last_needed_n + 100000,
                // and so on until we reach last_n. Also include the last_n.

                const JUMP_START: u64 = 1000;
                const JUMP_MULTIPLIER: u64 = 10;

                let mut block_hints = Vec::new();

                let lane = match self.lanes.get(&proposer_sig) {
                    Some(lane) => lane,
                    None => {
                        warn!("Lane {:?} not found for GetHints", proposer_sig);
                        let _ = sender.send(vec![]).await;
                        return;
                    }
                };

                let last_n = lane.back().map_or(0, |block| block.block.n);
                let mut curr_n = last_needed_n;
                let mut curr_jump = JUMP_START;
                let mut curr_jump_used_for = 0;

                if curr_n == 0 {
                    curr_n = 1;
                }

                while curr_n < last_n {
                    let block = match self.get_block(&proposer_sig, curr_n).await {
                        Some(block) => block,
                        None => {
                            break;
                        }
                    };
                    block_hints.push(ProtoBlockHint {
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
                    let block = match self.get_block(&proposer_sig, last_n).await {
                        Some(block) => block,
                        None => {
                            // This should never happen.
                            panic!("Block {} not found in lane {:?}", last_n, proposer_sig);
                        }
                    };
                    block_hints.push(ProtoBlockHint {
                        block_n: block.block.n,
                        digest: block.block_hash.clone(),
                    });
                }

                // Wrap the block hints in ProtoLaneBlockHints
                let lane_hints = vec![ProtoLaneBlockHints {
                    name: proposer_sig.clone(),
                    hints: block_hints,
                }];

                let len = lane_hints.len();

                let res = sender.send(lane_hints).await;
                info!("Sent lane hints size {}, result = {:?}", len, res);
            }
            LaneLogServerQuery::GetBlock(lane_id, n, sender) => {
                let block = self.get_block(&lane_id, n).await;
                let _ = sender.send(block).await;
            }
        }
    }

    /// Invariant: Each lane is continuous, increasing seq num and maintains hash chain continuity
    async fn handle_new_block(&mut self, lane_id: String, block: CachedBlock) {
        // Get or create the lane for this sender
        let lane = self
            .lanes
            .entry(lane_id.clone())
            .or_insert_with(VecDeque::new);

        let last_n = lane.back().map_or(0, |block| block.block.n);
        if block.block.n != last_n + 1 {
            error!(
                "Block {} is not the next block in lane {}, last_n: {}",
                block.block.n, lane_id, last_n
            );
            return;
        }

        if last_n > 0 && !block.block.parent.eq(&lane.back().unwrap().block_hash) {
            error!(
                "Parent hash mismatch for block {} in lane {}",
                block.block.n, lane_id
            );
            return;
        }

        lane.push_back(block);
    }

    async fn handle_rollback(&mut self, lane_id: String, mut n: u64) {
        if n <= self.bci {
            n = self.bci + 1;
        }

        // Rollback the specified lane
        if let Some(lane) = self.lanes.get_mut(&lane_id) {
            lane.retain(|block| block.block.n <= n);
        }

        // Clean up read cache for this lane
        if let Some(cache) = self.read_caches.get_mut(&lane_id) {
            cache.cache.retain(|k, _| *k <= n);
        }
    }
}
