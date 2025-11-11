/// Block Receiver
/// Receives and processes AppendBlock messages from workers in the DAG dissemination layer.
/// Key differences from ForkReceiver:
/// - Handles single blocks instead of forks
/// - Accepts messages from any worker (not just leader)
/// - Maintains per-lane continuity tracking
use std::{collections::HashMap, io::Error, sync::Arc};

use log::{debug, info, warn};
use prost::Message;
use tokio::sync::{oneshot, Mutex};

use crate::{
    config::AtomicConfig,
    crypto::{CachedBlock, CryptoServiceConnector, FutureHash},
    proto::{checkpoint::ProtoBackfillNack, consensus::ProtoAppendBlock, rpc::ProtoPayload},
    rpc::{client::PinnedClient, MessageRef, SenderType},
    utils::{
        channel::{make_channel, Receiver, Sender},
        deserialize_proto_block, get_parent_hash_in_proto_block_ser,
    },
};

use super::lane_logserver::LaneLogServerQuery;

/// Command messages for BlockReceiver control
pub enum BlockReceiverCommand {
    /// Process a backfill response
    UseBackfillResponse(ProtoAppendBlock, SenderType),
}

/// Metadata associated with an AppendBlock message
#[derive(Debug, Clone)]
pub struct AppendBlockStats {
    pub view: u64,
    pub view_is_stable: bool,
    pub config_num: u64,
    pub sender: String,
    pub ci: u64,
    pub lane_id: String, // Lane identifier (sender name)
}

/// A single block with its verification future, ready to send to broadcaster
pub struct SingleBlock {
    pub block_future: oneshot::Receiver<Result<CachedBlock, Error>>,
    pub stats: AppendBlockStats,
}

/// Tracks continuity for a single lane
struct LaneContinuityStats {
    last_block_hash: FutureHash,
    last_block_n: u64,
    waiting_on_nack_reply: bool,
}

impl LaneContinuityStats {
    fn new() -> Self {
        Self {
            last_block_hash: FutureHash::None,
            last_block_n: 0,
            waiting_on_nack_reply: false,
        }
    }
}

macro_rules! ask_lane_logserver {
    ($me:expr, $query:expr, $($args:expr),+) => {
        {
            let (tx, rx) = make_channel(1);
            $me.lane_logserver_query_tx.send($query($($args),+, tx)).await.unwrap();
            rx.recv().await.unwrap()
        }
    };
}

/// Receives AppendBlock messages from workers in the DAG dissemination layer.
///
/// Key differences from ForkReceiver:
/// - Handles single blocks instead of forks
/// - Accepts messages from any worker (not just leader)
/// - Maintains per-lane continuity tracking
/// - No multipart buffer or blocking states
/// - Simpler validation logic (parent hash check per lane)
///
/// Flow:
/// 1. Receive AppendBlock message
/// 2. Extract proposer signature to identify lane
/// 3. Check lane continuity (parent hash matches)
/// 4. Verify block cryptographically
/// 5. Forward to LaneBlockBroadcaster
/// 6. Update lane continuity state
pub struct BlockReceiver {
    config: AtomicConfig,
    crypto: CryptoServiceConnector,
    client: PinnedClient,

    // Current view/config for validation
    view: u64,
    config_num: u64,

    // Message channels
    block_rx: Receiver<(ProtoAppendBlock, SenderType /* Sender */)>,
    command_rx: Receiver<BlockReceiverCommand>,

    broadcaster_tx: Sender<SingleBlock>,

    // Per-lane continuity tracking
    // Key: lane_id (sender name)
    // Value: continuity stats for that lane
    lane_continuity: HashMap<String, LaneContinuityStats>,

    // Communication with lane log server
    lane_logserver_query_tx: Sender<LaneLogServerQuery>,
}

impl BlockReceiver {
    pub fn new(
        config: AtomicConfig,
        crypto: CryptoServiceConnector,
        client: PinnedClient,
        block_rx: Receiver<(ProtoAppendBlock, SenderType)>,
        command_rx: Receiver<BlockReceiverCommand>,
        broadcaster_tx: Sender<SingleBlock>,
        lane_logserver_query_tx: Sender<LaneLogServerQuery>,
    ) -> Self {
        let ret = Self {
            config,
            crypto,
            client,
            view: 0,
            config_num: 0,
            block_rx,
            command_rx,
            broadcaster_tx,
            lane_continuity: HashMap::new(),
            lane_logserver_query_tx,
        };

        #[cfg(not(feature = "view_change"))]
        {
            // TODO: Initialize view and config_num based on view_change feature
            // For now, keeping initialization in struct construction
        }

        ret
    }

    pub async fn run(block_receiver: Arc<Mutex<Self>>) {
        let mut block_receiver = block_receiver.lock().await;

        loop {
            if let Err(_) = block_receiver.worker().await {
                break;
            }
        }
    }

    async fn worker(&mut self) -> Result<(), ()> {
        // Check if any lane is waiting on NACK reply
        let waiting_on_nack = self
            .lane_continuity
            .values()
            .any(|stats| stats.waiting_on_nack_reply);

        if waiting_on_nack {
            // Only process commands when waiting on NACK
            let cmd = self.command_rx.recv().await.unwrap();
            self.handle_command(cmd).await;
        } else {
            tokio::select! {
                block_sender = self.block_rx.recv() => {
                    if let Some((block, SenderType::Auth(sender, _))) = block_sender {
                        debug!("Received AppendBlock(n={}) from {}",
                            block.block.as_ref().map_or(0, |b| b.n), sender);
                        self.process_block(block, sender).await;
                    }
                },
                cmd = self.command_rx.recv() => {
                    if let Some(cmd) = cmd {
                        self.handle_command(cmd).await;
                    }
                }
            }
        }

        Ok(())
    }

    async fn process_block(&mut self, block: ProtoAppendBlock, sender: String) {
        if block.view < self.view || block.config_num < self.config_num {
            warn!(
                "Old view AppendBlock received: block view {} < my view {} or block config {} < my config {}",
                block.view, self.view, block.config_num, self.config_num
            );
            return;
        }

        // Use sender name as lane identifier
        // In DAG mode, each sender has their own lane
        let lane_id = sender.clone();

        // Check if this lane is waiting on NACK reply
        if let Some(stats) = self.lane_continuity.get(&lane_id) {
            if stats.waiting_on_nack_reply {
                info!("Possible AppendBlock after NACK for lane {}", lane_id);
            }
        }

        // Check lane continuity
        if self.ensure_lane_continuity(&lane_id, &block).await.is_err() {
            // Send NACK for this lane
            self.send_lane_nack(lane_id.clone(), sender, block).await;
            info!("Returning after sending NACK for lane {}", lane_id);
            return;
        }

        // Mark that we're no longer waiting on NACK for this lane
        if let Some(stats) = self.lane_continuity.get_mut(&lane_id) {
            stats.waiting_on_nack_reply = false;
        }

        let half_serialized = match block.block {
            Some(b) => b,
            None => return,
        };

        // Verify the single block cryptographically
        // The crypto service returns:
        // - block_rx: oneshot::Receiver<CachedBlock> (the verified block)
        // - hash_rx: oneshot::Receiver<Vec<u8>> (the block hash)
        // - hash_rx2: oneshot::Receiver<Vec<u8>> (duplicate hash for convenience)
        let (block_rx, hash_rx, _hash_rx2) = self
            .crypto
            .prepare_block(
                match deserialize_proto_block(&half_serialized.serialized_body) {
                    Ok(b) => b,
                    Err(_) => {
                        warn!("Failed to deserialize block body");
                        return;
                    }
                },
                true,             // Always sign in DAG mode
                FutureHash::None, // Parent hash is in the block already
            )
            .await;

        // Create stats for this block
        let stats = AppendBlockStats {
            view: block.view,
            view_is_stable: block.view_is_stable,
            config_num: block.config_num,
            sender,
            ci: block.commit_index,
            lane_id: lane_id.clone(),
        };

        // Wrap the block receiver to match the expected Result type
        // The crypto service guarantees the block is valid at this point
        let (result_tx, result_rx) = oneshot::channel();
        tokio::spawn(async move {
            match block_rx.await {
                Ok(block) => {
                    let _ = result_tx.send(Ok(block));
                }
                Err(_) => {
                    let _ = result_tx.send(Err(Error::new(
                        std::io::ErrorKind::Other,
                        "Block verification cancelled",
                    )));
                }
            }
        });

        // Forward to broadcaster
        let single_block = SingleBlock {
            block_future: result_rx,
            stats,
        };

        self.broadcaster_tx.send(single_block).await.unwrap();

        // Update lane continuity with the hash of this block
        // Wrap hash receiver to match FutureResult type
        let (hash_result_tx, hash_result_rx) = oneshot::channel();
        tokio::spawn(async move {
            match hash_rx.await {
                Ok(hash) => {
                    let _ = hash_result_tx.send(Ok(hash));
                }
                Err(_) => {
                    let _ = hash_result_tx.send(Err(Error::new(
                        std::io::ErrorKind::Other,
                        "Hash calculation cancelled",
                    )));
                }
            }
        });

        let lane_stats = self
            .lane_continuity
            .entry(lane_id.clone())
            .or_insert_with(LaneContinuityStats::new);

        lane_stats.last_block_hash = FutureHash::FutureResult(hash_result_rx);
        lane_stats.last_block_n = half_serialized.n;
    }

    async fn handle_command(&mut self, cmd: BlockReceiverCommand) {
        match cmd {
            BlockReceiverCommand::UseBackfillResponse(block, sender) => {
                let (name, _) = sender.to_name_and_sub_id();
                self.process_block(block, name).await;
            }
        }
    }

    /// Check if the block connects to the lane's existing chain
    ///
    /// Logic:
    /// 1. If parent hash matches last block we forwarded in this lane -> OK
    /// 2. If parent hash exists in lane's log server history -> OK
    /// 3. Otherwise -> NACK needed
    async fn ensure_lane_continuity(
        &mut self,
        lane_id: &String,
        block: &ProtoAppendBlock,
    ) -> Result<(), ()> {
        let half_serialized = match &block.block {
            Some(b) => b,
            None => {
                warn!("Block has no serialized body");
                return Err(());
            }
        };

        if half_serialized.n == 1 {
            // First block in lane, no parent to check
            return Ok(());
        }

        let parent_hash = get_parent_hash_in_proto_block_ser(&half_serialized.serialized_body)
            .ok_or_else(|| {
                warn!("Could not extract parent hash from block");
            })?;

        // Check local continuity for this lane
        let lane_stats = self.lane_continuity.get_mut(lane_id);

        if let Some(stats) = lane_stats {
            let hsh = match stats.last_block_hash.take() {
                FutureHash::None => None,
                FutureHash::Immediate(hsh) => {
                    stats.last_block_hash = FutureHash::Immediate(hsh.clone());
                    Some(hsh.clone())
                }
                FutureHash::Future(receiver) => {
                    let hsh = receiver.await.unwrap();
                    stats.last_block_hash = FutureHash::Immediate(hsh.clone());
                    Some(hsh)
                }
                FutureHash::FutureResult(receiver) => {
                    let hsh = receiver.await.unwrap();
                    if hsh.is_err() {
                        stats.last_block_hash = FutureHash::None;
                        None
                    } else {
                        let hsh = hsh.unwrap();
                        stats.last_block_hash = FutureHash::Immediate(hsh.clone());
                        Some(hsh)
                    }
                }
            };

            if let Some(hsh) = hsh {
                if hsh.eq(&parent_hash) {
                    // Parent matches last forwarded block in this lane
                    return Ok(());
                }
            }
        }

        // Ask LaneLogServer if parent exists in this lane's history
        let parent_n = half_serialized.n - 1;
        let logserver_has_block = ask_lane_logserver!(
            self,
            LaneLogServerQuery::CheckHash,
            lane_id.clone(),
            parent_n,
            parent_hash
        );

        if logserver_has_block {
            Ok(())
        } else {
            Err(())
        }
    }

    /// Send a NACK for a specific lane requesting backfill
    async fn send_lane_nack(&mut self, lane_id: String, sender: String, block: ProtoAppendBlock) {
        info!("NACKing AppendBlock to {} for lane {}", sender, lane_id);

        // Mark this lane as waiting on NACK reply
        let lane_stats = self
            .lane_continuity
            .entry(lane_id.clone())
            .or_insert_with(LaneContinuityStats::new);
        lane_stats.waiting_on_nack_reply = true;

        let first_block_n = block.block.as_ref().map_or(block.commit_index, |b| b.n);
        let last_index_needed = if first_block_n > 100 {
            first_block_n - 100
        } else {
            0
        };

        // Get hints from lane log server for this specific lane
        let hints = ask_lane_logserver!(
            self,
            LaneLogServerQuery::GetHints,
            lane_id.clone(),
            last_index_needed
        );

        let my_name = self.config.get().net_config.name.clone();

        // Use AppendBlockLane origin for DAG mode backfill
        let nack = ProtoBackfillNack {
            hints: Some(crate::proto::checkpoint::proto_backfill_nack::Hints::Blocks(
                crate::proto::checkpoint::ProtoBlockHintsWrapper { hints }
            )),
            last_index_needed,
            reply_name: my_name,
            origin: Some(crate::proto::checkpoint::proto_backfill_nack::Origin::Abl(
                crate::proto::consensus::ProtoAppendBlockLane {
                    name: lane_id.clone(),
                    ab: Some(crate::proto::consensus::ProtoAppendBlock {
                        block: block.block,
                        commit_index: block.commit_index,
                        view: block.view,
                        view_is_stable: block.view_is_stable,
                        config_num: block.config_num,
                        is_backfill_response: false,
                    }),
                },
            )),
        };

        let payload = ProtoPayload {
            message: Some(crate::proto::rpc::proto_payload::Message::BackfillNack(
                nack,
            )),
        };

        let buf = payload.encode_to_vec();
        let sz = buf.len();

        let _ = PinnedClient::send(
            &self.client,
            &sender,
            MessageRef(&buf, sz, &SenderType::Anon),
        )
        .await;
    }

    #[allow(dead_code)]
    fn liveness_threshold(&self) -> usize {
        #[cfg(feature = "platforms")]
        {
            let n = self.config.get().consensus_config.node_list.len();
            let u = self.config.get().consensus_config.liveness_u as usize;
            if n <= u {
                return 1;
            }
            u + 1
        }

        #[cfg(not(feature = "platforms"))]
        {
            let n = self.config.get().consensus_config.node_list.len();
            let f = n / 3;
            f + 1
        }
    }
}
