/// Staging area for lane-based data dissemination.
///
/// Unlike the existing Staging module which handles fork choice and leader-based consensus,
/// LaneStaging is significantly simpler:
/// - First-come-first-served: First block at each (lane, seq_num) wins
/// - No fork choice: Duplicates are ignored
/// - No view changes: Lanes operate independently
/// - Simple lifecycle: Store → Acknowledge → Form CAR
///
/// Flow:
/// 1. Receive blocks from BlockBroadcaster (already stored)
/// 2. Wait for storage completion
/// 3. Send BlockAck to all nodes (or lane owner)
/// 4. Collect BlockAcks from other nodes
/// 5. Form CAR when liveness threshold reached
/// 6. Broadcast CAR to all nodes
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use ed25519_dalek::SIGNATURE_LENGTH;
use log::{debug, error, info, trace, warn};
use prost::Message;
use tokio::sync::{oneshot, Mutex};

use crate::{
    config::AtomicConfig,
    crypto::{CachedBlock, CryptoServiceConnector},
    proto::{
        checkpoint::{proto_backfill_nack, ProtoBackfillNack, ProtoBlockHint, ProtoLaneBlockHints},
        consensus::{ProtoBlockAck, ProtoBlockCar, ProtoNameWithSignature},
        rpc::{proto_payload, ProtoPayload},
    },
    rpc::{client::PinnedClient, MessageRef, SenderType},
    utils::{
        channel::{Receiver, Sender},
        StorageAck,
    },
};

use super::{
    super::client_reply::ClientReplyCommand,
    block_receiver::AppendBlockStats,
    lane_logserver::{CheckCarResult, LaneLogServerCommand, LaneLogServerQuery},
};

/// Represents the current tip cut across all lanes
#[derive(Clone, Debug)]
pub struct TipCut {
    /// One CAR per lane (at most)
    /// Maps lane_id (sender name) -> CAR
    pub cars: HashMap<String, ProtoBlockCar>,

    /// View number when this tip cut was constructed
    pub view: u64,

    /// Config number
    pub config_num: u64,
}

/// Query interface for LaneStaging
pub enum LaneStagingQuery {
    /// Get the current tip cut (one CAR per lane)
    GetCurrentTipCut(oneshot::Sender<Option<TipCut>>),
}

/// Information about a block stored in a lane
struct StoredBlock {
    block: CachedBlock,
    stats: AppendBlockStats,

    /// Acknowledgments received from other nodes
    /// Maps node name -> signature bytes
    acknowledgments: HashMap<String, Vec<u8>>,

    /// CAR (Certificate of Availability and Replication)
    car: Option<ProtoBlockCar>,
    car_broadcasted: bool,
}

/// Staging area for DAG-based dissemination with per-lane block storage.
/// Simpler than existing Staging because:
/// - No fork choice (first block wins)
/// - No view changes (lanes independent)
/// - Simpler commit model (store → ack → CAR)
pub struct LaneStaging {
    config: AtomicConfig,
    client: PinnedClient,
    crypto: CryptoServiceConnector,

    // Current state
    #[allow(dead_code)]
    ci: u64,
    view: u64,
    config_num: u64,

    // Per-lane, per-sequence-number storage
    // Outer key: lane_id (sender name)
    // Inner key: sequence number (block.n)
    // Value: block info with acknowledgments
    lane_blocks: HashMap<String, HashMap<u64, StoredBlock>>,

    // Current tip cut (one CAR per lane)
    current_tip_cut: TipCut,

    // Input channels
    block_rx: Receiver<(
        CachedBlock,
        oneshot::Receiver<StorageAck>,
        AppendBlockStats,
        bool, /* this_is_final_block */
    )>,

    block_ack_rx: Receiver<(ProtoBlockAck, SenderType)>,

    car_rx: Receiver<(ProtoBlockCar, SenderType)>,

    query_rx: Receiver<LaneStagingQuery>,

    // Output channels
    #[allow(dead_code)]
    client_reply_tx: Sender<ClientReplyCommand>,
    lane_logserver_tx: Sender<LaneLogServerCommand>,
    lane_logserver_query_tx: Sender<LaneLogServerQuery>,

    // Child CARs awaiting their parent CAR (keyed by (lane_id, parent_n))
    pending_children_by_parent: HashMap<(String, u64), Vec<ProtoBlockCar>>,
}

impl LaneStaging {
    pub fn new(
        config: AtomicConfig,
        client: PinnedClient,
        crypto: CryptoServiceConnector,
        block_rx: Receiver<(
            CachedBlock,
            oneshot::Receiver<StorageAck>,
            AppendBlockStats,
            bool,
        )>,
        block_ack_rx: Receiver<(ProtoBlockAck, SenderType)>,
        car_rx: Receiver<(ProtoBlockCar, SenderType)>,
        query_rx: Receiver<LaneStagingQuery>,
        client_reply_tx: Sender<ClientReplyCommand>,
        lane_logserver_tx: Sender<LaneLogServerCommand>,
        lane_logserver_query_tx: Sender<LaneLogServerQuery>,
    ) -> Self {
        Self {
            config,
            client,
            crypto,
            ci: 0,
            view: 0,
            config_num: 0,
            lane_blocks: HashMap::new(),
            current_tip_cut: TipCut {
                cars: HashMap::new(),
                view: 0,
                config_num: 0,
            },
            block_rx,
            block_ack_rx,
            car_rx,
            query_rx,
            client_reply_tx,
            lane_logserver_tx,
            lane_logserver_query_tx,
            pending_children_by_parent: HashMap::new(),
        }
    }

    pub async fn run(lane_staging: Arc<Mutex<Self>>) {
        let mut lane_staging = lane_staging.lock().await;

        loop {
            if let Err(_) = lane_staging.worker().await {
                break;
            }
        }
    }

    async fn worker(&mut self) -> Result<(), ()> {
        tokio::select! {
            block = self.block_rx.recv() => {
                if block.is_none() {
                    return Err(());
                }
                let (block, storage_ack, stats, _this_is_final_block) = block.unwrap();
                self.process_block(block, storage_ack, stats).await?;
            },

            block_ack = self.block_ack_rx.recv() => {
                if block_ack.is_none() {
                    return Err(());
                }
                let (block_ack, sender) = block_ack.unwrap();
                self.process_block_ack(block_ack, sender).await?;
            },

            car = self.car_rx.recv() => {
                if car.is_none() {
                    return Err(());
                }
                let (car, sender) = car.unwrap();
                self.process_remote_car(car, sender).await?;
            },

            query = self.query_rx.recv() => {
                if query.is_none() {
                    return Err(());
                }
                self.handle_query(query.unwrap());
            },
        }

        Ok(())
    }

    /// Process a block received from BlockBroadcaster.
    /// BlockBroadcaster has already initiated storage, we just wait for completion.
    async fn process_block(
        &mut self,
        block: CachedBlock,
        storage_ack: oneshot::Receiver<StorageAck>,
        stats: AppendBlockStats,
    ) -> Result<(), ()> {
        let lane_id = stats.lane_id.clone();
        let seq_num = block.block.n;

        debug!(
            "Received block n={} for lane {} from {}",
            seq_num, lane_id, stats.sender
        );

        // Get or create lane entry
        let lane = self
            .lane_blocks
            .entry(lane_id.clone())
            .or_insert_with(HashMap::new);

        // Check if this sequence number is already occupied (first-come-first-served)
        if lane.contains_key(&seq_num) {
            debug!(
                "Block n={} in lane {:?} already stored - ignoring duplicate",
                seq_num, lane_id
            );
            return Ok(());
        }

        // Create stored block entry
        let stored_block = StoredBlock {
            block: block.clone(),
            stats,
            acknowledgments: HashMap::new(),
            car: None,
            car_broadcasted: false,
        };

        lane.insert(seq_num, stored_block);

        // Wait for storage to complete (BlockBroadcaster initiated this)
        match storage_ack.await {
            Ok(Ok(())) => {
                debug!(
                    "Block n={} in lane {:?} stored successfully",
                    seq_num, lane_id
                );

                // Forward to LaneLogServer for persistence and querying
                self.lane_logserver_tx
                    .send(LaneLogServerCommand::NewBlock(
                        lane_id.clone(),
                        block.clone(),
                    ))
                    .await
                    .unwrap();

                // Send acknowledgment to other nodes
                self.send_block_ack(&block, &lane_id).await?;
            }
            Ok(Err(e)) => {
                error!(
                    "Storage failed for block n={} in lane {:?}: {:?}",
                    seq_num, lane_id, e
                );
                // Remove from our tracking
                if let Some(lane) = self.lane_blocks.get_mut(&lane_id) {
                    lane.remove(&seq_num);
                }
                return Err(());
            }
            Err(_) => {
                error!(
                    "Storage ack channel closed for block n={} in lane {:?}",
                    seq_num, lane_id
                );
                // Remove from our tracking
                if let Some(lane) = self.lane_blocks.get_mut(&lane_id) {
                    lane.remove(&seq_num);
                }
                return Err(());
            }
        }

        Ok(())
    }

    /// Send BlockAck message after successfully storing a block.
    ///
    /// Fanout optimization: send only to the lane owner (origin node) rather than broadcasting
    /// to all nodes. Only the lane owner collects acks and forms CARs.
    async fn send_block_ack(&mut self, block: &CachedBlock, lane_id: &String) -> Result<(), ()> {
        let config = self.config.get();
        let my_name = &config.net_config.name;

        // Create signature on block digest
        let sig = self.crypto.sign(&block.block_hash).await;

        // Build BlockAck message
        let block_ack = ProtoBlockAck {
            digest: block.block_hash.clone().try_into().unwrap(),
            n: block.block.n,
            lane: lane_id.as_bytes().to_vec(),
            sig: sig.to_vec(),
        };

        // If we're the lane owner, no need to send an ack to ourselves.
        if lane_id == my_name {
            trace!(
                "Lane owner {} stored its own block n={} — not sending BlockAck to self",
                my_name,
                block.block.n
            );
            return Ok(());
        }

        debug!(
            "Sending BlockAck for n={} in lane {} to lane owner only",
            block.block.n, lane_id
        );

        // Encode payload
        let payload = ProtoPayload {
            message: Some(proto_payload::Message::BlockAck(block_ack.clone())),
        };
        let buf = payload.encode_to_vec();
        let sz = buf.len();

        // Send only to the lane owner/origin node
        if config.consensus_config.node_list.contains(lane_id) {
            let _ = PinnedClient::send(
                &self.client,
                lane_id,
                MessageRef(&buf, sz, &SenderType::Anon),
            )
            .await;
        } else {
            warn!(
                "Lane id {} not found in node list; cannot send BlockAck for n={}",
                lane_id, block.block.n
            );
        }

        Ok(())
    }

    /// Process a BlockAck received from another node.
    async fn process_block_ack(
        &mut self,
        block_ack: ProtoBlockAck,
        sender: SenderType,
    ) -> Result<(), ()> {
        let (sender_name, _) = sender.to_name_and_sub_id();

        debug!(
            "Received BlockAck for n={} lane={:?} from {}",
            block_ack.n, block_ack.lane, sender_name
        );

        // Verify the signature
        let digest_hash: Vec<u8> = match block_ack.digest.clone().try_into() {
            Ok(h) => h,
            Err(_) => {
                warn!("Malformed digest in BlockAck from {}", sender_name);
                return Ok(());
            }
        };

        let sig: [u8; SIGNATURE_LENGTH] = match block_ack.sig.clone().try_into() {
            Ok(s) => s,
            Err(_) => {
                warn!("Malformed signature in BlockAck from {}", sender_name);
                return Ok(());
            }
        };

        let verified = self
            .crypto
            .verify_nonblocking(digest_hash, sender_name.clone(), sig)
            .await
            .await
            .unwrap();

        if !verified {
            warn!("Failed to verify BlockAck from {}", sender_name);
            return Ok(());
        }

        // Convert lane bytes to String
        let lane_id = match String::from_utf8(block_ack.lane.clone()) {
            Ok(s) => s,
            Err(_) => {
                warn!("Invalid UTF-8 in lane identifier from {}", sender_name);
                return Ok(());
            }
        };

        // Find the block in our lane storage
        let lane = match self.lane_blocks.get_mut(&lane_id) {
            Some(l) => l,
            None => {
                debug!(
                    "Received ack for unknown lane {} from {}",
                    lane_id, sender_name
                );
                return Ok(());
            }
        };

        let stored_block = match lane.get_mut(&block_ack.n) {
            Some(b) => b,
            None => {
                debug!(
                    "Received ack for unknown block n={} in lane from {}",
                    block_ack.n, sender_name
                );
                return Ok(());
            }
        };

        // Verify digest matches our stored block
        let expected_digest: Vec<u8> = stored_block.block.block_hash.clone().try_into().unwrap();
        if expected_digest != block_ack.digest {
            warn!(
                "BlockAck digest mismatch from {} for block n={}",
                sender_name, block_ack.n
            );
            return Ok(());
        }

        // Store the acknowledgment
        stored_block
            .acknowledgments
            .insert(sender_name.clone(), block_ack.sig);

        debug!(
            "Block n={} in lane now has {}/{} acks",
            block_ack.n,
            stored_block.acknowledgments.len(),
            self.car_threshold()
        );

        // Check if we've reached the threshold to form a CAR
        self.maybe_form_car(&lane_id, block_ack.n).await?;

        Ok(())
    }

    /// Form a CAR (Certificate of Availability and Replication) if threshold reached.
    async fn maybe_form_car(&mut self, lane_id: &String, seq_num: u64) -> Result<(), ()> {
        // Check if CAR already formed and get the necessary data
        let (should_form_car, block_hash, view, acks) = {
            let lane = match self.lane_blocks.get(lane_id) {
                Some(l) => l,
                None => return Ok(()),
            };

            let stored_block = match lane.get(&seq_num) {
                Some(b) => b,
                None => return Ok(()),
            };

            // Check if CAR already formed
            if stored_block.car.is_some() {
                return Ok(());
            }

            // Check if we have enough acknowledgments
            let threshold = self.car_threshold();
            let ack_count = stored_block.acknowledgments.len();

            if ack_count < threshold {
                trace!(
                    "Block n={} in lane has {}/{} acks - waiting for more",
                    seq_num,
                    ack_count,
                    threshold
                );
                return Ok(());
            }

            info!(
                "Forming CAR for block n={} in lane {:?} (acks: {}/{})",
                seq_num, lane_id, ack_count, threshold
            );

            // Collect the data we need
            let block_hash = stored_block.block.block_hash.clone();
            let view = stored_block.stats.view;
            let acks: Vec<_> = stored_block
                .acknowledgments
                .iter()
                .map(|(name, sig)| ProtoNameWithSignature {
                    name: name.clone(),
                    sig: sig.clone(),
                })
                .collect();

            (true, block_hash, view, acks)
        };

        // Now we don't hold any references, so we can mutate self
        if !should_form_car {
            return Ok(());
        }

        // Build the CAR
        let my_name = self.config.get().net_config.name.clone();
        let car = ProtoBlockCar {
            digest: block_hash.try_into().unwrap(),
            n: seq_num,
            sig: acks,
            view,
            origin_node: my_name, // Track which node accepted the client requests
        };

        // Store the CAR
        {
            if let Some(lane) = self.lane_blocks.get_mut(lane_id) {
                if let Some(stored_block) = lane.get_mut(&seq_num) {
                    stored_block.car = Some(car.clone());
                }
            }
        } // drop mutable borrow before awaits

        // Persist CAR in lane_logserver before broadcasting
        // Insert only if it doesn't exist yet
        // NOTE: If there's a hash collision, we overwrite - this is extremely unlikely
        let should_insert = {
            use crate::utils::channel::make_channel;
            let (tx, rx) = make_channel(1);
            self.lane_logserver_query_tx
                .send(LaneLogServerQuery::CheckCar(
                    lane_id.clone(),
                    seq_num,
                    car.digest.clone(),
                    tx,
                ))
                .await
                .unwrap();
            matches!(rx.recv().await.unwrap(), CheckCarResult::NotExists)
        };

        if should_insert {
            self.lane_logserver_tx
                .send(LaneLogServerCommand::NewCar(lane_id.clone(), car.clone()))
                .await
                .unwrap();
        }

        // Broadcast the CAR to all nodes
        self.broadcast_car(car.clone()).await?;

        // Mark as broadcasted
        {
            if let Some(lane) = self.lane_blocks.get_mut(lane_id) {
                if let Some(stored_block) = lane.get_mut(&seq_num) {
                    stored_block.car_broadcasted = true;
                }
            }
        }

        // Update the current tip cut with this new CAR
        self.update_tip_cut(lane_id.clone(), car.clone());

        // Process any children that were waiting on this parent
        self.process_pending_children(lane_id, seq_num).await?;

        info!(
            "Block n={} in lane {} is now stable with CAR",
            seq_num, lane_id
        );

        Ok(())
    }

    /// Broadcast a formed CAR to all nodes.
    // HACK: Do a better broadcasting implementation later
    // - Can add the piggyback optimization later
    async fn broadcast_car(&mut self, car: ProtoBlockCar) -> Result<(), ()> {
        let config = self.config.get();
        let my_name = &config.net_config.name;

        debug!("Broadcasting CAR for block n={}", car.n);

        let payload = ProtoPayload {
            message: Some(proto_payload::Message::BlockCar(car)),
        };
        let buf = payload.encode_to_vec();
        let sz = buf.len();

        for node in &config.consensus_config.node_list {
            if node == my_name {
                continue;
            }
            let _ = PinnedClient::send(&self.client, node, MessageRef(&buf, sz, &SenderType::Anon))
                .await;
        }

        Ok(())
    }

    /// Process a CAR received from another node via RPC.
    /// Car validation:
    /// - Check that CAR is not malformed (Sender matches origin, signatures valid, threshold met)
    /// - Verify that block for the CAR is known/stored locally
    ///     - If missing blocks, backfill lane
    /// - Verify that digest in CAR matches stored block hash
    /// - Verify causal history from CAR through parents to most recent committed TC
    ///     - If any parent blocks are missing CARs, request them
    /// - Once history is verified, attach CAR to stored block
    /// - Update tip cut to include the new CAR
    async fn process_remote_car(
        &mut self,
        car: ProtoBlockCar,
        sender: SenderType,
    ) -> Result<(), ()> {
        let sender_name = match &sender {
            SenderType::Auth(name, _) => name.clone(),
            SenderType::Anon => {
                warn!("Received CAR from anonymous sender - rejecting");
                return Ok(());
            }
        };

        let lane_id = &car.origin_node;

        debug!(
            "Processing remote CAR from {} for lane {} seq {}",
            sender_name, lane_id, car.n
        );

        // Basic validation
        if lane_id.is_empty() {
            warn!("Received CAR with empty origin_node - rejecting");
            return Ok(());
        }

        if car.sig.is_empty() {
            warn!(
                "Received CAR with no signatures from {} - rejecting",
                sender_name
            );
            return Ok(());
        }

        // Verify the sender is the owner of the lane (origin_node should match sender)
        if lane_id != &sender_name {
            warn!(
                "Received CAR for lane {} from different sender {} - rejecting",
                lane_id, sender_name
            );
            return Ok(());
        }

        // Verify signatures over digest with deduplicated signer names
        let threshold = self.car_threshold();
        let digest_hash: Vec<u8> = match car.digest.clone().try_into() {
            Ok(h) => h,
            Err(_) => {
                warn!("Malformed digest in CAR from {} - rejecting", sender_name);
                return Ok(());
            }
        };

        // Verify we have enough unique valid signatures
        let mut unique_valid_signers: HashSet<String> = HashSet::new();
        for signed in &car.sig {
            // Ensure signer is a known node
            if !self
                .config
                .get()
                .consensus_config
                .node_list
                .contains(&signed.name)
            {
                trace!("Ignoring CAR signature from unknown signer {}", signed.name);
                continue;
            }

            // Skip duplicate signer names
            if unique_valid_signers.contains(&signed.name) {
                continue;
            }

            // Parse signature
            let Ok(sig_bytes): Result<[u8; SIGNATURE_LENGTH], _> = signed.sig.clone().try_into()
            else {
                trace!(
                    "Malformed signature for signer {} in CAR — skipping",
                    signed.name
                );
                continue;
            };

            // Verify signature against CAR digest
            let verified = self
                .crypto
                .verify_nonblocking(digest_hash.clone(), signed.name.clone(), sig_bytes)
                .await
                .await
                .unwrap_or(false);

            if verified {
                unique_valid_signers.insert(signed.name.clone());
            } else {
                trace!("Invalid CAR signature from {} — skipping", signed.name);
            }
        }

        if unique_valid_signers.len() < threshold {
            warn!(
                "Rejecting CAR for lane {} seq {}: valid unique signatures {} below threshold {}",
                lane_id,
                car.n,
                unique_valid_signers.len(),
                threshold
            );
            return Ok(());
        }

        // TODO: Check sequence number is reasonable (not too far in future)
        // This prevents memory exhaustion attacks

        // Determine local lane state without holding borrow across awaits
        let (have_block, max_seq_we_have) = {
            let lane_entry = self
                .lane_blocks
                .entry(lane_id.clone())
                .or_insert_with(HashMap::new);
            let have_block = lane_entry.contains_key(&car.n);
            let max_seq_we_have = lane_entry.keys().max().cloned().unwrap_or(0);
            (have_block, max_seq_we_have)
        }; // borrow dropped

        // If missing block: try GetBlock from LaneLogServer; if still missing, then backfill
        if !have_block {
            let fetched = self.ensure_block_in_memory(lane_id, car.n).await.is_some();
            if !fetched {
                let last_index_needed = if max_seq_we_have + 1 < car.n {
                    max_seq_we_have.saturating_add(1)
                } else {
                    car.n.saturating_sub(100)
                };
                trace!(
                    "Missing block for remote CAR lane {} seq {} (max local seq {}), requesting backfill from {}",
                    lane_id, car.n, max_seq_we_have, sender_name
                );
                self.request_lane_backfill_for_car(lane_id, &sender_name, &car, last_index_needed)
                    .await?;
            }
        }

        // Verify block now exists and digest matches
        let digest_matches = {
            if let Some(lane_map) = self.lane_blocks.get(lane_id) {
                if let Some(stored_block) = lane_map.get(&car.n) {
                    let expected: Vec<u8> = stored_block
                        .block
                        .block_hash
                        .clone()
                        .try_into()
                        .unwrap_or_default();
                    expected == car.digest
                } else {
                    false
                }
            } else {
                false
            }
        };

        if !digest_matches {
            warn!(
                "Remote CAR digest mismatch or block still missing for lane {} seq {} - not attaching",
                lane_id, car.n
            );
            return Ok(());
        }

        // Verify causal history (parent CAR chain) using strict sequence:
        // 1) If n<=1, accept (genesis parent)
        // 2) If local parent block has a CAR and its digest matches, accept
        // 3) Else CheckCar with logserver:
        //    - Success: accept
        //    - Failure: reject (digest mismatch)
        //    - NotExists: queue child pending parent and return
        if car.n > 1 {
            // Parent digest from the stored child block we just ensured exists
            let parent_digest_opt: Option<Vec<u8>> = self
                .lane_blocks
                .get(lane_id)
                .and_then(|m| m.get(&car.n))
                .map(|sb| sb.block.block.parent.clone());

            let Some(parent_digest) = parent_digest_opt else {
                // Shouldn't happen if child block exists, but be safe: queue pending
                // QUESTION: should we queue here? seems like a block form problem
                self.add_pending_child(lane_id, car.n - 1, car.clone());
                trace!(
                    "Queued CAR lane {} n {} pending parent n {} (no parent digest)",
                    lane_id,
                    car.n,
                    car.n - 1
                );
                return Ok(());
            };

            // Step 2: local parent CAR present and matches?
            let local_parent_has_matching_car = self
                .lane_blocks
                .get(lane_id)
                .and_then(|m| m.get(&(car.n - 1)))
                .and_then(|psb| psb.car.as_ref())
                .map(|pc| pc.digest.as_slice() == parent_digest.as_slice())
                .unwrap_or(false);

            if !local_parent_has_matching_car {
                // Step 3: check with logserver
                use crate::utils::channel::make_channel;
                let (tx, rx) = make_channel(1);
                self.lane_logserver_query_tx
                    .send(LaneLogServerQuery::CheckCar(
                        lane_id.clone(),
                        car.n - 1,
                        parent_digest.clone(),
                        tx,
                    ))
                    .await
                    .unwrap();
                match rx.recv().await.unwrap() {
                    CheckCarResult::Success => {
                        // ok, continue to attach child
                    }
                    CheckCarResult::Failure => {
                        warn!(
                            "Rejecting CAR lane {} n {}: parent CAR exists with different digest",
                            lane_id, car.n
                        );
                        return Ok(());
                    }
                    CheckCarResult::NotExists => {
                        // queue pending until parent arrives
                        self.add_pending_child(lane_id, car.n - 1, car.clone());
                        trace!(
                            "Queued CAR lane {} n {} pending parent n {} (not exists)",
                            lane_id,
                            car.n,
                            car.n - 1
                        );
                        return Ok(());
                    }
                }
            }
        }

        info!(
            "Accepting remote CAR from {} for lane {} seq {} with {} signatures",
            sender_name,
            lane_id,
            car.n,
            car.sig.len()
        );

        // Attach CAR to stored block (scope-limited borrow) then persist and update tip cut
        {
            if let Some(lane_map) = self.lane_blocks.get_mut(lane_id) {
                if let Some(stored_block) = lane_map.get_mut(&car.n) {
                    stored_block.car = Some(car.clone());
                }
            }
        }

        // Persist remote CAR in lane_logserver if not present
        // TODO: Shouldw e just overwrite the car always?
        {
            use crate::utils::channel::make_channel;
            let (tx, rx) = make_channel(1);
            self.lane_logserver_query_tx
                .send(LaneLogServerQuery::CheckCar(
                    lane_id.clone(),
                    car.n,
                    car.digest.clone(),
                    tx,
                ))
                .await
                .unwrap();
            if matches!(rx.recv().await.unwrap(), CheckCarResult::NotExists) {
                self.lane_logserver_tx
                    .send(LaneLogServerCommand::NewCar(lane_id.clone(), car.clone()))
                    .await
                    .unwrap();
            }
        }

        // Update tip cut with this remote CAR (latest per-lane CAR)
        self.update_tip_cut(lane_id.clone(), car.clone());

        // Process any children now unblocked by this CAR
        self.process_pending_children(lane_id, car.n).await?;

        Ok(())
    }

    /// Ensure (lane_id, n) block exists in memory by querying LaneLogServer when missing.
    async fn ensure_block_in_memory(&mut self, lane_id: &String, n: u64) -> Option<CachedBlock> {
        if let Some(m) = self.lane_blocks.get(lane_id) {
            if let Some(sb) = m.get(&n) {
                return Some(sb.block.clone());
            }
        }

        use crate::utils::channel::make_channel;
        let (tx, rx) = make_channel(1);
        let _ = self
            .lane_logserver_query_tx
            .send(LaneLogServerQuery::GetBlock(lane_id.clone(), n, tx))
            .await;
        if let Some(Some(block)) = rx.recv().await {
            let lane_entry = self
                .lane_blocks
                .entry(lane_id.clone())
                .or_insert_with(HashMap::new);
            lane_entry.entry(n).or_insert_with(|| StoredBlock {
                block: block.clone(),
                stats: AppendBlockStats {
                    view: block.block.view,
                    view_is_stable: block.block.view_is_stable,
                    config_num: block.block.config_num,
                    sender: lane_id.clone(),
                    ci: 0,
                    lane_id: lane_id.clone(),
                },
                acknowledgments: HashMap::new(),
                car: None,
                car_broadcasted: false,
            });
            return Some(block);
        }
        None
    }

    /// Fetch CAR from LaneLogServer if present
    #[allow(dead_code)]
    async fn get_car_from_logserver(&mut self, lane_id: &String, n: u64) -> Option<ProtoBlockCar> {
        use crate::utils::channel::make_channel;
        let (tx, rx) = make_channel(1);
        let _ = self
            .lane_logserver_query_tx
            .send(LaneLogServerQuery::GetCar(lane_id.clone(), n, tx))
            .await;
        rx.recv().await.flatten()
    }

    /// Queue a child CAR pending on its parent (lane_id, parent_n)
    fn add_pending_child(&mut self, parent_lane: &String, parent_n: u64, child: ProtoBlockCar) {
        self.pending_children_by_parent
            .entry((parent_lane.clone(), parent_n))
            .or_insert_with(Vec::new)
            .push(child);
    }

    /// After accepting CAR(lane_id, n), try to accept any pending children
    async fn process_pending_children(&mut self, lane_id: &String, n: u64) -> Result<(), ()> {
        if let Some(mut children) = self
            .pending_children_by_parent
            .remove(&(lane_id.clone(), n))
        {
            for child in children.drain(..) {
                // Re-run acceptance flow for child now that parent is available
                self.accept_car_after_parent_ready(child).await?;
            }
        }
        Ok(())
    }

    /// Accept a CAR assuming signatures were already validated earlier; focus on block/digest and persistence.
    async fn accept_car_after_parent_ready(&mut self, car: ProtoBlockCar) -> Result<(), ()> {
        let lane_id = car.origin_node.clone();

        // Ensure block exists
        if self.ensure_block_in_memory(&lane_id, car.n).await.is_none() {
            // Fallback to minimal backfill
            let last_index_needed = car.n.saturating_sub(100);
            self.request_lane_backfill_for_car(&lane_id, &lane_id, &car, last_index_needed)
                .await?;
        }

        // Digest check
        let digest_matches = if let Some(map) = self.lane_blocks.get(&lane_id) {
            if let Some(sb) = map.get(&car.n) {
                let expected: Vec<u8> = sb.block.block_hash.clone().try_into().unwrap_or_default();
                expected == car.digest
            } else {
                false
            }
        } else {
            false
        };
        if !digest_matches {
            return Ok(());
        }

        // Attach
        if let Some(map) = self.lane_blocks.get_mut(&lane_id) {
            if let Some(sb) = map.get_mut(&car.n) {
                sb.car = Some(car.clone());
            }
        }

        // Persist if missing
        {
            use crate::utils::channel::make_channel;
            let (tx, rx) = make_channel(1);
            self.lane_logserver_query_tx
                .send(LaneLogServerQuery::CheckCar(
                    lane_id.clone(),
                    car.n,
                    car.digest.clone(),
                    tx,
                ))
                .await
                .unwrap();
            if matches!(rx.recv().await.unwrap(), CheckCarResult::NotExists) {
                self.lane_logserver_tx
                    .send(LaneLogServerCommand::NewCar(lane_id.clone(), car.clone()))
                    .await
                    .unwrap();
            }
        }

        // Update tip cut (children will be processed by the caller that accepted the parent)
        self.update_tip_cut(lane_id.clone(), car.clone());
        Ok(())
    }

    /// Request lane backfill using the same AppendBlockLane-based NACK path as BlockReceiver.
    /// We ask the lane owner (sender_name) to send us blocks in [last_index_needed, car.n].
    async fn request_lane_backfill_for_car(
        &mut self,
        lane_id: &String,
        sender_name: &String,
        car: &ProtoBlockCar,
        last_index_needed: u64,
    ) -> Result<(), ()> {
        info!(
            "Requesting backfill for lane {} up to seq {} (start from {})",
            lane_id, car.n, last_index_needed
        );

        // Build a minimal AppendBlocks wrapper the responder can echo fields from.
        // We don't have the actual blocks here; we only set metadata.
        let ab = crate::proto::consensus::ProtoAppendBlocks {
            serialized_blocks: Vec::new(),
            commit_index: car.n,         // Request up to this seq
            view: car.view,              // Use the CAR's view as a hint
            view_is_stable: false,       // Unknown; not required for backfill
            config_num: self.config_num, // Best-effort
            is_backfill_response: false,
        };

        let abl = crate::proto::consensus::ProtoAppendBlockLane {
            name: lane_id.clone(),
            ab: Some(ab),
        };

        // Lane hints: include digests we know locally to allow responder to stop early.
        // Strategy: sample up to MAX_HINTS evenly across [last_index_needed, car.n] from our known ns,
        // always including the last known n within the range if present.
        const MAX_HINTS: usize = 128;
        let hints: Vec<ProtoBlockHint> = if let Some(lane_map) = self.lane_blocks.get(lane_id) {
            let mut ns: Vec<u64> = lane_map
                .keys()
                .cloned()
                .filter(|n| *n >= last_index_needed && *n <= car.n)
                .collect();
            if ns.is_empty() {
                Vec::new()
            } else {
                ns.sort_unstable();
                let len = ns.len();
                let step = std::cmp::max(1, len / MAX_HINTS);
                let mut sampled: Vec<u64> = ns
                    .iter()
                    .enumerate()
                    .filter_map(|(i, n)| if i % step == 0 { Some(*n) } else { None })
                    .collect();
                if let Some(&last_known) = ns.last() {
                    if sampled.last().copied() != Some(last_known) {
                        sampled.push(last_known);
                    }
                }

                sampled
                    .into_iter()
                    .filter_map(|n| lane_map.get(&n).map(|sb| (n, sb)))
                    .map(|(n, sb)| ProtoBlockHint {
                        block_n: n,
                        digest: sb.block.block_hash.clone(),
                    })
                    .collect()
            }
        } else {
            Vec::new()
        };

        let lane_hints = ProtoLaneBlockHints {
            name: lane_id.clone(),
            hints,
        };

        let nack = ProtoBackfillNack {
            origin: Some(proto_backfill_nack::Origin::Abl(abl)),
            hints: Some(proto_backfill_nack::Hints::Lane(lane_hints)),
            last_index_needed,
            reply_name: self.config.get().net_config.name.clone(),
        };

        let payload = ProtoPayload {
            message: Some(proto_payload::Message::BackfillNack(nack)),
        };
        let buf = payload.encode_to_vec();
        let sz = buf.len();

        // Send the backfill request to the lane owner (origin node)
        let _ = PinnedClient::send(
            &self.client,
            sender_name,
            MessageRef(&buf, sz, &SenderType::Anon),
        )
        .await;

        Ok(())
    }

    /// Calculate the threshold of acknowledgments needed to form CARs.
    fn car_threshold(&self) -> usize {
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

    /// Handle query from TipCutProposal or other components
    fn handle_query(&mut self, query: LaneStagingQuery) {
        match query {
            LaneStagingQuery::GetCurrentTipCut(reply_tx) => {
                let tip_cut = self.construct_tip_cut();
                let _ = reply_tx.send(tip_cut);
            }
        }
    }

    /// Construct the current tip cut by selecting the latest CAR from each lane.
    /// Returns None if no CARs are available yet.
    fn construct_tip_cut(&self) -> Option<TipCut> {
        let mut cars = HashMap::new();

        // For each lane, find the CAR with the highest sequence number
        for (lane_id, blocks) in &self.lane_blocks {
            let mut highest_seq = None;
            let mut highest_car = None;

            for (seq_num, stored_block) in blocks {
                if let Some(ref car) = stored_block.car {
                    if highest_seq.is_none() || *seq_num > highest_seq.unwrap() {
                        highest_seq = Some(*seq_num);
                        highest_car = Some(car.clone());
                    }
                }
            }

            // Add the highest CAR for this lane to the tip cut
            if let Some(car) = highest_car {
                cars.insert(lane_id.clone(), car);
            }
        }

        // Return None if we have no CARs yet
        if cars.is_empty() {
            return None;
        }

        Some(TipCut {
            cars,
            view: self.view,
            config_num: self.config_num,
        })
    }

    /// Update the current tip cut with a newly formed CAR.
    /// Called after we successfully form and broadcast a CAR.
    fn update_tip_cut(&mut self, lane_id: String, car: ProtoBlockCar) {
        self.current_tip_cut.cars.insert(lane_id, car);
        self.current_tip_cut.view = self.view;
        self.current_tip_cut.config_num = self.config_num;
    }
}
