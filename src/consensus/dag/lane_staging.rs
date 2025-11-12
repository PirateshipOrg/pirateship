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
use std::{collections::HashMap, sync::Arc};

use ed25519_dalek::SIGNATURE_LENGTH;
use log::{debug, error, info, trace, warn};
use prost::Message;
use tokio::sync::{oneshot, Mutex};

use crate::{
    config::AtomicConfig,
    crypto::{CachedBlock, CryptoServiceConnector},
    proto::{
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
    super::{app::AppCommand, client_reply::ClientReplyCommand},
    block_receiver::AppendBlockStats,
    lane_logserver::LaneLogServerCommand,
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
    client_reply_tx: Sender<ClientReplyCommand>,
    app_tx: Sender<AppCommand>,
    lane_logserver_tx: Sender<LaneLogServerCommand>,
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
        app_tx: Sender<AppCommand>,
        lane_logserver_tx: Sender<LaneLogServerCommand>,
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
            app_tx,
            lane_logserver_tx,
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
                    .send(LaneLogServerCommand::NewBlock(lane_id.clone(), block.clone()))
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

    /// Send BlockAck message to all nodes after successfully storing a block.
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

        debug!(
            "Sending BlockAck for n={} in lane {} to all nodes",
            block.block.n, lane_id
        );

        // Encode payload
        let payload = ProtoPayload {
            message: Some(proto_payload::Message::BlockAck(block_ack.clone())),
        };
        let buf = payload.encode_to_vec();
        let sz = buf.len();

        // Broadcast to all nodes (except self)
        for node in &config.consensus_config.node_list {
            if node == my_name {
                continue; // Don't send to self
            }

            let _ = PinnedClient::send(&self.client, node, MessageRef(&buf, sz, &SenderType::Anon))
                .await;
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
            self.liveness_threshold()
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
            let threshold = self.liveness_threshold();
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
            origin_node: my_name,  // Track which node accepted the client requests
        };

        // Store the CAR
        if let Some(lane) = self.lane_blocks.get_mut(lane_id) {
            if let Some(stored_block) = lane.get_mut(&seq_num) {
                stored_block.car = Some(car.clone());
            }
        }

        // Broadcast the CAR to all nodes
        self.broadcast_car(car.clone()).await?;

        // Mark as broadcasted
        if let Some(lane) = self.lane_blocks.get_mut(lane_id) {
            if let Some(stored_block) = lane.get_mut(&seq_num) {
                stored_block.car_broadcasted = true;
            }
        }

        // Update the current tip cut with this new CAR
        self.update_tip_cut(lane_id.clone(), car);

        info!(
            "Block n={} in lane {} is now stable with CAR",
            seq_num, lane_id
        );

        Ok(())
    }

    /// Broadcast a formed CAR to all nodes.
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
    /// Validate the CAR and update the tip cut state if valid.
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

        // Verify signature threshold
        let threshold = self.liveness_threshold();
        if car.sig.len() < threshold {
            warn!(
                "Received CAR with insufficient signatures ({} < {}) - rejecting",
                car.sig.len(),
                threshold
            );
            return Ok(());
        }

        // TODO: Verify signatures are valid (crypto verification)
        // For now, we trust authenticated senders

        // TODO: Verify parent references match expected DAG structure
        // This would require querying LaneLogServer for parent blocks

        // TODO: Check sequence number is reasonable (not too far in future)
        // This prevents memory exhaustion attacks

        info!(
            "Accepting remote CAR from {} for lane {} seq {} with {} signatures",
            sender_name,
            lane_id,
            car.n,
            car.sig.len()
        );

        // Update tip cut with this remote CAR
        self.update_tip_cut(lane_id.clone(), car);

        Ok(())
    }

    /// Calculate the liveness threshold for acknowledgments and CARs.
    /// Must match BlockReceiver's threshold calculation.
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
