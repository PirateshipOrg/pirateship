/// Tip Cut Sort Module
///
/// This module performs topological sorting on committed tip cuts to determine
/// a deterministic execution order for batches across lanes.
///
/// Architecture:
/// ```
/// Staging (tip cut committed)
///     ↓
/// TipCutSort (topological sort on DAG)
///     ↓
/// Application (execute in sorted order)
/// ```
///
/// Key Concepts:
/// - Tip cuts represent snapshots of the DAG (one CAR per lane)
/// - Between consecutive committed tip cuts, each lane may have 0+ new CARs
/// - CARs in the DAG have parent references forming a directed acyclic graph
/// - We perform deterministic topological sort to induce total order
/// - Batches are then executed in this deterministic order
///
/// Deterministic Sorting:
/// - Must produce same order on all replicas
/// - Uses lexicographic tiebreaking (lane name, then sequence number)
/// - Ensures safety and consistency across nodes
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
};

use log::{debug, error, info, trace, warn};
use tokio::sync::{oneshot, Mutex};

use crate::{
    config::AtomicConfig,
    crypto::{CachedBlock, HashType},
    proto::consensus::ProtoBlockCar,
    utils::channel::{Receiver, Sender},
};

use super::super::{
    dag::lane_logserver::LaneLogServerQuery,
};

/// Represents a block (batch) in the DAG that needs to be sorted
#[derive(Debug, Clone)]
pub struct DagBlock {
    /// Lane identifier (sender name)
    pub lane_id: String,

    /// Sequence number within the lane
    pub seq_num: u64,

    /// Block hash (for verification)
    pub block_hash: HashType,

    /// Parent block hash (for DAG structure)
    pub parent_hash: HashType,

    /// View and config when this block was created
    pub view: u64,
    pub config_num: u64,
}

impl DagBlock {
    /// Create a unique identifier for this block
    pub fn id(&self) -> String {
        format!("{}:{}", self.lane_id, self.seq_num)
    }

    /// Compare blocks for deterministic ordering (lexicographic)
    /// First by lane_id, then by seq_num
    pub fn cmp_deterministic(&self, other: &Self) -> std::cmp::Ordering {
        match self.lane_id.cmp(&other.lane_id) {
            std::cmp::Ordering::Equal => self.seq_num.cmp(&other.seq_num),
            other => other,
        }
    }
}

/// Represents a committed tip cut with its associated blocks
#[derive(Debug, Clone)]
pub struct CommittedTipCut {
    /// Tip cut sequence number (from consensus)
    pub tip_cut_n: u64,

    /// View when committed
    pub view: u64,

    /// CARs included in this tip cut (one per lane)
    /// Maps lane_id -> CAR
    pub cars: HashMap<String, ProtoBlockCar>,
}

/// Command messages for TipCutSort
pub enum TipCutSortCommand {
    /// Process a newly committed tip cut
    /// The sorter will extract blocks between this and previous tip cut,
    /// perform topological sort, and send to execution
    ProcessCommittedTipCut(CommittedTipCut),
}

/// TipCutSort performs topological sorting on committed tip cuts
/// to determine execution order of batches
pub struct TipCutSort {
    config: AtomicConfig,

    /// Last committed tip cut processed
    last_committed_tip_cut: Option<CommittedTipCut>,

    /// Input channel for committed tip cuts
    cmd_rx: Receiver<TipCutSortCommand>,

    /// Reference to Staging to add sorted blocks
    staging: Arc<Mutex<super::Staging>>,

    /// Query channel to lane logserver for fetching blocks
    lane_logserver_query_tx: Sender<LaneLogServerQuery>,
}

impl TipCutSort {
    pub fn new(
        config: AtomicConfig,
        cmd_rx: Receiver<TipCutSortCommand>,
        staging: Arc<Mutex<super::Staging>>,
        lane_logserver_query_tx: Sender<LaneLogServerQuery>,
    ) -> Self {
        Self {
            config,
            last_committed_tip_cut: None,
            cmd_rx,
            staging,
            lane_logserver_query_tx,
        }
    }

    pub async fn run(tip_cut_sort: Arc<Mutex<Self>>) {
        let mut tip_cut_sort = tip_cut_sort.lock().await;

        info!("TipCutSort worker starting");

        loop {
            if let Err(_) = tip_cut_sort.worker().await {
                break;
            }
        }

        info!("TipCutSort worker stopped");
    }

    async fn worker(&mut self) -> Result<(), ()> {
        let cmd = self.cmd_rx.recv().await;

        if cmd.is_none() {
            return Err(());
        }

        match cmd.unwrap() {
            TipCutSortCommand::ProcessCommittedTipCut(tip_cut) => {
                self.process_committed_tip_cut(tip_cut).await;
            }
        }

        Ok(())
    }

    /// Process a newly committed tip cut
    /// 1. Extract blocks between previous and current tip cut
    /// 2. Build DAG from parent references
    /// 3. Perform topological sort
    /// 4. Send sorted batches to application for execution
    async fn process_committed_tip_cut(&mut self, tip_cut: CommittedTipCut) {
        info!(
            "Processing committed tip cut {} with {} lanes",
            tip_cut.tip_cut_n,
            tip_cut.cars.len()
        );

        // Extract blocks from this tip cut
        let blocks = self.extract_blocks_from_tip_cut(&tip_cut);

        if blocks.is_empty() {
            debug!("No new blocks in tip cut {}", tip_cut.tip_cut_n);
            self.last_committed_tip_cut = Some(tip_cut);
            return;
        }

        info!(
            "Extracted {} blocks from tip cut {}",
            blocks.len(),
            tip_cut.tip_cut_n
        );

        // Build DAG structure
        let dag = self.build_dag(&blocks);

        // Perform deterministic topological sort
        let sorted_blocks = match self.topological_sort(&dag, &blocks) {
            Ok(sorted) => sorted,
            Err(e) => {
                error!(
                    "Failed to topologically sort tip cut {}: {}",
                    tip_cut.tip_cut_n, e
                );
                // Store tip cut anyway to maintain progress
                self.last_committed_tip_cut = Some(tip_cut);
                return;
            }
        };

        info!(
            "Topologically sorted {} blocks from tip cut {}",
            sorted_blocks.len(),
            tip_cut.tip_cut_n
        );

        // Fetch CachedBlocks from lane logserver in sorted order
        let mut cached_blocks = Vec::with_capacity(sorted_blocks.len());
        
        for (idx, block) in sorted_blocks.iter().enumerate() {
            debug!(
                "Fetching block {}/{}: lane={}, seq_num={}, hash={:?}",
                idx + 1,
                sorted_blocks.len(),
                block.lane_id,
                block.seq_num,
                &block.block_hash[..8]
            );

            // Query lane logserver for this block
            let (response_tx, response_rx) = oneshot::channel();
            let query = LaneLogServerQuery::GetBlock(
                block.lane_id.clone(),
                block.seq_num,
                response_tx,
            );

            if let Err(e) = self.lane_logserver_query_tx.send(query).await {
                error!(
                    "Failed to send GetBlock query for {}:{}: {:?}",
                    block.lane_id, block.seq_num, e
                );
                // Skip this tip cut and maintain progress
                self.last_committed_tip_cut = Some(tip_cut);
                return;
            }

            // Wait for response
            match response_rx.await {
                Ok(Some(cached_block)) => {
                    debug!(
                        "Successfully fetched block {}:{}",
                        block.lane_id, block.seq_num
                    );
                    cached_blocks.push(cached_block);
                }
                Ok(None) => {
                    warn!(
                        "Block {}:{} not found in lane logserver",
                        block.lane_id, block.seq_num
                    );
                    // Skip this tip cut - missing blocks indicate inconsistency
                    self.last_committed_tip_cut = Some(tip_cut);
                    return;
                }
                Err(e) => {
                    error!(
                        "Failed to receive GetBlock response for {}:{}: {:?}",
                        block.lane_id, block.seq_num, e
                    );
                    self.last_committed_tip_cut = Some(tip_cut);
                    return;
                }
            }
        }

        info!(
            "Fetched {} CachedBlocks for tip cut {} in sorted order",
            cached_blocks.len(),
            tip_cut.tip_cut_n
        );

        // Build mapping of block hash → origin node for proxy pattern
        // Each block in a lane inherits the origin_node from its lane's CAR
        #[cfg(feature = "dag")]
        let mut origin_map = std::collections::HashMap::new();
        
        #[cfg(feature = "dag")]
        for cached_block in &cached_blocks {
            // Find which lane this block belongs to by checking the CAR digests
            // The block's hash should match a CAR's digest in the tip cut
            for (lane_id, car) in &tip_cut.cars {
                // Check if this block could belong to this lane's CAR
                // In DAG mode, each lane has one CAR per tip cut, and the CAR
                // covers blocks up to sequence number car.n
                if cached_block.block_hash.as_ref() == car.digest.as_slice() {
                    // This block is the one certified by this CAR
                    origin_map.insert(
                        cached_block.block_hash.clone(),
                        car.origin_node.clone(),
                    );
                    break;
                }
            }
        }

        #[cfg(feature = "dag")]
        info!(
            "Built origin_map with {} entries for proxy pattern",
            origin_map.len()
        );

        // Call Staging directly to add sorted blocks and trigger Byzantine commit
        // This reuses all existing Byzantine commit logic from steady_state.rs
        let mut staging = self.staging.lock().await;
        
        #[cfg(feature = "dag")]
        staging.add_sorted_tipcut_blocks_with_origins(cached_blocks, origin_map).await;
        
        #[cfg(not(feature = "dag"))]
        staging.add_sorted_tipcut_blocks(cached_blocks).await;
        
        drop(staging);  // Release lock

        info!(
            "Added {} sorted blocks to Staging for tip cut {}",
            sorted_blocks.len(),
            tip_cut.tip_cut_n
        );

        // Update last processed tip cut
        self.last_committed_tip_cut = Some(tip_cut);
    }

    /// Extract blocks from a tip cut
    /// For each lane, extract blocks between previous tip cut and current tip cut
    fn extract_blocks_from_tip_cut(&self, tip_cut: &CommittedTipCut) -> Vec<DagBlock> {
        let mut blocks = Vec::new();

        // For each lane in the current tip cut
        for (lane_id, car) in &tip_cut.cars {
            // Determine the range of blocks to extract
            let start_seq = self.get_last_seq_for_lane(lane_id);
            let end_seq = car.n;

            // Extract blocks in range (start_seq, end_seq]
            for seq_num in (start_seq + 1)..=end_seq {
                // TODO: Fetch block metadata from lane logserver
                // For now, create placeholder blocks
                // In real implementation, we need:
                // - block_hash
                // - parent_hash
                // - view, config_num
                // from the lane logserver

                let block = DagBlock {
                    lane_id: lane_id.clone(),
                    seq_num,
                    block_hash: vec![0; 32],  // Placeholder
                    parent_hash: vec![0; 32], // Placeholder
                    view: tip_cut.view,
                    config_num: 0, // Placeholder
                };

                blocks.push(block);
            }
        }

        blocks
    }

    /// Get the last sequence number processed for a lane from previous tip cut
    fn get_last_seq_for_lane(&self, lane_id: &str) -> u64 {
        if let Some(last_tip_cut) = &self.last_committed_tip_cut {
            if let Some(car) = last_tip_cut.cars.get(lane_id) {
                return car.n;
            }
        }
        0
    }

    /// Build DAG structure from blocks
    /// Returns: (block_id -> children_ids, block_id -> DagBlock)
    fn build_dag(
        &self,
        blocks: &[DagBlock],
    ) -> (HashMap<String, Vec<String>>, HashMap<String, DagBlock>) {
        let mut children: HashMap<String, Vec<String>> = HashMap::new();
        let mut block_map: HashMap<String, DagBlock> = HashMap::new();

        // Build block map and initialize children lists
        for block in blocks {
            let block_id = block.id();
            block_map.insert(block_id.clone(), block.clone());
            children.insert(block_id, Vec::new());
        }

        // Build parent-child relationships
        // For each block, find its parent and add this block as a child
        for block in blocks {
            let block_id = block.id();

            // Find parent block by matching parent_hash
            // Parent could be in current blocks or in previous tip cut
            for potential_parent in blocks {
                if potential_parent.block_hash == block.parent_hash {
                    let parent_id = potential_parent.id();
                    children.get_mut(&parent_id).unwrap().push(block_id.clone());
                    break;
                }
            }

            // If parent not found in current blocks, it's in previous tip cut
            // This block has no parents in current set (frontier block)
        }

        (children, block_map)
    }

    /// Perform deterministic topological sort on the DAG
    /// Uses Kahn's algorithm with lexicographic tiebreaking for determinism
    ///
    /// Returns sorted list of blocks in execution order
    fn topological_sort(
        &self,
        dag: &(HashMap<String, Vec<String>>, HashMap<String, DagBlock>),
        blocks: &[DagBlock],
    ) -> Result<Vec<DagBlock>, String> {
        let (children, block_map) = dag;

        // Compute in-degree for each block
        let mut in_degree: HashMap<String, usize> = HashMap::new();
        for block in blocks {
            in_degree.insert(block.id(), 0);
        }

        for block in blocks {
            let block_id = block.id();
            if let Some(child_list) = children.get(&block_id) {
                for child_id in child_list {
                    *in_degree.get_mut(child_id).unwrap() += 1;
                }
            }
        }

        // Find all blocks with in-degree 0 (no dependencies)
        // These are frontier blocks (parents in previous tip cut)
        let mut ready_blocks: Vec<DagBlock> = blocks
            .iter()
            .filter(|b| *in_degree.get(&b.id()).unwrap() == 0)
            .cloned()
            .collect();

        // Sort ready blocks deterministically
        ready_blocks.sort_by(|a, b| a.cmp_deterministic(b));

        let mut sorted = Vec::new();
        let mut queue = VecDeque::from(ready_blocks);

        while let Some(block) = queue.pop_front() {
            sorted.push(block.clone());

            let block_id = block.id();

            // Process children
            if let Some(child_ids) = children.get(&block_id) {
                let mut newly_ready = Vec::new();

                for child_id in child_ids {
                    let degree = in_degree.get_mut(child_id).unwrap();
                    *degree -= 1;

                    if *degree == 0 {
                        // Child is now ready
                        if let Some(child_block) = block_map.get(child_id) {
                            newly_ready.push(child_block.clone());
                        }
                    }
                }

                // Sort newly ready blocks deterministically before adding to queue
                newly_ready.sort_by(|a, b| a.cmp_deterministic(b));
                queue.extend(newly_ready);
            }
        }

        // Check if all blocks were sorted (no cycles)
        if sorted.len() != blocks.len() {
            return Err(format!(
                "Cycle detected in DAG: sorted {} out of {} blocks",
                sorted.len(),
                blocks.len()
            ));
        }

        Ok(sorted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dag_block_deterministic_ordering() {
        let block1 = DagBlock {
            lane_id: "node1".to_string(),
            seq_num: 1,
            block_hash: vec![1],
            parent_hash: vec![0],
            view: 1,
            config_num: 1,
        };

        let block2 = DagBlock {
            lane_id: "node1".to_string(),
            seq_num: 2,
            block_hash: vec![2],
            parent_hash: vec![1],
            view: 1,
            config_num: 1,
        };

        let block3 = DagBlock {
            lane_id: "node2".to_string(),
            seq_num: 1,
            block_hash: vec![3],
            parent_hash: vec![0],
            view: 1,
            config_num: 1,
        };

        // Test ordering: node1 < node2 (lexicographic)
        assert_eq!(block1.cmp_deterministic(&block3), std::cmp::Ordering::Less);

        // Test ordering: seq_num 1 < seq_num 2 (same lane)
        assert_eq!(block1.cmp_deterministic(&block2), std::cmp::Ordering::Less);
    }

    #[test]
    fn test_build_simple_dag() {
        // Create a simple linear DAG: block1 -> block2 -> block3
        let block1 = DagBlock {
            lane_id: "node1".to_string(),
            seq_num: 1,
            block_hash: vec![1],
            parent_hash: vec![0],
            view: 1,
            config_num: 1,
        };

        let block2 = DagBlock {
            lane_id: "node1".to_string(),
            seq_num: 2,
            block_hash: vec![2],
            parent_hash: vec![1], // Parent is block1
            view: 1,
            config_num: 1,
        };

        let block3 = DagBlock {
            lane_id: "node1".to_string(),
            seq_num: 3,
            block_hash: vec![3],
            parent_hash: vec![2], // Parent is block2
            view: 1,
            config_num: 1,
        };

        let blocks = vec![block1.clone(), block2.clone(), block3.clone()];

        // Build DAG (this would be in TipCutSort)
        let mut children: HashMap<String, Vec<String>> = HashMap::new();
        let mut block_map: HashMap<String, DagBlock> = HashMap::new();

        for block in &blocks {
            let block_id = block.id();
            block_map.insert(block_id.clone(), block.clone());
            children.insert(block_id, Vec::new());
        }

        for block in &blocks {
            let block_id = block.id();
            for potential_parent in &blocks {
                if potential_parent.block_hash == block.parent_hash {
                    let parent_id = potential_parent.id();
                    children.get_mut(&parent_id).unwrap().push(block_id.clone());
                    break;
                }
            }
        }

        // Check structure
        assert_eq!(children.get(&block1.id()).unwrap(), &vec![block2.id()]);
        assert_eq!(children.get(&block2.id()).unwrap(), &vec![block3.id()]);
        assert_eq!(children.get(&block3.id()).unwrap().len(), 0);
    }
}
