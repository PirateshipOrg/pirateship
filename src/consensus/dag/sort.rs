//! DAG Tip Cut sorting utilities
//!
//! Given a committed tip cut (as a map of lane_id -> ProtoBlockCar) and the last
//! processed sequence per lane, fetch the newly committed blocks, perform a
//! deterministic topological sort across lanes, and return:
//! - the sorted list of `CachedBlock`s to execute,
//! - an origin map: block_hash -> origin_node (from that lane's CAR), needed for proxying.
//!
//! Notes:
//! - This module is only relevant in DAG mode.
//! - Origin information is always included and required by callers on both crash and byzantine paths.
//! - The fetch function is supplied by the caller to avoid coupling to LaneLogServer here.

#![cfg(feature = "dag")]

use std::collections::{HashMap, VecDeque};
use std::future::Future;

use crate::{
    crypto::{CachedBlock, HashType},
    proto::consensus::ProtoBlockCar,
};

/// Error types for tip cut sorting/fetching
#[derive(Debug)]
pub enum TipCutSortError {
    /// A required block was not found during fetch
    MissingBlock { lane: String, seq: u64 },
    /// A cycle was detected while sorting (should not happen if parents only refer backward)
    Cycle { sorted: usize, total: usize },
}

/// Fetch and sort all newly committed blocks for a tip cut.
///
/// Inputs:
/// - cars: lane_id -> CAR for this tip cut
/// - last_lane_seq: lane_id -> last committed seq from previous tip cut (0 if none)
/// - fetch: async function to fetch a specific block by (lane, seq)
///
/// Output:
/// - (sorted_blocks, origin_map) where origin_map maps each block_hash to the lane's origin_node
pub async fn fetch_and_sort_tipcut_blocks<F, Fut>(
    cars: &HashMap<String, ProtoBlockCar>,
    last_lane_seq: &HashMap<String, u64>,
    mut fetch: F,
) -> Result<(Vec<CachedBlock>, HashMap<HashType, String>), TipCutSortError>
where
    F: FnMut(&str, u64) -> Fut,
    Fut: Future<Output = Option<CachedBlock>>,
{
    // 1) Fetch all new blocks for each lane
    // Also build a per-lane origin mapping from CARs
    // Keep (block, lane_id) pairs to enable deterministic tie-breaking by lane then seq
    let mut blocks: Vec<(CachedBlock, String)> = Vec::new();
    let mut origin_map: HashMap<HashType, String> = HashMap::new();

    for (lane_id, car) in cars {
        let start_seq = *last_lane_seq.get(lane_id.as_str()).unwrap_or(&0);
        if car.n <= start_seq {
            continue; // no new blocks for this lane
        }

        // Fetch blocks in (start_seq, car.n]
        for seq in (start_seq + 1)..=car.n {
            match fetch(lane_id.as_str(), seq).await {
                Some(cb) => {
                    // Origin for all blocks of this lane is the CAR's origin_node
                    origin_map
                        .entry(cb.block_hash.clone())
                        .or_insert_with(|| car.origin_node.clone());
                    blocks.push((cb, lane_id.clone()));
                }
                None => {
                    return Err(TipCutSortError::MissingBlock {
                        lane: lane_id.clone(),
                        seq,
                    });
                }
            }
        }
    }

    if blocks.is_empty() {
        return Ok((Vec::new(), origin_map));
    }

    // 2) Topological sort with deterministic tie-breaking (lane_id, seq)
    let sorted = topo_sort_blocks(blocks)?;

    // 3) Ensure every returned block has an origin mapping
    // (some implementations could choose to map only CAR-certified hashes; ensure all are covered)
    for cb in &sorted {
        origin_map
            .entry(cb.block_hash.clone())
            .or_insert_with(String::new);
    }

    Ok((sorted, origin_map))
}

/// Deterministic topological sort using block parent hashes to form edges.
fn topo_sort_blocks(
    blocks_with_lane: Vec<(CachedBlock, String)>,
) -> Result<Vec<CachedBlock>, TipCutSortError> {
    // Split for convenience
    let blocks: Vec<CachedBlock> = blocks_with_lane.iter().map(|(b, _)| b.clone()).collect();
    let lanes: Vec<String> = blocks_with_lane.iter().map(|(_, l)| l.clone()).collect();

    // Map hash -> index for quick parent lookups
    let mut hash_to_idx: HashMap<&[u8], usize> = HashMap::with_capacity(blocks.len());
    for (i, b) in blocks.iter().enumerate() {
        hash_to_idx.insert(b.block_hash.as_slice(), i);
    }

    // Build adjacency and in-degrees
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); blocks.len()];
    let mut indegree: Vec<usize> = vec![0; blocks.len()];

    for (i, b) in blocks.iter().enumerate() {
        if let Some(&p_idx) = hash_to_idx.get(b.block.parent.as_slice()) {
            children[p_idx].push(i);
            indegree[i] += 1;
        }
    }

    // Ready queue: indices with indegree 0
    let mut ready: Vec<usize> = indegree
        .iter()
        .enumerate()
        .filter(|(_, &d)| d == 0)
        .map(|(i, _)| i)
        .collect();

    // Deterministic tie-breaker: (lane_id, seq)
    ready.sort_by(|&i, &j| {
        cmp_block_keys(&lanes[i], blocks[i].block.n, &lanes[j], blocks[j].block.n)
    });

    let mut out: Vec<CachedBlock> = Vec::with_capacity(blocks.len());
    let mut q: VecDeque<usize> = VecDeque::from(ready);

    while let Some(i) = q.pop_front() {
        out.push(blocks[i].clone());

        // Collect children that become ready
        let mut newly_ready: Vec<usize> = Vec::new();
        for &c in &children[i] {
            indegree[c] -= 1;
            if indegree[c] == 0 {
                newly_ready.push(c);
            }
        }
        newly_ready.sort_by(|&a, &b| {
            cmp_block_keys(&lanes[a], blocks[a].block.n, &lanes[b], blocks[b].block.n)
        });
        for idx in newly_ready {
            q.push_back(idx);
        }
    }

    if out.len() != blocks.len() {
        return Err(TipCutSortError::Cycle {
            sorted: out.len(),
            total: blocks.len(),
        });
    }

    Ok(out)
}

#[inline]
fn cmp_block_keys(a_lane: &str, a_n: u64, b_lane: &str, b_n: u64) -> std::cmp::Ordering {
    match a_lane.cmp(b_lane) {
        std::cmp::Ordering::Equal => a_n.cmp(&b_n),
        other => other,
    }
}
