use std::collections::HashMap;

use crate::{
    crypto::{default_hash, hash_proto_block_ser},
    proto::consensus::{ProtoFork, ProtoViewChange},
    rpc::SenderType,
    utils::get_parent_hash_in_proto_block_ser,
};

use super::{view_change::ForkStat, Staging};

impl Staging {
    pub(super) async fn vc_to_stats(
        &mut self,
        forks: &HashMap<SenderType, ProtoViewChange>,
    ) -> HashMap<SenderType, ForkStat> {
        let mut fork_stats = HashMap::new();
        for (sender, vc) in forks {
            let fork_len = vc.fork.as_ref().unwrap().serialized_blocks.len();
            let mut block_hashes = Vec::with_capacity(fork_len);
            if fork_len > 0 {
                // Instead of calculating the hashes again, we can just use the parent relations.
                // Just need to compute the last hash.
                let last_hash = hash_proto_block_ser(
                    &vc.fork
                        .as_ref()
                        .unwrap()
                        .serialized_blocks
                        .last()
                        .unwrap()
                        .serialized_body,
                );
                for i in 1..fork_len {
                    block_hashes.push(
                        get_parent_hash_in_proto_block_ser(
                            &vc.fork.as_ref().unwrap().serialized_blocks[i].serialized_body,
                        )
                        .unwrap(),
                    );
                }
                block_hashes.push(last_hash);
            }

            let (last_view, last_config_num, last_n) = vc
                .fork
                .as_ref()
                .unwrap()
                .serialized_blocks
                .last()
                .map_or((0, 0, 0), |b| (b.view, b.config_num, b.n));

            fork_stats.insert(
                sender.clone(),
                ForkStat {
                    fork_last_n: last_n,
                    block_hashes,
                    first_n: vc
                        .fork
                        .as_ref()
                        .unwrap()
                        .serialized_blocks
                        .first()
                        .map_or(0, |b| b.n),
                    first_parent: vc.fork.as_ref().unwrap().serialized_blocks.first().map_or(
                        default_hash(),
                        |b| {
                            get_parent_hash_in_proto_block_ser(&b.serialized_body)
                                .unwrap_or(default_hash())
                        },
                    ),
                    last_qc: vc.fork_last_qc.clone(),
                    last_view,
                    last_config_num,
                },
            );
        }

        fork_stats
    }
    pub(super) async fn fork_choice_filter_from_forks(
        &mut self,
        forks: &HashMap<SenderType, ProtoViewChange>,
        fork_stats: &mut HashMap<SenderType, ForkStat>,
    ) -> Vec<ProtoViewChange> {
        let fast_path_threshold = self.fast_path_selection_threshold();

        let applicable_senders = Self::fork_choice_filter(fork_stats, fast_path_threshold).await;

        applicable_senders
            .iter()
            .map(|s| {
                let vc = forks.get(s).unwrap();
                vc.clone()
            })
            .collect()
    }

    fn fast_path_selection_threshold(&self) -> usize {
        (self.config.get().consensus_config.liveness_u + 1) as usize
    }

    pub async fn fork_choice_filter(
        fork_stats: &mut HashMap<SenderType, ForkStat>,
        fast_path_threshold: usize,
    ) -> Vec<SenderType> {
        Self::fork_choice_filter_highest_qc_view(fork_stats);

        #[cfg(feature = "fast_path")]
        Self::fork_choice_filter_fast_path(fork_stats, fast_path_threshold);

        Self::fork_choice_filter_highest_view(fork_stats);

        Self::fork_choice_filter_highest_len(fork_stats);

        fork_stats.keys().map(|s| s.clone()).collect()
    }

    fn fork_choice_filter_highest_qc_view(fork_stats: &mut HashMap<SenderType, ForkStat>) {
        // Rule 1: Highest stable view => Highest view in last qcs.
        let highest_qc_view = fork_stats
            .iter()
            .map(|(_, f)| f.last_qc.as_ref().map_or(0, |qc| qc.view))
            .max()
            .unwrap_or(0);

        fork_stats.retain(|_, f| {
            if highest_qc_view == 0 {
                return true;
            }
            f.last_qc
                .as_ref()
                .map_or(false, |qc| qc.view == highest_qc_view)
        });
    }

    /// Take the highest QC.n (since this is called after subrule1, highest QC from each fork will be of the highest possible view)
    /// See if |forks sharing that QC| >= u + 1, otherwise, nobody could've gone fast path.
    /// For all positions after the highest QC.n
    ///     See if one block has support of >= (u + 1) forks,
    ///     but doesn't conflict with another block that has >= (u + 1) forks
    /// Take the fork for which this signed block is the highest.
    /// (There should be at least (u + 1) that match this.)
    /// Drop everything else.
    fn fork_choice_filter_fast_path(
        fork_stats: &mut HashMap<SenderType, ForkStat>,
        fast_path_threshold: usize,
    ) {
        let highest_qc_n = fork_stats
            .iter()
            .map(|(_, f)| f.last_qc.as_ref().map_or(0, |qc| qc.n))
            .max()
            .unwrap_or(0);
        let highest_qc_n_matching_forks = fork_stats
            .iter()
            .filter(|(_, f)| f.last_qc.as_ref().map_or(false, |qc| qc.n == highest_qc_n))
            .count();

        if highest_qc_n_matching_forks < fast_path_threshold {
            // Nobody could've gone fast path.
            return;
        }

        let mut highest_fast_path_committed_forks = HashMap::new();

        for (sender, stat) in fork_stats.iter() {
            let fork_len = stat.block_hashes.len();
            for i in 0..fork_len {
                let block_n = stat.first_n + i as u64;
                let my_block_hash = &stat.block_hashes[i];

                let mut support = 0; // Number of forks that support this block.
                let mut anti_support = HashMap::new(); // Block hashes at the same index, but different from this one.
                for (_, other_stat) in fork_stats.iter() {
                    // Find a block with the same seq num in this fork.
                    if other_stat.first_n > block_n {
                        continue;
                    }
                    if other_stat.fork_last_n <= block_n {
                        continue;
                    }
                    let idx = block_n - other_stat.first_n;

                    let other_block_hash = &other_stat.block_hashes[idx as usize];

                    if other_block_hash.eq(my_block_hash) {
                        support += 1;
                    } else {
                        // Must be part of anti-support.
                        if let Some(count) = anti_support.get_mut(other_block_hash) {
                            *count += 1;
                        } else {
                            anti_support.insert(other_block_hash.clone(), 1);
                        }
                    }
                }

                if support >= fast_path_threshold
                    && anti_support.values().map(|v| *v).max().unwrap_or(0) < fast_path_threshold
                {
                    // This COULD have gone fast path.
                    highest_fast_path_committed_forks.insert(sender.clone(), block_n);
                }
            }
        }

        let max_fast_path_committed_index = highest_fast_path_committed_forks
            .values()
            .map(|v| *v)
            .max()
            .unwrap_or(0);
        let applicable_senders = highest_fast_path_committed_forks
            .iter()
            .filter(|(_, v)| **v >= max_fast_path_committed_index)
            .map(|(s, _)| s.clone())
            .collect::<Vec<SenderType>>();

        fork_stats.retain(|s, _| applicable_senders.contains(s));
    }

    fn fork_choice_filter_highest_view(fork_stats: &mut HashMap<SenderType, ForkStat>) {
        let highest_view = fork_stats
            .iter()
            .map(|(_, f)| f.last_view)
            .max()
            .unwrap_or(0);

        fork_stats.retain(|_, f| f.last_view == highest_view);
    }

    fn fork_choice_filter_highest_len(fork_stats: &mut HashMap<SenderType, ForkStat>) {
        let highest_len = fork_stats
            .iter()
            .map(|(_, f)| f.fork_last_n)
            .max()
            .unwrap_or(0);

        fork_stats.retain(|_, f| f.fork_last_n == highest_len);
    }
}
