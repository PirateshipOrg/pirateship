use std::{collections::HashMap, sync::atomic::fence};

use log::{info, trace, warn};
use prost::Message as _;

use crate::{
    consensus::{
        block_broadcaster::BlockBroadcasterCommand, block_sequencer::BlockSequencerControlCommand, client_reply::ClientReplyCommand, fork_receiver::ForkReceiverCommand, pacemaker::PacemakerCommand
    }, crypto::{default_hash, HashType}, proto::{consensus::{HalfSerializedBlock, ProtoFork, ProtoForkValidation, ProtoQuorumCertificate, ProtoViewChange}, rpc::ProtoPayload}, rpc::{client::PinnedClient, server::LatencyProfile, PinnedMessage, SenderType}, utils::get_parent_hash_in_proto_block_ser
};

use super::Staging;

#[derive(Clone, Debug)]
pub struct ForkStat {
    pub block_hashes: Vec<HashType>,
    pub fork_last_n: u64,
    pub first_n: u64,
    pub first_parent: HashType,
    pub last_qc: Option<ProtoQuorumCertificate>,
    pub last_view: u64,
    pub last_config_num: u64,
}


impl Staging {
    pub(super) async fn process_view_change_message(
        &mut self,
        cmd: PacemakerCommand,
    ) -> Result<(), ()> {
        match cmd {
            PacemakerCommand::UpdateView(view_num, config_num) => {
                self.maybe_update_view(view_num, config_num).await;
            }
            PacemakerCommand::NewViewForks(view_num, config_num, forks) => {
                self.propose_new_view(view_num, config_num, forks).await;
            }
            _ => {
                unreachable!("Invalid message from pacemaker");
            }
        }
        Ok(())
    }

    pub(super) async fn maybe_update_view(&mut self, view_num: u64, config_num: u64) {
        if self.view >= view_num {
            return;
        }

        self.update_view(view_num, config_num).await;
    }

    pub(super) async fn update_view(&mut self, view_num: u64, config_num: u64) {
        self.view = view_num;
        self.config_num = config_num;
        self.view_is_stable = false;

        let vc_msg = self.create_my_vc_msg().await;
        trace!("VC Msg: {:?}", vc_msg);

        let (payload, vc_msg) = { // Jumping through hoops to avoid cloning.
            let payload = ProtoPayload {
                message: Some(crate::proto::rpc::proto_payload::Message::ViewChange(vc_msg)),
            };
            let buf = payload.encode_to_vec();
            let sz = buf.len();
            let msg = PinnedMessage::from(buf, sz, SenderType::Anon);

            if let Some(crate::proto::rpc::proto_payload::Message::ViewChange(vc_msg)) = payload.message {
                (msg, vc_msg)
            } else {
                unreachable!();
            }
        };

        
        // Memory fence to prevent reordering.
        fence(std::sync::atomic::Ordering::SeqCst);
        // Once the signal to update view is sent,
        // all blocks that are already in the queue must be dropped by staging.
        // To guarantee this, even in the face of compiler optimizations,
        // we must ensure that the view update signal is sent after the fence.
        // (I realize there is already a data dependency here, so may not be necessary :-))


        // Send the signal to everywhere
        self.block_sequencer_command_tx
            .send(BlockSequencerControlCommand::NewUnstableView(
                self.view,
                self.config_num,
            ))
            .await
            .unwrap();

        let current_leader = self.config.get().consensus_config.get_leader_for_view(self.view);
        self.batch_proposer_command_tx.send((false, current_leader)).await.unwrap();
        self.client_reply_tx.send(ClientReplyCommand::CancelAllRequests).await.unwrap();
        self.fork_receiver_command_tx
            .send(ForkReceiverCommand::UpdateView(self.view, self.config_num))
            .await
            .unwrap();
        self.pacemaker_tx
            .send(PacemakerCommand::MyViewJumped(self.view, self.config_num, vc_msg))
            .await
            .unwrap();
        self.__ae_seen_in_this_view = 0;


        // Broadcast the view change message
        let bcast_names = self.get_everyone_except_me();
        let _ = PinnedClient::broadcast(
            &self.client, &bcast_names, 
            &payload, &mut LatencyProfile::new(),
            self.byzantine_liveness_threshold() - 1
        ).await;
        

    }

    async fn propose_new_view(
        &mut self,
        view_num: u64,
        config_num: u64,
        mut forks: HashMap<SenderType, ProtoViewChange>,
    ) {

        // With view_is_stable == false, the sequencer will not produce any new blocks.
        // The staging `process_block_as_leader/follower` will reject all blocks in the queue,
        // until it is completely drained.
        // The next block must come from sending NewViewMessage to the sequencer.

        if view_num != self.view || config_num != self.config_num {
            return;
        }

        if self.view_is_stable || !self.i_am_leader() {
            return;
        }

        
        // Choose a fork to propose.
        let (chosen_fork, fork_validation) = self.apply_fork_choice_rule(&mut forks).await;

        let retain_n = self.check_byz_commit_invariant(&chosen_fork)
            .expect("Invariant <ByzCommit> violated");

        // Clean up pending_blocks
        self.pending_blocks.retain(|b| b.block.block.n <= retain_n);
        if self.ci > retain_n {
            self.ci = retain_n;
            // Signal rollback.
            self.app_tx.send(crate::consensus::app::AppCommand::Rollback(self.ci)).await.unwrap();
        }

        // Send the chosen fork to sequencer.
        let new_last_n = chosen_fork.fork_last_n;
        let new_parent_hash = if chosen_fork.block_hashes.len() > 0 { 
            chosen_fork.block_hashes[chosen_fork.block_hashes.len() - 1].clone()
        } else if self.pending_blocks.len() > 0 { 
            self.pending_blocks.back().unwrap().block.block_hash.clone()
        } else if self.curr_parent_for_pending.is_some() {
            self.curr_parent_for_pending.as_ref().unwrap().block_hash.clone()
        } else {
            default_hash()
        };
        self.block_sequencer_command_tx.send(
            BlockSequencerControlCommand::NewViewMessage(self.view, self.config_num, fork_validation, new_parent_hash, new_last_n)
        ).await.unwrap();
        // This + signal to BlockBroadcaster about chosen fork means that the blocks will be fed back in with the NewView AE.

    }

    pub(super) async fn maybe_stabilize_view(&mut self, qc: &ProtoQuorumCertificate) {
        // The new view message must be the VERY LAST block in pending now.
        // The QC present here must on that last block.
        // let last_n = self.pending_blocks.back().as_ref().unwrap().block.block.n;
        // if qc.n < last_n {
        //     info!("Fail 1");
        //     return;
        // }

        if qc.view != self.view {
            return;
        }

        // If the QC is on the last block, we can now stabilize the view.
        self.view_is_stable = true;

        // Send the signal to sequencer to produce new blocks.
        self.block_sequencer_command_tx
            .send(BlockSequencerControlCommand::ViewStabilised(
                self.view,
                self.config_num,
            ))
            .await
            .unwrap();

        let current_leader = self.config.get().consensus_config.get_leader_for_view(self.view);
        if self.i_am_leader() {
            self.batch_proposer_command_tx.send((true, current_leader)).await.unwrap();
        } else {
            self.batch_proposer_command_tx.send((false, current_leader)).await.unwrap();
        }

        info!("View {} stabilized", self.view);

        self.client_reply_tx.send(ClientReplyCommand::StopCancelling).await.unwrap();
    }

    async fn create_my_vc_msg(&mut self) -> ProtoViewChange {
        // We will send everything from pending_blocks and the curr parent.
        // ie self.bci onwards
        let mut my_fork = if self.curr_parent_for_pending.is_some() {
            let _parent = self.curr_parent_for_pending.as_ref().unwrap();
            let half_serialized_block = HalfSerializedBlock {
                n: _parent.block.n,
                view: _parent.block.view,
                view_is_stable: _parent.block.view_is_stable,
                config_num: _parent.block.config_num,
                serialized_body: _parent.block_ser.clone(),
            };
            ProtoFork {
                serialized_blocks: vec![half_serialized_block]
            }
        } else {
            ProtoFork {
                serialized_blocks: Vec::new()
            }
        };

        my_fork.serialized_blocks.extend(self
            .pending_blocks
            .iter()
            .map(|b| HalfSerializedBlock {
                n: b.block.block.n,
                view: b.block.block.view,
                view_is_stable: b.block.block.view_is_stable,
                config_num: b.block.block.config_num,
                serialized_body: b.block.block_ser.clone(),
            }));

        // Fork sig will be the sig on the hash of the last block.
        let fork_last_n = if self.pending_blocks.len() > 0 {
            self.pending_blocks.back().unwrap().block.block.n
        } else if self.curr_parent_for_pending.is_some() {
            self.curr_parent_for_pending.as_ref().unwrap().block.n
        } else {
            0
        };

        let vc = ProtoViewChange {
            view: self.view,
            config_num: self.config_num,
            fork: Some(my_fork),
            fork_sig: vec![],
            fork_last_n,
            fork_last_qc: self.last_qc.clone(),
        };

        let vc = self.crypto.prepare_vc(vc).await;

        vc

    }

    fn get_everyone_except_me(&self) -> Vec<String> {
        let my_name = &self.config.get().net_config.name;
        self.config.get().consensus_config.node_list
            .iter().filter(|name| !((*name).eq(my_name)))
            .map(|name| name.clone())
            .collect()
    }


    /// Advance the bci from all the forks received.
    /// Returns the stats from the chosen fork (as ForkStats) that the leader is supposed to install.
    /// Also returns the validation messages that the leader must send to the followers.
    async fn apply_fork_choice_rule(&mut self, forks: &mut HashMap<SenderType, ProtoViewChange>) -> (ForkStat, Vec<ProtoForkValidation>) {
        let mut fork_stats = self.vc_to_stats(forks).await;

        let fork_validation = self.stats_to_validation(&fork_stats, forks);

        let mut applicable_forks = self.fork_choice_filter_from_forks(forks, &mut fork_stats).await;
        assert!(applicable_forks.len() > 0);
        let chosen_fork = applicable_forks.remove(0);
        let chosen_fork_stat = self.send_blocks_to_broadcaster_and_get_stats(chosen_fork).await;

        (chosen_fork_stat, fork_validation)
    }

    fn stats_to_validation(&self, fork_stats: &HashMap<SenderType, ForkStat>, vc: &HashMap<SenderType, ProtoViewChange>) -> Vec<ProtoForkValidation> {
        fork_stats.iter().map(|(sender, stat)| {
            let (vc_view, vc_config_num, vc_sig) = vc.get(sender).map(|e| (e.view, e.config_num, e.fork_sig.clone())).unwrap();
            let (sender, _) = sender.to_name_and_sub_id();
            ProtoForkValidation {
                vc_view,
                vc_config_num,
                block_hashes: stat.block_hashes.clone(),
                fork_last_n: stat.fork_last_n,
                fork_last_qc: stat.last_qc.clone(),
                fork_last_view: stat.last_view,
                fork_last_config_num: stat.last_config_num,
                vc_sig,
                sender,
            }
        }).collect()
    }

    async fn send_blocks_to_broadcaster_and_get_stats(&mut self, vc: ProtoViewChange) -> ForkStat {
        let fork = vc.fork.as_ref().unwrap();
        let block_and_hash_futs = self.crypto.prepare_for_rebroadcast(fork.serialized_blocks.clone(), self.byzantine_liveness_threshold()).await;
        
        let (block_futs, hash_futs) = block_and_hash_futs.into_iter().collect::<(Vec<_>, Vec<_>)>();
        
        self.block_broadcaster_command_tx.send(
            BlockBroadcasterCommand::NextAEForkPrefix(block_futs)
        ).await.unwrap();

        let mut block_hashes = Vec::new();
        for hash_fut in hash_futs {
            // Since Pacemaker is supposed to verify all these blocks before sending them here, unwrap is safe.
            block_hashes.push(hash_fut.await.unwrap().unwrap());
        }

        let (first_n, first_parent) = if fork.serialized_blocks.len() > 0 {
            let first_block = &fork.serialized_blocks[0];
            (first_block.n, get_parent_hash_in_proto_block_ser(&first_block.serialized_body).unwrap())
        } else {
            (0, default_hash())
        };

        let (last_view, last_config_num, last_n) = fork.serialized_blocks.last().map_or((0, 0, 0), |b| (b.view, b.config_num, b.n));

        ForkStat {
            fork_last_n: last_n,
            block_hashes,
            first_n,
            first_parent,
            last_qc: vc.fork_last_qc.clone(),  
            last_view,
            last_config_num,    
        }
    }


    /// Invariant <ByzCommit>:
    /// Remember that pending_blocks.first() is the first block that's not byz committed.
    /// So it's parent must be byz committed. Let's call it `curr_parent`.
    /// This leaves with 2 cases:
    /// - Chosen fork starts with some seq num n <= bci, then `curr_parent` must be part of the fork.
    /// - Chosen fork starts with some seq num n > bci, then the parent of the first block must be either in pending_blocks or be `curr_parent`.
    /// (To ensure this, the pacemaker must have Nacked until there was a fork history match).
    /// On success, returns the max seq num to retain in pending_blocks.
    fn check_byz_commit_invariant(&self, chosen_fork: &ForkStat) -> Result<u64, ()> {
        if self.bci == 0 {
            // Nothing to do here.
            warn!("Case 0");
            return Ok(0);
        }

        let curr_parent = self.curr_parent_for_pending.as_ref().unwrap();

        if chosen_fork.fork_last_n == 0 {
            // Retain everything in pending_blocks.
            let last_n = self.pending_blocks.back().map_or(self.bci, |b| b.block.block.n);
            warn!("Case 0.1");
            return Ok(last_n);
        }

        if chosen_fork.first_n <= self.bci {
            // 1st case
            if !chosen_fork.block_hashes.iter().any(|h| h.eq(&curr_parent.block_hash)) {
                return Err(());
            } else {
                // Wipe everything from pending_blocks.
                warn!("Case 1");
                return Ok(self.bci);
            }
        } else {
            let parent_hash = &chosen_fork.first_parent;
            // 2nd case
            if chosen_fork.first_n == self.bci + 1 {
                if !curr_parent.block_hash.eq(parent_hash) {
                    return Err(());
                } else {
                    // Wipe everything from pending_blocks.
                    warn!("Case 2.1");

                    return Ok(self.bci);
                }
            } else { // first_block.block.n > self.bci + 1
                let find_n_in_pending = chosen_fork.first_n - 1;
                if !self.pending_blocks.iter().any(|b| 
                    b.block.block.n == find_n_in_pending
                    && b.block.block_hash.eq(parent_hash)
                ) {
                    return Err(());
                } else {
                    // Wipe everything from pending_blocks before first_block.block.n
                    warn!("Case 2.2 {} {}", find_n_in_pending, self.bci);

                    return Ok(find_n_in_pending);
                }
            }
        }

    }
}
