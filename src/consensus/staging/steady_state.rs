use async_recursion::async_recursion;
use bytes::{BufMut as _, BytesMut};
use futures::{future::try_join_all, FutureExt};
use log::{debug, error, info, trace, warn};
use prost::Message;
use std::collections::{HashMap, HashSet};
use tokio::{sync::oneshot, task::spawn_local};

use crate::{
    consensus::{
        dag::lane_staging,
        extra_2pc::{EngraftActionAfterFutureDone, EngraftTwoPCFuture, TwoPCCommand},
        logserver::LogServerCommand,
        pacemaker::PacemakerCommand,
    },
    crypto::{CachedBlock, HashType, DIGEST_LENGTH},
    proto::{
        consensus::{
            proto_block::Sig, ProtoNameWithSignature, ProtoQuorumCertificate,
            ProtoSignatureArrayEntry, ProtoTipCut, ProtoVote,
        },
        rpc::ProtoPayload,
    },
    rpc::{client::PinnedClient, PinnedMessage, SenderType},
    utils::StorageAck,
};

use super::{
    super::{
        app::AppCommand,
        block_broadcaster::BlockBroadcasterCommand,
        block_sequencer::BlockSequencerControlCommand,
        client_reply::ClientReplyCommand,
        fork_receiver::{AppendEntriesStats, ForkReceiverCommand},
    },
    BlockOrTipCut, CachedBlockWithVotes, CachedWithVotes, Staging,
};

impl Staging {
    pub(super) fn i_am_leader(&self) -> bool {
        let config = self.config.get();
        let leader = config.consensus_config.get_leader_for_view(self.view);
        leader == config.net_config.name
    }

    // TODO: Update perf stats to include tip cuts.
    fn perf_register_block(&self, block: &CachedBlock) {
        #[cfg(feature = "perf")]
        if let Some(Sig::ProposerSig(_)) = block.block.sig {
            self.leader_perf_counter_signed
                .borrow_mut()
                .register_new_entry(block.block.n);
        } else {
            self.leader_perf_counter_unsigned
                .borrow_mut()
                .register_new_entry(block.block.n);
        }
    }

    // TODO: Update perf stats to include tip cuts.
    fn perf_deregister_block(&self, block: &CachedBlock) {
        #[cfg(feature = "perf")]
        if let Some(Sig::ProposerSig(_)) = block.block.sig {
            self.leader_perf_counter_signed
                .borrow_mut()
                .deregister_entry(&block.block.n);
        } else {
            self.leader_perf_counter_unsigned
                .borrow_mut()
                .deregister_entry(&block.block.n);
        }
    }

    // TODO: Update perf stats to include tip cuts.
    #[cfg(feature = "perf")]
    fn perf_add_event(
        &self,
        block: &CachedBlock,
        event: &str,
    ) -> (bool /* signed */, u64 /* block_n */) {
        if let Some(Sig::ProposerSig(_)) = block.block.sig {
            self.leader_perf_counter_signed
                .borrow_mut()
                .new_event(event, &block.block.n);
            (true, block.block.n)
        } else {
            self.leader_perf_counter_unsigned
                .borrow_mut()
                .new_event(event, &block.block.n);
            (false, block.block.n)
        }
    }

    // TODO: Update perf stats to include tip cuts.
    #[cfg(not(feature = "perf"))]
    fn perf_add_event(&self, _block: &CachedBlock, _event: &str) {}

    // TODO: Update perf stats to include tip cuts.
    fn perf_add_event_from_perf_stats(&self, signed: bool, block_n: u64, event: &str) {
        #[cfg(feature = "perf")]
        if signed {
            self.leader_perf_counter_signed
                .borrow_mut()
                .new_event(event, &block_n);
        } else {
            self.leader_perf_counter_unsigned
                .borrow_mut()
                .new_event(event, &block_n);
        }
    }

    fn crash_commit_threshold(&self) -> usize {
        let n = self.config.get().consensus_config.node_list.len();

        // Majority
        n / 2 + 1
    }

    fn byzantine_commit_threshold(&self) -> usize {
        // TODO: Change this to u + r + 1
        self.byzantine_liveness_threshold()
    }

    pub(super) fn byzantine_liveness_threshold(&self) -> usize {
        let config = self.config.get();
        let n = config.consensus_config.node_list.len();

        #[cfg(feature = "platforms")]
        {
            let u = config.consensus_config.liveness_u as usize;

            assert!(n >= u);

            n - u
        }

        #[cfg(not(feature = "platforms"))]
        {
            let f = n / 3;
            n - f
        }
    }

    fn byzantine_fast_path_threshold(&self) -> usize {
        // All nodes
        self.config.get().consensus_config.node_list.len()
    }

    /// Either block.n === last block of pending_blocks + 1 and the hash link matches.
    /// Or block.n is in pending blocks, so it's hash must be present.
    /// Or block.n <= self.bci, so we can return false and safely ignore doing anything with this block.
    fn check_continuity(&self, btc: &BlockOrTipCut) -> bool {
        let n = btc.n();
        if self.pending_votes.len() == 0 {
            if self.curr_parent_for_pending.is_none() {
                return n == 1;
            } else {
                let parent = btc.parent();

                return parent.eq(&self.curr_parent_for_pending.as_ref().unwrap().digest())
                    && n == self.curr_parent_for_pending.as_ref().unwrap().n() + 1;
            }
        }

        let last_entry = self.pending_votes.back().unwrap();
        let first_entry = self.pending_votes.front().unwrap();

        if n > last_entry.block_or_tc.n() + 1 {
            return false;
        }
        if n < first_entry.block_or_tc.n() {
            return false;
        }
        if n == last_entry.block_or_tc.n() + 1 {
            let parent = btc.parent();
            return parent.eq(&last_entry.block_or_tc.parent());
        }

        self.pending_votes
            .iter()
            .any(|b| b.block_or_tc.n() == n && b.block_or_tc.digest().eq(&btc.digest()))
    }

    pub(super) async fn handle_view_change_timer_tick(&mut self) -> Result<(), ()> {
        #[cfg(not(feature = "view_change"))]
        return Ok(());

        warn!("View change timer fired");
        if self.view == 0 || self.view_is_stable {
            self.maybe_update_view(self.view + 1, self.config_num).await;

            return Ok(());
        }

        // View is not stable.
        // I may be timing out in the middle of another view change.
        // In that case, check if I have received enough view change messages
        // such that if the leader got these messages, it must have sent a new view message.
        // If not, stay in the same view, ignore the view timer tick.
        // If yes, (and we are after GST), the leader may have crashed or is among r_live.
        // In that case, I should update my view.

        let (tx, rx) = oneshot::channel();
        self.pacemaker_tx
            .send(PacemakerCommand::QueryEnoughVCMsg(
                self.view,
                self.config_num,
                tx,
            ))
            .await
            .unwrap();
        let enough = rx.await.unwrap();

        if enough {
            if self.__vc_retry_num >= 100 {
                self.maybe_update_view(self.view + 1, self.config_num).await;
                self.__vc_retry_num = 0;
            } else {
                self.__vc_retry_num += 1;
            }
        }
        Ok(())
    }

    async fn vote_on_last_btc_for_self(
        &mut self,
        storage_ack: oneshot::Receiver<StorageAck>,
    ) -> Result<(), ()> {
        let name = self.config.get().net_config.name.clone();

        let last_btc = match self.pending_votes.back() {
            Some(b) => b,
            None => return Err(()),
        };

        // Wait for it to be stored.
        // Invariant: I vote => I stored
        for ack in self.__storage_ack_buffer.drain(..) {
            let _ = ack.await.unwrap();
        }
        let _ = storage_ack.await.unwrap();

        // FIXME: Handle tip cuts here.
        // self.perf_add_event(&last_btc.block, "Storage");

        let mut vote = ProtoVote {
            sig_array: Vec::with_capacity(1),
            digest: last_btc.block_or_tc.digest(),
            n: last_btc.block_or_tc.n(),
            view: self.view,
            config_num: self.config_num,
        };

        #[cfg(feature = "extra_2pc")]
        let (_vote_n, _vote_view, _vote_digest) = (vote.n, vote.view, vote.digest.clone());

        // If this block is signed, need a signature for the vote.
        if let Some(_) = last_btc.block_or_tc.sig() {
            let vote_sig = self.crypto.sign(&last_btc.block_or_tc.digest()).await;

            vote.sig_array.push(ProtoSignatureArrayEntry {
                n: last_btc.block_or_tc.n(),
                sig: vote_sig.to_vec(),
            });
        }

        // FIXME: Handle tip cuts here.
        // self.perf_add_event(&last_block.block, "Vote to Self");

        #[cfg(feature = "extra_2pc")]
        {
            // This is for Engraft.
            // Need to store Raft meta file which is vote.n || vote.view
            // And hash of last block.
            let mut raft_meta_file = BytesMut::with_capacity(16);
            raft_meta_file.put_u64(_vote_n);
            raft_meta_file.put_u64(_vote_view);

            let mut log_meta_file = BytesMut::with_capacity(DIGEST_LENGTH);
            log_meta_file.put_slice(&_vote_digest);

            let raft_meta_2pc_cmd = TwoPCCommand::new(
                "raft_meta".to_string(),
                raft_meta_file.to_vec(),
                EngraftActionAfterFutureDone::None,
            );
            let log_meta_2pc_cmd = TwoPCCommand::new(
                "log_meta".to_string(),
                log_meta_file.to_vec(),
                EngraftActionAfterFutureDone::AsLeader(name, vote),
            );

            self.two_pc_command_tx
                .send(raft_meta_2pc_cmd)
                .await
                .unwrap();
            self.two_pc_command_tx.send(log_meta_2pc_cmd).await.unwrap();

            // self.engraft_2pc_futures.push_back(
            //     async move {
            //         EngraftTwoPCFuture::new(
            //             _vote_n, raft_meta_2pc_res, log_meta_2pc_res,
            //             EngraftActionAfterFutureDone::AsLeader(name, vote)
            //         ).await
            //     }.boxed()
            // );

            Ok(())
        }

        #[cfg(not(feature = "extra_2pc"))]
        {
            let res = self.process_vote(name, vote).await;
            res
        }
    }

    async fn send_vote_on_last_btc_to_leader(
        &mut self,
        storage_ack: oneshot::Receiver<StorageAck>,
    ) -> Result<(), ()> {
        let last_btc = match self.pending_votes.back() {
            Some(b) => b,
            None => return Err(()),
        };

        // Wait for it to be stored.
        // Invariant: I vote => I stored
        for ack in self.__storage_ack_buffer.drain(..) {
            let _ = ack.await.unwrap();
        }
        let _ = storage_ack.await.unwrap();

        // I will resend all the signatures in pending_blocks that I have not received a QC for.
        // But only if the last block was signed.
        let sig_array = if let Some(_) = last_btc.block_or_tc.sig() {
            self.pending_signatures
                .iter()
                .map(|(_, sig)| sig.clone())
                .collect()
        } else {
            Vec::new()
        };

        let mut vote = ProtoVote {
            sig_array,
            digest: last_btc.block_or_tc.digest(),
            n: last_btc.block_or_tc.n(),
            view: self.view,
            config_num: self.config_num,
        };

        #[cfg(feature = "extra_2pc")]
        let (_vote_n, _vote_view, _vote_digest) = (vote.n, vote.view, vote.digest.clone());

        // If this block is signed, need a signature for the vote.
        if let Some(_) = last_btc.block_or_tc.sig() {
            let vote_sig = self.crypto.sign(&last_btc.block_or_tc.digest()).await;
            let sig_entry = ProtoSignatureArrayEntry {
                n: last_btc.block_or_tc.n(),
                sig: vote_sig.to_vec(),
            };
            vote.sig_array.push(sig_entry.clone());

            self.pending_signatures
                .push_back((last_btc.block_or_tc.n(), sig_entry));
        }

        let leader = self
            .config
            .get()
            .consensus_config
            .get_leader_for_view(self.view);

        let rpc = ProtoPayload {
            message: Some(crate::proto::rpc::proto_payload::Message::Vote(vote)),
        };
        let data = rpc.encode_to_vec();
        let sz = data.len();
        let data = PinnedMessage::from(data, sz, SenderType::Anon);

        #[cfg(feature = "extra_2pc")]
        {
            // This is for Engraft.
            // Need to store Raft meta file which is vote.n || vote.view
            // And hash of last block.
            let mut raft_meta_file = BytesMut::with_capacity(16);
            raft_meta_file.put_u64(_vote_n);
            raft_meta_file.put_u64(_vote_view);

            let mut log_meta_file = BytesMut::with_capacity(DIGEST_LENGTH);
            log_meta_file.put_slice(&_vote_digest);

            let raft_meta_2pc_cmd = TwoPCCommand::new(
                "raft_meta".to_string(),
                raft_meta_file.to_vec(),
                EngraftActionAfterFutureDone::None,
            );
            let log_meta_2pc_cmd = TwoPCCommand::new(
                "log_meta".to_string(),
                log_meta_file.to_vec(),
                EngraftActionAfterFutureDone::AsFollower(leader, data),
            );

            self.two_pc_command_tx
                .send(raft_meta_2pc_cmd)
                .await
                .unwrap();
            self.two_pc_command_tx.send(log_meta_2pc_cmd).await.unwrap();

            // self.engraft_2pc_futures.push_back(
            //     async move {
            //         EngraftTwoPCFuture::new(
            //             _vote_n, raft_meta_2pc_res, log_meta_2pc_res,
            //             EngraftActionAfterFutureDone::AsFollower(leader, data)
            //         ).await
            //     }.boxed()
            // );
        }

        #[cfg(not(feature = "extra_2pc"))]
        {
            let _ = PinnedClient::send(&self.client, &leader, data.as_ref()).await;
            // .unwrap();

            if last_btc.block_or_tc.view_is_stable() {
                trace!("Sent vote to {} for {}", leader, last_btc.block_or_tc.n());
            } else {
                info!("Sent vote to {} for {}", leader, last_btc.block_or_tc.n());
            }
        }

        Ok(())
    }

    #[async_recursion]
    pub(super) async fn process_btc_as_leader(
        &mut self,
        btc: BlockOrTipCut,
        storage_ack: oneshot::Receiver<StorageAck>,
        ae_stats: AppendEntriesStats,
        this_is_final: bool,
    ) -> Result<(), ()> {
        if !self.view_is_stable {
            trace!("Processing block {} as leader", btc.n());
        }
        if ae_stats.view < self.view {
            // Do not accept anything from a lower view.
            return Ok(());
        } else if ae_stats.view == self.view {
            // if !self.view_is_stable && block.block.view_is_stable {
            //     // Notify upstream stages of view stabilization
            //     self.block_sequencer_command_tx
            //         .send(BlockSequencerControlCommand::ViewStabilised(
            //             self.view,
            //             self.config_num,
            //         ))
            //         .await
            //         .unwrap();
            // }
            if self.view_is_stable || !ae_stats.view_is_stable {
                self.view_is_stable = ae_stats.view_is_stable;

                // Allowed unchecked transitions:
                // Stable --> Stable
                // Stable --> Unstable
                // Unstable --> Unstable
                // But not Unstable --> Stable; it has to be checked through QCs.
            }
            if !self.view_is_stable {
                if !btc.view_is_stable() {
                    info!("New View message for view {}", self.view);
                }
                // Signal a rollback, if necessary
                // self.pending_blocks
                //     .retain(|e| e.block.block.n < block.block.n);
                self.rollback(btc.n() - 1).await;
            }
            // Invariant <ViewLock>: Within the same view, the log must be append-only.
            if !self.check_continuity(&btc) {
                warn!("Continuity broken");
                if btc.n() == self.bci {
                    // This is just a sanity check.
                    if self.curr_parent_for_pending.is_some()
                        && !self
                            .curr_parent_for_pending
                            .as_ref()
                            .unwrap()
                            .digest()
                            .eq(&btc.digest())
                    {
                        error!("Trying to override a byz-committed block!!");
                    }
                }
                return Ok(());
            }
        } else {
            // If from a higher view, this must mean I am no longer the leader in the cluster.
            // Precondition: The blocks I am receiving have been verified earlier,
            // So the sequence of new view messages have been verified before reaching here.

            // Jump to the new view
            self.view = ae_stats.view;
            self.__ae_seen_in_this_view = 0;

            self.view_is_stable = false;
            self.config_num = ae_stats.config_num;

            // Notify upstream stages of view change
            self.block_sequencer_command_tx
                .send(BlockSequencerControlCommand::NewUnstableView(
                    self.view,
                    self.config_num,
                ))
                .await
                .unwrap();
            self.fork_receiver_command_tx
                .send(ForkReceiverCommand::UpdateView(self.view, self.config_num))
                .await
                .unwrap();

            // Flush the pending queue and cancel client requests.
            self.rollback(btc.n() - 1).await;
            // let old_pending_len = self.pending_blocks.len();
            // self.pending_blocks
            //     .retain(|e| e.block.block.n < block.block.n);
            // let new_pending_len = self.pending_blocks.len();
            // if new_pending_len < old_pending_len {
            //     // Signal a rollback
            // }
            // self.pending_signatures.retain(|(n, _)| *n < block.block.n);
            self.client_reply_tx
                .send(ClientReplyCommand::CancelAllRequests)
                .await
                .unwrap();

            // None of the votes from the lower views should count anymore!
            self.pending_votes.iter_mut().for_each(|e| {
                e.replication_set.clear();
                e.vote_sigs.clear();
            });

            // Ready to accept the block normally.
            if self.i_am_leader() {
                return self
                    .process_btc_as_leader(btc, storage_ack, ae_stats, this_is_final)
                    .await;
            } else {
                return self
                    .process_btc_as_follower(btc, storage_ack, ae_stats, this_is_final)
                    .await;
            }
        }

        // FIXME
        // self.perf_register_block(&block);
        match &btc {
            BlockOrTipCut::Block(b) => {
                self.logserver_tx
                    .send(LogServerCommand::NewBlock(b.clone()))
                    .await
                    .unwrap();
            }
            BlockOrTipCut::TipCut(tc) => {
                self.logserver_tx
                    .send(LogServerCommand::NewTipCut(tc.clone()))
                    .await
                    .unwrap();
            }
        }
        self.__ae_seen_in_this_view += if this_is_final { 1 } else { 0 };

        // Postcondition here: block.view == self.view && check_continuity() == true && i_am_leader
        let block_view_is_stable = btc.view_is_stable();
        let block_view = btc.view();

        let btc_with_votes = CachedWithVotes {
            block_or_tc: btc,
            vote_sigs: HashMap::new(),
            replication_set: HashSet::new(),
            qc_is_proposed: false,
            fast_qc_is_proposed: false,
        };

        self.pending_votes.push_back(btc_with_votes);

        // FIXME
        // self.perf_add_event(
        //     &self.pending_votes.iter().last().unwrap().block,
        //     "Push to Pending",
        // );

        // Now vote for self

        // if block_view < self.view {
        //     return Ok(());
        // }

        // if !self.view_is_stable && block_view_is_stable {
        //     return Ok(());
        // }

        if this_is_final {
            self.vote_on_last_btc_for_self(storage_ack).await?;
        } else {
            self.__storage_ack_buffer.push_back(storage_ack);
        }

        Ok(())
    }

    /// This has a lot of similarities with process_block_as_leader.
    #[async_recursion]
    pub(super) async fn process_btc_as_follower(
        &mut self,
        // block: CachedBlock,
        btc: BlockOrTipCut,
        storage_ack: oneshot::Receiver<StorageAck>,
        ae_stats: AppendEntriesStats,
        this_is_final: bool,
    ) -> Result<(), ()> {
        if !self.view_is_stable {
            trace!("Processing block {} as follower", btc.n());
        }
        if ae_stats.view < self.view {
            // Do not accept anything from a lower view.
            warn!(
                "Received block from lower view {}. Already in {}",
                ae_stats.view, self.view
            );
            return Ok(());
        } else if ae_stats.view == self.view {
            // if !self.view_is_stable && block.block.view_is_stable {
            //     // Notify upstream stages of view stabilization
            //     self.block_sequencer_command_tx
            //         .send(BlockSequencerControlCommand::ViewStabilised(
            //             self.view,
            //             self.config_num,
            //         ))
            //         .await
            //         .unwrap();
            // }
            if self.view_is_stable || !ae_stats.view_is_stable {
                self.view_is_stable = ae_stats.view_is_stable;

                // Allowed unchecked transitions:
                // Stable --> Stable
                // Stable --> Unstable
                // Unstable --> Unstable
                // But not Unstable --> Stable; it has to be checked through QCs.
            }
            if !self.view_is_stable {
                if !btc.view_is_stable() {
                    info!("New View message for view {}", self.view);
                }
                // Signal a rollback, if necessary
                self.rollback(btc.n() - 1).await;
                // self.pending_blocks
                //     .retain(|e| e.block.block.n < block.block.n);
            }

            // Invariant <ViewLock>: Within the same view, the log must be append-only.
            if !self.check_continuity(&btc) {
                warn!("Continuity broken");
                return Ok(());
            }
        } else {
            // If from a higher view, this may mean I am now the leader in the cluster.
            // Precondition: The blocks I am receiving have been verified earlier,
            // So the sequence of new view messages have been verified before reaching here.

            // Jump to the new view
            self.view = ae_stats.view;
            self.__ae_seen_in_this_view = 0;

            self.view_is_stable = false;
            self.config_num = btc.config_num();

            // Notify upstream stages of view change
            self.block_sequencer_command_tx
                .send(BlockSequencerControlCommand::NewUnstableView(
                    self.view,
                    self.config_num,
                ))
                .await
                .unwrap();
            self.fork_receiver_command_tx
                .send(ForkReceiverCommand::UpdateView(self.view, self.config_num))
                .await
                .unwrap();

            // Flush the pending queue and cancel client requests.
            self.pending_votes.retain(|e| e.block_or_tc.n() < btc.n());
            self.pending_signatures.retain(|(n, _)| *n < btc.n());
            self.client_reply_tx
                .send(ClientReplyCommand::CancelAllRequests)
                .await
                .unwrap();

            // None of the votes from the lower views should count anymore!
            self.pending_votes.iter_mut().for_each(|e| {
                e.replication_set.clear();
                e.vote_sigs.clear();
            });

            // Ready to accept the block normally.
            if self.i_am_leader() {
                return self
                    .process_btc_as_leader(btc, storage_ack, ae_stats, this_is_final)
                    .await;
            } else {
                return self
                    .process_btc_as_follower(btc, storage_ack, ae_stats, this_is_final)
                    .await;
            }
        }

        match &btc {
            BlockOrTipCut::Block(block) => {
                self.logserver_tx
                    .send(LogServerCommand::NewBlock(block.clone()))
                    .await
                    .unwrap();
            }
            BlockOrTipCut::TipCut(tc) => {
                self.logserver_tx
                    .send(LogServerCommand::NewTipCut(tc.clone()))
                    .await
                    .unwrap();
            }
        }
        self.__ae_seen_in_this_view += if this_is_final { 1 } else { 0 };

        // Postcondition here: block.view == self.view && check_continuity() == true && !i_am_leader
        let btc_with_votes = CachedWithVotes {
            block_or_tc: btc,
            vote_sigs: HashMap::new(),
            replication_set: HashSet::new(),
            qc_is_proposed: false,
            fast_qc_is_proposed: false,
        };
        self.pending_votes.push_back(btc_with_votes);

        // Now crash commit blindly
        if this_is_final {
            self.do_crash_commit(self.ci, ae_stats.ci).await;
        }

        let old_view_is_stable = self.view_is_stable;

        let mut qc_list = self
            .pending_votes
            .iter()
            .last()
            .unwrap()
            .block_or_tc
            .qc()
            .iter()
            .map(|e| e.clone())
            .collect::<Vec<_>>();

        for qc in qc_list.drain(..) {
            if !old_view_is_stable {
                // Try to see if this QC can stabilize the view.
                trace!("Trying to stabilize view {} with QC", self.view);
                self.maybe_stabilize_view(&qc).await;
            }

            self.maybe_byzantine_commit(qc).await?;
        }

        #[cfg(feature = "no_qc")]
        {
            if this_is_final_block {
                self.do_byzantine_commit(self.bci, self.ci).await;
            }
        }

        // Reply vote to the leader.
        if this_is_final {
            self.send_vote_on_last_btc_to_leader(storage_ack).await?;
        } else {
            self.__storage_ack_buffer.push_back(storage_ack);
        }

        let (hard_gap, soft_gap) = {
            let config = &self.config.get().consensus_config;
            (config.commit_index_gap_hard, config.commit_index_gap_soft)
        };

        if old_view_is_stable && self.__ae_seen_in_this_view > soft_gap as usize
        /* don't trigger unnecessarily on new view messages */
        && self.ci as i64 - self.bci as i64 > hard_gap as i64
        {
            // Trigger a view change
            warn!(
                "Triggering view change due to too much gap between CI and BCI: {} {}",
                self.ci, self.bci
            );
            self.view_change_timer.fire_now().await;
        }

        Ok(())
    }

    pub(super) async fn verify_and_process_vote(
        &mut self,
        sender: String,
        vote: ProtoVote,
    ) -> Result<(), ()> {
        let _n = vote.n;
        debug!("Got vote on {} from {}", _n, sender);
        let mut verify_futs = Vec::new();
        for sig in &vote.sig_array {
            let found_block = self
                .pending_votes
                .binary_search_by(|b| b.block_or_tc.n().cmp(&sig.n));

            match found_block {
                Ok(idx) => {
                    let block = &self.pending_votes[idx];
                    let _sig = sig.sig.clone().try_into();
                    match _sig {
                        Ok(_sig) => {
                            verify_futs.push(
                                self.crypto
                                    .verify_nonblocking(
                                        block.block_or_tc.digest().clone(),
                                        sender.clone(),
                                        _sig,
                                    )
                                    .await,
                            );
                        }
                        Err(_) => {
                            warn!("Malformed signature in vote");
                            return Ok(());
                        }
                    }
                }
                Err(_) => {
                    trace!(
                        "This is a vote for a block I have byz committed. n = {}",
                        _n
                    );
                    continue;
                }
            }
        }

        let results = try_join_all(verify_futs).await.unwrap();
        if !results.iter().all(|e| *e) {
            trace!("Failed to verify vote on {} from {}", _n, sender);
            return Ok(());
        }

        self.process_vote(sender, vote).await
    }

    /// Precondition: The vote has been cryptographically verified to be from sender.
    async fn process_vote(&mut self, sender: String, mut vote: ProtoVote) -> Result<(), ()> {
        if !self.view_is_stable {
            info!("Processing vote on {} from {}", vote.n, sender);
        }
        if self.view != vote.view {
            return Ok(());
        }

        if self.pending_votes.len() == 0 {
            return Ok(());
        }

        let first_n = self.pending_votes.front().unwrap().block_or_tc.n();
        let last_n = self.pending_votes.back().unwrap().block_or_tc.n();

        if !(first_n <= vote.n && vote.n <= last_n) {
            return Ok(());
        }
        // Vote for a block is a vote on all its ancestors.
        for block in self.pending_votes.iter_mut() {
            if block.block_or_tc.n() <= vote.n {
                block.replication_set.insert(sender.clone());
            }

            if let Some(_) = block.block_or_tc.sig() {
                // If this block is signed, the sig array may have a signature for it.
                vote.sig_array.retain(|e| {
                    if e.n != block.block_or_tc.n() {
                        true
                    } else {
                        block.vote_sigs.insert(sender.clone(), e.clone());
                        false
                    }
                });
            }
        }

        self.maybe_crash_commit().await?;

        #[cfg(not(feature = "no_qc"))]
        self.maybe_create_qcs().await?;

        #[cfg(feature = "no_qc")]
        self.do_byzantine_commit(self.bci, self.ci).await;
        // This is needed to prevent a memory leak.

        Ok(())
    }

    /// Crash commit blindly; checking is left on the caller.
    async fn do_crash_commit(&mut self, old_ci: u64, new_ci: u64) {
        if new_ci <= old_ci {
            return;
        }
        self.ci = new_ci;
        // Notify
        self.block_broadcaster_command_tx
            .send(BlockBroadcasterCommand::UpdateCI(new_ci))
            .await
            .unwrap();

        #[cfg(not(feature = "dag"))]
        let blocks = {
            let committed_blocks = self
                .pending_votes
                .iter()
                .filter(|e| e.block_or_tc.n() > old_ci && e.block_or_tc.n() <= new_ci)
                .map(|e| match &e.block_or_tc {
                    BlockOrTipCut::Block(b) => b.clone(),
                    _ => {
                        warn!("Found committed tip cut during crash commit");
                        panic!("Found committed tip cut during crash commit");
                    }
                })
                .collect::<Vec<_>>();

            self.app_tx
                .send(AppCommand::CrashCommit(committed_blocks))
                .await
                .unwrap();

            committed_blocks
        };

        #[cfg(feature = "dag")]
        let blocks = {
            // Collect the committed tip cuts first to avoid borrowing self across await
            let tipcuts: Vec<ProtoTipCut> = self
                .pending_votes
                .iter()
                .filter(|entry| entry.block_or_tc.n() > old_ci && entry.block_or_tc.n() <= new_ci)
                .filter_map(|entry| match &entry.block_or_tc {
                    BlockOrTipCut::TipCut(tc) => Some(tc.tipcut.clone()),
                    _ => None,
                })
                .collect();

            let mut origin_map_total: std::collections::HashMap<HashType, String> =
                std::collections::HashMap::new();
            let mut committed_blocks: Vec<CachedBlock> = Vec::new();

            for tipcut in tipcuts {
                match self.dag_fetch_and_sort_tipcut(&tipcut).await {
                    Ok((mut sorted_blocks, origin_map)) => {
                        // Merge origin maps (do not override existing entries)
                        for (k, v) in origin_map.into_iter() {
                            origin_map_total.entry(k).or_insert(v);
                        }
                        committed_blocks.append(&mut sorted_blocks);

                        // Update per-lane last committed sequence
                        for car in &tipcut.tips {
                            self.last_lane_seq.insert(car.origin_node.clone(), car.n);
                        }
                    }
                    Err(e) => {
                        warn!("DAG crash-commit: failed to fetch/sort tip cut: {:?}", e);
                    }
                }
            }

            // Send to app with origin info
            let _ = self
                .app_tx
                .send(AppCommand::CrashCommitWithOrigins(
                    committed_blocks.clone(),
                    origin_map_total,
                ))
                .await;

            committed_blocks
        };

        #[cfg(feature = "perf")]
        let mut block_perf_stats = Vec::new();
        #[cfg(feature = "perf")]
        for b in &blocks {
            block_perf_stats.push(self.perf_add_event(&b, "Crash Commit"));
        }

        #[cfg(feature = "perf")]
        for (signed, block_n) in block_perf_stats {
            self.perf_add_event_from_perf_stats(signed, block_n, "Send Crash Commit to App");
        }
    }

    async fn maybe_crash_commit(&mut self) -> Result<(), ()> {
        let old_ci = self.ci;

        let soft_gap = {
            let config = &self.config.get().consensus_config;
            config.commit_index_gap_soft
        };
        let non_bcied = self.ci as i64 - self.bci as i64;

        #[cfg(feature = "no_qc")]
        let thresh = self.crash_commit_threshold();

        #[cfg(not(feature = "no_qc"))]
        let thresh = if non_bcied > soft_gap as i64 {
            self.byzantine_commit_threshold()
        } else {
            self.crash_commit_threshold()
        };

        for entry in self.pending_votes.iter() {
            if entry.block_or_tc.n() <= self.ci {
                continue;
            }

            if entry.replication_set.len() >= thresh {
                self.ci = entry.block_or_tc.n();
            }
        }
        let new_ci = self.ci;

        self.do_crash_commit(old_ci, new_ci).await;

        Ok(())
    }

    async fn maybe_create_qcs(&mut self) -> Result<(), ()> {
        let mut qcs = Vec::new();

        let thresh = self.byzantine_commit_threshold();
        let fast_thresh = self.byzantine_fast_path_threshold();
        for entry in &mut self.pending_votes {
            if entry.qc_is_proposed && entry.fast_qc_is_proposed {
                continue;
            }

            // We only want to propose a QC at max twice.
            // Once when the slow path threshold is reached.
            // Once when the fast path threshold is reached.
            // If we already have proposed a slow path QC,
            // there is no need to propose another until we can safely do the fast path.

            let thresh = if entry.qc_is_proposed {
                fast_thresh
            } else {
                thresh
            };

            if entry.vote_sigs.len() >= thresh {
                let qc = ProtoQuorumCertificate {
                    n: entry.block_or_tc.n(),
                    view: self.view,
                    sig: entry
                        .vote_sigs
                        .iter()
                        .map(|(k, v)| ProtoNameWithSignature {
                            name: k.clone(),
                            sig: v.sig.clone(),
                        })
                        .collect(),
                    digest: entry.block_or_tc.digest(),
                };
                qcs.push(qc);
                entry.qc_is_proposed = true;

                if entry.vote_sigs.len() >= fast_thresh {
                    entry.fast_qc_is_proposed = true;
                }
            }
        }

        for qc in qcs.drain(..) {
            if !self.view_is_stable {
                // Try to see if this QC can stabilize the view.
                self.maybe_stabilize_view(&qc).await;
            }

            // This send needs to be non-blocking.
            // Hence can't avoid using an unbounded channel.
            // Otherwise: block_broadcaster_tx -> staging_tx -> qc_tx forms a cycle since BlockSequencer consumes from qc_rx.
            // Had there been another thread consuming qc_rx, this would not have been a problem since there will always be an enabled consumer.
            // But since this thread will block on block_broadcaster_tx.send, it will not be able to consume from qc_rx.
            // Once the queues are saturated, the system will deadlock.
            let _ = self.qc_tx.send(qc.clone());
            self.maybe_byzantine_commit(qc).await?;
        }

        Ok(())
    }

    /// Will push to pending_qcs and notify block_broadcaster to attach this qc.
    /// Then will try to byzantine commit.
    /// Precondition: All qcs in self.pending_qcs has same view as qc.view.
    /// Fast path rule:
    /// If qc_n has votes from all nodes, then qc.n is byz committed.
    /// Slow path rule:
    /// If \E (block_n, qc2) in self.pending_qcs: qc.n >= block_n then qc2.n is byz committed.
    /// This is PBFT/Jolteon-style 2-hop rule.
    /// If this happens then all QCs in self.pending_qcs such that block_n <= new_bci is removed.
    async fn maybe_byzantine_commit(
        &mut self,
        incoming_qc: ProtoQuorumCertificate,
    ) -> Result<(), ()> {
        // Reset view timer. Getting a QC signals that byzantine progress can still be made.
        if self.view <= incoming_qc.view /* no old */
            && self.last_qc.as_ref().map(|e| e.n).unwrap_or(0) < incoming_qc.n
        /* dedup */
        {
            self.view_change_timer.reset();
            self.maybe_update_last_qc(&incoming_qc);
        }

        // Clean out the pending_signatures
        self.pending_signatures.retain(|(n, _)| *n > incoming_qc.n);
        let old_bci = self.bci;

        // Fast path: All votes rule; only applicable if view is stable already.
        let new_bci_fast_path = if self.view_is_stable
            && incoming_qc.sig.len() >= self.byzantine_fast_path_threshold()
        {
            #[cfg(feature = "fast_path")]
            {
                incoming_qc.n
            }
            #[cfg(not(feature = "fast_path"))]
            {
                old_bci
            }
        } else {
            old_bci
        };

        // Slow path: 2-hop rule
        let mut new_bci_slow_path = self
            .pending_votes
            .iter()
            .rev()
            .filter(|b| b.block_or_tc.n() <= incoming_qc.n) // The blocks pointed by this QC (and all its ancestors)
            .map(|b| b.block_or_tc.qc().iter().map(|qc| qc.n).collect::<Vec<_>>()) // Collect all the QCs in those blocks
            .flatten()
            .max()
            .unwrap_or(old_bci); // All such qc.n must be byz committed, so new_bci = max(all such qc.n)

        #[cfg(feature = "extra_qc_check")]
        {
            // Extra QC check for Hotstuff
            // new_bci_slow_path now has highest QC over QC.
            // Check one more QC hop for all blocks <= new_bci_slow_path.
            // This combined with no_pipeline will give maintain Hotstuff-safety.

            if new_bci_slow_path > old_bci {
                new_bci_slow_path = self
                    .pending_blocks
                    .iter()
                    .rev()
                    .filter(|b| b.block.block.n <= new_bci_slow_path)
                    .map(|b| b.block.block.qc.iter().map(|qc| qc.n))
                    .flatten()
                    .max()
                    .unwrap_or(old_bci);
            }
        }

        let new_bci = new_bci_fast_path.max(new_bci_slow_path);

        self.do_byzantine_commit(old_bci, new_bci).await;
        Ok(())
    }

    pub(crate) async fn do_byzantine_commit(&mut self, old_bci: u64, new_bci: u64) {
        if new_bci <= old_bci {
            return;
        }

        self.bci = new_bci;

        // Invariant: All blocks in pending_blocks is in order.
        let mut byz_blocks = Vec::new();

        while let Some(entry) = self.pending_votes.front() {
            if entry.block_or_tc.n() > new_bci {
                break;
            }

            let btc = self.pending_votes.pop_front().unwrap().block_or_tc;
            // FIXME
            // self.perf_add_event(&btc, "Byz Commit");

            if btc.n() == new_bci {
                self.curr_parent_for_pending = Some(btc.clone());
            }

            // FIXME
            // self.perf_deregister_block(&btc);
            byz_blocks.push(btc);
        }

        // Execute committed entries
        #[cfg(not(feature = "dag"))]
        {
            // In non-DAG mode, byz_blocks should all be Blocks; filter and send
            let blocks: Vec<CachedBlock> = byz_blocks
                .into_iter()
                .filter_map(|btc| match btc {
                    BlockOrTipCut::Block(b) => Some(b),
                    _ => None,
                })
                .collect();
            let _ = self.app_tx.send(AppCommand::ByzCommit(blocks)).await;
        }

        #[cfg(feature = "dag")]
        {
            // Build a combined list of blocks and origins from any committed tip cuts
            let mut blocks_for_app: Vec<CachedBlock> = Vec::new();
            let mut origin_map_total: std::collections::HashMap<HashType, String> =
                std::collections::HashMap::new();

            for btc in byz_blocks.into_iter() {
                match btc {
                    BlockOrTipCut::Block(b) => {
                        // Rare in DAG path, but include if present
                        blocks_for_app.push(b);
                    }
                    BlockOrTipCut::TipCut(tc) => {
                        let tipcut = tc.tipcut.clone();
                        match self.dag_fetch_and_sort_tipcut(&tipcut).await {
                            Ok((mut sorted_blocks, origin_map)) => {
                                for (k, v) in origin_map.into_iter() {
                                    origin_map_total.entry(k).or_insert(v);
                                }
                                blocks_for_app.append(&mut sorted_blocks);
                                // Update per-lane last committed sequence
                                for car in &tipcut.tips {
                                    self.last_lane_seq.insert(car.origin_node.clone(), car.n);
                                }
                            }
                            Err(e) => {
                                warn!("DAG byz-commit: failed to fetch/sort tip cut: {:?}", e);
                            }
                        }
                    }
                }
            }

            let _ = self
                .app_tx
                .send(AppCommand::ByzCommitWithOrigins(
                    blocks_for_app,
                    origin_map_total,
                ))
                .await;
        }
        let _ = self
            .logserver_tx
            .send(LogServerCommand::UpdateBCI(self.bci))
            .await;
    }

    fn maybe_update_last_qc(&mut self, qc: &ProtoQuorumCertificate) {
        if qc.n > self.last_qc.as_ref().map(|e| e.n).unwrap_or(0) {
            self.last_qc = Some(qc.clone());
        }
    }

    async fn rollback(&mut self, n: u64) {
        self.pending_votes.retain(|e| e.block_or_tc.n() <= n);
        self.pending_signatures.retain(|(_n, _)| *_n <= n);
        self.app_tx.send(AppCommand::Rollback(n)).await.unwrap();
        self.logserver_tx
            .send(LogServerCommand::Rollback(n))
            .await
            .unwrap();
    }

    pub(crate) async fn process_2pc_result(
        &mut self,
        cmd: EngraftActionAfterFutureDone,
    ) -> Result<(), ()> {
        match cmd {
            EngraftActionAfterFutureDone::None => {}
            EngraftActionAfterFutureDone::AsLeader(name, vote) => {
                trace!("Processing continuation as leader");
                let _ = self.process_vote(name, vote).await;
            }
            EngraftActionAfterFutureDone::AsFollower(leader, data) => {
                trace!("Processing continuation as follower");
                let _ = PinnedClient::send(&self.client, &leader, data.as_ref()).await;
            }
        }

        Ok(())
    }
}
