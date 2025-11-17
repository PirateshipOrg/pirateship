use std::{
    cell::RefCell,
    collections::{HashMap, HashSet, VecDeque},
    io::Error,
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use futures::{future::BoxFuture, stream::FuturesOrdered, StreamExt as _};
use log::{debug, error, info, trace, warn};
use tokio::sync::{mpsc::UnboundedSender, oneshot, Mutex};

use crate::crypto::HashType;
use crate::{
    config::AtomicConfig,
    crypto::{CachedBlock, CryptoServiceConnector},
    proto::consensus::{
        ProtoForkValidation, ProtoQuorumCertificate, ProtoSignatureArrayEntry, ProtoTipCut,
        ProtoTipCutValidation, ProtoVote,
    },
    rpc::{client::PinnedClient, SenderType},
    utils::{
        channel::{Receiver, Sender},
        timer::ResettableTimer,
        PerfCounter, StorageAck,
    },
};

use super::{
    app::AppCommand,
    batch_proposal::BatchProposerCommand,
    block_broadcaster::BlockBroadcasterCommand,
    block_sequencer::BlockSequencerControlCommand,
    block_tipcut::BlockOrTipCut,
    client_reply::ClientReplyCommand,
    extra_2pc::{EngraftActionAfterFutureDone, EngraftTwoPCFuture, TwoPCCommand},
    fork_receiver::{AppendEntriesStats, ForkReceiverCommand},
    logserver::{self, LogServerCommand},
    pacemaker::PacemakerCommand,
};

#[cfg(feature = "dag")]
use crate::consensus::dag::lane_logserver::LaneLogServerQuery;
#[cfg(feature = "dag")]
use crate::consensus::dag::sort::{fetch_and_sort_tipcut_blocks, TipCutSortError};
#[cfg(feature = "dag")]
use crate::crypto::CachedTipCut;
#[cfg(feature = "dag")]
use crate::proto::consensus::ProtoBlockCar;
#[cfg(feature = "dag")]
use crate::utils::channel::make_channel;

pub(super) mod fork_choice;
pub(super) mod steady_state;
pub(super) mod view_change;

struct CachedBlockWithVotes {
    block: CachedBlock,

    vote_sigs: HashMap<String, ProtoSignatureArrayEntry>,
    replication_set: HashSet<String>,

    qc_is_proposed: bool,
    fast_qc_is_proposed: bool,
}

pub struct CachedWithVotes {
    block_or_tc: BlockOrTipCut,
    vote_sigs: HashMap<String, ProtoSignatureArrayEntry>,
    replication_set: HashSet<String>,
    qc_is_proposed: bool,
    fast_qc_is_proposed: bool,
}

impl From<CachedWithVotes> for CachedBlockWithVotes {
    fn from(cached: CachedWithVotes) -> Self {
        match cached.block_or_tc {
            BlockOrTipCut::Block(block) => Self {
                block,
                vote_sigs: cached.vote_sigs,
                replication_set: cached.replication_set,
                qc_is_proposed: cached.qc_is_proposed,
                fast_qc_is_proposed: cached.fast_qc_is_proposed,
            },
            #[cfg(feature = "dag")]
            BlockOrTipCut::TipCut(_) => {
                panic!("Cannot convert TipCut to CachedBlockWithVotes")
            }
        }
    }
}

pub type VoteWithSender = (SenderType /* Sender */, ProtoVote);
pub type SignatureWithBlockN = (
    u64, /* Block the QC was attached to */
    ProtoSignatureArrayEntry,
);

/// Reperesent a fork or tip cut received for consensus voting
pub struct Proposal {
    pub entry: BlockOrTipCut,
    pub storage_ack: oneshot::Receiver<StorageAck>,
    pub ae_stats: AppendEntriesStats,
    pub this_is_final: bool,
}

/// This is where all the consensus decisions are made.
/// Feeds in blocks from block_broadcaster (or tip cuts in DAG mode)
/// Waits for vote / Sends vote.
/// Whatever makes it to this stage must have been properly verified before.
/// So this stage will not bother about checking cryptographic validity.
pub struct Staging {
    config: AtomicConfig,
    client: PinnedClient,
    crypto: CryptoServiceConnector,

    ci: u64,
    bci: u64,
    view: u64,
    view_is_stable: bool,
    config_num: u64,
    last_qc: Option<ProtoQuorumCertificate>,
    curr_parent_for_pending: Option<BlockOrTipCut>,

    /// pending_votes holds blocks or tip cuts waiting on commit
    /// Invariant: pending_votes.len() == 0 || bci == pending_votes.front().n - 1
    pending_votes: VecDeque<CachedWithVotes>,
    /// pending_exec_blocks holds committed blocks waiting on execution
    /// In traditional mode, these come directly from pending_votes
    /// In DAG mode, these come from tip cut sort processing
    pending_exec_blocks: VecDeque<CachedBlockWithVotes>,

    /// Signed votes for blocks in pending_blocks
    pending_signatures: VecDeque<SignatureWithBlockN>,

    view_change_timer: Arc<Pin<Box<ResettableTimer>>>,

    block_rx: Receiver<Proposal>,
    vote_rx: Receiver<VoteWithSender>,
    pacemaker_rx: Receiver<PacemakerCommand>,
    pacemaker_tx: Sender<PacemakerCommand>,

    client_reply_tx: Sender<ClientReplyCommand>,
    app_tx: Sender<AppCommand>,
    block_broadcaster_command_tx: Sender<BlockBroadcasterCommand>,
    block_sequencer_command_tx: Sender<BlockSequencerControlCommand>,
    // TODO: What should this channel point to in DAG mode? Probably tip cut proposer?
    batch_proposer_command_tx: Sender<BatchProposerCommand>,
    fork_receiver_command_tx: Sender<ForkReceiverCommand>,
    qc_tx: UnboundedSender<ProtoQuorumCertificate>,
    logserver_tx: Sender<LogServerCommand>,

    leader_perf_counter_unsigned: RefCell<PerfCounter<u64>>,
    leader_perf_counter_signed: RefCell<PerfCounter<u64>>,

    __vc_retry_num: usize,
    __storage_ack_buffer: VecDeque<oneshot::Receiver<Result<(), Error>>>,
    __ae_seen_in_this_view: usize,

    #[cfg(feature = "extra_2pc")]
    two_pc_command_tx: Sender<TwoPCCommand>,

    #[cfg(feature = "extra_2pc")]
    engraft_2pc_futures_rx: Receiver<EngraftActionAfterFutureDone>,

    // DAG-only fields for tip cut sorting and block fetching
    #[cfg(feature = "dag")]
    lane_logserver_query_tx: Sender<LaneLogServerQuery>,
    #[cfg(feature = "dag")]
    last_lane_seq: HashMap<String, u64>,
}

impl Staging {
    pub fn new(
        config: AtomicConfig,
        client: PinnedClient,
        crypto: CryptoServiceConnector,
        block_rx: Receiver<Proposal>,
        vote_rx: Receiver<VoteWithSender>,
        pacemaker_rx: Receiver<PacemakerCommand>,
        pacemaker_tx: Sender<PacemakerCommand>,
        client_reply_tx: Sender<ClientReplyCommand>,
        app_tx: Sender<AppCommand>,
        block_broadcaster_command_tx: Sender<BlockBroadcasterCommand>,
        block_sequencer_command_tx: Sender<BlockSequencerControlCommand>,
        fork_receiver_command_tx: Sender<ForkReceiverCommand>,
        qc_tx: UnboundedSender<ProtoQuorumCertificate>,
        batch_proposer_command_tx: Sender<BatchProposerCommand>,
        logserver_tx: Sender<LogServerCommand>,
        #[cfg(feature = "dag")] lane_logserver_query_tx: Sender<LaneLogServerQuery>,

        #[cfg(feature = "extra_2pc")] two_pc_command_tx: Sender<TwoPCCommand>,

        #[cfg(feature = "extra_2pc")] engraft_2pc_futures_rx: Receiver<
            EngraftActionAfterFutureDone,
        >,
    ) -> Self {
        let _config = config.get();
        let _chan_depth = _config.rpc_config.channel_depth as usize;
        let view_timeout = Duration::from_millis(_config.consensus_config.view_timeout_ms);
        let view_change_timer = ResettableTimer::new(view_timeout);
        let leader_staging_event_order = vec![
            "Push to Pending",
            "Storage",
            "Vote to Self",
            "Crash Commit",
            "Send Crash Commit to App",
            "Byz Commit",
        ];
        let leader_perf_counter_signed = RefCell::new(PerfCounter::<u64>::new(
            "LeaderStagingSigned",
            &leader_staging_event_order,
        ));
        let leader_perf_counter_unsigned = RefCell::new(PerfCounter::<u64>::new(
            "LeaderStagingUnsigned",
            &leader_staging_event_order,
        ));

        let mut ret = Self {
            config,
            client,
            crypto,
            ci: 0,
            bci: 0,
            view: 0,
            view_is_stable: false,
            last_qc: None,
            curr_parent_for_pending: None,
            config_num: 1,
            pending_votes: VecDeque::with_capacity(_chan_depth),
            pending_exec_blocks: VecDeque::with_capacity(_chan_depth),
            pending_signatures: VecDeque::with_capacity(_chan_depth),
            view_change_timer,
            block_rx,
            vote_rx,
            pacemaker_rx,
            pacemaker_tx,
            client_reply_tx,
            app_tx,
            block_broadcaster_command_tx,
            block_sequencer_command_tx,
            fork_receiver_command_tx,
            qc_tx,
            leader_perf_counter_signed,
            leader_perf_counter_unsigned,
            batch_proposer_command_tx,
            logserver_tx,
            #[cfg(feature = "dag")]
            lane_logserver_query_tx,

            __vc_retry_num: 0,
            __storage_ack_buffer: VecDeque::new(),
            __ae_seen_in_this_view: 0,
            #[cfg(feature = "dag")]
            last_lane_seq: HashMap::new(),

            #[cfg(feature = "extra_2pc")]
            two_pc_command_tx,

            #[cfg(feature = "extra_2pc")]
            engraft_2pc_futures_rx,
        };

        #[cfg(not(feature = "view_change"))]
        {
            ret.view = 1;
            ret.view_is_stable = true;
        }

        ret
    }

    pub async fn run(staging: Arc<Mutex<Self>>) {
        let mut staging = staging.lock().await;
        let view_timer_handle = staging.view_change_timer.run().await;

        let mut total_work = 0;

        staging.view_change_timer.fire_now().await;
        loop {
            if let Err(_) = staging.worker().await {
                break;
            }

            total_work += 1;
            if total_work % 1000 == 0 {
                staging.leader_perf_counter_signed.borrow().log_aggregate();
                staging
                    .leader_perf_counter_unsigned
                    .borrow()
                    .log_aggregate();
            }
        }

        view_timer_handle.abort();
    }

    async fn worker(&mut self) -> Result<(), ()> {
        let i_am_leader = self.i_am_leader();

        #[cfg(feature = "extra_2pc")]
        tokio::select! {
            _tick = self.view_change_timer.wait() => {
                self.handle_view_change_timer_tick().await?;
            },
            msg = self.block_rx.recv() => {
                if msg.is_none() {
                    return Err(())
                }
                let proposal = msg.unwrap();
                if i_am_leader {
                    self.process_btc_as_leader(
                        proposal.entry,
                        proposal.storage_ack,
                        proposal.ae_stats,
                        proposal.this_is_final
                    ).await?;
                } else {
                    self.process_btc_as_follower(
                        proposal.entry,
                        proposal.storage_ack,
                        proposal.ae_stats,
                        proposal.this_is_final
                    ).await?;
                }
            },
            vote = self.vote_rx.recv() => {
                if vote.is_none() {
                    return Err(())
                }
                let vote = vote.unwrap();
                if i_am_leader {
                    let (sender_name, _) = vote.0.to_name_and_sub_id();
                    self.verify_and_process_vote(sender_name, vote.1).await?;
                } else {
                    warn!("Received vote while being a follower");
                }
            },
            cmd = self.pacemaker_rx.recv() => {
                if cmd.is_none() {
                    return Err(())
                }
                let cmd = cmd.unwrap();
                self.process_view_change_message(cmd).await?;
            },

            two_pc_fut = self.engraft_2pc_futures_rx.recv() => {
                if two_pc_fut.is_none() {
                    error!("2PC future is none");
                    return Ok(())
                }
                trace!("Processing 2PC future");
                let cmd = two_pc_fut.unwrap();

                self.process_2pc_result(cmd).await?;
            },
        }

        #[cfg(not(feature = "extra_2pc"))]
        tokio::select! {
            _tick = self.view_change_timer.wait() => {
                self.handle_view_change_timer_tick().await?;
            },
            msg = self.block_rx.recv() => {
                if msg.is_none() {
                    return Err(())
                }
                let proposal = msg.unwrap();
                if i_am_leader {
                    self.process_btc_as_leader(
                        proposal.entry,
                        proposal.storage_ack,
                        proposal.ae_stats,
                        proposal.this_is_final
                    ).await?;
                } else {
                    self.process_btc_as_follower(
                        proposal.entry,
                        proposal.storage_ack,
                        proposal.ae_stats,
                        proposal.this_is_final
                    ).await?;
                }
            },
            vote = self.vote_rx.recv() => {
                if vote.is_none() {
                    return Err(())
                }
                let vote = vote.unwrap();
                if i_am_leader {
                    let (sender_name, _) = vote.0.to_name_and_sub_id();
                    self.verify_and_process_vote(sender_name, vote.1).await?;
                } else {
                    warn!("Received vote while being a follower");
                }
            },
            cmd = self.pacemaker_rx.recv() => {
                if cmd.is_none() {
                    return Err(())
                }
                let cmd = cmd.unwrap();
                self.process_view_change_message(cmd).await?;
            },
        }

        Ok(())
    }

    /// DAG-only: Build inputs and call the sorter for a committed tip cut.
    /// Returns sorted blocks and origin map. Does not execute or update commit indices.
    #[cfg(feature = "dag")]
    pub async fn dag_fetch_and_sort_tipcut(
        &mut self,
        tipcut: &ProtoTipCut,
    ) -> Result<(Vec<CachedBlock>, HashMap<HashType, String>), TipCutSortError> {
        // Build cars map keyed by origin_node (serves as lane_id)
        let mut cars: HashMap<String, ProtoBlockCar> = HashMap::new();
        for car in &tipcut.tips {
            cars.insert(car.origin_node.clone(), car.clone());
        }

        let last_lane_seq = &self.last_lane_seq;
        let query_tx = self.lane_logserver_query_tx.clone();

        // Fetch function to retrieve a block from a lane by sequence number
        let fetch = move |lane: &str, seq: u64| {
            let query_tx = query_tx.clone();
            let lane = lane.to_string();
            async move {
                let (tx, rx) = make_channel(1);
                let _ = query_tx
                    .send(LaneLogServerQuery::GetBlock(lane.clone(), seq, tx))
                    .await;
                rx.recv().await.flatten()
            }
        };

        fetch_and_sort_tipcut_blocks(&cars, last_lane_seq, fetch).await
    }
}
