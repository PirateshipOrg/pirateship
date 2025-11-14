/// Tip Cut Proposal Module for DAG Consensus
///
/// This module is responsible for proposing tip cuts in the DAG.
/// Only the leader proposes tip cuts for each view.
///
/// Flow:
/// 1. Leader periodically checks if a new tip cut should be proposed
/// 2. Query lane_staging for the current tip cut (one CAR per lane)
/// 3. Construct ProtoTipCut message with the tip cut information
/// 4. Send ProtoTipCut to BlockSequencer for sequencing and broadcasting
/// 5. Nodes vote on the tip cut via tip_cut_voting component
///
/// Leadership:
/// - Only the current leader proposes tip cuts
/// - View changes update leadership via command channel
/// - Non-leaders skip proposal logic
use std::sync::Arc;
use std::time::Duration;

use log::{debug, error, info, trace};
use tokio::sync::{oneshot, Mutex};

use crate::{
    config::AtomicConfig,
    proto::consensus::ProtoTipCut,
    utils::{
        channel::{Receiver, Sender},
        timer::ResettableTimer,
    },
};

use super::lane_staging::{LaneStagingQuery, TipCut};

/// Commands to control TipCutProposal behavior
pub enum TipCutProposalCommand {
    /// Update leadership status and current leader name
    UpdateLeadership(bool, String), // (am_i_leader, leader_name)

    /// Update view number
    UpdateView(u64),

    /// Update view stability
    UpdateViewStability(bool),
}

/// TipCutProposal is responsible for periodically proposing tip cuts.
/// Only the leader proposes tip cuts.
pub struct TipCutProposal {
    config: AtomicConfig,

    // Current state
    ci: u64,
    view: u64,
    view_is_stable: bool,

    // Leadership state
    i_am_leader: bool,
    current_leader: String,

    // Timer for periodic proposals
    tip_cut_timer: Arc<std::pin::Pin<Box<ResettableTimer>>>,

    // Query channel to LaneStaging
    lane_staging_query_tx: Sender<LaneStagingQuery>,

    // Send tip cuts to BlockSequencer for wrapping and broadcasting
    consensus_sequencer_tx: Sender<ProtoTipCut>,

    // Command channel for view changes and leadership updates
    cmd_rx: Receiver<TipCutProposalCommand>,
}

impl TipCutProposal {
    pub fn new(
        config: AtomicConfig,
        lane_staging_query_tx: Sender<LaneStagingQuery>,
        consensus_sequencer_tx: Sender<ProtoTipCut>,
        cmd_rx: Receiver<TipCutProposalCommand>,
    ) -> Self {
        // Get initial configuration
        let config_snapshot = config.get();

        // Set up timer for periodic tip cut proposals
        // Default to 100ms if not configured
        let tip_cut_delay_ms = 100; // TODO: Add tip_cut_max_delay_ms to ConsensusConfig
        let tip_cut_timer = ResettableTimer::new(Duration::from_millis(tip_cut_delay_ms));

        // Determine initial leadership
        #[cfg(feature = "view_change")]
        let (view, i_am_leader, current_leader) = {
            let my_name = &config_snapshot.net_config.name;
            let leader = config_snapshot.consensus_config.get_leader_for_view(0);
            (0, leader == *my_name, leader)
        };

        #[cfg(not(feature = "view_change"))]
        let (view, i_am_leader, current_leader) = {
            let my_name = &config_snapshot.net_config.name;
            let leader = config_snapshot.consensus_config.get_leader_for_view(1);
            (1, leader == *my_name, leader)
        };

        info!(
            "TipCutProposal initialized: view={}, i_am_leader={}, leader={}",
            view, i_am_leader, current_leader
        );

        Self {
            config,
            ci: 0,
            view,
            view_is_stable: false,
            i_am_leader,
            current_leader,
            tip_cut_timer,
            lane_staging_query_tx,
            consensus_sequencer_tx,
            cmd_rx,
        }
    }

    pub async fn run(tip_cut_proposal: Arc<Mutex<Self>>) {
        let mut tip_cut_proposal = tip_cut_proposal.lock().await;

        // Start the timer
        let timer_handle = tip_cut_proposal.tip_cut_timer.run().await;

        info!("TipCutProposal worker starting");

        loop {
            if let Err(_) = tip_cut_proposal.worker().await {
                break;
            }
        }

        timer_handle.abort();
        info!("TipCutProposal worker stopped");
    }

    async fn worker(&mut self) -> Result<(), ()> {
        let mut timer_tick = false;
        let mut cmd = None;

        tokio::select! {
            _cmd = self.cmd_rx.recv() => {
                cmd = _cmd;
            },
            _tick = self.tip_cut_timer.wait() => {
                timer_tick = _tick;
            }
        }

        // Handle commands (leadership updates, view changes)
        if let Some(command) = cmd {
            self.handle_command(command);
            return Ok(());
        }

        // Handle timer tick - propose tip cut if we're the leader
        if timer_tick {
            if self.i_am_leader && self.should_propose_tip_cut() {
                if let Err(_) = self.propose_tip_cut().await {
                    error!("Failed to propose tip cut");
                }
            } else {
                trace!(
                    "Skipping tip cut proposal: i_am_leader={}",
                    self.i_am_leader
                );
            }
            return Ok(());
        }

        // Channel closed
        Err(())
    }

    fn i_am_leader(&self) -> bool {
        self.config.get().net_config.name == self.current_leader
    }

    fn handle_command(&mut self, command: TipCutProposalCommand) {
        match command {
            TipCutProposalCommand::UpdateLeadership(am_i_leader, leader_name) => {
                let was_leader = self.i_am_leader;
                self.i_am_leader = am_i_leader;
                self.current_leader = leader_name.clone();

                if was_leader != am_i_leader {
                    info!(
                        "Leadership changed: i_am_leader={}, new_leader={}",
                        am_i_leader, leader_name
                    );
                }
            }
            TipCutProposalCommand::UpdateView(view) => {
                if view != self.view {
                    info!("View changed: {} -> {}", self.view, view);
                    self.view = view;
                }
            }
            TipCutProposalCommand::UpdateViewStability(stable) => {
                if stable != self.view_is_stable {
                    debug!("View stability changed: {}", stable);
                    self.view_is_stable = stable;
                }
            }
        }
    }

    /// Determine if a tip cut should be proposed.
    ///
    /// TODO: Implement more sophisticated logic:
    /// - Timer-based: Propose every N milliseconds (current behavior)
    /// - Threshold-based: Propose when enough new CARs are available
    /// - Hybrid: Propose when timer expires AND threshold met
    /// - Adaptive: Adjust timing based on network conditions
    ///
    /// For now, returns true (always propose on timer tick if leader).
    fn should_propose_tip_cut(&self) -> bool {
        true // For now, always propose when timer ticks
    }

    /// Query lane_staging for current tip cut and broadcast it to all nodes.
    async fn propose_tip_cut(&mut self) -> Result<(), ()> {
        // Query LaneStaging for the current tip cut
        let tip_cut = match self.query_tip_cut().await? {
            Some(tc) => tc,
            None => {
                debug!("No CARs available yet for tip cut proposal");
                return Ok(());
            }
        };

        // Check if tip cut is valid (has at least one CAR)
        if tip_cut.cars.is_empty() {
            debug!("Tip cut is empty, skipping proposal");
            return Ok(());
        }

        info!(
            "Proposing tip cut with {} CARs for view {} (ci={})",
            tip_cut.cars.len(),
            self.view,
            self.ci
        );

        // Collect CARs into a vec
        let cars: Vec<_> = tip_cut.cars.into_values().collect();

        // Construct ProtoTipCut message
        let proto_tip_cut = ProtoTipCut {
            digest: vec![], // Will be computed by BlockSequencer
            parent: vec![], // Will be computed by BlockSequencer
            tips: cars,
        };

        // Send to BlockSequencer which will:
        // 1. Compute digest and parent
        // 2. Send to BlockBroadcaster
        // 3. BlockBroadcaster wraps in AppendEntries and broadcasts to all nodes
        self.consensus_sequencer_tx
            .send(proto_tip_cut)
            .await
            .map_err(|e| {
                error!("Failed to send tip cut to BlockSequencer: {:?}", e);
            })?;

        info!("Sent tip cut to BlockSequencer for sequencing and broadcasting");
        Ok(())
    }

    /// Query lane_staging for the current tip cut.
    async fn query_tip_cut(&mut self) -> Result<Option<TipCut>, ()> {
        let (reply_tx, reply_rx) = oneshot::channel();

        // Send query
        self.lane_staging_query_tx
            .send(LaneStagingQuery::GetCurrentTipCut(reply_tx))
            .await
            .map_err(|e| {
                error!("Failed to send query to LaneStaging: {:?}", e);
            })?;

        // Wait for response
        reply_rx.await.map_err(|e| {
            error!("Failed to receive tip cut from LaneStaging: {:?}", e);
        })
    }
}
