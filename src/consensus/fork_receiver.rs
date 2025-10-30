use std::{collections::VecDeque, io::Error, sync::Arc};
use crate::{crypto::FutureHash, utils::channel::make_channel};

use log::{debug, info, warn};
use prost::Message;
use tokio::sync::{oneshot, Mutex};

use crate::{config::AtomicConfig, crypto::{CachedBlock, CryptoServiceConnector}, proto::{checkpoint::ProtoBackfillNack, consensus::{HalfSerializedBlock, ProtoAppendEntries}, rpc::ProtoPayload}, rpc::{client::PinnedClient, MessageRef, SenderType}, utils::{channel::{Receiver, Sender}, get_parent_hash_in_proto_block_ser}};

use super::logserver::LogServerQuery;


pub enum ForkReceiverCommand {
    UpdateView(u64 /* view num */, u64 /* config num */), // Also acts as a Ack for MultiPartFork
    MultipartNack(usize /* delete these many parts from the multipart buffer */),
    UseBackfillResponse(ProtoAppendEntries, SenderType),
}

/// Shortcut stats for AppendEntries
#[derive(Debug, Clone)]
pub struct AppendEntriesStats {
    pub view: u64,
    pub view_is_stable: bool,
    pub config_num: u64,
    pub sender: String,
    pub ci: u64,
}

pub struct MultipartFork {
    pub fork_future: Vec<   // vector of ...
        Option <
            oneshot::Receiver<  // futures that will return ...
                Result<CachedBlock, Error> // a block or an error
            >
        > // The option is just to make it easier to remove the future from the vector
    >,
    pub remaining_parts: usize, // How many other such MultipartForks are there?
    pub ae_stats: AppendEntriesStats,
    
}

impl MultipartFork {
    pub async fn await_all(&mut self) -> Vec<Result<CachedBlock, Error>> {
        let mut results = Vec::with_capacity(self.fork_future.len());
        for future in self.fork_future.iter_mut() {
            results.push(future.take().unwrap()
                .await.unwrap());
        }
        results
    }
}

struct ContinuityStats {
    last_ae_view: u64,
    last_ae_block_hash: FutureHash,
    waiting_on_nack_reply: bool
}

macro_rules! ask_logserver {
    ($me:expr, $query:expr, $($args:expr),+) => {
        {
            let (tx, rx) = make_channel(1);
            $me.logserver_query_tx.send($query($($args),+, tx)).await.unwrap();
            rx.recv().await.unwrap()
        }
    };
}


/// Receives AppendEntries from other nodes in the network.
/// Verifies the view change and config change sequence in the sent fork.
/// If the fork is valid, it sends the block to staging.
/// If not, this will just drop the message. No further processing/NACKing is done.
/// This WILL NOT CHECK if fork in AppendEntry and my own fork have an intersection or not.
pub struct ForkReceiver {
    config: AtomicConfig,
    crypto: CryptoServiceConnector,
    client: PinnedClient,

    view: u64,
    config_num: u64,

    fork_rx: Receiver<(ProtoAppendEntries, SenderType /* Sender */)>,
    command_rx: Receiver<ForkReceiverCommand>,
    broadcaster_tx: Sender<MultipartFork>,

    multipart_buffer: VecDeque<(Vec<HalfSerializedBlock>, AppendEntriesStats)>,

    // Invariant <blocked_on_multipart>: multipart_buffer contains only parts from one AppendEntries.
    // If multipart_buffer is empty, blocked_on_multipart must be false.
    // If blocked_on_multipart is true, multipart_buffer must not be empty
    // AND no new AppendEntries will be processed.
    blocked_on_multipart: bool,

    continuity_stats: ContinuityStats,

    logserver_query_tx: Sender<LogServerQuery>,

}


impl ForkReceiver {
    pub fn new(
        config: AtomicConfig,
        crypto: CryptoServiceConnector,
        client: PinnedClient,
        fork_rx: Receiver<(ProtoAppendEntries, SenderType)>,
        command_rx: Receiver<ForkReceiverCommand>,
        broadcaster_tx: Sender<MultipartFork>,
        logserver_query_tx: Sender<LogServerQuery>,
    ) -> Self {
        #[allow(unused_mut)]
        let mut ret = Self {
            config,
            crypto,
            client,
            view: 0,
            config_num: 0,
            fork_rx,
            command_rx,
            broadcaster_tx,
            multipart_buffer: VecDeque::new(),
            blocked_on_multipart: false,
            continuity_stats: ContinuityStats {
                last_ae_view: 0,
                last_ae_block_hash: FutureHash::None,
                waiting_on_nack_reply: false
            },
            logserver_query_tx,
        };

        #[cfg(not(feature = "view_change"))]
        {
            ret.view = 1;
            ret.config_num = 1;
        }

        ret
    }

    pub async fn run(fork_receiver: Arc<Mutex<Self>>) {
        let mut fork_receiver = fork_receiver.lock().await;

        loop {
            if let Err(_) = fork_receiver.worker().await {
                break;
            }
        }
    }

    async fn worker(&mut self) -> Result<(), ()> {
        if self.blocked_on_multipart || self.continuity_stats.waiting_on_nack_reply {
            let cmd = self.command_rx.recv().await.unwrap();
            self.handle_command(cmd).await;
        } else {
            tokio::select! {
                ae_sender = self.fork_rx.recv() => {
                    if let Some((ae, SenderType::Auth(sender, _))) = ae_sender {
                        debug!("Received AppendEntries({}) from {}", ae.fork.as_ref().unwrap().serialized_blocks.last().unwrap().n, sender);
                        self.process_fork(ae, sender).await;
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

    fn get_leader_for_view(&self, view: u64) -> String {
        self.config.get().consensus_config.get_leader_for_view(view)
    }

    async fn process_fork(&mut self, mut ae: ProtoAppendEntries, sender: String) {
        if self.continuity_stats.waiting_on_nack_reply {
            info!("Possible AE after nack!");
        }

        if !ae.view_is_stable {
            info!("Got New View message for view {}", ae.view);
        }
        
        if ae.view < self.view || ae.config_num < self.config_num {
            warn!("Old view AppendEntry received: ae view {} < my view {} or ae config num {} < my config num {}", ae.view, self.view, ae.config_num, self.config_num);
            return;
        }

        if ae.config_num == self.config_num {
            // If in the same config, I can check if the sender is supposed to send this AE.
            let leader = self.get_leader_for_view(ae.view);
            if leader != sender {
                return;
            }
        }


        // BELOW IS A TEST FOR NACKS. DISABLED IN PRODUCTION.
        // if self.config.get().net_config.name == "node7" 
        // && ae.view_is_stable
        // && (ae.fork.as_ref().unwrap().serialized_blocks.last().unwrap().n >= 10000
        //     && ae.fork.as_ref().unwrap().serialized_blocks.last().unwrap().n < 10105)
        // && !self.continuity_stats.waiting_on_nack_reply
        // {
        //     info!("Skipping to generate Nack!");
        //     return;
        // }

        // Not going to check for ViewLock here.
        // Staging takes care of that.
        // But at least I can make sure that the AppendEntries start from a common prefix.
        if self.ensure_common_prefix(&ae).await.is_err() {
            // Send Nack
            self.send_nack(sender, ae).await;
            info!("Returning after sending nack!");
            return;
        }

        let fork = match &mut ae.fork {
            Some(f) => f,
            None => return,
        };




        // if ae.view > self.view {
            // The first block of each view from self.view+1..=ae.view must have view_is_stable = false
            let mut test_view = self.view;
            for block in &fork.serialized_blocks {
                if block.view > test_view {
                    if block.view_is_stable {
                        self.send_nack(sender, ae).await;
                        return;
                    } else {
                        info!("Got New View message for view {}", block.view);
                    }

                    test_view = block.view;
                }
            }

            if test_view < ae.view {
                warn!("Malformed AppendEntries: Missing blocks for view {} in AppendEntries", ae.view);
                // NAck the AppendEntries; ask to backfill.
                self.send_nack(sender, ae).await;
                return;
            }
        // }

        self.continuity_stats.waiting_on_nack_reply = false;




        // The fork will have the following general structure
        // (view1, config1) <- (view1, config1) <- ... <- (view1, config1)
        // <- (view2, config1, <New View block with view_is_stable = false>)
        // <- ... <- (ViewN, config2, <New View block with view_is_stable = false>) <- (viewN, config2) ...

        // Since keystore will change with config change (or before that, but definitely not after),
        // we can only verify blocks with same config + the first (unstable) block of the next config, in parallel.
        // Once we verify and forward that to staging,
        // we must wait until staging updates its view and config.
        let mut parts = Vec::new();
        let mut curr_part = Some(Vec::new());
        let mut curr_config = self.config_num;

        for block in fork.serialized_blocks.drain(..) {
            if block.config_num == curr_config {
                curr_part.as_mut().unwrap().push(block);
            } else {
                curr_config = block.config_num;
                // First block of the new config must have view_is_stable = false
                if block.view_is_stable {
                    warn!("Invalid block in AppendEntries: First block for config {} has view_is_stable = true", curr_config);
                    
                    return;
                }
                curr_part.as_mut().unwrap().push(block);
                if let Some(part) = curr_part.take() {
                    parts.push(part);
                }

                curr_part = Some(Vec::new());
            }
        }

        if let Some(part) = curr_part.take() {
            if part.len() > 0 {
                parts.push(part);
            }
        }

        if parts.len() == 0 {
            // Unreachable
            return;
        }

        let first_part = parts.remove(0);

        let (multipart_fut, mut hash_receivers) = self.crypto.prepare_fork(first_part, parts.len(), AppendEntriesStats {
            view: ae.view,
            view_is_stable: ae.view_is_stable,
            config_num: ae.config_num,
            sender: sender.clone(),
            ci: ae.commit_index,
        }, self.byzantine_liveness_threshold()).await;
        self.broadcaster_tx.send(multipart_fut).await.unwrap();

        self.continuity_stats.last_ae_block_hash = FutureHash::FutureResult(hash_receivers.pop().unwrap());

        if parts.len() > 0 {
            assert_eq!(self.multipart_buffer.len(), 0); // Due to the Invariant <blocked_on_multipart>
            self.multipart_buffer.extend(parts.iter().map(|part| (part.clone(), AppendEntriesStats {
                view: ae.view,
                view_is_stable: ae.view_is_stable,
                config_num: ae.config_num,
                sender: sender.clone(),
                ci: ae.commit_index,
            })));
            self.blocked_on_multipart = true;
        }


    }

    async fn handle_command(&mut self, cmd: ForkReceiverCommand) {
        match cmd {
            ForkReceiverCommand::UpdateView(view, config_num) => {
                if self.view != view {
                    self.continuity_stats.last_ae_view = view;
                    self.continuity_stats.last_ae_block_hash = FutureHash::None;
                }
                self.view = view;
                let config_is_updating = self.config_num < config_num;
                self.config_num = config_num;

                if config_is_updating && self.multipart_buffer.len() > 0 {
                    // Forward the next multipart buffer
                    let (part, ae_stats) = self.multipart_buffer.pop_front().unwrap();
                    
                    // If this is the last part, then the sender must be the leader for this view in this config.
                    let maybe_legit =
                    if self.multipart_buffer.len() == 0 {
                        let leader = self.get_leader_for_view(self.view);
                        if leader == ae_stats.sender {
                            true
                        } else {
                            false
                        }
                    } else {
                        true
                    };

                    if maybe_legit {
                        let (multipart_fut, mut hash_receivers) = self.crypto.prepare_fork(part, self.multipart_buffer.len(), ae_stats, self.byzantine_liveness_threshold()).await;
                        self.broadcaster_tx.send(multipart_fut).await.unwrap();
                        self.continuity_stats.last_ae_block_hash = FutureHash::FutureResult(hash_receivers.pop().unwrap());
                    }

                }

                if self.multipart_buffer.len() == 0 {
                    self.blocked_on_multipart = false;
                }
            },
            ForkReceiverCommand::MultipartNack(n) => {
                assert_eq!(n, self.multipart_buffer.len()); // Due to Invariant <blocked_on_multipart>
                for _ in 0..n {
                    self.multipart_buffer.pop_front();
                }

                if self.multipart_buffer.len() == 0 {
                    self.blocked_on_multipart = false;
                }
            },
            ForkReceiverCommand::UseBackfillResponse(ae, sender) => {
                let (name, _) = sender.to_name_and_sub_id();
                self.process_fork(ae, name).await;
            }
        }
    }


    async fn send_nack(&mut self, sender: String, ae: ProtoAppendEntries) {
        info!("Nacking AE to {}", sender);
        self.continuity_stats.waiting_on_nack_reply = true;
        let first_block_n = ae.fork.as_ref().map_or(ae.commit_index, |f| f.serialized_blocks.first().unwrap().n);
        let last_index_needed = if first_block_n > 100 { first_block_n - 100 } else { 0 };
        
        let hints = ask_logserver!(self, LogServerQuery::GetHints, last_index_needed);
        
        let my_name = self.config.get().net_config.name.clone();
        
        let nack = ProtoBackfillNack {
            hints,
            last_index_needed,
            reply_name: my_name,
            origin: Some(crate::proto::checkpoint::proto_backfill_nack::Origin::Ae(ae)),
        };

        let payload = ProtoPayload {
            message: Some(crate::proto::rpc::proto_payload::Message::BackfillNack(nack)),
        };


        let buf = payload.encode_to_vec();
        let sz = buf.len();

        let _ = PinnedClient::send(&self.client, &sender,
            MessageRef(&buf, sz, &SenderType::Anon)
        ).await;

    }


    /// This doesn't have an exact logic.
    /// Since due to no locking, the log server works with a slightly outdated view of the log than staging.
    /// For safety, it is ok to send a nack when the block could pass through staging.
    /// But it is not ok to send a block to staging when it should have been nacked.
    /// Since staging doesn't have the context to send the nack.
    /// 
    /// Logic:
    /// - If the parent of the ae was the last one this fork receiver forwarded, then the fork may be valid. Forward it.
    /// - If the parent of the ae is seen by the log server, then the fork may be valid. Forward it.
    /// If none of these cases match, then there is high probability you do actually need to backfill.
    /// Assumption on Logserver: Eventually, the log server has all the log entries that staging has.
    async fn ensure_common_prefix(&mut self, ae: &ProtoAppendEntries) -> Result<(), ()> {
        let fork = ae.fork.as_ref().unwrap();
        if fork.serialized_blocks.len() == 0 {
            warn!("Empty AppendEntries received");
            return Ok(());
        }
        
        let parent_hash = 
            get_parent_hash_in_proto_block_ser(
                &fork.serialized_blocks.first().unwrap().serialized_body
            ).unwrap();
        
        let hsh = match self.continuity_stats.last_ae_block_hash.take() {
            FutureHash::None => None,
            FutureHash::Immediate(hsh) => {
                self.continuity_stats.last_ae_block_hash = FutureHash::Immediate(hsh.clone());
                Some(hsh.clone())
            },
            FutureHash::Future(receiver) => {
                let hsh = receiver.await.unwrap();
                self.continuity_stats.last_ae_block_hash = FutureHash::Immediate(hsh.clone());
                Some(hsh)
            },
            FutureHash::FutureResult(receiver) => {
                let hsh = receiver.await.unwrap();
                if hsh.is_err() {
                    self.continuity_stats.last_ae_block_hash = FutureHash::None;
                    None
                } else {
                    let hsh = hsh.unwrap();
                    self.continuity_stats.last_ae_block_hash = FutureHash::Immediate(hsh.clone());
                    Some(hsh)
                }
            },
        };
        if hsh.is_some() {
            let hsh = hsh.unwrap();
            let local_hash_check = hsh.eq(&parent_hash);

            if local_hash_check {
                return Ok(());
            }
        }

        // Ask Logserver
        let parent_n = fork.serialized_blocks.first().unwrap().n - 1;
        let _logserver_has_block = ask_logserver!(self, LogServerQuery::CheckHash, parent_n, parent_hash);


        if _logserver_has_block { Ok(()) } else { Err(()) }
    }

    fn byzantine_liveness_threshold(&self) -> usize {
        let n = self.config.get().consensus_config.node_list.len();
        
        #[cfg(feature = "platforms")]
        {
            let u = self.config.get().consensus_config.liveness_u as usize;
            n - u
        }

        #[cfg(not(feature = "platforms"))]
        {
            let f = n / 3;
            n - f
        }
    }
}