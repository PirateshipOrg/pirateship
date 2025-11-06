use std::{
    collections::{HashMap, VecDeque},
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};

use log::info;
use nix::libc::exit;

use crate::utils::{channel::Receiver, timer::ResettableTimer};

pub enum ClientWorkerStat {
    CrashCommitLatency(Duration),
    ByzCommitLatency(Duration),
    ByzCommitPending(usize /* client_id */, usize /* pending size */),
}

pub struct ClientStatLogger {
    stat_rx: Receiver<ClientWorkerStat>,
    log_timer: Arc<Pin<Box<ResettableTimer>>>,
    average_window: Duration,
    max_duration: Duration,

    crash_commit_latency_window: VecDeque<(
        Instant,  /* when it was registered */
        Duration, /* latency value */
    )>,

    byz_commit_latency_window: VecDeque<(Instant, Duration)>,

    byz_commit_pending_per_worker: HashMap<usize, usize>,
}

impl ClientStatLogger {
    pub fn new(
        stat_rx: Receiver<ClientWorkerStat>,
        interval: Duration,
        average_window: Duration,
        max_duration: Duration,
    ) -> Self {
        let log_timer = ResettableTimer::new(interval);
        Self {
            stat_rx,
            log_timer,
            average_window,
            crash_commit_latency_window: VecDeque::new(),
            byz_commit_latency_window: VecDeque::new(),
            byz_commit_pending_per_worker: HashMap::new(),
            max_duration,
        }
    }

    pub async fn run(&mut self) {
        self.log_timer.run().await;

        let logger_start_time = Instant::now();

        while logger_start_time.elapsed() < self.max_duration {
            tokio::select! {
                _ = self.log_timer.wait() => {
                    self.log_stats();
                }
                entry = self.stat_rx.recv() => {
                    if let Some(stat) = entry {
                        self.collect_stat(stat);
                    } else {
                        break;
                    }
                }
            }
        }

        info!(
            "Logging over after {} s",
            logger_start_time.elapsed().as_secs()
        );
        self.log_stats();
    }

    fn collect_stat(&mut self, stat: ClientWorkerStat) {
        match stat {
            ClientWorkerStat::CrashCommitLatency(latency) => {
                while let Some((registered_time, _latency)) =
                    self.crash_commit_latency_window.front()
                {
                    if registered_time.elapsed() > self.average_window {
                        self.crash_commit_latency_window.pop_front();
                    } else {
                        break;
                    }
                }
                self.crash_commit_latency_window
                    .push_back((Instant::now(), latency));
            }
            ClientWorkerStat::ByzCommitLatency(latency) => {
                while let Some((registered_time, _latency)) = self.byz_commit_latency_window.front()
                {
                    if registered_time.elapsed() > self.average_window {
                        self.byz_commit_latency_window.pop_front();
                    } else {
                        break;
                    }
                }
                self.byz_commit_latency_window
                    .push_back((Instant::now(), latency));
            }
            ClientWorkerStat::ByzCommitPending(id, pending) => {
                self.byz_commit_pending_per_worker.insert(id, pending);
            }
        }
    }

    fn log_stats(&mut self) {
        let crash_commit_avg = if self.crash_commit_latency_window.len() > 0 {
            self.crash_commit_latency_window
                .iter()
                .fold(Duration::from_secs(0), |acc, (_, latency)| acc + *latency)
                .as_secs_f64()
                / self.crash_commit_latency_window.len() as f64
        } else {
            0.0
        };
        let byz_commit_avg = if self.byz_commit_latency_window.len() > 0 {
            self.byz_commit_latency_window
                .iter()
                .fold(Duration::from_secs(0), |acc, (_, latency)| acc + *latency)
                .as_secs_f64()
                / self.byz_commit_latency_window.len() as f64
        } else {
            0.0
        };

        info!(
            "Average Crash commit latency: {} us, Average Byz commit latency: {} us",
            (crash_commit_avg * 1.0e+6) as u64,
            (byz_commit_avg * 1.0e+6) as u64
        );

        let total_pending = self
            .byz_commit_pending_per_worker
            .iter()
            .map(|(_, pending)| *pending)
            .sum::<usize>();
        let max_pending = self
            .byz_commit_pending_per_worker
            .iter()
            .map(|(_, pending)| *pending)
            .max()
            .unwrap_or(0);
        let min_pending = self
            .byz_commit_pending_per_worker
            .iter()
            .map(|(_, pending)| *pending)
            .min()
            .unwrap_or(0);

        info!(
            "Total Byz commit pending: {}, Max pending: {}, Min pending: {}",
            total_pending, max_pending, min_pending
        );
    }
}
