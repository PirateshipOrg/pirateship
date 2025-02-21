use std::{collections::HashMap, time::{Duration, Instant}};
use std::cmp::Eq;
use std::hash::Hash;

use indexmap::IndexMap;
use log::info;

#[derive(Debug, Clone)]
struct PerfEntry {
    total_time: Duration,
    count: usize,
}

impl PerfEntry {
    fn new() -> Self {
        Self {
            total_time: Duration::new(0, 0),
            count: 0,
        }
    }

    fn add_time(&mut self, time: Duration) {
        self.total_time += time;
        self.count += 1;
    }

    fn avg_time(&self) -> Duration {
        if self.count > 0 {
            self.total_time.div_f64(self.count as f64)
        } else {
            Duration::new(0, 0)
        }
    }
}

#[derive(Debug, Clone)]
pub struct PerfCounter<K> {
    name: String,
    entry_starts: HashMap<K, Instant>,
    event_stats: IndexMap<String, PerfEntry>
}

impl<K: Eq + Hash> PerfCounter<K> {
    pub fn new(name: &str, event_order: &Vec<&str>) -> Self {
        Self {
            name: name.to_string(),
            entry_starts: HashMap::new(),
            event_stats: event_order.into_iter()
                .map(|name| (name.to_string(), PerfEntry::new())).collect()
        }
    }

    pub fn register_new_entry(&mut self, entry: K) {
        self.entry_starts.insert(entry, Instant::now());
    }

    pub fn deregister_entry(&mut self, entry: &K) {
        self.entry_starts.remove(entry);
    }

    pub fn new_event(&mut self, event: &str, entry: &K) {
        if let Some(entry) = self.entry_starts.get(entry) {
            let elapsed = entry.elapsed();
            let event_stats = self.event_stats.get_mut(event);
            if let Some(event_stats) = event_stats {
                event_stats.add_time(elapsed);
            }
        }
    }

    pub fn log_aggregate(&self) {
        let mut last_event_time = Duration::new(0, 0);
        for (event, stats) in self.event_stats.iter() {
            let avg_time = stats.avg_time();
            
            info!("[Perf:{}] Event: {}, Avg time: {} us, Avg cumulative time: {} us",
                self.name,
                event,
                avg_time.as_micros() - last_event_time.as_micros(),
                avg_time.as_micros()
            );
            last_event_time = stats.avg_time();
        }
    }
}