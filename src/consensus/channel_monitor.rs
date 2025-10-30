use std::collections::HashMap;

use log::info;

use crate::{config::AtomicConfig, utils::channel::{Receiver, Sender}};

pub struct ChannelMonitor {
    _config: AtomicConfig,
    channels: HashMap<String, ChannelInfo>,
}

enum ChannelInfo {
    Sender(Box<dyn ChannelSender + Send + Sync>),
    Receiver(Box<dyn ChannelReceiver + Send + Sync>),
}

trait ChannelSender {
    fn len(&self) -> usize;
}

trait ChannelReceiver {
    fn len(&self) -> usize;
}

impl<T: Send + 'static> ChannelSender for Sender<T> {
    fn len(&self) -> usize {
        self.len()
    }
}

impl<T: Send + 'static> ChannelReceiver for Receiver<T> {
    fn len(&self) -> usize {
        self.len()
    }
}

impl ChannelMonitor {
    pub fn new(config: AtomicConfig) -> Self {
        Self {
            _config: config,
            channels: HashMap::new(),
        }
    }

    pub fn register_sender<T: Send + 'static>(&mut self, name: String, sender: Sender<T>) {
        self.channels.insert(name, ChannelInfo::Sender(Box::new(sender)));
    }

    pub fn register_receiver<T: Send + 'static>(&mut self, name: String, receiver: Receiver<T>) {
        self.channels.insert(name, ChannelInfo::Receiver(Box::new(receiver)));
    }

    pub async fn log_stats(&self) {
        let mut channel_stats = Vec::new();
        
        for (name, channel_info) in &self.channels {
            let len = match channel_info {
                ChannelInfo::Sender(sender) => sender.len(),
                ChannelInfo::Receiver(receiver) => receiver.len(),
            };
            
            channel_stats.push(format!("{}={}", name, len));
        }

        if !channel_stats.is_empty() {
            info!("Channel lengths: {}", channel_stats.join(", "));
        }
    }


}
