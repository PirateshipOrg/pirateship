use std::io::{Error, ErrorKind};
use std::sync::Arc;

use log::{info, trace, warn};
use tokio::sync::Mutex;

use crate::proto::consensus::ProtoAppendEntries;
use crate::rpc::SenderType;
use crate::utils::channel::{Receiver, Sender};

pub struct ForkReceiver {
    incoming_block_rx: Receiver<(ProtoAppendEntries, SenderType)>,
    storage_tx: Sender<(Vec<u8>, u64, String)>,
}

impl ForkReceiver {
    pub fn new(
        incoming_block_rx: Receiver<(ProtoAppendEntries, SenderType)>,
        storage_tx: Sender<(Vec<u8>, u64, String)>,
    ) -> Self {
        Self {
            incoming_block_rx,
            storage_tx,
        }
    }

    pub async fn run(fork_receiver: Arc<Mutex<Self>>) {
        let mut fr = fork_receiver.lock().await;

        loop {
            if let Err(_) = fr.worker().await {
                break;
            }
        }

        info!("Worker fork receiver exited.");
    }

    async fn worker(&mut self) -> Result<(), Error> {
        let incoming = self.incoming_block_rx.recv().await;
        if incoming.is_none() {
            return Err(Error::new(ErrorKind::BrokenPipe, "incoming_block_rx closed"));
        }
        let (ae, sender) = incoming.unwrap();
        trace!(
            "Received block {} from {:?}",
            ae.fork.as_ref().unwrap().serialized_blocks[0].n, sender
        );
        self.handle_incoming_block(ae, sender).await
    }

    async fn handle_incoming_block(
        &mut self,
        ae: ProtoAppendEntries,
        sender: SenderType,
    ) -> Result<(), Error> {
        let fork = match ae.fork {
            Some(f) => f,
            None => {
                warn!("Received worker block with no fork");
                return Ok(());
            }
        };

        let sender_name = match &sender {
            SenderType::Auth(name, _) => name.clone(),
            SenderType::Anon => {
                warn!("Received worker block from anon sender");
                return Ok(());
            }
        };

        for half_block in fork.serialized_blocks {
            self.storage_tx
                .send((half_block.serialized_body, half_block.n, sender_name.clone()))
                .await
                .expect("storage_tx send error");
        }

        Ok(())
    }
}
