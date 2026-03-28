use std::io::{Error, ErrorKind};
use std::sync::Arc;

use ed25519_dalek::SIGNATURE_LENGTH;
use log::{info, trace, warn};
use tokio::sync::Mutex;

use crate::config::AtomicConfig;
use crate::crypto::{hash, hash_proto_block_ser, AtomicKeyStore, HashType};
use crate::proto::consensus::{proto_block, ProtoAppendEntries};
use crate::rpc::SenderType;
use crate::utils::channel::{Receiver, Sender};
use crate::utils::{deserialize_proto_block, get_parent_hash_in_proto_block_ser};

pub struct ForkReceiver {
    config: AtomicConfig,
    keystore: AtomicKeyStore,
    incoming_block_rx: Receiver<(ProtoAppendEntries, SenderType)>,
    storage_tx: Sender<(Vec<u8>, u64, String)>,
    last_hash: Option<HashType>,
}

impl ForkReceiver {
    pub fn new(
        config: AtomicConfig,
        keystore: AtomicKeyStore,
        incoming_block_rx: Receiver<(ProtoAppendEntries, SenderType)>,
        storage_tx: Sender<(Vec<u8>, u64, String)>,
    ) -> Self {
        Self {
            config,
            keystore,
            incoming_block_rx,
            storage_tx,
            last_hash: None,
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
            let parent_hash = match get_parent_hash_in_proto_block_ser(&half_block.serialized_body) {
                Some(h) => h,
                None => {
                    warn!("Block {} has malformed serialized_body (too short)", half_block.n);
                    return Ok(());
                }
            };

            if let Some(ref expected) = self.last_hash {
                if &parent_hash != expected {
                    warn!(
                        "Hash chain broken for worker {} at block {}: expected parent {}, got {}",
                        sender_name,
                        half_block.n,
                        hex::encode(expected),
                        hex::encode(&parent_hash)
                    );
                    return Ok(());
                }
            }

            // Verify proposer signature if present
            match deserialize_proto_block(&half_block.serialized_body) {
                Ok(block) => {
                    if let Some(proto_block::Sig::ProposerSig(sig)) = &block.sig {
                        let partial_hsh = hash(&half_block.serialized_body[SIGNATURE_LENGTH..]);
                        let sender_name = sender_name.clone();
                        let sig_bytes: Result<&[u8; SIGNATURE_LENGTH], _> = sig.as_slice().try_into();
                        match sig_bytes {
                            Ok(sig_bytes) => {
                                if !self.keystore.get().verify(&sender_name, sig_bytes, &partial_hsh) {
                                    warn!("Invalid proposer signature on block {}", half_block.n);
                                    return Ok(());
                                }
                            }
                            Err(_) => {
                                warn!("Malformed signature on block {}", half_block.n);
                                return Ok(());
                            }
                        }
                    }
                }
                Err(_) => {
                    warn!("Failed to deserialize block {}", half_block.n);
                    return Ok(());
                }
            }

            self.last_hash = Some(hash_proto_block_ser(&half_block.serialized_body));

            self.storage_tx
                .send((half_block.serialized_body, half_block.n, sender_name.clone()))
                .await
                .expect("storage_tx send error");
        }

        Ok(())
    }
}
