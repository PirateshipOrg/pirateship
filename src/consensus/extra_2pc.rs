use std::{collections::HashMap, future::Future, sync::Arc};

use bytes::{BufMut as _, BytesMut};
use log::{error, info, trace, warn};
use prost::Message;
use tokio::sync::{oneshot, Mutex};

use crate::{
    config::AtomicConfig,
    proto::{
        client::{ProtoClientReply, ProtoClientRequest},
        consensus::ProtoVote,
        execution::{
            ProtoTransaction, ProtoTransactionOp, ProtoTransactionOpResult, ProtoTransactionOpType,
            ProtoTransactionPhase, ProtoTransactionResult,
        },
        rpc::ProtoPayload,
    },
    rpc::{client::PinnedClient, PinnedMessage},
    utils::{
        channel::{Receiver, Sender},
        StorageServiceConnector,
    },
};

pub struct TwoPCCommand {
    key: String,
    value: Vec<u8>,
    // result_sender: oneshot::Sender<u64 /* index assigned */>,
    action: EngraftActionAfterFutureDone,
}

impl TwoPCCommand {
    pub fn new(key: String, value: Vec<u8>, action: EngraftActionAfterFutureDone) -> Self {
        Self { key, value, action }
    }
}

pub struct TwoPCHandler {
    config: AtomicConfig,
    client: PinnedClient,
    storage: Option<StorageServiceConnector>,
    storage2: StorageServiceConnector,

    local_index_counter: HashMap<String, u64>,
    client_tag_counter: u64,

    command_rx: Receiver<TwoPCCommand>,
    staging_tx: Sender<EngraftActionAfterFutureDone>,

    /// 2PC happens as a sequence of on_receive Transactions.
    /// So as to bypass the consensus protocol.
    /// WRITE ops will be treated as Store (aka Phase 1) commands.
    /// CUSTOM ops will be treated as ConfirmStore (aka Phase 2) commands.
    phase_message_rx: Option<Receiver<(ProtoTransaction, oneshot::Sender<ProtoTransactionResult>)>>,
}

impl TwoPCHandler {
    pub fn new(
        config: AtomicConfig,
        client: PinnedClient,
        storage: StorageServiceConnector,
        storage2: StorageServiceConnector,
        command_rx: Receiver<TwoPCCommand>,
        phase_message_rx: Receiver<(ProtoTransaction, oneshot::Sender<ProtoTransactionResult>)>,
        staging_tx: Sender<EngraftActionAfterFutureDone>,
    ) -> Self {
        Self {
            config,
            client,
            storage: Some(storage),
            storage2,
            command_rx,
            phase_message_rx: Some(phase_message_rx),
            local_index_counter: HashMap::new(),
            client_tag_counter: 0,
            staging_tx,
        }
    }

    pub async fn run(twopc: Arc<Mutex<Self>>) {
        let mut twopc = twopc.lock().await;
        let storage = twopc.storage.take().unwrap();
        let phase_message_rx = twopc.phase_message_rx.take().unwrap();
        tokio::spawn(async move {
            let mut storage = storage;
            while let Some((tx, result_sender)) = phase_message_rx.recv().await {
                Self::handle_phase_message(&mut storage, tx, result_sender).await;
            }
        });

        loop {
            twopc.worker().await;
        }
    }

    async fn worker(&mut self) {
        if let Some(command) = self.command_rx.recv().await {
            self.handle_command(command).await;
        }
    }

    async fn handle_command(&mut self, cmd: TwoPCCommand) {
        let index = self.local_index_counter.entry(cmd.key.clone()).or_insert(0);
        *index += 1;

        let _index = *index;

        let my_name = self.config.get().net_config.name.clone();
        let final_key_name = format!("{}:{}", my_name, cmd.key);
        let mut val = BytesMut::with_capacity(8 + cmd.value.len());
        val.put_u64(_index);
        val.put_slice(&cmd.value);

        // First: Store locally.
        let ack = self
            .storage2
            .put_raw(final_key_name.clone(), val.to_vec())
            .await;
        if let Err(e) = ack.await {
            error!("Failed to store value: {:?}", e);
            return;
        }

        // let _ = cmd.result_sender.send(_index);

        // Second: Broadcast to all nodes and collect majority acks.
        while !self.phase1(&final_key_name, &val).await {
            // Retry until success.
        }

        // Third: Broadcast ConfirmStore and collect majority acks.
        while !self.phase2(&final_key_name, &val).await {
            // Retry until success.
        }

        // Finally send the result back
        let _ = self.staging_tx.send(cmd.action).await;

        trace!("2PC success for key {} index {}", cmd.key, _index);
    }

    async fn handle_phase_message(
        storage: &mut StorageServiceConnector,
        tx: ProtoTransaction,
        result_sender: oneshot::Sender<ProtoTransactionResult>,
    ) {
        let mut res = ProtoTransactionResult {
            result: vec![ProtoTransactionOpResult {
                success: false,
                values: vec![],
            }],
        };

        trace!("Handling 2PC phase message: {:?}", tx);

        if !tx.is_2pc {
            error!("Transaction is not 2PC");
            let _ = result_sender.send(res);
            return;
        }

        if tx.on_receive.is_none() {
            error!("Transaction has no on_receive phase");
            let _ = result_sender.send(res);
            return;
        }

        let ops = tx.on_receive.unwrap().ops;
        if ops.is_empty() {
            warn!("Transaction has no ops");
            let _ = result_sender.send(res);
            return;
        }

        let op = &ops[0];
        if op.operands.len() < 2 {
            warn!("Transaction has invalid number of operands");
            let _ = result_sender.send(res);
            return;
        }

        let key = String::from_utf8(op.operands[0].clone());
        if let Err(key) = key {
            warn!("Failed to decode key: {:?}", key);
            let _ = result_sender.send(res);
            return;
        }

        let key = key.unwrap();

        let val = op.operands[1].clone();

        let op_type = ProtoTransactionOpType::from_i32(op.op_type);

        match op_type {
            Some(ProtoTransactionOpType::Write) => {
                let ack = storage.put_raw(key, val).await;
                if let Err(e) = ack.await {
                    error!("Failed to store value: {:?}", e);
                    let _ = result_sender.send(res);
                    return;
                }

                res.result[0].success = true;
            }
            Some(ProtoTransactionOpType::Custom) => {
                let stored_val = storage.get_raw(key).await;
                if let Err(e) = stored_val {
                    error!("Failed to get stored value: {:?}", e);
                    let _ = result_sender.send(res);
                    return;
                }

                let stored_val = stored_val.unwrap();
                if stored_val != val {
                    warn!("Stored value does not match: {:?} != {:?}", stored_val, val);
                    let _ = result_sender.send(res);
                    return;
                }

                res.result[0].success = true;
            }
            _ => {
                warn!("Invalid op_type: {:?}", op_type);
                let _ = result_sender.send(res);
                return;
            }
        }

        trace!("2PC phase message success for {:?}", res);
        let _ = result_sender.send(res);
    }

    async fn phase1(&mut self, key: &str, value: &BytesMut) -> bool {
        self.generic_phase(key, value, ProtoTransactionOpType::Write)
            .await
    }

    async fn phase2(&mut self, key: &str, value: &BytesMut) -> bool {
        self.generic_phase(key, value, ProtoTransactionOpType::Custom)
            .await
    }

    async fn generic_phase(
        &mut self,
        key: &str,
        value: &BytesMut,
        op_type: ProtoTransactionOpType,
    ) -> bool {
        let tx = ProtoTransaction {
            on_receive: Some(ProtoTransactionPhase {
                ops: vec![ProtoTransactionOp {
                    op_type: op_type.into(),
                    operands: vec![key.as_bytes().to_vec(), value.to_vec(), vec![0u8; 1024]],
                }],
            }),
            on_crash_commit: None,
            on_byzantine_commit: None,
            is_reconfiguration: false,
            is_2pc: true,
        };

        let my_name = self.config.get().net_config.name.clone();
        self.client_tag_counter += 1;

        let payload = ProtoPayload {
            message: Some(crate::proto::rpc::proto_payload::Message::ClientRequest(
                ProtoClientRequest {
                    tx: Some(tx),
                    origin: my_name.clone(),
                    sig: vec![0u8; 1],
                    client_tag: self.client_tag_counter,
                },
            )),
        };
        let buf = payload.encode_to_vec();
        let sz = buf.len();

        let msg = PinnedMessage::from(buf, sz, crate::rpc::SenderType::Anon);

        let send_list = self
            .config
            .get()
            .consensus_config
            .node_list
            .iter()
            .filter(|n| n != &&my_name)
            .cloned()
            .collect::<Vec<_>>();

        // send_list.truncate(1);

        // This blocks till responses from all nodes are received.
        // TODO: Change it so that it returns after majority quorum.
        let n = self.config.get().consensus_config.node_list.len();
        let majority = n / 2 + 1;

        let res = PinnedClient::broadcast_and_await_quorum_reply(
            &self.client,
            &send_list,
            &msg,
            majority - 1,
        )
        .await;

        if let Err(e) = res {
            error!("Failed to broadcast: {:?}", e);
            return false;
        }
        let res = res.unwrap();
        // let res = Vec::<PinnedMessage>::new();

        // Count success acks.
        let success_acks = res.iter().map(|msg| {
            let sz = msg.as_ref().1;
            let payload = ProtoClientReply::decode(&msg.as_ref().0.as_slice()[..sz]);
            if let Err(payload) = payload {
                warn!("Failed to decode ProtoClientReply: {:?}", payload);
                return false;
            }
            let payload = payload.unwrap();
            if payload.client_tag != self.client_tag_counter {
                warn!("Client tag mismatch: {} != {}", payload.client_tag, self.client_tag_counter);
                return false;
            }

            let reply = payload.reply;
            if reply.is_none() {
                warn!("Reply is None");
                return false;
            }

            let reply = reply.unwrap();
            match reply {
                crate::proto::client::proto_client_reply::Reply::Receipt(proto_transaction_receipt) => {
                    let results = proto_transaction_receipt.results;
                    if results.is_none() {
                        warn!("Results is none");
                        return false;
                    }

                    let result = results.unwrap().result;
                    if result.is_empty() {
                        warn!("Result is empty");
                        return false;
                    }

                    let result = &result[0];

                    result.success
                },
                _ => {
                    warn!("Reply is not Receipt");
                    false
                }
            }
        }).filter(|x| *x).count() + 1 /* for myself */;

        success_acks >= majority
    }
}

pub enum EngraftActionAfterFutureDone {
    None,
    AsLeader(String, ProtoVote),
    AsFollower(String, PinnedMessage),
}
pub struct EngraftTwoPCFuture {
    pub block_n: u64,
    pub raft_meta_res_rx: oneshot::Receiver<u64>,
    pub log_meta_res_rx: oneshot::Receiver<u64>,
    pub raft_meta_received_val: Option<u64>,
    pub log_meta_received_val: Option<u64>,
    pub action: Option<EngraftActionAfterFutureDone>,
}

impl EngraftTwoPCFuture {
    pub fn new(
        block_n: u64,
        raft_meta_res_rx: oneshot::Receiver<u64>,
        log_meta_res_rx: oneshot::Receiver<u64>,
        action: EngraftActionAfterFutureDone,
    ) -> Self {
        Self {
            block_n,
            raft_meta_res_rx,
            log_meta_res_rx,
            raft_meta_received_val: None,
            log_meta_received_val: None,
            action: Some(action),
        }
    }

    pub fn is_ready(&mut self) -> bool {
        if self.raft_meta_received_val.is_none() {
            match self.raft_meta_res_rx.try_recv() {
                Ok(val) => {
                    self.raft_meta_received_val = Some(val);
                }
                _ => {}
            };
        }

        if self.log_meta_received_val.is_none() {
            match self.log_meta_res_rx.try_recv() {
                Ok(val) => {
                    self.log_meta_received_val = Some(val);
                }
                _ => {}
            };
        }

        self.raft_meta_received_val.is_some() && self.log_meta_received_val.is_some()
    }

    pub async fn wait(mut self) -> bool {
        if self.raft_meta_received_val.is_none() {
            match self.raft_meta_res_rx.await {
                Ok(val) => {
                    self.raft_meta_received_val = Some(val);
                }
                _ => {}
            };
        }

        if self.log_meta_received_val.is_none() {
            match self.log_meta_res_rx.await {
                Ok(val) => {
                    self.log_meta_received_val = Some(val);
                }
                _ => {}
            };
        }

        self.raft_meta_received_val.is_some() && self.log_meta_received_val.is_some()
    }
}

impl Future for EngraftTwoPCFuture {
    type Output = EngraftActionAfterFutureDone;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        if self.is_ready() {
            std::task::Poll::Ready(self.action.take().unwrap())
        } else {
            std::task::Poll::Pending
        }
    }
}
