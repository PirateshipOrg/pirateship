use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use log::{debug, error, info, trace};
use nix::libc::stat;
use prost::Message as _;
use tokio::{sync::oneshot::error, task::JoinSet, time::sleep};

use super::{
    logger::ClientWorkerStat,
    workload_generators::{Executor, PerWorkerWorkloadGenerator},
};
use crate::rpc::MessageRef;
use crate::{
    config::ClientConfig,
    proto::{
        client::{self, ProtoClientReply, ProtoClientRequest},
        rpc::ProtoPayload,
    },
    rpc::client::PinnedClient,
    utils::channel::{make_channel, Receiver, Sender},
};

pub struct ClientWorker<Gen: PerWorkerWorkloadGenerator> {
    config: ClientConfig,
    client: PinnedClient,
    generator: Gen,
    id: usize,
    stat_tx: Sender<ClientWorkerStat>,
}

#[derive(Debug, Clone)]
struct CheckerTask {
    start_time: Instant,
    wait_from: String,
    id: u64,
    executor_mode: Executor,
}

enum CheckerResponse {
    TryAgain(
        CheckerTask,
        Option<Vec<String>>, /* New Node list */
        Option<usize>,       /* New Leader id */
    ),
    Success(u64 /* id */),
}

struct OutstandingRequest {
    id: u64,
    payload: Vec<u8>,
    executor_mode: Executor,
    last_sent_to: String,
    start_time: Instant,
}

impl OutstandingRequest {
    pub fn get_checker_task(&self) -> CheckerTask {
        CheckerTask {
            start_time: self.start_time.clone(),
            wait_from: self.last_sent_to.clone(),
            id: self.id,
            executor_mode: self.executor_mode.clone(),
        }
    }

    pub fn default() -> Self {
        Self {
            id: 0,
            payload: Vec::new(),
            last_sent_to: String::new(),
            start_time: Instant::now(),
            executor_mode: Executor::Any,
        }
    }
}

impl<Gen: PerWorkerWorkloadGenerator + Send + Sync + 'static> ClientWorker<Gen> {
    pub fn new(
        config: ClientConfig,
        client: PinnedClient,
        generator: Gen,
        id: usize,
        stat_tx: Sender<ClientWorkerStat>,
    ) -> Self {
        Self {
            config,
            client,
            generator,
            id,
            stat_tx,
        }
    }

    pub async fn launch(mut worker: Self, js: &mut JoinSet<()>) {
        // This will act as a semaphore.
        // Anytime the checker task processes a reply successfully, it sends a `Success` message to the generator task.
        // The generator waits to receive this message before sending the next request.
        // However, if the generator task receives a `TryAgain` message, it will send the same request again.
        let max_outstanding_requests = worker.config.workload_config.max_concurrent_requests;
        let (backpressure_tx, backpressure_rx) = make_channel(max_outstanding_requests);

        // This is to let the checker task know about new requests.
        let (generator_tx, generator_rx) = make_channel(max_outstanding_requests);

        let _client = worker.client.clone();
        let _stat_tx = worker.stat_tx.clone();
        let _backpressure_tx = backpressure_tx.clone();

        let id = worker.id;
        js.spawn(async move {
            // Fill the backpressure channel with `Success` messages.
            // So that the generator task can start sending requests.
            for _ in 0..max_outstanding_requests {
                backpressure_tx
                    .send(CheckerResponse::Success(0))
                    .await
                    .unwrap();
            }

            // Can't let the checker_task consume this worker (or lock it for indefinite time).
            Self::checker_task(backpressure_tx, generator_rx, _client, _stat_tx, id).await;
        });

        js.spawn(async move {
            worker
                .generator_task(generator_tx, backpressure_rx, _backpressure_tx, id)
                .await;
        });
    }

    async fn checker_task(
        backpressure_tx: Sender<CheckerResponse>,
        generator_rx: Receiver<CheckerTask>,
        client: PinnedClient,
        stat_tx: Sender<ClientWorkerStat>,
        id: usize,
    ) {
        let mut waiting_for_byz_response = HashMap::<u64, CheckerTask>::new();
        let mut out_of_order_byz_response = HashMap::<u64, Instant>::new();
        let mut alleged_leader = String::new();
        loop {
            match generator_rx.recv().await {
                Some(req) => {
                    if alleged_leader.len() == 0 && req.executor_mode == Executor::Leader {
                        alleged_leader = req.wait_from.clone();
                    }

                    if alleged_leader != req.wait_from && req.executor_mode == Executor::Leader {
                        // This is a bug.
                        trace!(
                            "Leader changed from {} to {}. This may be a bug.",
                            alleged_leader,
                            req.wait_from
                        );
                    }
                    // This is a new request.
                    if let Some(byz_resp_time) = out_of_order_byz_response.remove(&req.id) {
                        // Got the response before, Nice!
                        if byz_resp_time > req.start_time {
                            let latency = byz_resp_time - req.start_time;
                            let _ = stat_tx
                                .send(ClientWorkerStat::ByzCommitLatency(latency))
                                .await;
                        } else {
                            error!("Byzantine response received before the request was sent. This is a bug.");
                        }
                    } else {
                        if req.executor_mode == Executor::Leader {
                            // If it is Executor::Any, it it probably a read request. There will be no byz commit.
                            waiting_for_byz_response.insert(req.id, req.clone());
                        }
                    }

                    if req.executor_mode == Executor::Leader {
                        let _ = stat_tx
                            .send(ClientWorkerStat::ByzCommitPending(
                                id,
                                waiting_for_byz_response.len(),
                            ))
                            .await;
                    }

                    // We will wait for the response.
                    let res = PinnedClient::await_reply(&client, &req.wait_from).await;
                    if res.is_err() {
                        // We need to try again.
                        let _ = backpressure_tx
                            .send(CheckerResponse::TryAgain(req, None, None))
                            .await;
                        continue;
                    }
                    let msg = res.unwrap();
                    let sz = msg.as_ref().1;
                    let resp = ProtoClientReply::decode(&msg.as_ref().0.as_slice()[..sz]);
                    if resp.is_err() {
                        // We need to try again.
                        let _ = backpressure_tx
                            .send(CheckerResponse::TryAgain(req, None, None))
                            .await;
                        continue;
                    }

                    let resp = resp.unwrap();

                    match resp.reply {
                        Some(client::proto_client_reply::Reply::Receipt(receipt)) => {
                            let _ = backpressure_tx.send(CheckerResponse::Success(req.id)).await;
                            let _ = stat_tx
                                .send(ClientWorkerStat::CrashCommitLatency(
                                    req.start_time.elapsed(),
                                ))
                                .await;
                            if req.executor_mode == Executor::Any {
                                trace!("Got reply for read request from {}!", req.wait_from);
                            }

                            for byz_resp in receipt.byz_responses.iter() {
                                if let Some(task) =
                                    waiting_for_byz_response.remove(&byz_resp.client_tag)
                                {
                                    let _ = stat_tx
                                        .send(ClientWorkerStat::ByzCommitLatency(
                                            task.start_time.elapsed(),
                                        ))
                                        .await;
                                } else {
                                    out_of_order_byz_response
                                        .insert(byz_resp.client_tag, Instant::now());
                                }
                            }
                        }
                        Some(client::proto_client_reply::Reply::TryAgain(_try_again)) => {
                            let _ = backpressure_tx
                                .send(CheckerResponse::TryAgain(req, None, None))
                                .await;
                        }
                        Some(client::proto_client_reply::Reply::TentativeReceipt(
                            _tentative_receipt,
                        )) => {
                            // We treat tentative receipt as a success.
                            let _ = backpressure_tx.send(CheckerResponse::Success(req.id)).await;
                            let _ = stat_tx
                                .send(ClientWorkerStat::CrashCommitLatency(
                                    req.start_time.elapsed(),
                                ))
                                .await;
                        }
                        Some(client::proto_client_reply::Reply::Leader(leader)) => {
                            // sleep(Duration::from_secs(1)).await;
                            // We need to try again but with the leader reset.
                            let curr_leader = leader.name;
                            let node_list =
                                crate::config::NodeInfo::deserialize(&leader.serialized_node_infos);
                            let mut node_list_vec = node_list
                                .nodes
                                .keys()
                                .map(|e| e.clone())
                                .collect::<Vec<_>>();
                            node_list_vec.sort();
                            let new_leader_id =
                                node_list_vec.iter().position(|e| e.eq(&curr_leader));
                            if new_leader_id.is_none() {
                                // Malformed!
                                error!(
                                    "Malformed leader response. Leader not found in the node list."
                                );
                                let _ = backpressure_tx
                                    .send(CheckerResponse::TryAgain(req, None, None))
                                    .await;
                                continue;
                            }
                            let mut config = client.0.config.get();
                            let config = Arc::make_mut(&mut config);
                            for (k, v) in node_list.nodes.iter() {
                                config.net_config.nodes.insert(k.clone(), v.clone());
                            }
                            client.0.config.set(config.clone());

                            // There is no point in waiting for responses for older requests.
                            if alleged_leader != curr_leader {
                                info!("Leader changed to {}", curr_leader);
                                waiting_for_byz_response.clear();
                                out_of_order_byz_response.clear();
                                alleged_leader = curr_leader;
                            }

                            let _ = backpressure_tx
                                .send(CheckerResponse::TryAgain(
                                    req,
                                    Some(node_list_vec),
                                    new_leader_id,
                                ))
                                .await;
                        }

                        None => {
                            // We need to try again.
                            let _ = backpressure_tx
                                .send(CheckerResponse::TryAgain(req, None, None))
                                .await;
                        }
                    }

                    // TODO: check response
                }
                None => {
                    break;
                }
            }
        }
    }

    async fn generator_task(
        &mut self,
        generator_tx: Sender<CheckerTask>,
        backpressure_rx: Receiver<CheckerResponse>,
        backpressure_tx: Sender<CheckerResponse>,
        id: usize,
    ) {
        let mut outstanding_requests = HashMap::<u64, OutstandingRequest>::new();

        let mut total_requests = 0;

        let duration = Duration::from_secs(self.config.workload_config.duration);
        let mut node_list = self
            .config
            .net_config
            .nodes
            .keys()
            .map(|e| e.clone())
            .collect::<Vec<_>>();
        node_list.sort();

        let mut curr_leader_id = 0;
        let mut curr_round_robin_id = id % node_list.len();

        let my_name = self.config.net_config.name.clone();

        sleep(Duration::from_secs(1)).await;

        let mut backoff_time = Duration::from_millis(1000);
        let mut curr_complaining_requests = 0;
        let max_inflight_requests = self.config.workload_config.max_concurrent_requests;

        let experiment_global_start = Instant::now();
        while experiment_global_start.elapsed() < duration {
            // Wait for the checker task to give a go-ahead.
            match backpressure_rx.recv().await {
                Some(CheckerResponse::Success(id)) => {
                    // Remove the request from the outstanding requests if possible.
                    outstanding_requests.remove(&id);
                    // We can send a new request.
                    let payload = self.generator.next();
                    let mut req = OutstandingRequest::default();
                    req.id = (total_requests + 1) as u64;
                    req.executor_mode = payload.executor;
                    let client_request = ProtoPayload {
                        message: Some(crate::proto::rpc::proto_payload::Message::ClientRequest(
                            ProtoClientRequest {
                                tx: Some(payload.tx),
                                origin: my_name.clone(),
                                sig: vec![0u8; 1],
                                client_tag: req.id,
                            },
                        )),
                    };

                    req.payload = client_request.encode_to_vec();

                    self.send_request(
                        &mut req,
                        &node_list,
                        &mut curr_leader_id,
                        &mut curr_round_robin_id,
                        &mut outstanding_requests,
                    )
                    .await;

                    generator_tx.send(req.get_checker_task()).await.unwrap();
                    outstanding_requests.insert(req.id, req);
                    total_requests += 1;
                }
                Some(CheckerResponse::TryAgain(task, node_vec, leader)) => {
                    // We need to send the same request again.
                    if leader.is_none() {
                        // This is a try again. So we need to backoff.
                        // All inflight requests may have been cancelled. But we can't sleep for all of them.
                        if curr_complaining_requests == 0 {
                            info!("Backing off for {} ms", backoff_time.as_millis());
                            sleep(backoff_time).await;
                        }
                        curr_complaining_requests += 1;
                        if curr_complaining_requests >= max_inflight_requests {
                            curr_complaining_requests = 0;
                        }
                    }

                    let old_leader_name = node_list[curr_leader_id].clone();

                    if let Some(_leader) = leader {
                        // PinnedClient::drop_all_connections(&self.client).await;
                        curr_leader_id = _leader;
                    }

                    if let Some(_node_list) = node_vec {
                        node_list.clear();
                        node_list.extend(_node_list.iter().map(|e| e.clone()));
                    }

                    let new_leader_name = node_list[curr_leader_id].clone();

                    if old_leader_name != new_leader_name {
                        info!(
                            "Leader changed from {} to {}",
                            old_leader_name, new_leader_name
                        );
                        outstanding_requests.clear();
                    }

                    let req = outstanding_requests.remove(&task.id);
                    if req.is_none() {
                        // Skip silently; try to create a new request for this
                        backpressure_tx
                            .send(CheckerResponse::Success(0))
                            .await
                            .unwrap();
                        continue;
                    }
                    let mut req = req.unwrap();
                    self.send_request(
                        &mut req,
                        &node_list,
                        &mut curr_leader_id,
                        &mut curr_round_robin_id,
                        &mut outstanding_requests,
                    )
                    .await;
                    generator_tx.send(req.get_checker_task()).await.unwrap();
                    outstanding_requests.insert(req.id, req);
                }
                None => {
                    break;
                }
            }
        }

        info!(
            "Experiment completed. Total requests: {} Total runtime: {} s",
            total_requests,
            experiment_global_start.elapsed().as_secs()
        );
    }

    /// Sets the req.last_sent_to.
    /// Increments the curr_round_robin_id if req.executor_mode is Any.
    /// Sends the request to the appropriate node.
    /// This will NOT add the requst to outstanding_requests. It only clears outstanding requests if the leader changes due to an error.
    async fn send_request(
        &self,
        req: &mut OutstandingRequest,
        node_list: &Vec<String>,
        curr_leader_id: &mut usize,
        curr_round_robin_id: &mut usize,
        outstanding_requests: &mut HashMap<u64, OutstandingRequest>,
    ) {
        let buf = &req.payload;
        let sz = buf.len();

        let __executor_mode = req.executor_mode.clone();
        loop {
            let res = match req.executor_mode {
                Executor::Leader => {
                    let curr_leader = &node_list[*curr_leader_id];
                    req.last_sent_to = curr_leader.clone();

                    PinnedClient::send(
                        &self.client,
                        &curr_leader,
                        MessageRef(buf, sz, &crate::rpc::SenderType::Anon),
                    )
                    .await
                }
                Executor::Any => {
                    let recv_node = &node_list[(*curr_round_robin_id) % node_list.len()];
                    // *curr_round_robin_id = *curr_round_robin_id + 1;
                    req.last_sent_to = recv_node.clone();
                    PinnedClient::send(
                        &self.client,
                        recv_node,
                        MessageRef(&buf, buf.len(), &crate::rpc::SenderType::Anon),
                    )
                    .await
                }
            };

            if res.is_err() {
                debug!("Error: {:?}", res);
                match __executor_mode {
                    Executor::Leader => {
                        *curr_leader_id = (*curr_leader_id + 1) % node_list.len();
                    }
                    Executor::Any => {
                        *curr_round_robin_id = (*curr_round_robin_id + 1) % node_list.len();
                    }
                }

                outstanding_requests.clear(); // Clear it out because I am not going to listen on that socket again
                                              // info!("Retrying with leader {} Backoff: {} ms: Error: {:?}", curr_leader, current_backoff_ms, res);
                                              // backoff!(*current_backoff_ms);
                continue;
            }
            break;
        }
    }
}
