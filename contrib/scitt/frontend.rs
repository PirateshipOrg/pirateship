use crate::cbor_utils::operation_props_to_cbor;

use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use log::warn;
use pft::config::Config;
use pft::consensus::batch_proposal::TxWithAckChanTag;
use pft::consensus::engines::scitt::TXID;
use pft::proto::client::proto_transaction_receipt::Receipt;
use pft::proto::client::{self, ProtoClientReply};
use pft::proto::execution::{ProtoTransaction, ProtoTransactionOp, ProtoTransactionPhase};
use pft::rpc::SenderType;
use pft::utils::channel::Sender;
use prost::Message;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

#[derive(Clone, Debug)]
struct SCITTResponse {
    block_n: u64,
    tx_n: u64,
    results: Option<Vec<(bool, Vec<Vec<u8>>)>>,
}

struct AppState {
    /// Global channel to feed into the consensusNode.
    batch_proposer_tx: Sender<TxWithAckChanTag>,
    /// Per-thread client tag counter remains.
    curr_client_tag: AtomicU64,
    /// Request cache to store responses for TXID lookups.
    request_cache: Arc<Mutex<HashMap<TXID, SCITTResponse>>>,
}

#[derive(Deserialize)]
struct ScanQueryParams {
    from: Option<String>,
    to: Option<String>,
}

/// Signed Statement Registration, 2.1.2 in
/// https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/
#[post("/entries")]
async fn register_signed_statement(
    cose_signed_statement: web::Bytes,
    state: web::Data<AppState>,
) -> impl Responder {
    // Should we check the statement/policy here? checking the statement is easy enough, the policy involves reading from the ledger

    let transaction_op = ProtoTransactionOp {
        op_type: pft::proto::execution::ProtoTransactionOpType::Write.into(),
        operands: vec![cose_signed_statement.to_vec()],
    };

    let result = match send(vec![transaction_op], &state, true).await {
        Ok(response) => response,
        Err(err) => return err,
    };

    let txid = TXID {
        block_n: result.block_n,
        tx_idx: TryFrom::try_from(result.tx_n).unwrap(),
    };

    state
        .request_cache
        .lock()
        .await
        .insert(txid.clone(), result);

    HttpResponse::Ok()
        .content_type("application/cbor")
        .body(operation_props_to_cbor(&txid.to_string(), "running", None, None, None).unwrap())
}

/// Resolve Receipt, 2.1.4 in
/// https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/
#[get("/entries/{txid}")]
async fn get_entry_receipt(txid: web::Path<String>, state: web::Data<AppState>) -> impl Responder {
    let txid = match TXID::from_string(&txid) {
        Some(tx_n) => tx_n,
        None => return HttpResponse::BadRequest().body("Invalid txid"),
    };

    // TODO not probe, this needs to be some sort of "get receipt" operation.
    let transaction_op = ProtoTransactionOp {
        op_type: pft::proto::execution::ProtoTransactionOpType::Probe.into(),
        operands: vec![txid.to_vec()],
    };

    let result = match send_read(vec![transaction_op], &state).await {
        Ok(response) => response,
        Err(err) => return err,
    };

    HttpResponse::Ok()
        .content_type("application/cose")
        .body(result.results.unwrap()[0].1[0].clone())
}

/// Retrieve Statement with Embedded Receipt
/// Not part of the spec, provided for convenience and compatibility with existing SCITT-CCF
#[get("/entries/{txid}/statement")]
async fn get_entry_statement(
    txid: web::Path<String>,
    state: web::Data<AppState>,
) -> impl Responder {
    let txid = match TXID::from_string(&txid) {
        Some(tx_n) => tx_n,
        None => return HttpResponse::BadRequest().body("Invalid txid"),
    };

    let transaction_op = ProtoTransactionOp {
        op_type: pft::proto::execution::ProtoTransactionOpType::Read.into(),
        operands: vec![txid.to_vec()],
    };

    let result = match send_read(vec![transaction_op], &state).await {
        Ok(response) => response,
        Err(err) => return err,
    };

    let results = result.results.unwrap();
    if results[0].1.is_empty() {
        return HttpResponse::NotFound().body("No results found for the given txid");
    }

    HttpResponse::Ok()
        .content_type("application/cose")
        .body(results[0].1[0].clone())
}

/// Retrieve IDs for all entries within a range
/// Not part of the spec, provided for convenience and compatibility with existing SCITT-CCF
#[get("/entries/txIds")]
async fn get_entries_tx_ids(
    info: web::Query<ScanQueryParams>,
    state: web::Data<AppState>,
) -> impl Responder {
    if let (Some(from), Some(to)) = (&info.from, &info.to) {
        let from_txid = TXID::from_string(from);
        let to_txid = TXID::from_string(to);

        if from_txid.is_none() {
            return HttpResponse::BadRequest().body("Invalid 'from' txid");
        }
        if to_txid.is_none() {
            return HttpResponse::BadRequest().body("Invalid 'to' txid");
        }

        let from_txid = from_txid.unwrap();
        let to_txid = to_txid.unwrap();

        if from_txid > to_txid {
            return HttpResponse::BadRequest()
                .body("'from' txid must be less than or equal to 'to' txid");
        }

        let transaction_op = ProtoTransactionOp {
            op_type: pft::proto::execution::ProtoTransactionOpType::Scan.into(),
            operands: vec![from_txid.to_vec(), to_txid.to_vec()],
        };

        let result = match send_read(vec![transaction_op], &state).await {
            Ok(response) => response,
            Err(err) => return err,
        };

        let mut tx_ids = Vec::new();
        let (success, values) = &result.results.unwrap()[0];
        if *success {
            for value in values {
                if let Some(txid) = TXID::from_vec(&value) {
                    tx_ids.push(txid.to_string());
                } else {
                    warn!("Invalid txid found in results: {:?}", value);
                }
            }
        } else {
            return HttpResponse::InternalServerError()
                .body("Error processing transaction results");
        }
        HttpResponse::Ok()
            .content_type("application/json")
            .json(serde_json::json!({ "transactionIds": tx_ids }))
    } else {
        HttpResponse::BadRequest().body("Missing 'from' or 'to' query parameters")
    }
}

#[get("/operations/{txid}")]
async fn get_operation_with_status(
    txid: web::Path<String>,
    state: web::Data<AppState>,
) -> impl Responder {
    let txid = match TXID::from_string(&txid) {
        Some(tx_n) => tx_n,
        None => return HttpResponse::BadRequest().body("Invalid txid"),
    };

    state
        .request_cache
        .lock()
        .await
        .get(&txid)
        .map(|_| {
            let txid_str = &txid.to_string();
            let cbor_response =
                operation_props_to_cbor(txid_str, "succeeded", Some(txid_str), None, None).unwrap();
            HttpResponse::Ok()
                .content_type("application/cbor")
                .body(cbor_response)
        })
        .unwrap_or_else(|| HttpResponse::NotFound().body("Operation not found"))
}

async fn send_read(
    transaction_ops: Vec<ProtoTransactionOp>,
    state: &AppState,
) -> Result<SCITTResponse, HttpResponse> {
    let transaction_phase = ProtoTransactionPhase {
        ops: transaction_ops,
    };

    let transaction = ProtoTransaction {
        on_receive: Some(transaction_phase),
        on_crash_commit: None,
        on_byzantine_commit: None,
        is_reconfiguration: false,
        is_2pc: false,
    };

    let receipt = base_send(transaction, state).await?;

    match receipt {
        Receipt::UnloggedReceipt(unlogged_receipt) => Ok(SCITTResponse {
            block_n: 0,
            tx_n: 0,
            results: Some(
                unlogged_receipt
                    .results
                    .unwrap()
                    .result
                    .into_iter()
                    .map(|tx| (tx.success, tx.values))
                    .collect(),
            ),
        }),
        _ => Err(HttpResponse::InternalServerError()
            .body("Only an unlogged receipt is expected in this context")),
    }
}

async fn send(
    transaction_ops: Vec<ProtoTransactionOp>,
    state: &AppState,
    byz_commit_probe: bool,
) -> Result<SCITTResponse, HttpResponse> {
    let transaction_phase = ProtoTransactionPhase {
        ops: transaction_ops,
    };

    let transaction = ProtoTransaction {
        on_receive: None,
        on_crash_commit: Some(transaction_phase),
        on_byzantine_commit: None,
        is_reconfiguration: false,
        is_2pc: false,
    };

    let receipt = base_send(transaction, state).await?;

    let req_receipt: SCITTResponse = match receipt {
        Receipt::CommitReceipt(commit_receipt) => SCITTResponse {
            block_n: commit_receipt.block_n,
            tx_n: commit_receipt.tx_n,
            results: Some(
                commit_receipt
                    .results
                    .unwrap()
                    .result
                    .into_iter()
                    .map(|tx| (tx.success, tx.values))
                    .collect(),
            ),
        },
        _ => {
            return Err(HttpResponse::InternalServerError()
                .body("Only a commit receipt is expected in this context"));
        }
    };

    if req_receipt.block_n != 0 && byz_commit_probe {
        let current_tag = state.curr_client_tag.fetch_add(1, Ordering::AcqRel);

        let probe_transaction = ProtoTransaction {
            on_receive: Some(ProtoTransactionPhase {
                ops: vec![ProtoTransactionOp {
                    op_type: pft::proto::execution::ProtoTransactionOpType::Probe.into(),
                    operands: vec![
                        req_receipt.block_n.to_be_bytes().to_vec(),
                        req_receipt.tx_n.to_be_bytes().to_vec(),
                    ],
                }],
            }),
            on_crash_commit: None,
            on_byzantine_commit: None,
            is_reconfiguration: false,
            is_2pc: false,
        };

        let (tx, mut rx) = mpsc::channel(1);
        let tx_with_ack_chan_tag: TxWithAckChanTag =
            (Some(probe_transaction), (tx, current_tag, SenderType::Anon));
        state
            .batch_proposer_tx
            .send(tx_with_ack_chan_tag)
            .await
            .unwrap();

        let _ = rx.recv().await;

        // Probe replies only after Byz commit
    }
    Ok(req_receipt)
}

async fn base_send(
    transaction: ProtoTransaction,
    state: &AppState,
) -> Result<Receipt, HttpResponse> {
    let current_tag = state.curr_client_tag.fetch_add(1, Ordering::AcqRel);

    let (tx, mut rx) = mpsc::channel(1);
    let tx_with_ack_chan_tag: TxWithAckChanTag =
        (Some(transaction), (tx, current_tag, SenderType::Anon));
    state
        .batch_proposer_tx
        .send(tx_with_ack_chan_tag)
        .await
        .unwrap();

    let (resp, _) = match rx.recv().await {
        Some(resp) => resp,
        None => {
            return Err(HttpResponse::InternalServerError().body("Error receiving response"));
        }
    };

    let resp = resp.as_ref();

    let decoded_payload = match ProtoClientReply::decode(&resp.0.as_slice()[0..resp.1]) {
        Ok(payload) => payload,
        Err(e) => {
            warn!("Error decoding response: {}", e);
            return Err(HttpResponse::InternalServerError().body("Error decoding response"));
        }
    };
    match decoded_payload.reply.unwrap() {
        client::proto_client_reply::Reply::Receipt(receipt) => {
            if let Some(unwrapped_receipt) = receipt.receipt {
                Ok(unwrapped_receipt)
            } else {
                Err(HttpResponse::InternalServerError()
                    .body("Transaction receipt does not contain results"))
            }
        }
        client::proto_client_reply::Reply::TryAgain(ta) => Err(HttpResponse::ServiceUnavailable()
            .body(format!(
                "Service temporarily unavailable, please try again: {}",
                ta.serialized_node_infos
            ))),
        client::proto_client_reply::Reply::Leader(l) => Err(HttpResponse::TemporaryRedirect()
            .body(format!(
                "Request should be sent to the leader node {}",
                l.name
            ))),
        client::proto_client_reply::Reply::TentativeReceipt(tr) => Err(HttpResponse::Accepted()
            .body(format!(
                "Transaction accepted but not yet committed: {} {}",
                tr.block_n, tr.tx_n
            ))),
    }
}

pub async fn run_actix_server(
    config: Config,
    batch_proposer_tx: pft::utils::channel::AsyncSenderWrapper<TxWithAckChanTag>,
    actix_threads: usize,
) -> std::io::Result<()> {
    let addr = config.net_config.addr.clone();
    // Add 1000 to the port.
    let (host, port) = addr.split_once(':').unwrap();
    let port: u16 = port.parse().unwrap();
    let port = port + 1000;
    let addr = format!("{}:{}", host, port);

    let batch_size = config.consensus_config.max_backlog_batch_size.max(256);

    HttpServer::new(move || {
        let state = AppState {
            batch_proposer_tx: batch_proposer_tx.clone(),
            curr_client_tag: AtomicU64::new(0),
            request_cache: Arc::new(Mutex::new(HashMap::new())),
        };

        App::new()
            .app_data(web::Data::new(state))
            .service(register_signed_statement)
            .service(get_entries_tx_ids) // The order matters. If this is registered after get_entry_receipt, it will match the same path and never work
            .service(get_entry_receipt)
            .service(get_entry_statement)
            .service(get_operation_with_status)
    })
    .workers(actix_threads)
    .max_connection_rate(batch_size) // Otherwise the server doesn't load consensus properly.
    .bind(addr)?
    .run()
    .await?;
    Ok(())
}
