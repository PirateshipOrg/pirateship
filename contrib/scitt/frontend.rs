use crate::cbor_utils::operation_props_to_cbor;

use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};

use rustls::{ServerConfig, Certificate, PrivateKey};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use log::warn;
use pft::config::Config;
use pft::consensus::app::TxWithValidationAck;
use pft::consensus::batch_proposal::TxWithAckChanTag;
use pft::consensus::engines::scitt::{SCITTWriteType, TXID};
use pft::proto::client::{self, ProtoClientReply, ProtoTransactionResponse};
use pft::proto::execution::{ProtoTransaction, ProtoTransactionOp, ProtoTransactionPhase};
use pft::rpc::SenderType;
use pft::utils::channel::Sender;
use prost::Message;
use serde::Deserialize;
use std::{collections::HashMap, fs::File, io::BufReader};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex};

struct AppState {
    /// Global channel to feed into the consensusNode.
    batch_proposer_tx: Sender<TxWithAckChanTag>,
    /// Per-thread client tag counter remains.
    curr_client_tag: AtomicU64,
    /// Request cache to store responses for TXID lookups.
    request_cache: Arc<Mutex<HashMap<TXID, ProtoTransactionResponse>>>,
    /// Global channel to validate claims before submission
    validator_tx: Sender<TxWithValidationAck>,
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
    let transaction_op = ProtoTransactionOp {
        op_type: pft::proto::execution::ProtoTransactionOpType::Write.into(),
        operands: vec![
            SCITTWriteType::Claim.to_slice().to_vec(),
            cose_signed_statement.to_vec(),
        ],
    };

    let (tx, rx) = oneshot::channel();
    state
        .validator_tx
        .send((transaction_op.clone(), tx))
        .await
        .expect("Failed to send validation request");
    match rx.await.expect("Failed to receive validation response") {
        Ok(_) => (),
        Err(err) => {
            return HttpResponse::BadRequest().body(format!("Claim validation failed: {}", err))
        }
    }

    let response = match send(vec![transaction_op], &state, true).await {
        Ok(response) => response,
        Err(err) => return err,
    };

    let txid = TXID {
        block_n: response.block_n,
        tx_idx: TryFrom::try_from(response.tx_n).unwrap(),
    };

    state
        .request_cache
        .lock()
        .await
        .insert(txid.clone(), response);

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

    let transaction_op = ProtoTransactionOp {
        op_type: {
            if cfg!(feature = "commit_receipts") {
                pft::proto::execution::ProtoTransactionOpType::ProbeCommit.into()
            } else {
                pft::proto::execution::ProtoTransactionOpType::ProbeAudit.into()
            }
        },
        operands: vec![txid.to_vec()],
    };

    let response = match send_read(vec![transaction_op], &state).await {
        Ok(response) => response,
        Err(err) => return err,
    };

    let results = response.results.unwrap().result;
    if results[0].values.is_empty() {
        return HttpResponse::NotFound().body("No results found for the given txid");
    }

    HttpResponse::Ok()
        .content_type("application/cose")
        .body(results[0].values[0].clone())
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

    let response = match send_read(vec![transaction_op], &state).await {
        Ok(response) => response,
        Err(err) => return err,
    };

    let results = response.results.unwrap().result;
    if results[0].values.is_empty() {
        return HttpResponse::NotFound().body("No results found for the given txid");
    }

    HttpResponse::Ok()
        .content_type("application/cose")
        .body(results[0].values[0].clone())
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

        let response = match send_read(vec![transaction_op], &state).await {
            Ok(response) => response,
            Err(err) => return err,
        };

        let mut tx_ids = Vec::new();
        let proto_result = &response.results.unwrap().result[0];
        if proto_result.success {
            for value in proto_result.values.iter() {
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

/// Retrieve Operation with Status
/// Not part of the spec, provided for compatibility with existing SCITT-CCF
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

/// Policy Registration
/// The endpoint itself if not part of the spec, this is a simplified solution in comparison with the CCF governance model
#[post("/policy")]
async fn register_policy(
    policy: web::Bytes,
    state: web::Data<AppState>,
) -> impl Responder {
    let transaction_op = ProtoTransactionOp {
        op_type: pft::proto::execution::ProtoTransactionOpType::Write.into(),
        operands: vec![
            SCITTWriteType::Policy.to_slice().to_vec(),
            policy.to_vec(),
        ],
    };

    let (tx, rx) = oneshot::channel();
    state
        .validator_tx
        .send((transaction_op.clone(), tx))
        .await
        .expect("Failed to send validation request");
    match rx.await.expect("Failed to receive validation response") {
        Ok(_) => (),
        Err(err) => {
            return HttpResponse::BadRequest().body(format!("policy validation failed: {}", err))
        }
    }

    let _result = match send(vec![transaction_op], &state, true).await {
        Ok(response) => response,
        Err(err) => return err,
    };

    HttpResponse::Ok()
        .content_type("application/text")
        .body("Policy registered successfully.")
}

async fn send_read(
    transaction_ops: Vec<ProtoTransactionOp>,
    state: &AppState,
) -> Result<ProtoTransactionResponse, HttpResponse> {
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

    base_send(transaction, state).await
}

async fn send(
    transaction_ops: Vec<ProtoTransactionOp>,
    state: &AppState,
    byz_commit_probe: bool,
) -> Result<ProtoTransactionResponse, HttpResponse> {
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

    let response = base_send(transaction, state).await?;

    if response.block_n != 0 && byz_commit_probe {
        let current_tag = state.curr_client_tag.fetch_add(1, Ordering::AcqRel);

        let probe_transaction = ProtoTransaction {
            on_receive: Some(ProtoTransactionPhase {
                ops: vec![ProtoTransactionOp {
                    op_type: {
                        if cfg!(feature = "commit_receipts") {
                            pft::proto::execution::ProtoTransactionOpType::ProbeCommit.into()
                        } else {
                            pft::proto::execution::ProtoTransactionOpType::ProbeAudit.into()
                        }
                    },
                    operands: vec![
                        response.block_n.to_be_bytes().to_vec(),
                        response.tx_n.to_be_bytes().to_vec(),
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
    Ok(response)
}

async fn base_send(
    transaction: ProtoTransaction,
    state: &AppState,
) -> Result<ProtoTransactionResponse, HttpResponse> {
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
        client::proto_client_reply::Reply::Response(response) => Ok(response),
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
        client::proto_client_reply::Reply::TentativeResponse(tr) => Err(HttpResponse::Accepted()
            .body(format!(
                "Transaction accepted but not yet committed: {} {}",
                tr.block_n, tr.tx_n
            ))),
        client::proto_client_reply::Reply::CommitReceipt(_) =>
            Err(HttpResponse::InternalServerError().body("Commit receipt not expected in this context")),
        client::proto_client_reply::Reply::AuditReceipt(_) => Err(HttpResponse::InternalServerError().body("Audit receipt not expected in this context")),
    }
}

pub async fn run_actix_server(
    config: Config,
    batch_proposer_tx: pft::utils::channel::AsyncSenderWrapper<TxWithAckChanTag>,
    validator_tx: pft::utils::channel::AsyncSenderWrapper<TxWithValidationAck>,
    actix_threads: usize,
) -> std::io::Result<()> {
    let addr = config.net_config.addr.clone();
    // Add 1000 to the port.
    let (host, port) = addr.split_once(':').unwrap();
    let port: u16 = port.parse().unwrap();
    let port = port + 1000;
    let addr = format!("{}:{}", host, port);

    let batch_size = config.consensus_config.max_backlog_batch_size.max(256);

    let cert_file = &mut BufReader::new(File::open(&config.net_config.tls_cert_path).expect("Invalid TLS cert file path"));
    let key_file = &mut BufReader::new(File::open(&config.net_config.tls_key_path).expect("Invalid TLS key file path"));

    let cert_chain: Vec<Certificate> = certs(cert_file)
        .expect("Invalid TLS cert file format")
        .into_iter()
        .map(Certificate)
        .collect();
    
    let mut keys: Vec<PrivateKey> = rsa_private_keys(key_file)
        .unwrap_or_else(|_| Vec::new())
        .into_iter()
        .map(PrivateKey)
        .collect();
    if keys.is_empty() {
        let key_file = &mut BufReader::new(File::open(&config.net_config.tls_key_path).expect("Invalid TLS key file path"));
        keys = pkcs8_private_keys(key_file)
            .expect("Invalid TLS key file format - not RSA or PKCS8")
            .into_iter()
            .map(PrivateKey)
            .collect();
    }
    if keys.is_empty() {
        panic!("Could not locate RSA or PKCS 8 private keys.");
    }
    let key = keys.remove(0);

    let tls_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .expect("Invalid TLS configuration");

    HttpServer::new(move || {
        let state = AppState {
            batch_proposer_tx: batch_proposer_tx.clone(),
            curr_client_tag: AtomicU64::new(0),
            request_cache: Arc::new(Mutex::new(HashMap::new())),
            validator_tx: validator_tx.clone(),
        };

        App::new()
            .app_data(web::Data::new(state))
            .service(register_signed_statement)
            .service(get_entries_tx_ids) // The order matters. If this is registered after get_entry_receipt, it will match the same path and never work
            .service(get_entry_receipt)
            .service(get_entry_statement)
            .service(get_operation_with_status)
            .service(register_policy)
    })
    .workers(actix_threads)
    .max_connection_rate(batch_size) // Otherwise the server doesn't load consensus properly.
    .bind_rustls(addr, tls_config)?
    .run()
    .await?;
    Ok(())
}
