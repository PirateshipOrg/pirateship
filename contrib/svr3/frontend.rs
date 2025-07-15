use actix_web::cookie::time::macros::datetime;
use actix_web::cookie::time::OffsetDateTime;
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use chrono::{DateTime, TimeZone};
use hex::ToHex;
use log::{debug, warn};
use pft::consensus::batch_proposal::TxWithAckChanTag;
use prost::Message;
use serde::ser::Error;
use serde_json::value;
use tokio::sync::{mpsc, Mutex};
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pft::config::Config;
use pft::crypto::{KeyStore, hash};
use pft::proto::execution::{ProtoTransaction, ProtoTransactionOp, ProtoTransactionPhase};
use pft::rpc::client::Client;
use pft::rpc::{PinnedMessage, SenderType};
use pft::{proto::{client::{self, ProtoClientReply, ProtoClientRequest}, rpc::ProtoPayload}, rpc::client::PinnedClient, utils::channel::{make_channel, Receiver, Sender}};
use crate::payloads::{AuthToken, GetTokenPayload, RecoverSecretPayload, RegisterPayload, StoreSecretPayload};



struct AppState {
    /// Global channel to feed into the consensusNode.
    batch_proposer_tx: Sender<TxWithAckChanTag>,
    /// Separate client instance for byz commit probe, so it doesn't interfere with other requests
    /// on the same worker thread.
    /// Arced since it is shared across threads.
    probe_for_byz_commit: Arc<AtomicBool>,
    /// Only a per-thread client tag counter remains.
    curr_client_tag: AtomicU64,
    keys: KeyStore,
    leader_name: String,

    secret_store: Arc<Mutex<HashMap<String, HashMap<u32, String>>>>,
}

#[post("/auth")]
async fn auth(payload: web::Json<RegisterPayload>, data: web::Data<AppState>) -> impl Responder {
    let username = payload.username.clone();
    let pin = payload.pin.clone();

    let transaction_op = ProtoTransactionOp {
        op_type: pft::proto::execution::ProtoTransactionOpType::Read.into(),
        operands: vec![username.clone().into_bytes()],
    };

    let result = match send(vec![transaction_op], true, &data).await {
        Ok(response) => response,
        Err(e) => return e,
    };

    if !result.is_empty() {
        return HttpResponse::Conflict().json(serde_json::json!({
            "message": "username already exists",
        }));
    }

    // Username does not exist; create new username and password.
    let create_user_op = ProtoTransactionOp {
        op_type: pft::proto::execution::ProtoTransactionOpType::Write.into(),
        operands: vec![username.clone().into_bytes(), hash(&pin.into_bytes())],
    };

    let _ = match send(vec![create_user_op], false, &data).await {
        Ok(response) => response,
        Err(e) => return e,
    };

    // Get list of users then add user to list of users.
    let get_user_op = ProtoTransactionOp {
        op_type: pft::proto::execution::ProtoTransactionOpType::Read.into(),
        operands: vec!["user".as_bytes().to_vec()],
    };

    let get_user_result = match send(vec![get_user_op], true, &data).await {
        Ok(response) => response,
        Err(e) => return e,
    };

    let mut users: Vec<String> = Vec::new();
    if !get_user_result.is_empty() {
        users = serde_json::from_slice(&get_user_result[0]).expect("Deserialization failed");
    }

    users.push(username.clone());
    let serialized_users: Vec<u8> = serde_json::to_vec(&users).expect("Serialization failed");

    let update_users_op = ProtoTransactionOp {
        op_type: pft::proto::execution::ProtoTransactionOpType::Write.into(),
        operands: vec!["user".as_bytes().to_vec(), serialized_users],
    };

    let _ = match send(vec![update_users_op],false, &data).await {
        Ok(response) => response,
        Err(e) => return e,
    };

    HttpResponse::Ok().json(serde_json::json!({
        "message": "user created",
        "users": users,
    }))
}

#[post("/storesecret")]
async fn storeSecret(payload: web::Json<StoreSecretPayload>, data: web::Data<AppState>) -> impl Responder {
    let token = payload.token.clone();
    let val = payload.val.clone();

    if let val @ Ok(false) | val @ Err(_) = validate_token(&token, &data).await {
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "message": "incorrect token",
            "result": format!("{:?}", val),
        }))
    }

    {
        let mut secret_store = data.secret_store.lock().await;
        let vec = secret_store.entry(token.username.clone())
            .or_insert_with(HashMap::new);

        vec.insert(payload.token.version, val.clone());


    }

    HttpResponse::Ok().json(serde_json::json!({
        "message": "user secret store",
        "user secret": val,
    }))
}

const MAX_GUESSES: i64 = 1_000_000;

#[get("/gettoken")]
async fn getToken(payload: web::Json<GetTokenPayload>, data: web::Data<AppState>) -> impl Responder {
    let username = payload.username.clone();
    let pin = payload.pin.clone();

    let res = authenticate_user(username.clone(), pin, &data).await;
    if res.is_err() {
        if let Err(e) = res {
            if e.status() == actix_web::http::StatusCode::NOT_FOUND {
                return e;
            }
        }
        // Blindly increment the pin guess.
        let mut user_retry_count = "retries:".to_string();
        user_retry_count.push_str(&payload.username);

        let increment_user_pin_op = ProtoTransactionOp {
            op_type: pft::proto::execution::ProtoTransactionOpType::Increment.into(),
            operands: vec![user_retry_count.clone().into_bytes()]
        };

        let increment_user_pin_result = match send(vec![increment_user_pin_op],false, &data).await {
            Ok(response) => response[0].clone(),
            Err(e) => return e,
        };

        let total_guesses = match increment_user_pin_result.as_slice().try_into() {
            Ok(arr) => {
                i64::from_be_bytes(arr)
            }
            _ => { 0 }
        };

        return HttpResponse::Unauthorized().json(serde_json::json!({
            "message": "incorrect pin",
            "retries": total_guesses,
        }))


    } else {
        // Check the pin guess.
        let transaction_op = ProtoTransactionOp {
            op_type: pft::proto::execution::ProtoTransactionOpType::Read.into(),
            operands: vec![("retries:".to_string() + &username).into_bytes()],
        };

        let read_user_pin_result = match send(vec![transaction_op], true, &data).await {
            Ok(response) if response.len() > 0 => response[0].clone(),
            Err(e) => return e,
            _ => {
                0i64.to_be_bytes().to_vec()
            }
        };

        let total_guesses = match read_user_pin_result.as_slice().try_into() {
            Ok(arr) => {
                i64::from_be_bytes(arr)
            }
            _ => { 0 }
        };

        if total_guesses > MAX_GUESSES {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "message": "too many guesses",
                "retries": total_guesses,
            }))
        }

        // Or try to CAS it 0.
        // If it fails, we don't retry.
        let reset_user_pin_op = ProtoTransactionOp {
            op_type: pft::proto::execution::ProtoTransactionOpType::Cas.into(),
            operands: vec![("retries:".to_string() + &username).into_bytes(), 0i64.to_be_bytes().to_vec(), total_guesses.to_be_bytes().to_vec()]
        };

        let _ = send(vec![reset_user_pin_op], false, &data).await;
    }

    let one_hour_from_now = chrono::Utc::now() + chrono::Duration::hours(1);
    let one_hour_from_now_str = one_hour_from_now.to_rfc3339();
    let sig = one_hour_from_now_str.clone() + &username + &data.leader_name;
    let signature = data.keys.sign(&sig.into_bytes());
    let signature_string: String = signature.encode_hex();

    let version = if payload.increment_version {
        let increment_user_version_op = ProtoTransactionOp {
            op_type: pft::proto::execution::ProtoTransactionOpType::Increment.into(),
            operands: vec![("version:".to_string() + &username).into_bytes()]
        };

        let increment_user_version_result = match send(vec![increment_user_version_op], false, &data).await {
            Ok(response) => response,
            Err(e) => return e,
        };

        let next_version = match increment_user_version_result[0].as_slice().try_into() {
            Ok(arr) => {
                i64::from_be_bytes(arr)
            }
            _ => { 0 }
        } as u32;

        next_version
    } else {
        // Just read the version.
        let transaction_op = ProtoTransactionOp {
            op_type: pft::proto::execution::ProtoTransactionOpType::Read.into(),
            operands: vec![("version:".to_string() + &username).into_bytes()],
        };

        let read_user_version_result = match send(vec![transaction_op], true, &data).await {
            Ok(response) if response.len() > 0 => response[0].clone(),
            Err(e) => return e,
            _ => {
                0i64.to_be_bytes().to_vec()
            }
        };
        let curr_version = match read_user_version_result.as_slice().try_into() {
            Ok(arr) => {
                i64::from_be_bytes(arr)
            }
            _ => { 0 }
        } as u32;

        curr_version
    };
    
    HttpResponse::Ok().json(serde_json::json!({
        "valid_until": one_hour_from_now_str, 
        "username": username,
        "signature": signature_string,
        "leader_name": &data.leader_name,
        "version": version,
    }))
}

#[get("/recoversecret")]
async fn recoverSecret(token: web::Json<AuthToken>, data: web::Data<AppState>) -> impl Responder {
    if let Ok(false) | Err(_) = validate_token(&token, &data).await {
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "message": "incorrect token",
        }))
    }

    let user_secret = {
        let secret_store = data.secret_store.lock().await;
        match secret_store.get(&token.username) {
            Some(secret) => match secret.get(&token.version) {
                Some(secret_value) => secret_value.clone(),
                None => return HttpResponse::NotFound().json(serde_json::json!({
                    "message": "user secret not found",
                })),
            },
            None => return HttpResponse::NotFound().json(serde_json::json!({
                "message": "user not found",
            })),
        }
    };

    HttpResponse::Ok().json(serde_json::json!({
        "message": "user secret store",
        "user secret": user_secret,
    }))
}

#[post("/toggle_byz_wait")]
async fn toggle_byz_wait(data: web::Data<AppState>) -> impl Responder {
    let mut state = data.probe_for_byz_commit.load(Ordering::SeqCst);
    state = !state;
    data.probe_for_byz_commit.store(state, Ordering::SeqCst);
    HttpResponse::Ok().json(serde_json::json!({
        "message": "byzantine wait toggled",
        "probe_for_byz_commit": state,
    }))
}

#[get("/")]
async fn home(_data: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "message": "hello from a non-shared, local state",
    }))
}

pub async fn run_actix_server(config: Config, batch_proposer_tx: pft::utils::channel::AsyncSenderWrapper<TxWithAckChanTag>, actix_threads: usize) -> std::io::Result<()> {
    let keys = KeyStore::new(&config.rpc_config.allowed_keylist_path, &config.rpc_config.signing_priv_key_path);
    // keys.priv_key = KeyStore::get_privkeys(&config.rpc_config.signing_priv_key_path);
    // let keys = keys.clone();
    let name =  config.net_config.name.clone();

    let addr = config.net_config.addr.clone();
    // Add 1000 to the port.
    let (host, port) = addr.split_once(':').unwrap();
    let port: u16 = port.parse().unwrap();
    let port = port + 1000;
    let addr = format!("{}:{}", host, port);

    let batch_size = config.consensus_config.max_backlog_batch_size.max(256);


    let probe_for_byz_commit = Arc::new(AtomicBool::new(false)); // This is a global state!
    let secret_store = Arc::new(Mutex::new(HashMap::new()));

    HttpServer::new(move || {
        // Each worker thread creates its own client instance.
        let state = AppState {
            batch_proposer_tx: batch_proposer_tx.clone(),
            probe_for_byz_commit: probe_for_byz_commit.clone(),
            curr_client_tag: AtomicU64::new(0),
            secret_store: secret_store.clone(),
            keys: keys.clone(),
            leader_name: name.clone(),
        };

        App::new()
            .app_data(web::Data::new(state))
            .service(home)
            .service(auth)
            .service(storeSecret)
            .service(recoverSecret)
            .service(toggle_byz_wait)
            .service(getToken)
    })
    .bind(addr)?
    .run()
    .await?;
    Ok(())
}

async fn send(transaction_ops: Vec<ProtoTransactionOp>, isRead: bool, state: &AppState) -> Result<Vec<Vec<u8>>, HttpResponse> {
    let transaction_phase = ProtoTransactionPhase {
        ops: transaction_ops,
    };

    let transaction = if isRead {
        ProtoTransaction {
            on_receive: Some(transaction_phase.clone()),
            on_crash_commit: None,
            on_byzantine_commit: None,
            is_reconfiguration: false,
            is_2pc: false,
        }
    } else {
        ProtoTransaction {
            on_receive: None,
            on_crash_commit: Some(transaction_phase.clone()),
            on_byzantine_commit: None,
            is_reconfiguration: false,
            is_2pc: false,
        }
    };
    
    let current_tag = state.curr_client_tag.fetch_add(1, Ordering::AcqRel);

    let (tx, mut rx) = mpsc::channel(1);
    let tx_with_ack_chan_tag: TxWithAckChanTag = (Some(transaction), (tx, current_tag, SenderType::Anon));
    state.batch_proposer_tx.send(tx_with_ack_chan_tag).await.unwrap();

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

    let mut result: Vec<Vec<u8>> = Vec::new();
    let block_n = 
    match decoded_payload.reply.unwrap() {
        pft::proto::client::proto_client_reply::Reply::Receipt(receipt_wrapper) => {
            let receipt = if let Some(pft::proto::client::proto_transaction_receipt::Receipt::CommitReceipt(receipt)) = receipt_wrapper.receipt {
                receipt
            } else {
                return Err(HttpResponse::NotFound().json(serde_json::json!({
                    "message": "error, no Receipt found",
                    "result": result,
                })));
            };
            if let Some(tx_result) = receipt.results {
                if tx_result.result.is_empty() {
                    return Ok(result);
                }
                for op_result in tx_result.result {
                    for value in op_result.values {
                        result.push(value);
                    }
                }
            }

            receipt.block_n
        },
        _ => {
            return Err(HttpResponse::NotFound().json(serde_json::json!({
                "message": "error, no Receipt found",
                "result": result,
            })))
        },
    };

    if !isRead && block_n != 0 && state.probe_for_byz_commit.load(Ordering::Relaxed) {
        let current_tag = state.curr_client_tag.fetch_add(1, Ordering::AcqRel);
    
        let probe_transaction = ProtoTransaction {
            on_receive: Some(ProtoTransactionPhase {
                ops: vec![ProtoTransactionOp {
                    op_type: pft::proto::execution::ProtoTransactionOpType::Probe.into(),
                    operands: vec![block_n.to_be_bytes().to_vec()],
                }]
            }),
            on_crash_commit: None,
            on_byzantine_commit: None,
            is_reconfiguration: false,
            is_2pc: false,
        };

        let (tx, mut rx) = mpsc::channel(1);
        let tx_with_ack_chan_tag: TxWithAckChanTag = (Some(probe_transaction), (tx, current_tag, SenderType::Anon));
        state.batch_proposer_tx.send(tx_with_ack_chan_tag).await.unwrap();

        let _ = rx.recv().await;

        // Probe replies only after Byz commit
    }
    Ok(result)
}

async fn authenticate_user(
    username: String,
    pin: String,
    data: &AppState,
) -> Result<(), HttpResponse> {
    let transaction_op = ProtoTransactionOp {
        op_type: pft::proto::execution::ProtoTransactionOpType::Read.into(),
        operands: vec![username.clone().into_bytes()],
    };

    let result = match send(vec![transaction_op], true, data).await {
        Ok(response) => response,
        Err(e) => return Err(e),
    };

    if result.is_empty() {
        return Err(HttpResponse::NotFound().json(serde_json::json!({
            "message": "username does not exist",
            "user": username,
        })));
    }

    if hash(&pin.into_bytes()) != result[0] {
        return Err(HttpResponse::Unauthorized().json(serde_json::json!({
            "message": "incorrect pin",
            "user": username,
        })));
    }
    Ok(())
}


async fn validate_token(token: &AuthToken, data: &AppState) -> Result< bool, Box<dyn std::error::Error>> {
    let parsed_time = DateTime::parse_from_rfc3339(&token.valid_until)?;

    if parsed_time.time() < chrono::Utc::now().time() {
        return Ok(false);
    }

    let check = token.valid_until.clone() + &token.username + &token.leader_name;
    Ok(data.keys.verify(&token.leader_name, hex::decode(token.signature.clone())?.as_slice().try_into()?, &check.into_bytes()))
}
/*
Example usage:
curl -X POST "http://localhost:8080/auth" -H "Content-Type: application/json" -d '{"username":"teddy", "password":"hi"}'

*/
