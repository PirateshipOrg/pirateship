use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use async_recursion::async_recursion;
use log::{debug, warn};
use pft::consensus::batch_proposal::TxWithAckChanTag;
use prost::Message;
use serde::Deserialize;
use sha2::digest::typenum::Integer;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

use crate::payloads::{PubKeyPayload, RegisterPayload};
use pft::config::Config;
use pft::crypto::{hash, KeyStore};
use pft::proto::execution::{ProtoTransaction, ProtoTransactionOp, ProtoTransactionPhase};
use pft::rpc::client::Client;
use pft::rpc::{MessageRef, PinnedMessage, SenderType};
use pft::{
    config::ClientConfig,
    proto::{
        client::{self, ProtoClientReply, ProtoClientRequest},
        rpc::ProtoPayload,
    },
    rpc::client::PinnedClient,
    utils::channel::{make_channel, Receiver, Sender},
};

use ed25519_dalek::{
    ed25519, SecretKey, SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH,
};

struct AppState {
    /// Global channel to feed into the consensusNode.
    batch_proposer_tx: Sender<TxWithAckChanTag>,
    /// Separate client instance for byz commit probe, so it doesn't interfere with other requests
    /// on the same worker thread.
    /// Arced since it is shared across threads.
    probe_for_byz_commit: Arc<AtomicBool>,
    /// Only a per-thread client tag counter remains.
    curr_client_tag: AtomicU64,
}

#[post("/register")]
async fn register(
    payload: web::Json<RegisterPayload>,
    data: web::Data<AppState>,
) -> impl Responder {
    let username = payload.username.clone();
    let password = payload.password.clone();

    // Query KMS for username.
    let transaction_op = ProtoTransactionOp {
        op_type: pft::proto::execution::ProtoTransactionOpType::Read.into(),
        operands: vec![username.clone().into_bytes()],
    };

    let result = match send(vec![transaction_op], true, data.as_ref()).await {
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
        operands: vec![username.clone().into_bytes(), hash(&password.into_bytes())],
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
        users = serde_json::from_slice(&get_user_result).expect("Deserialization failed");
    }
    users.push(username.clone());
    let serialized_users: Vec<u8> = serde_json::to_vec(&users).expect("Serialization failed");

    let update_users_op = ProtoTransactionOp {
        op_type: pft::proto::execution::ProtoTransactionOpType::Write.into(),
        operands: vec!["user".as_bytes().to_vec(), serialized_users],
    };

    // Increment the counter for number of users.
    let user_count_op = ProtoTransactionOp {
        op_type: pft::proto::execution::ProtoTransactionOpType::Increment.into(),
        operands: vec!["user_count".as_bytes().to_vec()],
    };

    let _ = match send(vec![update_users_op, user_count_op], false, &data).await {
        Ok(response) => response,
        Err(e) => return e,
    };

    HttpResponse::Ok().json(serde_json::json!({
        "message": "user created",
        "users": users,
    }))
}

#[post("/refresh")]
async fn refresh(payload: web::Json<RegisterPayload>, data: web::Data<AppState>) -> impl Responder {
    let mut csprng = rand::rngs::OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);

    match authenticate_user(payload.username.clone(), payload.password.clone(), &data).await {
        Ok(valid) => valid,
        Err(e) => return e,
    };

    let private_key = signing_key.verifying_key().to_bytes();
    let public_key = signing_key.to_bytes();

    let mut public_insert_key = "pub:".to_string();
    public_insert_key.push_str(&payload.username);

    let mut priv_insert_key = "priv:".to_string();
    priv_insert_key.push_str(&payload.username);

    let write_pub_key_op = ProtoTransactionOp {
        op_type: pft::proto::execution::ProtoTransactionOpType::Write.into(),
        operands: vec![public_insert_key.into_bytes(), public_key.to_vec()],
    };

    let write_priv_key_op = ProtoTransactionOp {
        op_type: pft::proto::execution::ProtoTransactionOpType::Write.into(),
        operands: vec![priv_insert_key.into_bytes(), private_key.to_vec()],
    };

    let _ = match send(vec![write_pub_key_op, write_priv_key_op], false, &data).await {
        Ok(response) => response,
        Err(e) => return e,
    };

    HttpResponse::Ok().json(serde_json::json!({
        "message": "created key pair for user",
        "username": &payload.username,
        "public key": public_key,
        "private key": private_key,
    }))
}

#[post("/toggle_byz_wait")]
async fn toggle_byz_wait(data: web::Data<AppState>) -> impl Responder {
    data.probe_for_byz_commit.fetch_not(Ordering::Relaxed);
    HttpResponse::Ok().json(serde_json::json!({
        "message": "byzantine wait toggled",
        "probe_for_byz_commit": data.probe_for_byz_commit.load(Ordering::Relaxed),
    }))
}

#[get("/listpubkeys")]
async fn listpubkeys(data: web::Data<AppState>) -> impl Responder {
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
        users = serde_json::from_slice(&get_user_result).expect("Deserialization failed");
    }

    let mut user_ops = Vec::new();
    for user in users {
        let mut key = "pub:".to_string();
        key.push_str(&user);
        let op = ProtoTransactionOp {
            op_type: pft::proto::execution::ProtoTransactionOpType::Read.into(),
            operands: vec![key.into_bytes()],
        };
        user_ops.push(op);
    }

    let mut public_keys = Vec::new();
    for op in user_ops {
        let user_public_key_result = match send(vec![op], true, &data).await {
            Ok(response) => response,
            Err(e) => return e,
        };

        let pub_key_arr: [u8; PUBLIC_KEY_LENGTH] = user_public_key_result
            .try_into()
            .expect("Vec has incorrect length");
        public_keys.push(pub_key_arr);
    }

    HttpResponse::Ok().json(serde_json::json!({
        "message": "public keys retrieved",
        "public keys": public_keys,
    }))
}

#[get("/num_users")]
async fn num_users(data: web::Data<AppState>) -> impl Responder {
    let transaction_op = ProtoTransactionOp {
        op_type: pft::proto::execution::ProtoTransactionOpType::Read.into(),
        operands: vec!["user_count".as_bytes().to_vec()],
    };

    let user_count_result = match send(vec![transaction_op], true, &data).await {
        Ok(response) => response,
        Err(e) => return e,
    };

    if user_count_result.is_empty() {
        return HttpResponse::NotFound().json(serde_json::json!({
            "message": "number of users",
            "user_count": 0,
        }));
    }

    let user_count = if let Ok(arr) = user_count_result.try_into() {
        i64::from_be_bytes(arr)
    } else {
        return HttpResponse::Ok().json(serde_json::json!({
            "message": "number of users",
            "user_count": 0,
        }));
    };

    HttpResponse::Ok().json(serde_json::json!({
        "message": "number of users",
        "user_count": user_count,
    }))
}

#[get("/pubkey")]
async fn pubkey(payload: web::Json<PubKeyPayload>, data: web::Data<AppState>) -> impl Responder {
    let mut key = "pub:".to_string();
    key.push_str(&payload.username);

    let transaction_op = ProtoTransactionOp {
        op_type: pft::proto::execution::ProtoTransactionOpType::Read.into(),
        operands: vec![key.into_bytes()],
    };

    let user_public_key_result = match send(vec![transaction_op], true, &data).await {
        Ok(response) => response,
        Err(e) => return e,
    };

    if user_public_key_result.is_empty() {
        return HttpResponse::NotFound().json(serde_json::json!({
            "message": "public key could not be found",
            "username": &payload.username,
        }));
    }

    let pub_key_arr: [u8; PUBLIC_KEY_LENGTH] = user_public_key_result
        .try_into()
        .expect("Vec has incorrect length");

    // The client tag is not incremented here.
    let current_tag = data.curr_client_tag.load(Ordering::Relaxed);
    HttpResponse::Ok().json(serde_json::json!({
        "message": "public key of user",
        "username": &payload.username,
        "public key": pub_key_arr,
        "client tag": current_tag,
    }))
}

#[get("/privkey")]
async fn privkey(payload: web::Json<RegisterPayload>, data: web::Data<AppState>) -> impl Responder {
    match authenticate_user(payload.username.clone(), payload.password.clone(), &data).await {
        Ok(valid) => valid,
        Err(e) => return e,
    };

    let mut key = "priv:".to_string();
    key.push_str(&payload.username);

    let transaction_op = ProtoTransactionOp {
        op_type: pft::proto::execution::ProtoTransactionOpType::Read.into(),
        operands: vec![key.into_bytes()],
    };

    let user_priv_key_result = match send(vec![transaction_op], true, &data).await {
        Ok(response) => response,
        Err(e) => return e,
    };

    if user_priv_key_result.is_empty() {
        return HttpResponse::NotFound().json(serde_json::json!({
            "message": "private key could not be found",
            "username": &payload.username,
        }));
    }

    let priv_key_arr: [u8; SECRET_KEY_LENGTH] = user_priv_key_result
        .try_into()
        .expect("Vec has incorrect length");

    HttpResponse::Ok().json(serde_json::json!({
        "message": "private key of user",
        "username": &payload.username,
        "private key": priv_key_arr,
    }))
}

#[get("/")]
async fn home(_data: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "message": "hello from a non-shared, local state",
    }))
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

    let probe_for_byz_commit = Arc::new(AtomicBool::new(false)); // This is a global state!

    HttpServer::new(move || {
        let state = AppState {
            batch_proposer_tx: batch_proposer_tx.clone(),
            probe_for_byz_commit: probe_for_byz_commit.clone(),
            curr_client_tag: AtomicU64::new(0),
        };

        App::new()
            .app_data(web::Data::new(state))
            .service(register)
            .service(pubkey)
            .service(listpubkeys)
            .service(refresh)
            .service(privkey)
            .service(home)
            .service(num_users)
            .service(toggle_byz_wait)
    })
    .workers(actix_threads)
    .max_connection_rate(batch_size) // Otherwise the server doesn't load consensus properly.
    .bind(addr)?
    .run()
    .await?;
    Ok(())
}

async fn send(
    transaction_ops: Vec<ProtoTransactionOp>,
    isRead: bool,
    state: &AppState,
) -> Result<Vec<u8>, HttpResponse> {
    let transaction_phase = ProtoTransactionPhase {
        ops: transaction_ops,
    };

    let transaction = if isRead {
        ProtoTransaction {
            on_receive: Some(transaction_phase),
            on_crash_commit: None,
            on_byzantine_commit: None,
            is_reconfiguration: false,
            is_2pc: false,
        }
    } else {
        ProtoTransaction {
            on_receive: None,
            on_crash_commit: Some(transaction_phase),
            on_byzantine_commit: None,
            is_reconfiguration: false,
            is_2pc: false,
        }
    };

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
    let mut result: Vec<u8> = Vec::new();
    let decoded_payload = match ProtoClientReply::decode(&resp.0.as_slice()[0..resp.1]) {
        Ok(payload) => payload,
        Err(e) => {
            warn!("Error decoding response: {}", e);
            return Err(HttpResponse::InternalServerError().body("Error decoding response"));
        }
    };

    let mut block_n = 0;

    match decoded_payload.reply.unwrap() {
        pft::proto::client::proto_client_reply::Reply::Receipt(receipt) => {
            if let Some(tx_result) = receipt.results {
                if tx_result.result.is_empty() {
                    return Ok(result);
                }
                for op_result in tx_result.result {
                    for value in op_result.values {
                        result = value; // Consider improving this aggregation logic.
                    }
                }
                block_n = receipt.block_n;
            }
        }
        _ => {
            return Err(HttpResponse::NotFound().json(serde_json::json!({
                "message": "error, no Receipt found",
                "result": result,
            })))
        }
    };

    if !isRead && block_n != 0 && state.probe_for_byz_commit.load(Ordering::Relaxed) {
        let current_tag = state.curr_client_tag.fetch_add(1, Ordering::AcqRel);

        let probe_transaction = ProtoTransaction {
            on_receive: Some(ProtoTransactionPhase {
                ops: vec![ProtoTransactionOp {
                    op_type: pft::proto::execution::ProtoTransactionOpType::Probe.into(),
                    operands: vec![block_n.to_be_bytes().to_vec()],
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
    Ok(result)
}

async fn authenticate_user(
    username: String,
    password: String,
    data: &AppState,
) -> Result<bool, HttpResponse> {
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

    if hash(&password.into_bytes()) != result {
        return Err(HttpResponse::Unauthorized().json(serde_json::json!({
            "message": "incorrect password",
            "user": username,
        })));
    }
    Ok(true)
}

/*
Example usage:
Register User:
curl -X POST "http://localhost:8080/register" -H "Content-Type: application/json" -d '{"username":"teddy", "password":"hi"}'

Create key pair:
curl -X POST "http://localhost:8080/refresh" -H "Content-Type: application/json" -d '{"username":"teddy", "password":"hi"}'

View public key:
curl -X GET "http://localhost:8080/pubkey" -H "Content-Type: application/json" -d '{"username":"teddy"}'

View private key:
curl -X GET "http://localhost:8080/privkey" -H "Content-Type: application/json" -d '{"username":"teddy", "password":"hi"}'

Create second user:
curl -X POST "http://localhost:8080/register" -H "Content-Type: application/json" -d '{"username":"teddy2", "password":"hi"}'

Create second user's key:
curl -X POST "http://localhost:8080/refresh" -H "Content-Type: application/json" -d '{"username":"teddy2", "password":"hi"}'

List all public keys:
curl -X GET "http://localhost:8080/listpubkeys" -H "Content-Type: application/json"
*/
