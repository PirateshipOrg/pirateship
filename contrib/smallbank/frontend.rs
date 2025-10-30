use actix_web::cookie::time::macros::datetime;
use actix_web::cookie::time::OffsetDateTime;
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use chrono::serde::ts_microseconds::serialize;
use chrono::{DateTime, TimeZone};
use hex::ToHex;
use log::{debug, warn};
use pft::consensus::batch_proposal::TxWithAckChanTag;
use prost::Message;
use serde::ser::Error;
use serde_json::value;
use tokio::sync::{mpsc, Mutex};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pft::config::Config;
use pft::crypto::{KeyStore, hash};
use pft::proto::execution::{ProtoTransaction, ProtoTransactionOp, ProtoTransactionPhase};
use pft::rpc::client::Client;
use pft::rpc::{PinnedMessage, SenderType};
use pft::{proto::{client::{self, ProtoClientReply, ProtoClientRequest}, rpc::ProtoPayload}, rpc::client::PinnedClient, utils::channel::{make_channel, Receiver, Sender}};
use crate::payloads::{RegisterPayload, SendPayload};



struct AppState {
    /// Global channel to feed into the consensusNode.
    batch_proposer_tx: Sender<TxWithAckChanTag>,
    /// Only a per-thread client tag counter remains.
    curr_client_tag: AtomicU64,
    keys: KeyStore,
    leader_name: String,
    send_threshold: i64,
}

#[get("/balance")]
async fn balance(payload: web::Json<RegisterPayload>, data: web::Data<AppState>) -> impl Responder {
    let username = payload.username.clone();
    let savings_account_name = "savings:".to_owned() + &username;
    let checking_account_name = "checking:".to_owned() + &username;

    let get_savings_op = ProtoTransactionOp {
        op_type: pft::proto::execution::ProtoTransactionOpType::Read.into(),
        operands: vec![savings_account_name.clone().into_bytes()],
    };

    let get_checking_op = ProtoTransactionOp {
        op_type: pft::proto::execution::ProtoTransactionOpType::Read.into(),
        operands: vec![checking_account_name.clone().into_bytes()],
    };

    let result = match send(vec![get_savings_op, get_checking_op], true, &data, false).await {
        Ok(response) => response,
        Err(e) => return e,
    };

    if result.len() != 2 {
        return HttpResponse::InternalServerError().body("user account does not exist");
    }

    let savings_account_balance: [u8; 8] = match result[0].as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => return HttpResponse::BadRequest().body("Expected 8 bytes for an i64"),
    };


    let checking_account_balance: [u8; 8] = match result[1].as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => return HttpResponse::BadRequest().body("Expected8 bytes for an i64"),
    };

    let savings_balance_message = format!(
        "${}",
        i64::from_be_bytes(savings_account_balance)
    );

    let checking_balance_message = format!(
        "${}",
        i64::from_be_bytes(checking_account_balance)
    );
    
    HttpResponse::Ok().json(serde_json::json!({
        "account name": username,
        "savings balance": savings_balance_message,
        "checking balance": checking_balance_message,
    }))
    
}   

#[post("/register")]
async fn register(payload: web::Json<RegisterPayload>, data: web::Data<AppState>) -> impl Responder {
    let username = payload.username.clone();

    // Query KMS for username.
    let transaction_op = ProtoTransactionOp {
        op_type: pft::proto::execution::ProtoTransactionOpType::Read.into(),
        operands: vec![username.clone().into_bytes()],
    };

    let result = match send(vec![transaction_op], true, &data, false).await {
        Ok(response) => response,
        Err(e) => return e,
    };

    if !result.is_empty() {
        return HttpResponse::Conflict().json(serde_json::json!({
            "message": "username already exists",
        }));
    }

    let savings_account_name = "savings:".to_owned() + &username;
    let checking_account_name = "checking:".to_owned() + &username;

    let create_savings_op = ProtoTransactionOp {
        op_type: pft::proto::execution::ProtoTransactionOpType::Write.into(),
        operands: vec![savings_account_name.clone().into_bytes(), (1000000 as i64).to_be_bytes().to_vec()],
    };

    let create_checking_op = ProtoTransactionOp {
        op_type: pft::proto::execution::ProtoTransactionOpType::Write.into(),
        operands: vec![checking_account_name.clone().into_bytes(), (1000000 as i64).to_be_bytes().to_vec()],
    };

    let _ = match send(vec![create_savings_op, create_checking_op], false, &data, false).await {
        Ok(response) => response,
        Err(e) => return e,
    };

    HttpResponse::Ok().json(serde_json::json!({
        "message": "created user with 1 million dollars in both accounts",
    }))
}


#[post("/sendpayment")]
async fn sendpayment(payload: web::Json<SendPayload>, data: web::Data<AppState>) -> impl Responder {
    let sender = payload.sender_account.clone();
    let receiver = payload.receiver_account.clone();
    let send_amount = payload.send_amount;

    if send_amount <= 0 {
        return HttpResponse::BadRequest().body("Send a positive value");
    }

    let sender_checking_account = "checking:".to_owned() + &sender;
    let receiver_checking_account = "checking:".to_owned() + &receiver;

    let mut send_attempts = 0;

    let mut resclone = Vec::new();

    loop {
        send_attempts += 1;
        //get sender account, reciever account
        let get_sender_balance_op = ProtoTransactionOp {
            op_type: pft::proto::execution::ProtoTransactionOpType::Read.into(),
            operands: vec![sender_checking_account.clone().into_bytes()],
        };

        let get_receiver_balance_op = ProtoTransactionOp {
            op_type: pft::proto::execution::ProtoTransactionOpType::Read.into(),
            operands: vec![receiver_checking_account.clone().into_bytes()],
        };
        
        let result = match send(vec![get_sender_balance_op, get_receiver_balance_op], true, &data, false).await {
            Ok(response) => response,
            Err(e) => return e,
        };

        //check if both accounts exists (?)
        if result.len() != 2 {
            return HttpResponse::InternalServerError().body("Sender/Reciever Account does not exist");
        }
        
         // Get the sender's account balance, check if it is > amount send
        let sender_balance = match result[0].as_slice().try_into() {
            Ok(arr) => i64::from_be_bytes(arr),
            Err(_) => return HttpResponse::BadRequest().body("Expected 8 bytes for an i64"),
        };    

        let receiver_balance = match result[1].as_slice().try_into() {
            Ok(arr) => i64::from_be_bytes(arr),
            Err(_) => return HttpResponse::BadRequest().body("Expected 8 bytes for an i64"),
        };

        if sender_balance < send_amount {
            return HttpResponse::BadRequest().body("Sender's Account does not have enough money");
        };
    
         //increment value with cas
        let credit_op = ProtoTransactionOp {
            op_type: pft::proto::execution::ProtoTransactionOpType::Cas.into(),
            operands: vec![receiver_checking_account.clone().into_bytes(), (receiver_balance + send_amount).to_be_bytes().to_vec(), receiver_balance.to_be_bytes().to_vec(), sender_checking_account.clone().into_bytes(), (sender_balance - send_amount).to_be_bytes().to_vec(), sender_balance.to_be_bytes().to_vec()],
        };

        // let debt_op = ProtoTransactionOp {
        //     op_type: pft::proto::execution::ProtoTransactionOpType::Cas.into(),
        //     operands: vec![],
        // };

        let result = match send(vec![credit_op], false, &data, send_amount >= data.send_threshold).await {
            Ok(response) => response,
            Err(e) => return e,
        };
        if result.len() == 2 {
            break;
        }

        resclone = result;

        if send_attempts == 20 {
            return HttpResponse::RequestTimeout().body(format!("retried CAS too many times: {:?}", resclone));
        }
    }

    let message = format!(
        "sent ${} successfully from {} to {}",
        send_amount, sender, receiver
    );

    HttpResponse::Ok().json(serde_json::json!({
        "message": message,
        "resclone": resclone,
        "send attempts": send_attempts,
        "send threshold": &data.send_threshold
    }))
}

#[get("/")]
async fn home(_data: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "message": "hello from a non-shared, local state",
    }))
}

pub async fn run_actix_server(config: Config, batch_proposer_tx: pft::utils::channel::AsyncSenderWrapper<TxWithAckChanTag>, actix_threads: usize, send_threshold: i64) -> std::io::Result<()> {
    let mut keys = KeyStore::empty();
    keys.priv_key = KeyStore::get_privkeys(&config.rpc_config.signing_priv_key_path);
    let keys = keys.clone();
    let name =  config.net_config.name.clone();

    let addr = config.net_config.addr.clone();
    // Add 1000 to the port.
    let (host, port) = addr.split_once(':').unwrap();
    let port: u16 = port.parse().unwrap();
    let port = port + 1000;
    let addr = format!("{}:{}", host, port);


    HttpServer::new(move || {
        // Each worker thread creates its own client instance.
        let state = AppState {
            batch_proposer_tx: batch_proposer_tx.clone(),
            curr_client_tag: AtomicU64::new(0),
            keys: keys.clone(),
            leader_name: name.clone(),
            send_threshold,
        };

        App::new()
            .app_data(web::Data::new(state))
            .service(home)
            .service(register)
            .service(balance)
            .service(sendpayment)
    })
    .bind(addr)?
    .run()
    .await?;
    Ok(())
}

async fn send(transaction_ops: Vec<ProtoTransactionOp>, isRead: bool, state: &AppState, byz_commit: bool) -> Result<Vec<Vec<u8>>, HttpResponse> {
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
        pft::proto::client::proto_client_reply::Reply::Response(response) => {
            if let Some(tx_result) = response.results {
                if tx_result.result.is_empty() {
                    return Ok(result);
                }
                for op_result in tx_result.result {
                    if op_result.success == false {
                        return Ok(Vec::new());
                    }
                    for value in op_result.values {
                        result.push(value);
                    }
                }
            }
            response.block_n
        },
        _ => {
            return Err(HttpResponse::NotFound().json(serde_json::json!({
                "message": "error, no Receipt found",
                "result": result,
            })))
        },
    };

    if !isRead && block_n != 0 && byz_commit {
        let current_tag = state.curr_client_tag.fetch_add(1, Ordering::AcqRel);
    
        let probe_transaction = ProtoTransaction {
            on_receive: Some(ProtoTransactionPhase {
                ops: vec![ProtoTransactionOp {
                    op_type: pft::proto::execution::ProtoTransactionOpType::ProbeAudit.into(),
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


/*
Example usage:

updated api calls:

curl -X POST "http://localhost:8080/register" -H "Content-Type: application/json" -d '{"username":"teddy1"}'
curl -X POST "http://localhost:8080/register" -H "Content-Type: application/json" -d '{"username":"teddy2"}'

curl -X GET "http://localhost:8080/balance" -H "Content-Type: application/json" -d '{"username":"teddy1"}'
curl -X GET "http://localhost:8080/balance" -H "Content-Type: application/json" -d '{"username":"teddy2"}'

curl -X POST "http://localhost:8080/sendpayment" -H "Content-Type: application/json" -d '{"sender_account":"teddy1", "receiver_account":"teddy2", "send_amount":1000}'


    pub sender_account: String,
    pub receiver_account: String,
    pub send_amount: i64,
}
*/
