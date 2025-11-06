// Copyright (c) Shubham Mishra. All rights reserved.
// Licensed under the MIT License.

use std::{
    fs,
    io::{Error, ErrorKind},
    path,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;
use log::info;
use tokio::time::sleep;

use crate::{
    config::Config,
    crypto::KeyStore,
    rpc::{
        client::Client,
        server::{LatencyProfile, Server},
        PinnedMessage,
    },
};

use super::{
    auth::HandshakeResponse,
    client::PinnedClient,
    server::{MsgAckChan, RespType, ServerContextType},
    MessageRef,
};

fn process_args(i: i32) -> Config {
    let _p = format!("configs/node{i}_config.json");
    let cfg_path = path::Path::new(&_p);
    if !cfg_path.exists() {
        panic!("Node configs not generated!");
    }

    let cfg_contents = fs::read_to_string(cfg_path).expect("Invalid file path");

    Config::deserialize(&cfg_contents)
}

fn mock_msg_handler(
    _ctx: &ServerEmptyCtx,
    buf: MessageRef,
    _tx: MsgAckChan,
) -> Result<RespType, Error> {
    info!(
        "Received message: {}",
        std::str::from_utf8(&buf).unwrap_or("Parsing error")
    );
    Ok(RespType::NoResp)
}

#[derive(Clone)]
struct ServerEmptyCtx;
impl ServerContextType for ServerEmptyCtx {
    fn get_server_keys(&self) -> Arc<Box<KeyStore>> {
        Arc::new(Box::new(KeyStore::empty()))
    }

    async fn handle_rpc(
        &self,
        msg: MessageRef<'_>,
        ack_chan: MsgAckChan,
    ) -> Result<RespType, Error> {
        mock_msg_handler(self, msg, ack_chan)
    }
}

async fn run_body(
    server: &Arc<Server<ServerEmptyCtx>>,
    client: &PinnedClient,
    config: &Config,
) -> Result<(), Error> {
    let server = server.clone();
    let server_handle = tokio::spawn(async move {
        let _ = Server::<ServerEmptyCtx>::run(server).await;
    });
    let data = String::from("Hello world!\n");
    let data = data.into_bytes();
    sleep(Duration::from_millis(100)).await;
    info!("Sending test message to self!");
    let _ = PinnedClient::send(
        &client.clone(),
        &config.net_config.name,
        MessageRef::from(&data, data.len(), &super::SenderType::Anon),
    )
    .await
    .expect("First send should have passed!");
    info!("Send done!");
    sleep(Duration::from_millis(100)).await;
    let _ = PinnedClient::send(
        &client.clone(),
        &config.net_config.name,
        MessageRef::from(&data, data.len(), &super::SenderType::Anon),
    )
    .await
    .expect_err("Second send should have failed!");
    info!("Send done twice!");
    PinnedClient::reliable_send(
        &client.clone(),
        &config.net_config.name,
        MessageRef::from(&data, data.len(), &super::SenderType::Anon),
    )
    .await
    .expect("Reliable send should have passed");
    info!("Reliable send!");
    sleep(Duration::from_millis(100)).await;
    server_handle.abort();
    sleep(Duration::from_millis(100)).await;
    PinnedClient::reliable_send(
        &client.clone(),
        &config.net_config.name,
        MessageRef::from(&data, data.len(), &super::SenderType::Anon),
    )
    .await
    .expect_err("Reliable send should fail after server abort");
    let _ = tokio::join!(server_handle);
    Ok(())
}
#[tokio::test]
async fn test_authenticated_client_server() {
    colog::init();
    let config = process_args(1);
    info!("Starting {}", config.net_config.name);
    let keys = KeyStore::new(
        &config.rpc_config.allowed_keylist_path,
        &config.rpc_config.signing_priv_key_path,
    );
    let server = Arc::new(Server::new(&config, ServerEmptyCtx {}, &keys));
    let client = Client::new(&config, &keys, false, 0).into();
    run_body(&server, &client, &config).await.unwrap();

    let server = Arc::new(Server::new(&config, ServerEmptyCtx {}, &keys));
    run_body(&server, &client, &config).await.unwrap();

    let server = Arc::new(Server::new(&config, ServerEmptyCtx {}, &keys));
    run_body(&server, &client, &config).await.unwrap();
}

#[tokio::test]
async fn test_unauthenticated_client_server() {
    colog::init();
    let config = process_args(1);
    info!("Starting {}", config.net_config.name);
    let server = Arc::new(Server::new_unauthenticated(&config, ServerEmptyCtx {}));
    let client = Client::new_unauthenticated(&config).into();
    run_body(&server, &client, &config).await.unwrap();

    let server = Arc::new(Server::new_unauthenticated(&config, ServerEmptyCtx {}));
    run_body(&server, &client, &config).await.unwrap();

    let server = Arc::new(Server::new_unauthenticated(&config, ServerEmptyCtx {}));
    run_body(&server, &client, &config).await.unwrap();
}

#[derive(Clone)]
struct ServerCtx(Arc<Mutex<Pin<Box<i32>>>>);

impl ServerContextType for ServerCtx {
    fn get_server_keys(&self) -> Arc<Box<KeyStore>> {
        Arc::new(Box::new(KeyStore::empty()))
    }

    async fn handle_rpc(
        &self,
        msg: MessageRef<'_>,
        ack_chan: MsgAckChan,
    ) -> Result<RespType, Error> {
        drop_after_n(self, msg, ack_chan)
    }
}

fn drop_after_n(ctx: &ServerCtx, m: MessageRef, _tx: MsgAckChan) -> Result<RespType, Error> {
    let mut _ctx = ctx.0.lock().unwrap();
    **_ctx -= 1;
    info!(
        "{:?} said: {}",
        m.sender(),
        std::str::from_utf8(&m).unwrap_or("Parsing error")
    );

    if **_ctx <= 0 {
        return Err(Error::new(ErrorKind::BrokenPipe, "breaking connection"));
    }
    Ok(RespType::NoResp)
}

#[tokio::test]
async fn test_3_node_bcast() {
    colog::init();
    let config1 = process_args(1);
    let config2 = process_args(2);
    let config3 = process_args(3);
    let keys1 = KeyStore::new(
        &config1.rpc_config.allowed_keylist_path,
        &config1.rpc_config.signing_priv_key_path,
    );
    let keys2 = KeyStore::new(
        &config2.rpc_config.allowed_keylist_path,
        &config2.rpc_config.signing_priv_key_path,
    );
    let keys3 = KeyStore::new(
        &config3.rpc_config.allowed_keylist_path,
        &config3.rpc_config.signing_priv_key_path,
    );
    let ctx1 = ServerCtx(Arc::new(Mutex::new(Box::pin(3))));
    let ctx2 = ServerCtx(Arc::new(Mutex::new(Box::pin(1))));
    let ctx3 = ServerCtx(Arc::new(Mutex::new(Box::pin(2))));
    let server1 = Arc::new(Server::new(&config1, ctx1, &keys1));
    let server2 = Arc::new(Server::new(&config2, ctx2, &keys2));
    let server3 = Arc::new(Server::new(&config3, ctx3, &keys3));

    let server_handle1 = tokio::spawn(async move {
        let _ = Server::run(server1).await;
    });
    let server_handle2 = tokio::spawn(async move {
        let _ = Server::run(server2).await;
    });
    let server_handle3 = tokio::spawn(async move {
        let _ = Server::run(server3).await;
    });

    let client = Client::new(&config1, &keys1, false, 0).into();
    let names = vec![
        String::from("node1"),
        String::from("node2"),
        String::from("node3"),
    ];
    let data = String::from("HelloWorld!!\n");
    let data = data.into_bytes();
    let sz = data.len();
    let data = PinnedMessage::from(data, sz, super::SenderType::Anon);
    PinnedClient::broadcast(
        &client,
        &names,
        &data,
        &mut LatencyProfile::new(),
        names.len(),
    )
    .await
    .expect("Broadcast should complete with 3 nodes!");
    sleep(Duration::from_millis(100)).await;
    server_handle1.abort();
    let _ = tokio::join!(server_handle1);
    sleep(Duration::from_millis(1000)).await;
    PinnedClient::broadcast(
        &client,
        &names,
        &data,
        &mut LatencyProfile::new(),
        names.len(),
    )
    .await
    .expect("Broadcast should complete with 2 nodes!");
    sleep(Duration::from_millis(100)).await;
    server_handle2.abort();
    let _ = tokio::join!(server_handle2);

    PinnedClient::broadcast(
        &client,
        &names,
        &data,
        &mut LatencyProfile::new(),
        names.len(),
    )
    .await
    .expect("There are not enough nodes!");

    sleep(Duration::from_millis(100)).await;
    server_handle3.abort();
    let _ = tokio::join!(server_handle3);
}

#[test]
pub fn test_auth_serde() {
    let h = HandshakeResponse {
        name: String::from("node1"),
        signature: Bytes::from(Vec::from(
            b"1234567812345678123456781234567812345678123456781234567812345678",
        )),
    };

    let resp_buf = h.serialize(false, 0);

    println!("{:?}", resp_buf);

    let resp = match HandshakeResponse::deserialize(&resp_buf) {
        Ok(r) => r,
        Err(e) => panic!("{}", e),
    };

    println!("{:?}", resp);

    if !(resp.0.name == h.name && resp.0.signature == h.signature) {
        panic!("Field mismatch: {:?} vs {:?}", h, resp);
    }
}
