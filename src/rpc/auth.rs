// Copyright (c) Shubham Mishra. All rights reserved.
// Licensed under the MIT License.

use bytes::Bytes;
use ed25519_dalek::SIGNATURE_LENGTH;
use log::debug;
use prost::Message;
use rand::prelude::*;
use std::{
    io::{Error, ErrorKind},
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{client, server};

use super::{
    client::PinnedClient,
    proto::auth::ProtoHandshakeResponse,
    server::{Server, ServerContextType},
};

#[derive(Clone, Debug)]
pub(crate) struct HandshakeResponse {
    pub name: String,
    pub signature: Bytes,
}

impl HandshakeResponse {
    pub(crate) fn serialize(&self, is_reply_channel: bool, client_sub_id: u64) -> Vec<u8> {
        let proto = ProtoHandshakeResponse {
            name: self.name.clone(),
            signature: self.signature.to_vec(),
            is_reply_channel,
            client_sub_id,
        };
        proto.encode_to_vec()
    }

    pub(crate) fn deserialize(arr: &Vec<u8>) -> Result<(HandshakeResponse, bool, u64), Error> {
        let proto = ProtoHandshakeResponse::decode(arr.as_slice());
        let deser = match proto {
            Ok(d) => (
                HandshakeResponse {
                    name: d.name,
                    signature: Bytes::from(d.signature),
                },
                d.is_reply_channel,
                d.client_sub_id,
            ),
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("Protobuf error: {}", e),
                ));
            }
        };

        Ok(deser)
    }
}

fn construct_payload(nonce: u32, name: &String) -> Vec<u8> {
    let nonce_enc = nonce.to_be_bytes();
    let mut result = vec![0u8; 0];
    result.extend(nonce_enc.as_slice());
    result.extend(name.as_bytes());
    result
}
/// Authentication handshake
/// Server                              Client
/// -----                               ------
/// Nonce   ---(TLS channel)-------->
///         <-----------------------    <name, Sign(Nonce||name)>
/// if name in keylist && signature verifies against registered pubkey
/// accept connection, or drop.
/// Returns name of peer or error.
pub async fn handshake_server<S>(
    server: &Arc<Server<S>>,
    stream: &mut server::TlsStream<TcpStream>,
) -> Result<
    (
        String,
        bool, /* is_reply_channel for full duplex */
        u64,  /* client sub id */
    ),
    Error,
>
where
    S: ServerContextType + Send + Sync + 'static,
{
    let mut rng = rand::rngs::OsRng;
    let nonce: u32 = rng.gen();
    stream.write_u32(nonce).await?;

    // Following usual message structure: Size(u32) | Body
    let sz = stream.read_u32().await? as usize;
    if sz == 0 {
        return Err(Error::new(ErrorKind::InvalidData, "invalid response"));
    }
    let mut buf = vec![0u8; sz];
    stream.read_exact(buf.as_mut()).await?;

    let resp = HandshakeResponse::deserialize(&buf)?;

    let name = resp.0.name;
    // String::from(std::str::from_utf8(resp.name).unwrap_or(""));
    if server.key_store.get().get_pubkey(&name).is_none() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("unknown peer: {}", name),
        ));
    }

    let payload = construct_payload(nonce, &name);
    let sig: &[u8; SIGNATURE_LENGTH] = resp
        .0
        .signature
        .as_ref()
        .try_into()
        .unwrap_or(&[0u8; SIGNATURE_LENGTH]);
    // Let's hope a blank signature is never a valid signature.

    if !server
        .key_store
        .get()
        .verify(&name, sig, payload.as_slice())
    {
        return Err(Error::new(ErrorKind::InvalidData, "invalid signature"));
    }

    Ok((name, resp.1, resp.2))
}

pub async fn handshake_client(
    client: &PinnedClient,
    stream: &mut client::TlsStream<TcpStream>,
    is_reply_chan: bool,
    client_sub_id: u64,
) -> Result<(), Error> {
    let nonce = stream.read_u32().await?;
    debug!("Received nonce: {}", nonce);
    let cfg = client.0.config.get();
    let payload = construct_payload(nonce, &cfg.net_config.name);
    let signature = client.0.key_store.get().sign(&payload.as_slice());
    let signature = Bytes::from(Vec::from(signature));
    let name = cfg.net_config.name.clone();
    let resp = HandshakeResponse { name, signature };
    let resp_buf = resp.serialize(is_reply_chan, client_sub_id);

    stream.write_u32(resp_buf.len() as u32).await?;
    stream.write_all(resp_buf.as_slice()).await?;

    Ok(())
}
