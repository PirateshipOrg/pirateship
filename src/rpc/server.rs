// Copyright (c) Shubham Mishra. All rights reserved.
// Licensed under the MIT License.

use std::{
    collections::HashMap,
    fs::File,
    future::Future,
    io::{self, Cursor, Error},
    path,
    sync::{atomic::AtomicBool, Arc},
    time::{Duration, Instant},
};

use crate::{
    config::{AtomicConfig, Config},
    crypto::{AtomicKeyStore, KeyStore},
    rpc::auth,
    utils::AtomicStruct,
};
use indexmap::IndexMap;
use log::{debug, info, trace, warn};
use rustls::{
    crypto::aws_lc_rs,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use rustls_pemfile::{certs, rsa_private_keys};
use tokio::{
    io::{split, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio::{
    io::{BufWriter, ReadHalf},
    sync::{mpsc, oneshot},
};
use tokio_rustls::{rustls, server::TlsStream, TlsAcceptor};

use super::{MessageRef, PinnedMessage, SenderType};

#[derive(Clone, Debug)]
pub struct LatencyProfile {
    pub start_time: Instant,
    pub should_print: bool,
    pub prefix: String,
    pub durations: IndexMap<String, Duration>,
}

impl LatencyProfile {
    pub fn new() -> LatencyProfile {
        LatencyProfile {
            start_time: Instant::now(),
            durations: IndexMap::new(),
            should_print: false,
            prefix: String::from(""),
        }
    }

    pub fn register(&mut self, s: &str) {
        let time = self.start_time.elapsed();
        self.durations.insert(s.to_string(), time);
    }

    pub fn print(&self) {
        if !self.should_print {
            return;
        }

        let str_list: Vec<String> = self
            .durations
            .iter()
            .map(|(k, v)| format!("{}: {} us", k, v.as_micros()))
            .collect();

        trace!("{}, {}", self.prefix, str_list.join(", "));
    }

    pub fn force_print(&self) {
        let str_list: Vec<String> = self
            .durations
            .iter()
            .map(|(k, v)| format!("{}: {} us", k, v.as_micros()))
            .collect();

        info!("{}, {}", self.prefix, str_list.join(", "));
    }
}

pub type MsgAckChan = mpsc::Sender<(PinnedMessage, LatencyProfile)>;

pub enum RespType {
    Resp = 1,
    NoResp = 2,
    NoRespAndReconf = 3,
    RespAndTrack = 4,
    RespAndTrackAndReconf = 5,
}

pub type HandlerType<ServerContext> = fn(
    &ServerContext, // State kept by upper layers
    MessageRef,     // New message
    MsgAckChan,
) -> Result<
    // Channel to receive response to message
    RespType, // Should the caller wait for a response from the channel?
    Error,
>; // Should this connection be dropped?

pub trait ServerContextType {
    fn get_server_keys(&self) -> Arc<Box<KeyStore>>;
    fn handle_rpc(
        &self,
        msg: MessageRef,
        ack_chan: MsgAckChan,
    ) -> impl Future<Output = Result<RespType, Error>> + Send;
}

pub struct Server<ServerContext>
where
    ServerContext: ServerContextType + Send + Sync + 'static,
{
    pub config: AtomicConfig,
    pub tls_certs: Vec<CertificateDer<'static>>,
    pub tls_keys: PrivateKeyDer<'static>,
    pub key_store: AtomicKeyStore,
    pub ctx: ServerContext,
    // pub msg_handler: HandlerType<ServerContext>, // Can't be a closure as msg_handler is called from another thread.
    do_auth: bool,
}

pub struct FrameReader {
    pub buffer: Vec<u8>,
    pub stream: ReadHalf<TlsStream<TcpStream>>,
    pub offset: usize,
    pub bound: usize,
}

impl FrameReader {
    pub fn new(stream: ReadHalf<TlsStream<TcpStream>>) -> FrameReader {
        FrameReader {
            buffer: vec![0u8; 65536],
            stream,
            offset: 0,
            bound: 0,
        }
    }

    async fn read_next_bytes(&mut self, n: usize, v: &mut Vec<u8>) -> io::Result<()> {
        let mut pos = 0;
        let mut n = n;
        let get_n = n;
        while n > 0 {
            if self.bound == self.offset {
                // Need to fetch more data.
                let read_n = self.stream.read(self.buffer.as_mut()).await?;
                debug!(
                    "Fetched {} bytes, Need to fetch {} bytes, pos {}, Currently at: {}",
                    read_n, get_n, pos, n
                );
                self.bound = read_n;
                self.offset = 0;
            }

            if self.bound - self.offset >= n {
                // Copy in full
                v[pos..][..n].copy_from_slice(&self.buffer[self.offset..self.offset + n]);
                self.offset += n;
                n = 0;
            } else {
                // Copy partial.
                // We'll get the rest in the next iteration of the loop.
                v[pos..][..self.bound - self.offset]
                    .copy_from_slice(&self.buffer[self.offset..self.bound]);
                n -= self.bound - self.offset;
                pos += self.bound - self.offset;
                self.offset = self.bound;
            }
        }

        Ok(())
    }

    pub async fn get_next_frame(&mut self, buff: &mut Vec<u8>) -> io::Result<usize> {
        let mut sz_vec = vec![0u8; 4];
        self.read_next_bytes(4, &mut sz_vec).await?;
        let mut sz_rdr = Cursor::new(sz_vec);
        let sz = sz_rdr.read_u32().await.unwrap() as usize;
        let len = buff.len();
        if sz > len {
            buff.extend(vec![0u8; sz - len]);
            // buff.reserve(sz - len);
        }

        self.read_next_bytes(sz, buff).await?;

        Ok(sz)
    }
}

macro_rules! ok_or_exit {
    ($e: expr) => {
        match $e {
            Ok(r) => r,
            Err(_) => return,
        }
    };
}

macro_rules! some_or_exit {
    ($e: expr) => {
        match $e {
            Some(r) => r,
            None => return,
        }
    };
}

impl<S> Server<S>
where
    S: ServerContextType + Send + Clone + Sync + 'static,
{
    // Following two functions ported from: https://github.com/rustls/tokio-rustls/blob/main/examples/server.rs
    fn load_certs(path: &String) -> Vec<CertificateDer<'static>> {
        let cert_path = path::Path::new(path.as_str());
        if !cert_path.exists() {
            panic!("Invalid Certificate Path: {}", path);
        }
        let f = match File::open(cert_path) {
            Ok(_f) => _f,
            Err(e) => {
                panic!("Problem reading cert file: {}", e);
            }
        };

        match certs(&mut io::BufReader::new(f)).collect() {
            Ok(cert) => cert,
            Err(e) => {
                panic!("Problem parsing cert: {}", e);
            }
        }
    }

    /// This currently reads RSA keys only.
    /// Make sure that the key in path is PKCS1 encoded
    /// ie, begins with "-----BEGIN RSA PRIVATE KEY-----"
    /// Command to do that: openssl rsa -in pkcs8.key -out pkcs1.key
    fn load_keys(path: &String) -> PrivateKeyDer<'static> {
        let key_path = path::Path::new(path.as_str());
        if !key_path.exists() {
            panic!("Invalid Key Path: {}", path);
        }
        let f = match File::open(key_path) {
            Ok(_f) => _f,
            Err(e) => {
                panic!("Problem reading keyfile: {}", e);
            }
        };

        let key_result = rsa_private_keys(&mut io::BufReader::new(f))
            .next()
            .unwrap()
            .map(Into::into);
        match key_result {
            Ok(key) => key,
            Err(e) => {
                panic!("Problem parsing key: {}", e);
            }
        }
    }

    pub fn new(cfg: &Config, ctx: S, key_store: &KeyStore) -> Server<S> {
        Server {
            config: AtomicConfig::new(cfg.clone()),
            tls_certs: Server::<S>::load_certs(&cfg.net_config.tls_cert_path),
            tls_keys: Server::<S>::load_keys(&cfg.net_config.tls_key_path),
            ctx,
            do_auth: true,
            key_store: AtomicKeyStore::new(key_store.to_owned()),
        }
    }

    pub fn new_atomic(config: AtomicConfig, ctx: S, key_store: AtomicKeyStore) -> Server<S> {
        Server {
            config: config.clone(),
            tls_certs: Server::<S>::load_certs(&config.get().net_config.tls_cert_path),
            tls_keys: Server::<S>::load_keys(&config.get().net_config.tls_key_path),
            ctx,
            do_auth: true,
            key_store,
        }
    }

    pub fn new_unauthenticated(cfg: &Config, ctx: S) -> Server<S> {
        Server {
            config: AtomicConfig::new(cfg.clone()),
            tls_certs: Server::<S>::load_certs(&cfg.net_config.tls_cert_path),
            tls_keys: Server::<S>::load_keys(&cfg.net_config.tls_key_path),
            ctx,
            do_auth: false,
            key_store: AtomicStruct::new(KeyStore::empty().to_owned()),
        }
    }

    pub async fn handle_auth(
        server: Arc<Self>,
        stream: &mut TlsStream<TcpStream>,
        addr: core::net::SocketAddr,
    ) -> io::Result<(SenderType, bool, u64)> {
        let mut sender = SenderType::Anon;
        let mut reply_chan = false;
        let mut client_sub_id = 0;
        if server.do_auth {
            let res = auth::handshake_server(&server, stream).await;
            let name = match res {
                Ok((nam, is_reply_chan, _client_sub_id)) => {
                    trace!("Authenticated {} at Addr {}", nam, addr);
                    reply_chan = is_reply_chan;
                    client_sub_id = _client_sub_id;
                    nam
                }
                Err(e) => {
                    warn!("Problem authenticating: {}", e);
                    return Err(e);
                }
            };
            sender = SenderType::Auth(name, client_sub_id);
        };

        Ok((sender, reply_chan, client_sub_id))
    }

    pub async fn handle_stream(
        server: Arc<Self>,
        stream: TlsStream<TcpStream>,
        stream_out: Option<TlsStream<TcpStream>>,
        addr: core::net::SocketAddr,
        sender: SenderType,
    ) -> io::Result<()> {
        let (rx, mut _tx) = split(stream);
        let mut read_buf = vec![0u8; server.config.get().rpc_config.recv_buffer_size as usize];
        let mut tx_buf = if stream_out.is_some() {
            let (__stream_out_rx, stream_out_tx) = split(stream_out.unwrap());
            BufWriter::new(stream_out_tx)
        } else {
            BufWriter::new(_tx)
        };
        let mut rx_buf = FrameReader::new(rx);
        let (ack_tx, mut ack_rx) = mpsc::channel(1000);
        let (resp_tx, mut resp_rx) = mpsc::channel(1000);

        let server2 = server.clone();
        let hndl = tokio::spawn(async move {
            while let Some(resp) = resp_rx.recv().await {
                if let Ok(RespType::Resp) = resp {
                    debug!("Waiting for response!");
                    let mref: (PinnedMessage, LatencyProfile) = some_or_exit!(ack_rx.recv().await);
                    let mref = mref.0.as_ref();
                    if let Err(_) = tx_buf.write_u32(mref.1 as u32).await {
                        break;
                    }
                    if let Err(_) = tx_buf.write_all(&mref.0[..mref.1]).await {
                        break;
                    };
                    match tx_buf.flush().await {
                        Ok(_) => {}
                        Err(e) => {
                            warn!("Error sending response: {}", e);
                            break;
                        }
                    };
                } else if let Ok(RespType::RespAndTrack) = resp {
                    debug!("Waiting for response!");
                    let (mref, mut profile) = some_or_exit!(ack_rx.recv().await);
                    profile.register("Ack Received");
                    let mref = mref.as_ref();
                    ok_or_exit!(tx_buf.write_u32(mref.1 as u32).await);
                    ok_or_exit!(tx_buf.write_all(&mref.0[..mref.1]).await);
                    match tx_buf.flush().await {
                        Ok(_) => {}
                        Err(e) => {
                            warn!("Error sending response: {}", e);
                            break;
                        }
                    };

                    profile.register("Ack sent");
                    profile.print();
                } else if let Ok(RespType::RespAndTrackAndReconf) = resp {
                    debug!("Waiting for response!");
                    let (mref, mut profile) = some_or_exit!(ack_rx.recv().await);
                    profile.register("Ack Received");
                    let mref = mref.as_ref();
                    ok_or_exit!(tx_buf.write_u32(mref.1 as u32).await);
                    ok_or_exit!(tx_buf.write_all(&mref.0[..mref.1]).await);
                    match tx_buf.flush().await {
                        Ok(_) => {}
                        Err(e) => {
                            warn!("Error sending response: {}", e);
                            break;
                        }
                    };

                    profile.register("Ack sent");
                    profile.print();

                    // Reconfigure the server to use the new public keys.
                    let new_keys = server2.ctx.get_server_keys();
                    info!("Resp to: {:?}, Resp: {:?}", mref.2, mref.0);
                    server2.key_store.set(new_keys.as_ref().clone());
                } else if let Ok(RespType::NoRespAndReconf) = resp {
                    // Reconfigure the server to use the new public keys.
                    let new_keys = server2.ctx.get_server_keys();
                    server2.key_store.set(new_keys.as_ref().clone());
                }
            }
        });

        loop {
            // Message format: Size(u32) | Message
            // Message size capped at 4GiB.
            // As message is multipart, TCP won't have atomic delivery.
            // It is better to just close connection if that happens.
            // That is why `await?` with all read calls.
            let sz = match rx_buf.get_next_frame(&mut read_buf).await {
                Ok(s) => s,
                Err(e) => {
                    debug!("Encountered error while reading frame: {}", e);
                    return Err(e);
                }
            };

            let resp = server
                .ctx
                .handle_rpc(MessageRef::from(&read_buf, sz, &sender), ack_tx.clone())
                .await;
            if let Err(e) = resp {
                warn!("Dropping connection: {}", e);
                break;
            }

            let _ = resp_tx.send(resp).await;
        }

        hndl.abort();

        warn!("Dropping connection from {:?}", addr);
        Ok(())
    }
    pub async fn run(server: Arc<Self>) -> io::Result<()> {
        let server_addr = &server.config.get().net_config.addr;
        info!("Listening on {}", server_addr);

        // aws_lc_rs::default_provider() uses AES-GCM. This automatically includes a MAC.
        // MAC checking is embedded in the TLS messaging, so upper layers don't need to worry.
        let tls_cfg =
            rustls::ServerConfig::builder_with_provider(aws_lc_rs::default_provider().into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth() // Client and Node auth happen separately after TLS handshake.
                .with_single_cert(server.tls_certs.clone(), server.tls_keys.clone_key())
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_cfg));

        let listener = TcpListener::bind(server_addr).await?;

        let mut parked_streams = HashMap::new();

        loop {
            let (socket, addr) = listener.accept().await?;
            socket.set_nodelay(true)?;
            let acceptor = tls_acceptor.clone();
            let server_ = server.clone();
            let mut stream = acceptor.accept(socket).await?;
            let (sender, is_reply_chan, client_sub_id) =
                Self::handle_auth(server.clone(), &mut stream, addr).await?;

            let map_name = sender.to_string() + "#" + &client_sub_id.to_string();

            if is_reply_chan {
                parked_streams.insert(map_name, stream);
                continue;
            }

            let stream_out = parked_streams.remove(&map_name);
            // It is cheap to open a lot of green threads in tokio
            // No need to have a list of sockets to select() from.
            tokio::spawn(async move {
                Self::handle_stream(server_, stream, stream_out, addr, sender.clone()).await?;
                // if let Some(stream_out) = ret {
                //     let stream = acceptor.accept(socket).await?;
                //     Self::handle_stream(server_, stream, Some(stream_out), addr).await?;
                // }
                Ok(()) as io::Result<()>
            });
        }
    }
}
