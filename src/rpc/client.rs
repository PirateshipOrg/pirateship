// Copyright (c) Shubham Mishra. All rights reserved.
// Licensed under the MIT License.

use crate::{config::{AtomicConfig, Config}, crypto::{AtomicKeyStore, KeyStore}, utils::{channel::make_channel, AtomicStruct}};
use futures::{future::BoxFuture, stream::FuturesUnordered, FutureExt, StreamExt, TryFutureExt};
use log::{debug, info, trace, warn};
use rustls::{crypto::aws_lc_rs, pki_types, RootCertStore};
use serde_cbor::ser::SliceWrite;
use std::{
    collections::{HashMap, HashSet}, fs::File, future::Future, io::{self, BufReader, Cursor, Error, ErrorKind}, ops::{Deref, DerefMut}, path, pin::Pin, sync::{atomic::{AtomicUsize, Ordering}, Arc}, time::Duration
};
use tokio::{
    io::{split, AsyncReadExt, AsyncWriteExt, BufWriter, ReadHalf, WriteHalf},
    net::TcpStream,
    sync::{
        mpsc::{self, Sender, UnboundedSender}, oneshot, Mutex, RwLock
    }, time::{sleep, timeout},
};
use std::time::Instant;
use tokio_rustls::{client::TlsStream, rustls, TlsConnector};

use super::{auth, server::LatencyProfile, MessageRef, PinnedMessage};

#[derive(Clone)]
pub struct PinnedHashMap<K, V>(Arc<Pin<Box<RwLock<HashMap<K, V>>>>>);
impl<K, V> PinnedHashMap<K, V> {
    fn new() -> PinnedHashMap<K, V> {
        PinnedHashMap(Arc::new(Box::pin(RwLock::new(HashMap::new()))))
    }
}

#[derive(Clone)]
pub struct PinnedHashSet<K>(Arc<Pin<Box<RwLock<HashSet<K>>>>>);
impl<K> PinnedHashSet<K> {
    fn new() -> PinnedHashSet<K> {
        PinnedHashSet(Arc::new(Box::pin(RwLock::new(HashSet::new()))))
    }
}

struct BufferedTlsStream {
    stream_tx: WriteHalf<TlsStream<TcpStream>>,
    stream_rx: ReadHalf<TlsStream<TcpStream>>,
    buffer: Vec<u8>,
    write_buffer: Vec<u8>,
    write_offset: usize,
    offset: usize,
    bound: usize
}

impl BufferedTlsStream {
    pub fn new(stream: TlsStream<TcpStream>) -> BufferedTlsStream {
        let (stream_rx, stream_tx) = split(stream);
        BufferedTlsStream {
            stream_tx, // : BufWriter::with_capacity(16 * 1024, stream),
            stream_rx,
            buffer: vec![0u8; 8192],
            write_buffer: vec![0u8; 8192],
            bound: 0,
            offset: 0,
            write_offset: 0
        }
    }

    pub async fn flush_write_buffer(&mut self) -> Result<(), Error> {
        self.stream_tx.write_all(&self.write_buffer[..self.write_offset]).await?;
        if self.write_offset > 0 && self.write_offset < self.write_buffer.len() {
            trace!("Flush underfull: {}", self.write_offset);
        } else if self.write_offset == self.write_buffer.len() {
            trace!("Flush full");
        }
        // info!("self.write_offset = {} buff: {:?}", self.write_offset, self.buffer);
        self.write_offset = 0;
        self.stream_tx.flush().await?;
        Ok(())
    }

    pub async fn write_all_bufffered(&mut self, buff: &[u8], len: usize) -> Result<(), Error> {
        let mut n = len;
        while n > 0 {
            let space_left = self.write_buffer.len() - self.write_offset;
            if space_left == 0 {
                self.flush_write_buffer().await?;
                continue;
            }
            let to_write = if n < space_left {
                n
            } else {
                space_left
            };
            
            // info!("self.write_offset = {}, to_write = {}, len = {}", self.write_offset, to_write, len);
            self.write_buffer[self.write_offset..][..to_write].copy_from_slice(&buff[(len - n)..(len - n + to_write)]);
            n -= to_write;
            self.write_offset += to_write;
        }

        Ok(())
    }

    pub async fn write_u32_buffered(&mut self, data: u32) -> Result<(), Error> {
        let buff = data.to_be_bytes();
        self.write_all_bufffered(&buff, 4).await?;
        Ok(())
    }

    async fn read_next_bytes(&mut self, n: usize, v: &mut Vec<u8>) -> io::Result<()> {
        let mut pos = 0;
        let mut n = n;
        let get_n = n;
        while n > 0 {
            if self.bound == self.offset {
                // Need to fetch more data.
                let read_n = self.stream_rx.read(self.buffer.as_mut()).await?;
                debug!("Fetched {} bytes, Need to fetch {} bytes, pos {}, Currently at: {}", read_n, get_n, pos, n);
                self.bound = read_n;
                self.offset = 0;
            }

            if self.bound - self.offset >= n {
                // Copy in full
                v[pos..][..n].copy_from_slice(&self.buffer[self.offset..self.offset+n]);
                self.offset += n;
                n = 0;
            }else{
                // Copy partial.
                // We'll get the rest in the next iteration of the loop.
                v[pos..][..self.bound - self.offset].copy_from_slice(&self.buffer[self.offset..self.bound]);
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

impl Deref for BufferedTlsStream {
    type Target = WriteHalf<TlsStream<TcpStream>>;

    fn deref(&self) -> &Self::Target {
        &self.stream_tx
    }
}

impl DerefMut for BufferedTlsStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.stream_tx
    }
}

#[derive(Clone)]
pub struct PinnedTlsStream(Arc<Pin<Box<Mutex<BufferedTlsStream>>>>);
impl PinnedTlsStream {
    fn new(stream: TlsStream<TcpStream>) -> PinnedTlsStream {
        PinnedTlsStream(Arc::new(Box::pin(Mutex::new(BufferedTlsStream::new(
            stream,
        )))))
    }
}

pub type AtomicString = AtomicStruct<Option<String>>;
pub struct Client {
    pub config: AtomicConfig,
    pub full_duplex: bool,
    pub client_sub_id: u64,
    pub tls_ca_root_cert: RootCertStore,
    pub sock_map: PinnedHashMap<String, PinnedTlsStream>,
    pub chan_map: PinnedHashMap<String, UnboundedSender<(PinnedMessage, LatencyProfile)>>,
    pub replying_chan_map: PinnedHashMap<String, UnboundedSender<(PinnedMessage, oneshot::Sender<PinnedMessage>)>>,
    pub worker_ready: PinnedHashSet<String>,
    pub key_store: AtomicKeyStore,
    do_auth: bool,
    graveyard_tx: Mutex<Option<UnboundedSender<BoxFuture<'static, ()>>>>,
    slowest_peer: AtomicString,
}

#[derive(Clone)]
pub struct PinnedClient(pub Arc<Pin<Box<Client>>>);

enum SendDataType<'a> {
    ByteType(MessageRef<'a>),
    SizeType(u32),
}

impl Client {
    fn load_root_ca_cert(path: &String) -> RootCertStore {
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

        let mut root_cert_store = rustls::RootCertStore::empty();
        let mut pem = BufReader::new(f);
        for cert in rustls_pemfile::certs(&mut pem) {
            root_cert_store
                .add(match cert {
                    Ok(_c) => _c,
                    Err(e) => {
                        panic!("Error reading cert: {}", e);
                    }
                })
                .unwrap();
        }
        root_cert_store
    }
    pub fn new(cfg: &Config, key_store: &KeyStore, full_duplex: bool, client_sub_id: u64) -> Client {
        Client {
            config: AtomicConfig::new(cfg.clone()),
            full_duplex,
            client_sub_id,
            tls_ca_root_cert: Client::load_root_ca_cert(&cfg.net_config.tls_root_ca_cert_path),
            sock_map: PinnedHashMap::new(),
            do_auth: true,
            chan_map: PinnedHashMap::new(),
            replying_chan_map: PinnedHashMap::new(),
            worker_ready: PinnedHashSet::new(),
            key_store: AtomicKeyStore::new(key_store.to_owned()),
            graveyard_tx: Mutex::new(None),
            slowest_peer: AtomicString::new(None),
        }
    }

    pub fn new_atomic(config: AtomicConfig, key_store: AtomicKeyStore, full_duplex: bool, client_sub_id: u64) -> Client {
        Client {
            config: config.clone(),
            full_duplex,
            client_sub_id,
            tls_ca_root_cert: Client::load_root_ca_cert(&config.get().net_config.tls_root_ca_cert_path),
            sock_map: PinnedHashMap::new(),
            do_auth: true,
            chan_map: PinnedHashMap::new(),
            replying_chan_map: PinnedHashMap::new(),
            worker_ready: PinnedHashSet::new(),
            key_store,
            graveyard_tx: Mutex::new(None),
            slowest_peer: AtomicStruct::new(None),
        }
    }

    pub fn new_unauthenticated(cfg: &Config) -> Client {
        Client {
            config: AtomicConfig::new(cfg.clone()),
            full_duplex: false,
            client_sub_id: 0,
            tls_ca_root_cert: Client::load_root_ca_cert(&cfg.net_config.tls_root_ca_cert_path),
            sock_map: PinnedHashMap::new(),
            do_auth: false,
            key_store: AtomicKeyStore::new(KeyStore::empty().to_owned()),
            chan_map: PinnedHashMap::new(),
            replying_chan_map: PinnedHashMap::new(),
            worker_ready: PinnedHashSet::new(),
            graveyard_tx: Mutex::new(None),
            slowest_peer: AtomicString::new(None),
        }
    }

    pub fn into(self) -> PinnedClient {
        PinnedClient(Arc::new(Box::pin(self)))
    }
}


impl PinnedClient {
    fn get_reply_name(client: &PinnedClient, name: &String) -> String {
        if client.0.full_duplex {
            name.to_owned() + ":reply"
        } else {
            name.to_owned()
        }
    }

    async fn connect(client: &PinnedClient, name: &String) -> Result<(PinnedTlsStream, Option<PinnedTlsStream>), Error> {
        let cfg = client.0.config.get();
        debug!("(Re)establishing connection to: {}", name);
        debug!("Node list: {:?}", cfg.net_config.nodes);
        let peer = cfg
            .net_config
            .nodes
            .get(name)
            .ok_or(ErrorKind::AddrNotAvailable)?;
        // Clones the root cert store. Connect() will be only be called once per node.
        // Or if the connection is dropped and needs to be re-established.
        // So, this should be acceptable.
        let tls_cfg =
            rustls::ClientConfig::builder_with_provider(aws_lc_rs::default_provider().into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(client.0.tls_ca_root_cert.clone())
                .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(tls_cfg));
        let stream = match TcpStream::connect(&peer.addr).await {
            Ok(s) => s,
            Err(e) => {
                static CONNECT_FAIL_COUNT: AtomicUsize = AtomicUsize::new(0);
                const LOG_EVERY_N: usize = 250;
                let count = CONNECT_FAIL_COUNT.fetch_add(1, Ordering::Relaxed);
                if count % LOG_EVERY_N == 0 {
                    warn!("Failed to connect: {} (failure #{})", e, count);
                }
                return Err(e); 
        }
        };
        stream.set_nodelay(true)?;
           let domain = pki_types::ServerName::try_from(peer.domain.as_str())
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid dnsname"))?
            .to_owned();

        let mut stream = match connector.connect(domain, stream).await
        {
                Ok(s) => s,
                Err(e) => {
                  warn!("Failed to connect (TLS): {}", e);
                  return Err(e); 
            }
       };

        if client.0.do_auth {
            auth::handshake_client(&client, &mut stream, client.0.full_duplex, client.0.client_sub_id).await?;
        }

        // println!("[{}] Client: Connected and Authenticated to {}:{}", client.0.client_sub_id, peer.domain, peer.addr);


        let stream_safe = PinnedTlsStream::new(stream.into());
        let reply_name = Self::get_reply_name(client, name);

        let mut sock_map = client.0.sock_map.0.write().await;

        sock_map.insert(reply_name, stream_safe.clone());

        let stream_safe2 = if client.0.full_duplex && client.0.do_auth {
            let stream2 = TcpStream::connect(&peer.addr).await?;
            stream2.set_nodelay(true)?;

            let domain = pki_types::ServerName::try_from(peer.domain.as_str())
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid dnsname"))?
                .to_owned();
            let mut stream2 = connector.connect(domain, stream2).await?;
            auth::handshake_client(&client, &mut stream2, false, client.0.client_sub_id).await?;
            let _s = PinnedTlsStream::new(stream2.into());
            sock_map.insert(name.clone(), _s.clone());
            Some(_s)            
        } else {
            None
        };

        if client.0.full_duplex {
            Ok((stream_safe2.unwrap(), Some(stream_safe)))
        } else {
            Ok((stream_safe, None))
        }
    
        // Ok((stream_safe, stream_reply))
    }

    async fn get_sock(client: &PinnedClient, name: &String, is_reply_chan: bool) -> Result<PinnedTlsStream, Error> {
        // Is there an open connection?
        let mut sock: Option<PinnedTlsStream> = None;
        {
            let sock_map_reader = client.0.sock_map.0.read().await;

            let name = if !is_reply_chan {
                name
            } else {
                &Self::get_reply_name(client, name)
            };

            let sock_ = sock_map_reader.get(name);
            if sock_.is_some() {
                sock = Some(sock_.unwrap().clone());
            }
        }

        if sock.is_none() {
            let (_sock, _) = PinnedClient::connect(&client.clone(), name).await?;
            println!("Reached here when trying to connect to {}", name);
            sock = Some(_sock);
        }

        Ok(sock.unwrap())
    }

    async fn send_raw<'a>(
        client: &PinnedClient,
        name: &String,
        sock: &PinnedTlsStream,
        data: SendDataType<'a>,
    ) -> Result<(), Error> {
        let e = match data {
            SendDataType::ByteType(d) => {
                let mut lsock = sock.0.lock().await;
                // info!("lsock.write_all_bufffered(&d.0 {}, d.1 {}).await", d.0.len(), d.1);
                lsock.write_all_bufffered(&d.0, d.1).await
            }
            SendDataType::SizeType(d) => {
                let mut lsock = sock.0.lock().await;
                lsock.write_u32_buffered(d).await // Does this take care of endianness?
            }
        };

        if let Err(e) = e {
            // There is some problem.
            // Reset connection.
            warn!(
                "Problem sending message to {}: {} ... Resetting connection.",
                name, e
            );
            let mut lsock = sock.0.lock().await;
            if let Err(e2) = lsock.shutdown().await {
                warn!(
                    "Problem shutting down socket of {}: {} ... Proceeding anyway",
                    name, e2
                );
            }

            client.0.sock_map.0.write().await.remove(name);
            debug!("Socket removed from sock_map");
            return Err(e);
        }

        Ok(())
    }
    pub async fn send<'b>(
        client: &PinnedClient,
        name: &String,
        data: MessageRef<'b>,
    ) -> Result<(), Error> {
        let sock = Self::get_sock(client, name, false).await?;
        let len = data.len() as u32;

        // These two calls will be buffered.
        Self::send_raw(client, name, &sock, SendDataType::SizeType(len)).await?;
        Self::send_raw(client, name, &sock, SendDataType::ByteType(data)).await?;

        {
            // This finally sends the message.
            sock.0.lock().await.flush_write_buffer().await?;
        }

        Ok(())
    }

    pub async fn send_buffered<'b>(
        client: &PinnedClient,
        name: &String,
        data: MessageRef<'b>,
    ) -> Result<(), Error> {
        let sock = Self::get_sock(client, name, false).await?;
        let len = data.len() as u32;

        // These two calls will be buffered.
        Self::send_raw(client, name, &sock, SendDataType::SizeType(len)).await?;
        Self::send_raw(client, name, &sock, SendDataType::ByteType(data)).await?;

        // {
        //     // This finally sends the message.
        //     sock.0.lock().await.flush().await?;
        // }

        Ok(())
    }

    pub async fn force_flush<'b>(
        client: &PinnedClient,
        name: &String
    ) -> Result<(), Error> {
        let sock = Self::get_sock(client, name, false).await?;
        sock.0.lock().await.flush_write_buffer().await?;
        Ok(())
    }

    pub async fn send_and_await_reply<'b>(
        client: &PinnedClient,
        name: &String,
        data: MessageRef<'b>,
    ) -> Result<PinnedMessage, Error> {
        let sock = Self::get_sock(client, name, false).await?;
        let len = data.len() as u32;

        let send_time = Instant::now();
        Self::send_raw(client, name, &sock, SendDataType::SizeType(len)).await?;
        let send_sz_time = send_time.elapsed().as_micros();
        Self::send_raw(client, name, &sock, SendDataType::ByteType(data)).await?;
        let send_time = send_time.elapsed().as_micros();

        debug!(
            "Send time: sz:{}, data: {}, total: {} us",
            send_sz_time,
            send_time - send_sz_time,
            send_time
        );

        {
            let mut lsock = sock.0.lock().await;
            lsock.flush_write_buffer().await?;  // Need this flush; otherwise it is a deadlock.
        }

        {
            // info!("Get sock: {} {}", name, client.0.full_duplex);
            let repl_sock = Self::get_sock(client, name, client.0.full_duplex).await?;
            let mut repl_sock = repl_sock.0.lock().await;

            let mut resp_buf = vec![0u8; 256];
            let sz = repl_sock.get_next_frame(&mut resp_buf).await? as usize;
            if sz == 0 {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "socket probably closed!",
                ));
            }
            
            Ok(PinnedMessage::from(
                resp_buf,
                sz as usize,
                super::SenderType::Auth(name.clone(), client.0.client_sub_id),
            ))
        }
    }

    pub async fn await_reply<'b>(
        client: &PinnedClient,
        name: &String,
    ) -> Result<PinnedMessage, Error> {
        let sock = Self::get_sock(client, name, client.0.full_duplex).await?;
        let mut lsock = sock.0.lock().await;
        let mut resp_buf = vec![0u8; 256];
        let sz = lsock.get_next_frame(&mut resp_buf).await? as usize;
        if sz == 0 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "socket probably closed!",
            ));
        }
        
        Ok(PinnedMessage::from(
            resp_buf,
            sz as usize,
            super::SenderType::Auth(name.clone(), client.0.client_sub_id),
        ))
    }

    pub async fn try_await_reply<'b>(
        client: &PinnedClient,
        name: &String,
    ) -> Result<PinnedMessage, Error> {
        let is_readable = {
            // Is there a partial message in the buffer?
            let sock = Self::get_sock(client, name, client.0.full_duplex).await?;
            let mut lsock = sock.0.lock().await;

            if lsock.bound != lsock.offset {
                true
            } else {
                // TODO: Is the underlying Tcpstream readable?
                false
            }
        
        };

        if is_readable {
            PinnedClient::await_reply(client, name).await
        } else {
            Err(Error::new(ErrorKind::WouldBlock, "Reading would block"))
        }
    }

    pub async fn broadcast_and_await_reply<'b>(
        client: &PinnedClient,
        send_list: &Vec<String>,
        data: &PinnedMessage,
    ) -> Result<Vec<PinnedMessage>, Error> {
        let mut result = Vec::new();

        for name in send_list {
            let res = PinnedClient::send_and_await_reply(client, name, data.as_ref()).await?;
            result.push(res);
        }

        Ok(result)
    }

    pub async fn broadcast_and_await_quorum_reply(
        client: &PinnedClient,
        send_list: &Vec<String>,
        data: &PinnedMessage,
        quorum: usize,
    ) -> Result<Vec<PinnedMessage>, Error> {
        assert!(quorum <= send_list.len());

        let mut need_to_spawn_workers = Vec::new();
        for name in send_list {
            let lworkers = client.0.worker_ready.0.read().await;
            if !lworkers.contains(name) {
                need_to_spawn_workers.push(name.clone());
            }
        }

        // info!("Need to spawn workes for {:?}", need_to_spawn_workers);

        for name in &need_to_spawn_workers {
            let (tx, mut rx) = mpsc::unbounded_channel();
            let mut lchans = client.0.replying_chan_map.0.write().await;
            lchans.insert(name.clone(), tx);

            let _name = name.clone();
            let _client = client.clone();
            // Register as ready.
            {
                let mut lworkers = _client.0.worker_ready.0.write().await;
                lworkers.insert(_name.clone());
            }
            tokio::spawn(async move {
                // Main loop: Fetch data from channel
                // Do reliable send
                // If reliable send fails, die.

                let mut msgs = Vec::new();
                // let c = _client.clone();
                let sock = loop {
                    let s = match Self::get_sock(&_client, &_name, false).await {
                        Ok(s) => s,
                        Err(e) => {
                            debug!("Broadcast worker dying for {}: {}", _name, e);
                            continue;
                        },
                    };

                    break s
                };

                let reply_sock = Self::get_sock(&_client, &_name, _client.0.full_duplex).await?;
                let mut reply_sock = reply_sock.0.lock().await;
                
                
                while rx.recv_many(&mut msgs, 10).await > 0 {
                    let mut should_die = false;
                    for (msg, reply_tx) in msgs.drain(..) {
                        let msg_ref = msg.as_ref();

                        let len = msg_ref.len() as u32;
                        if let Err(e) = Self::send_raw(&_client, &_name, &sock, SendDataType::SizeType(len)).await {
                            warn!("Broadcast worker for {} dying: {}", _name, e);
                            should_die = true;
                            break;
                        }
                        if let Err(e) = Self::send_raw(&_client, &_name, &sock, SendDataType::ByteType(msg_ref)).await {
                            warn!("Broadcast worker for {} dying: {}", _name, e);
                            should_die = true;
                            break;
                        }

                        let _ = sock.0.lock().await.flush_write_buffer().await;

                        let mut resp_buf = vec![0u8; 4096];
                        let sz = reply_sock.get_next_frame(&mut resp_buf).await? as usize;
                        if sz == 0 {
                            return Err(Error::new(
                                ErrorKind::InvalidData,
                                "socket probably closed!",
                            ));
                        }
                        
                        let _ = reply_tx.send(PinnedMessage::from(
                            resp_buf,
                            sz as usize,
                            super::SenderType::Auth(_name.clone(), _client.0.client_sub_id),
                        ));
                    }
                    

                    if should_die {
                        // info!("Broadcast worker for {} dying", _name);
                        rx.close();
                        break;
                    }
                }

                // Deregister as ready.
                {
                    let mut lworkers = _client.0.worker_ready.0.write().await;
                    lworkers.remove(&_name);
                }
                Ok(())
            });
        }

        // At this point, all name in names have a dedicated broadcast worker running.
        let mut receivers = Vec::new();
        {
            let lchans = client.0.replying_chan_map.0.read().await;
            for name in send_list {
                let chan = lchans.get(name).unwrap();
                let (tx, rx) = oneshot::channel();
                if let Err(e) = chan.send((data.clone(), tx)) {
                    warn!("Broadcast error: {}", e);
                }

                receivers.push(rx);
            }
        }
    
        
        let mut result = Vec::new();

        let mut futures = FuturesUnordered::new();
        for rx in receivers.drain(..) {
            futures.push(async move {
                rx.await
            }.boxed());
        }

        let (tx, rx) = make_channel(quorum);

        tokio::spawn(async move {
            let mut count = 0;
            while let Some(res) = futures.next().await {
                match res {
                    Ok(res) => {
                        if count < quorum {
                            tx.send(res).await.unwrap();
                        }
                        count += 1;
                    }
                    Err(e) => {
                        warn!("Error in broadcast_and_await_quorum_reply: {}", e);
                    }
                }
            }
        });

        while let Some(res) = rx.recv().await {
            result.push(res);
        }

        Ok(result)
    }


    pub async fn reliable_send<'b>(
        client: &PinnedClient,
        name: &String,
        data: MessageRef<'b>,
    ) -> Result<(), Error> {
        let cfg = client.0.config.get();
        let mut i = cfg.net_config.client_max_retry;
        while i > 0 {
            let done = match Self::send(client, name, data.clone()).await {
                Ok(()) => true,
                Err(e) => {
                    warn!("Error in reliable send: {}", e);
                    i -= 1;
                    false
                }
            };

            if done {
                return Ok(());
            }
        }

        Err(Error::new(
            ErrorKind::NotConnected,
            "Could not send within max_retries",
        ))
    }

    /// Sends messages to all peers in `names.`
    /// Returns Ok(n) if >= `min_success` sends could be done.
    /// Else returns Err(n)
    /// Each send will be retried for `rpc_config.client_max_retry` consecutively without delay.
    /// Any clever retry mechanism for the broadcast should be implemented by the caller of this function.
    /// (Such as AIMD.)
    pub async fn broadcast(
        client: &PinnedClient,
        names: &Vec<String>,
        data: &PinnedMessage,
        profile: &mut LatencyProfile,
        min_success: usize,
    ) -> Result<(), Error> {
        let mut need_to_spawn_workers = Vec::new();
        for name in names {
            let lworkers = client.0.worker_ready.0.read().await;
            if !lworkers.contains(name) {
                need_to_spawn_workers.push(name.clone());
            }
        }

        // info!("Need to spawn workes for {:?}", need_to_spawn_workers);

        for name in &need_to_spawn_workers {
            let (tx, mut rx) = mpsc::unbounded_channel();
            let mut lchans = client.0.chan_map.0.write().await;
            lchans.insert(name.clone(), tx);

            let _name = name.clone();
            let _client = client.clone();
            // Register as ready.
            {
                let mut lworkers = _client.0.worker_ready.0.write().await;
                lworkers.insert(_name.clone());
            }
            tokio::spawn(async move {
                // Main loop: Fetch data from channel
                // Do reliable send
                // If reliable send fails, die.

                let mut msgs = Vec::new();
                // let c = _client.clone();
                let sock = loop {
                    let s = match Self::get_sock(&_client, &_name, false).await {
                        Ok(s) => s,
                        Err(e) => {
                            debug!("Broadcast worker dying for {}: {}", _name, e);
                            continue;
                        },
                    };

                    break s
                };
                
                while rx.recv_many(&mut msgs, 10).await > 0 {
                    let mut should_print_flush_time = false;
                    let mut combined_prefix = String::from("");
                    let mut should_die = false;
                    for (msg, profile) in &mut msgs {
                        // let instant = msg.1;
                        profile.register("Broadcast chan wait");
                        let msg_ref = msg.as_ref();

                        let len = msg_ref.len() as u32;
                        // info!("Client for {} sending message of size: {}. Queue len: {}", _name, len, rx.len());
                        if let Err(e) = Self::send_raw(&_client, &_name, &sock, SendDataType::SizeType(len)).await {
                            warn!("Broadcast worker for {} dying: {}", _name, e);
                            should_die = true;
                            break;
                        }
                        if let Err(e) = Self::send_raw(&_client, &_name, &sock, SendDataType::ByteType(msg_ref)).await {
                            warn!("Broadcast worker for {} dying: {}", _name, e);
                            should_die = true;
                            break;
                        }

                        profile.register("Broadcast send raw");
                
                        profile.prefix += &String::from(format!(" to {} ", _name));
                        if profile.should_print {
                            should_print_flush_time = true;
                            combined_prefix += &profile.prefix.clone();
                        }

                        profile.print();
                        // info!("Client for {} sent message of size: {}", _name, len);

                    }
                    
                    // let flush_time = Instant::now();
                    let _ = sock.0.lock().await.flush_write_buffer().await;
                    // info!("Client for {} flushed", _name);
                    
                    // if should_print_flush_time {
                        //     trace!("[{}] Flush time: {} us", combined_prefix, flush_time.elapsed().as_micros());
                        // }
                    msgs.clear();

                    if should_die {
                        // info!("Broadcast worker for {} dying", _name);
                        rx.close();
                        break;
                    }
                    
                    
                }

                // Deregister as ready.
                {
                    let mut lworkers = _client.0.worker_ready.0.write().await;
                    lworkers.remove(&_name);
                }
            });
        }

        // At this point, all name in names have a dedicated broadcast worker running.
        {
            let lchans = client.0.chan_map.0.read().await;
            let mut total_success = 0;
            // let mut futs = FuturesUnordered::new();
            let slowest_peer = client.0.slowest_peer.get();
            let slowest_peer = slowest_peer.as_slice();
            let mut slowest_time = Duration::new(0, 0);
            let mut new_slowest_peer = String::from("");

            // Always start sending from the slowest peer.
            // This is a rate control mechanism.
            // Better everybody be slow than some be fast and some slow.
            // Saves from the queue congestion.
            if slowest_peer.len() > 0 && names.contains(&slowest_peer[0]) {
                let chan = lchans.get(&slowest_peer[0]).unwrap();
                // chans.push(chan.clone());
                let __start = Instant::now();
                if total_success < min_success {
                    if let Err(e) = chan.send((data.clone(), profile.clone())) {
                        warn!("Broadcast error: {}", e);
                    }
                } else {
                    if let Err(e) = chan.send((data.clone(), profile.clone())) {
                        // Best effort only
                        trace!("Broadcast error: {}", e);
                    }
                }

                let __duration = __start.elapsed();
                if __duration > slowest_time {
                    slowest_time = __duration;
                    new_slowest_peer = slowest_peer[0].clone();
                }

                // futs.push(chan.send((data.clone(), profile.clone())));

                total_success += 1;
            }

            for name in names {
                if slowest_peer.len() > 0 && *name == slowest_peer[0] {
                    // We already sent this before.
                    continue;
                }
                let chan = lchans.get(name).unwrap();

                let __start = Instant::now();
                // chans.push(chan.clone());
                if total_success < min_success {
                    if let Err(e) = chan.send((data.clone(), profile.clone())) {
                        warn!("Broadcast error: {}", e);
                    }
                } else {
                    if let Err(e) = chan.send((data.clone(), profile.clone())) {
                        // Best effort only
                        trace!("Broadcast error: {}", e);
                    }
                }
                let __duration = __start.elapsed();
                if __duration > slowest_time {
                    slowest_time = __duration;
                    new_slowest_peer = name.clone();
                }

                // futs.push(chan.send((data.clone(), profile.clone())));

                total_success += 1;
            }

            if new_slowest_peer.len() > 0 {
                client.0.slowest_peer.set(Box::new(Some(new_slowest_peer)));
            }



            // while let Some(res) = futs.next().await {
            //     if res.is_ok() {
            //         total_success += 1;
            //     }

            //     if total_success >= min_success {
            //         break;
            //     }
            // }

            // if futs.len() > 0 {
            //     while let Ok(Some(res)) = timeout(Duration::from_millis(10), futs.next()).await {
            //         if res.is_ok() {
            //             total_success += 1;
            //         }
            //     }
            // }

            // if futs.len() > 0 {
            //     futs.clear();
            // }


        }
        
        // let mut bcast_futs = FuturesUnordered::new();
        // {
        //     let lchans = client.0.chan_map.0.read().await;

        //     for name in names {
        //         let chan = lchans.get(name).unwrap();
        //         let _chan = chan.clone();
        //         let _profile = profile.clone();
        //         let _data = data.clone();
        //         let _name = name.clone();
        //         bcast_futs.push(Box::pin(async move {
        //             let ret = _chan.try_send((_data.clone(), _profile.clone()));
        //             match ret {
        //                 Ok(_) => {
        //                     Ok(())
        //                 },
        //                 Err(_) => {
        //                     trace!("Channel congestion for {} Queue len: {}", _name, 10 - _chan.capacity());
        //                     _chan.send((_data, _profile)).await
        //                 }
        //             }
        //         }));
                
        //         // let mut try_num = 0;
        //         // let max_try_num = client.0.config.get().net_config.client_max_retry;
        //         // while let Err(_) = chan.send((data.clone(), profile.clone())).await {
        //         //     try_num += 1;
        //         //     if try_num > max_try_num {
        //         //         break;
        //         //     }
        //         //     sleep(Duration::from_millis(1)).await;
        //         // }
        //     }
        // }

        // // let mut total_success = 0;
        // // while let Some(res) = bcast_futs.next().await {
        // //     if res.is_ok() {
        // //         total_success += 1;
        // //     }

        // //     if total_success >= min_success {
        // //         break;
        // //     }
        // // }

        // // trace!("Broadcast done. Success: {}", total_success);

        // if bcast_futs.len() == 0 {
        //     return Ok(());
        // }

        // // let mut lgraveyard = client.0.graveyard_tx.lock().await;
        // // if lgraveyard.is_none() {
        // //     let (tx, mut rx) = mpsc::unbounded_channel();
        // //     tokio::spawn(async move {
        // //         while let Some(fut) = rx.recv().await {
        // //             let _ = timeout(Duration::from_secs(2), fut).await;
        // //         }
        // //     });

        // //     *lgraveyard = Some(tx);
        // // }


        // // let _ = lgraveyard.as_ref().unwrap().send(Box::pin(async move {
        // //     while bcast_futs.len() > 0 {
        // //         let _ = bcast_futs.next().await;
        // //     }
        // // }));



        // // let _bcast_res = chans.iter().map(|c| c.send((data.clone(), Some(Instant::now()))));

        // // join_all(bcast_futs).await;

        Ok(())
    }


    pub async fn drop_connection(client: &PinnedClient, name: &String) {
        let _sock = {
            let mut lsock = client.0.sock_map.0.write().await;
            lsock.remove(name);
            lsock.remove(&Self::get_reply_name(client, name));
        };

        // if sock.is_some() {
        //     let sock = sock.unwrap();
        //     let mut lsock = sock.0.lock().await;
        //     let _ = lsock.shutdown().await;
        // }
    }

    pub async fn drop_all_connections(client: &PinnedClient) {
        let lsock_map = client.0.sock_map.0.read().await;
        let names = lsock_map.iter().map(|(k, _v)| {
            k.clone()
        }).collect::<Vec<_>>();
        drop(lsock_map);

        for name in &names {
            PinnedClient::drop_connection(client, name).await;
        }
    }
}
