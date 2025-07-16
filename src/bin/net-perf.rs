// Copyright (c) Shubham Mishra. All rights reserved.
// Licensed under the MIT License.

use log::{debug, error, info};
use pft::{config::{self, Config}, crypto::{AtomicKeyStore, KeyStore}, rpc::{client::{Client, PinnedClient}, server::{LatencyProfile, MsgAckChan, RespType, Server, ServerContextType}, MessageRef, PinnedMessage}};
use tokio::{runtime, signal, task::JoinSet, time::sleep};
use std::{env, fs, io::{self, Error}, path, pin::Pin, sync::{atomic::{AtomicUsize, Ordering}, Arc, Mutex}, time::Duration};
use std::io::Write;

// #[global_allocator]
// static ALLOC: snmalloc_rs::SnMalloc = snmalloc_rs::SnMalloc;

/// Fetch json config file from command line path.
/// Panic if not found or parsed properly.
const DEFAULT_PAYLOAD_SIZE: usize = 4096;

fn process_args() -> (Config, usize) {
    macro_rules! usage_str {
        () => {
            "\x1b[31;1mUsage: {} path/to/config.json [payload_size]\x1b[0m"
        };
    }

    let args: Vec<_> = env::args().collect();

    if args.len() != 2 && args.len() != 3 {
        panic!(usage_str!(), args[0]);
    }

    let cfg_path = path::Path::new(args[1].as_str());
    if !cfg_path.exists() {
        panic!(usage_str!(), args[0]);
    }

    let cfg_contents = fs::read_to_string(cfg_path).expect("Invalid file path");

    let payload_size = if args.len() == 2 {
        DEFAULT_PAYLOAD_SIZE
    } else {
        let res = usize::from_str_radix(&args[2], 10);
        match res {
            Ok(sz) => sz,
            Err(_) => {
                panic!(usage_str!(), args[0]);
            },
        }
    };

    (Config::deserialize(&cfg_contents), payload_size)
}


pub struct ProfilerContext {
    pub bytes_completed_bcasts: AtomicUsize,
    pub bytes_received_msgs: AtomicUsize,
    pub key_store: AtomicKeyStore,
    pub config: Config,
}


#[derive(Clone)]
pub struct PinnedProfilerContext(pub Arc<Pin<Box<ProfilerContext>>>);

impl ServerContextType for PinnedProfilerContext {
    fn get_server_keys(&self) -> Arc<Box<pft::crypto::KeyStore>> {
        self.0.key_store.get()
    }
    
    async fn handle_rpc(&self, msg: MessageRef<'_>, ack_chan: MsgAckChan) -> Result<RespType, Error> {
        profiler_rpc_handler(self, msg, ack_chan)
    }
}

impl PinnedProfilerContext {
    pub fn new(config: &Config, key_store: &KeyStore) -> PinnedProfilerContext {
        PinnedProfilerContext(Arc::new(Box::pin(ProfilerContext {
            bytes_completed_bcasts: AtomicUsize::new(0),
            bytes_received_msgs: AtomicUsize::new(0),
            key_store: AtomicKeyStore::new(key_store.clone()),
            config: config.clone(),
        })))
    }
}

pub struct ProfilerNode
{
    pub server: Arc<Server<PinnedProfilerContext>>,
    pub client: PinnedClient,
    pub ctx: PinnedProfilerContext,
}

pub fn profiler_rpc_handler<'a>(
    ctx: &PinnedProfilerContext,
    m: MessageRef<'a>,
    _ack_tx: MsgAckChan,
) -> Result<RespType, Error> {

    ctx.0.bytes_received_msgs.fetch_add(m.1, Ordering::SeqCst);
    Ok(RespType::NoResp)
}


impl ProfilerNode
{
    pub fn new(config: &Config) -> ProfilerNode {
        let key_store = KeyStore::new(
            &config.rpc_config.allowed_keylist_path,
            &config.rpc_config.signing_priv_key_path,
        );
        
        let ctx = PinnedProfilerContext::new(config, &key_store);
        ProfilerNode {
            server: Arc::new(Server::new(config, ctx.clone(), &key_store)),
            client: Client::new(config, &key_store, false, 0).into(),
            ctx: ctx.clone(),
        }
    }

    pub fn run(node: Arc<Self>, payload_sz: usize) -> JoinSet<()> {
        // These are just increasing ref counts.
        // It is pointing to the same server instance.
        let mut js = JoinSet::new();
        let node1 = node.clone();
        let node2 = node.clone();
        let node3 = node.clone();

        js.spawn(async move {
            let _ = Server::<PinnedProfilerContext>::run(node1.server.clone())
                .await;
        });

        js.spawn(async move {
            let payload = vec![2u8; payload_sz];
            let msg = PinnedMessage::from(payload, payload_sz, pft::rpc::SenderType::Anon);
            // let send_list = get_everyone_except_me(
                // &node2.ctx.0.config.net_config.name,
                // &node2.ctx.0.config.consensus_config.node_list);

            let send_list = node2.ctx.0.config.consensus_config.node_list.iter()
                .filter(|e| *e != &node2.ctx.0.config.net_config.name)
                .map(|e| e.clone()).collect::<Vec<String>>();
            
            info!("{:?}", send_list);
            if node2.ctx.0.config.net_config.name == "node1" {
                // I will broadcast
                loop {
                    let mut profile = LatencyProfile::new();
                    let min_success = send_list.len();
                    let _ = PinnedClient::broadcast(
                        &node2.client,
                        &send_list,
                        &msg, &mut profile, min_success).await;

                    node2.ctx.0.bytes_completed_bcasts.fetch_add(payload_sz * send_list.len(), Ordering::SeqCst);
                }
            }

        });

        js.spawn(async move {
            let mut last = 0;
            loop {
                sleep(Duration::from_secs(1)).await;
                #[allow(unused_assignments)]
                let mut now = last;
                if node3.ctx.0.config.net_config.name == "node1" {
                    now = node3.ctx.0.bytes_completed_bcasts.load(Ordering::SeqCst);
                } else {
                    now = node3.ctx.0.bytes_received_msgs.load(Ordering::SeqCst);
                }

                info!("Throughput estimate: {} Mbps", ((now - last) as f64) * 8.0 / (1024.0 * 1024.0));
                last = now;
            }
        });

        js
    }
}



async fn run_main(cfg: Config, payload_sz: usize) -> io::Result<()> {
    let node = Arc::new(ProfilerNode::new(&cfg));
    let mut handles = ProfilerNode::run(node, payload_sz);

    match signal::ctrl_c().await {
        Ok(_) => {
            info!("Received SIGINT. Shutting down.");
            handles.abort_all();
        },
        Err(e) => {
            error!("Signal: {:?}", e);
        }
    }

    while let Some(res) = handles.join_next().await {
        info!("Task completed with {:?}", res);
    }
    Ok(())
}

const NUM_THREADS: usize = 8;

fn main() {
    log4rs::init_config(config::default_log4rs_config()).unwrap();

    let (cfg, payload_sz) = process_args();

    let core_ids = 
        Arc::new(Mutex::new(Box::pin(core_affinity::get_core_ids().unwrap())));

    // let start_idx = cfg.consensus_config.node_list.iter().position(|r| r.eq(&cfg.net_config.name)).unwrap();
    let mut num_threads = NUM_THREADS;
    {
        let _num_cores = core_ids.lock().unwrap().len();
        if _num_cores < num_threads {
            num_threads = _num_cores;
        }
    }

    let start_idx = 0; // start_idx * num_threads;
    
    let i = Box::pin(AtomicUsize::new(0));
    let runtime = runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(num_threads)
        .on_thread_start(move || {
            let _cids = core_ids.clone();
            let lcores = _cids.lock().unwrap();
            let id = (start_idx + i.fetch_add(1, std::sync::atomic::Ordering::SeqCst)) % lcores.len();
            let res = core_affinity::set_for_current(lcores[id]);
            
            if res {
                debug!("Thread pinned to core {:?}", id);
            }else{
                debug!("Thread pinning to core {:?} failed", id);
            }

            std::io::stdout().flush()
                .unwrap();
        })
        .build()
        .unwrap();

    let _ = runtime.block_on(run_main(cfg, payload_sz));
}
