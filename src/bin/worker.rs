use log::{error, info};
use pft::config::{self, Config};
use pft::worker::WorkerNode;
use std::process::exit;
use std::{env, fs, path};
use tokio::{runtime, signal};

#[global_allocator]
static ALLOC: snmalloc_rs::SnMalloc = snmalloc_rs::SnMalloc;

fn process_args() -> Config {
    macro_rules! usage_str {
        () => {
            "\x1b[31;1mUsage: {} path/to/config.json\x1b[0m"
        };
    }

    let args: Vec<_> = env::args().collect();

    if args.len() != 2 {
        panic!(usage_str!(), args[0]);
    }

    let cfg_path = path::Path::new(args[1].as_str());
    if !cfg_path.exists() {
        panic!(usage_str!(), args[0]);
    }

    let cfg_contents = fs::read_to_string(cfg_path).expect("Invalid file path");

    Config::deserialize(&cfg_contents)
}

fn offset_port(addr: &str, offset: u16) -> String {
    let colon_pos = addr.rfind(':').expect("Address must contain ':'");
    let (host, port_str) = addr.split_at(colon_pos);
    let port: u16 = port_str[1..].parse().expect("Invalid port number");
    format!("{}:{}", host, port + offset)
}

fn offset_all_ports(config: &mut Config, offset: u16) {
    config.net_config.addr = offset_port(&config.net_config.addr, offset);
    for (_name, node_info) in config.net_config.nodes.iter_mut() {
        node_info.addr = offset_port(&node_info.addr, offset);
    }
}

async fn run_main(cfg: Config) -> std::io::Result<()> {
    let mut node = WorkerNode::new(cfg);
    let mut handles = node.run().await;

    match signal::ctrl_c().await {
        Ok(_) => {
            info!("Received SIGINT. Shutting down worker.");
            handles.abort_all();
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            info!("Force shutdown.");
            exit(0);
        }
        Err(e) => {
            error!("Signal: {:?}", e);
        }
    }

    while let Some(res) = handles.join_next().await {
        info!("Task completed with {:?}", res);
    }
    Ok(())
}

const NUM_THREADS: usize = 16;

fn main() {
    log4rs::init_config(config::default_log4rs_config()).unwrap();

    let mut cfg = process_args();

    info!("Worker for node: {}", cfg.net_config.name);

    offset_all_ports(&mut cfg, 1111);

    info!("Worker listening on: {}", cfg.net_config.addr);

    let runtime = runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(NUM_THREADS)
        .build()
        .unwrap();
    let _ = runtime.block_on(run_main(cfg));
}
