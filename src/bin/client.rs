use std::{sync::Arc, time::Duration};

use pft::{
    client::{
        logger::{ClientStatLogger, ClientWorkerStat},
        worker::ClientWorker,
        workload_generators::{
            BlankWorkloadGenerator, KVReadWriteUniformGenerator, KVReadWriteYCSBGenerator,
            MockSQLGenerator, PerWorkerWorkloadGenerator,
        },
    },
    config::{default_log4rs_config, ClientConfig, RequestConfig},
    crypto::KeyStore,
    rpc::client::{Client, PinnedClient},
    utils::channel::make_channel,
};
use tokio::{sync::Mutex, task::JoinSet};

#[global_allocator]
static ALLOC: snmalloc_rs::SnMalloc = snmalloc_rs::SnMalloc;

fn process_args() -> ClientConfig {
    macro_rules! usage_str {
        () => {
            "\x1b[31;1mUsage: {} path/to/config.json\x1b[0m"
        };
    }

    let args: Vec<_> = std::env::args().collect();

    if args.len() != 2 {
        panic!(usage_str!(), args[0]);
    }

    let cfg_path = std::path::Path::new(args[1].as_str());
    if !cfg_path.exists() {
        panic!(usage_str!(), args[0]);
    }

    let cfg_contents = std::fs::read_to_string(cfg_path).expect("Invalid file path");

    ClientConfig::deserialize(&cfg_contents)
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    log4rs::init_config(default_log4rs_config()).unwrap();
    let config = process_args();

    let mut keys = KeyStore::empty();
    keys.priv_key = KeyStore::get_privkeys(&config.rpc_config.signing_priv_key_path);

    let mut client_handles = JoinSet::new();

    let (stat_tx, stat_rx) = make_channel(1000);

    let mut stat_worker = ClientStatLogger::new(
        stat_rx,
        Duration::from_millis(1000),
        Duration::from_secs(1),
        Duration::from_secs(config.workload_config.duration),
    );
    client_handles.spawn(async move {
        stat_worker.run().await;
    });

    for id in 0..config.workload_config.num_clients {
        let config = config.clone();
        let keys = keys.clone();
        let _stat_tx = stat_tx.clone();
        let client =
            Client::new(&config.fill_missing(), &keys, config.full_duplex, id as u64).into();
        match config.workload_config.request_config {
            RequestConfig::Blanks => {
                let generator = BlankWorkloadGenerator {};
                let worker = ClientWorker::new(config, client, generator, id, _stat_tx);
                ClientWorker::launch(worker, &mut client_handles).await;
            }
            RequestConfig::KVReadWriteUniform(kvread_write_uniform) => {
                let generator = KVReadWriteUniformGenerator::new(&kvread_write_uniform.clone());
                let worker = ClientWorker::new(config, client, generator, id, _stat_tx);
                ClientWorker::launch(worker, &mut client_handles).await;
            }
            RequestConfig::KVReadWriteYCSB(kvread_write_ycsb) => {
                let generator = KVReadWriteYCSBGenerator::new(
                    &kvread_write_ycsb,
                    id,
                    config.workload_config.num_clients,
                );
                let worker = ClientWorker::new(config, client, generator, id, _stat_tx);
                ClientWorker::launch(worker, &mut client_handles).await;
            }
            RequestConfig::MockSQL() => {
                let generator = MockSQLGenerator::new();
                let worker = ClientWorker::new(config, client, generator, id, _stat_tx);
                ClientWorker::launch(worker, &mut client_handles).await;
            }
        };
    }

    client_handles.join_all().await;

    Ok(())
}
