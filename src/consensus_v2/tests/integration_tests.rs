use std::time::{Duration, Instant};

use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use core_affinity::CoreId;
use log::{error, info};
use tokio::sync::mpsc::unbounded_channel;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio::time::timeout;
use crate::config::AtomicConfig;
use crate::consensus_v2::app::Application;
use crate::consensus_v2::batch_proposal::BatchProposer;
use crate::consensus_v2::block_broadcaster::BlockBroadcaster;
use crate::consensus_v2::block_sequencer::BlockSequencer;
use crate::consensus_v2::client_reply::ClientReplyHandler;
use crate::consensus_v2::engines::null_app::NullApp;
use crate::consensus_v2::staging::Staging;
use crate::crypto::{AtomicKeyStore, CryptoService, KeyStore};
use crate::rpc::client::Client;
use crate::utils::channel::make_channel;
use crate::utils::{RocksDBStorageEngine, StorageService};
use crate::{config::Config, consensus_v2::batch_proposal::{MsgAckChanWithTag, TxWithAckChanTag}, proto::execution::{ProtoTransaction, ProtoTransactionOp, ProtoTransactionPhase}, utils::channel::{Receiver, Sender}};


const PAYLOAD_SIZE: usize = 512;
const RUNTIME: Duration = Duration::from_secs(30);
const NUM_CLIENTS: usize = 24000;
const NUM_CONCURRENT_REQUESTS: usize = 10;
const TEST_CRYPTO_NUM_TASKS: usize = 3;

async fn load_close_loop(batch_proposer_tx: Sender<TxWithAckChanTag>, client_id: usize) -> (Duration, usize) {
    let start = Instant::now();
    let transaction = ProtoTransaction {
        on_receive: None,
        on_crash_commit: Some(ProtoTransactionPhase {
            ops: vec![ProtoTransactionOp {
                op_type: crate::proto::execution::ProtoTransactionOpType::Noop.into(),
                operands: vec![vec![rand::random(); PAYLOAD_SIZE]],
            }; 1],
        }),
        on_byzantine_commit: None,
        is_reconfiguration: false,
    };

    let mut num_tx = 0;
    tokio::time::sleep(Duration::from_millis(10)).await;
    let (tx, mut rx) = tokio::sync::mpsc::channel(NUM_CONCURRENT_REQUESTS);
    let mut latencies_total = Duration::from_micros(0);
    let mut latencies_total_num = 0;

    let tout = Duration::from_secs(1);
    
    'main: while start.elapsed() < RUNTIME {
        let mut _start_times = Vec::new();
        for _ in 0..NUM_CONCURRENT_REQUESTS {
            if start.elapsed() > RUNTIME {
                break 'main;
            }

            let ack_chan_with_tag: MsgAckChanWithTag = (tx.clone(), num_tx);
    
            let res = timeout(tout, batch_proposer_tx.send((Some(transaction.clone()), ack_chan_with_tag))).await;
            match res {
                Ok(Ok(_)) => {
                    _start_times.push(Instant::now());
                },
                Ok(Err(_)) => {
                    break 'main;
                },
                Err(_) => {
                    continue;
                }
            }
        }
        let mut total_replies = 0;
        while total_replies < NUM_CONCURRENT_REQUESTS {
            if start.elapsed() > RUNTIME {
                break 'main;
            }
            let mut replies = Vec::with_capacity(NUM_CONCURRENT_REQUESTS);
            let res = timeout(tout, rx.recv_many(&mut replies, NUM_CONCURRENT_REQUESTS)).await;
            if let Err(_) = res {
                continue;
            }

            num_tx += replies.len() as u64;
            for _reply in replies {
                let latency = _start_times[total_replies].elapsed();
                latencies_total += latency;
                total_replies += 1;
                latencies_total_num += 1;
            }
        }
    }

    (latencies_total, latencies_total_num)


}

macro_rules! pinned_runtime {
    ($fn_name: expr) => {
        // Generate configs first
        let cfg_path = "configs/node1_config.json";
        let cfg_contents = std::fs::read_to_string(cfg_path).expect("Invalid file path");

        let config = Config::deserialize(&cfg_contents);
        let _chan_depth = config.rpc_config.channel_depth as usize;
        
        colog::init();
        let num_cores = num_cpus::get();
        let id = Arc::new(std::sync::Mutex::new(AtomicUsize::new(0)));
        let (batch_proposer_tx, batch_proposer_rx) = make_channel(_chan_depth);

        let num_consensus_cores = num_cores / 2;
        let num_client_cores = num_cores - num_consensus_cores;

        let id1 = id.clone();
        let client_rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(num_client_cores)
            .enable_all()
            .on_thread_start(move || {
                let id = id1.lock().unwrap();
                let _ = core_affinity::set_for_current(CoreId{ id: id.fetch_add(1, std::sync::atomic::Ordering::SeqCst) % num_cores});
            })
            .build()
            .unwrap();

        // Pin thread to core
        let consensus_rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(num_consensus_cores)
            .enable_all()
            .on_thread_start(move || {
                let id = id.lock().unwrap();
                let _ = core_affinity::set_for_current(CoreId{ id: id.fetch_add(1, std::sync::atomic::Ordering::SeqCst) % num_cores});
            })
            .build()
            .unwrap();

        let client_handle = client_rt.spawn(client_runner(batch_proposer_tx, NUM_CLIENTS));

        consensus_rt.block_on($fn_name(config, batch_proposer_rx, NUM_CLIENTS));

        client_rt.block_on(async move {
            client_handle.await.unwrap();
        });
    };
}

async fn client_runner(batch_proposer_tx: Sender<TxWithAckChanTag>, num_clients: usize) {
    let mut handles = Vec::new();
    for client_id in 0..num_clients {
        let batch_proposer_tx = batch_proposer_tx.clone();
        let handle = tokio::spawn(async move {
            load_close_loop(batch_proposer_tx, client_id).await
        });
        handles.push(handle);
    }

    let mut latencies_total = Duration::from_micros(0);
    let mut latencies_total_num = 0;

    for handle in handles {
        let (latencies, total) = handle.await.unwrap();
        latencies_total += latencies;
        latencies_total_num += total;
    }

    println!("Average latency: {} us", latencies_total.div_f64(latencies_total_num as f64).as_micros());
}


#[test]
fn test_client_reply() {
    pinned_runtime!(_test_client_reply);
}

async fn _test_client_reply(config: Config, batch_proposer_rx: Receiver<TxWithAckChanTag>, num_clients: usize) {
    // Generate configs first
    let cfg_path = "configs/node1_config.json";
    let cfg_contents = std::fs::read_to_string(cfg_path).expect("Invalid file path");

    let config = Config::deserialize(&cfg_contents);
    let _chan_depth = config.rpc_config.channel_depth as usize;
    let key_store = KeyStore::new(&config.rpc_config.allowed_keylist_path, &config.rpc_config.signing_priv_key_path);

    let config = AtomicConfig::new(config);
    let keystore = AtomicKeyStore::new(key_store);
    let mut crypto = CryptoService::new(TEST_CRYPTO_NUM_TASKS, keystore.clone());
    crypto.run();

    let client = Client::new_atomic(config.clone(), keystore.clone(), false, 0);
    let staging_client = Client::new_atomic(config.clone(), keystore.clone(), false, 0);

    let storage_config = &config.get().consensus_config.log_storage_config;
    let (mut storage, storage_path) = match storage_config {
        rocksdb_config @ crate::config::StorageConfig::RocksDB(_inner) => {
            let _db = RocksDBStorageEngine::new(rocksdb_config.clone());
            (StorageService::new(_db, _chan_depth), _inner.db_path.clone())
        },
        crate::config::StorageConfig::FileStorage(_) => {
            panic!("File storage not supported!");
        },
    };


    let (block_maker_tx, block_maker_rx) = make_channel(_chan_depth);
    let (control_command_tx, control_command_rx) = make_channel(_chan_depth);
    let (qc_tx, qc_rx) = unbounded_channel();
    let (block_broadcaster_tx, block_broadcaster_rx) = make_channel(_chan_depth);
    let (other_block_tx, other_block_rx) = make_channel(_chan_depth);
    let (client_reply_tx, client_reply_rx) = make_channel(_chan_depth);
    let (client_reply_command_tx, client_reply_command_rx) = make_channel(_chan_depth);
    let (broadcaster_control_command_tx, broadcaster_control_command_rx) = make_channel(_chan_depth);
    let (staging_tx, staging_rx) = make_channel(_chan_depth);
    let (logserver_tx, mut logserver_rx) = make_channel(_chan_depth);
    let (vote_tx, vote_rx) = make_channel(_chan_depth);
    let (view_change_tx, view_change_rx) = make_channel(_chan_depth);
    let (app_tx, app_rx) = make_channel(_chan_depth);
    let (fork_receiver_command_tx, mut fork_receiver_command_rx) = make_channel(_chan_depth);
    let (unlogged_tx, unlogged_rx) = make_channel(_chan_depth);

    let block_maker_crypto = crypto.get_connector();
    let block_broadcaster_crypto = crypto.get_connector();
    let block_broadcaster_storage = storage.get_connector(block_broadcaster_crypto);
    let staging_crypto = crypto.get_connector();

    let batch_proposer = Arc::new(Mutex::new(BatchProposer::new(config.clone(), batch_proposer_rx, block_maker_tx, app_tx.clone())));
    let block_maker = Arc::new(Mutex::new(BlockSequencer::new(config.clone(), control_command_rx, block_maker_rx, qc_rx, block_broadcaster_tx, client_reply_tx, block_maker_crypto)));
    let block_broadcaster = Arc::new(Mutex::new(BlockBroadcaster::new(config.clone(), client.into(), block_broadcaster_rx, other_block_rx, broadcaster_control_command_rx, block_broadcaster_storage, staging_tx, logserver_tx, fork_receiver_command_tx.clone(), app_tx.clone())));
    let staging = Arc::new(Mutex::new(Staging::new(config.clone(), staging_client.into(), staging_crypto, staging_rx, vote_rx, view_change_rx, client_reply_command_tx.clone(), app_tx, broadcaster_control_command_tx, control_command_tx, fork_receiver_command_tx, qc_tx)));
    let app = Arc::new(Mutex::new(Application::<NullApp>::new(config.clone(), app_rx, unlogged_rx, client_reply_command_tx)));
    let client_reply = Arc::new(Mutex::new(ClientReplyHandler::new(config.clone(), client_reply_rx, client_reply_command_rx)));
    let mut handles = JoinSet::new();

    handles.spawn(async move {
        storage.run().await;
    });

    handles.spawn(async move {
        BatchProposer::run(batch_proposer).await;
        println!("Batch proposer quits");
    });

    handles.spawn(async move {
        ClientReplyHandler::run(client_reply).await;
        println!("Client reply quits");
    });

    handles.spawn(async move {
        while let Some(_) = fork_receiver_command_rx.recv().await {
            // Sink
        }
    });



    handles.spawn(async move {
        BlockSequencer::run(block_maker).await;
        println!("Block maker quits");
    });

    handles.spawn(async move {
        BlockBroadcaster::run(block_broadcaster).await;
        println!("Block broadcaster quits");
    });

    handles.spawn(async move {
        Staging::run(staging).await;
        println!("Staging quits");
    });

    handles.spawn(async move {
        Application::<NullApp>::run(app).await;
        println!("Application quits");
    });

    let mut total_txs_output = 0;

    let start = Instant::now();
    let tout = Duration::from_secs(1);
    while start.elapsed() < RUNTIME {
        let block = timeout(tout, logserver_rx.recv()).await;
        if block.is_err() {
            continue;
        }
        total_txs_output += block.unwrap().unwrap().block.tx_list.len();
    }
    let total_time = start.elapsed().as_secs_f64();
    let throughput = total_txs_output as f64 / total_time;
    println!("Crash Throughput: {} req/s", throughput);
    
    tokio::time::sleep(Duration::from_secs(1)).await;

    println!("Errors appearing after this are inconsequential");
    std::fs::remove_dir_all(&storage_path).unwrap();
}