// Copyright (c) Shubham Mishra. All rights reserved.
// Licensed under the MIT License.

use core::panic;
use std::{collections::HashMap, sync::Arc, time::Duration};

use tokio::{join, time::sleep};

use crate::config::{
    AppConfig, ClientConfig, ClientNetConfig, ClientRpcConfig, Config, ConsensusConfig, EvilConfig,
    KVReadWriteUniform, NetConfig, NodeNetInfo, RocksDBConfig, RpcConfig, WorkloadConfig,
};

use super::AtomicConfig;

#[test]
fn test_nodeconfig_serialize() {
    let mut net_config = NetConfig {
        name: "node1".to_string(),
        addr: "0.0.0.0:3001".to_string(),
        tls_cert_path: String::from("blah"),
        tls_key_path: String::from("blah"),
        tls_root_ca_cert_path: String::from("blah"),
        nodes: HashMap::new(),
        client_max_retry: 10,
    };

    for n in 0..5 {
        let mut name = "node".to_string();
        name.push_str(n.to_string().as_str());
        let mut addr = "127.0.0.1:300".to_string();
        addr.push_str(n.to_string().as_str());
        net_config.nodes.insert(
            name,
            NodeNetInfo {
                addr: addr.to_owned(),
                domain: String::from("blah.com"),
            },
        );
    }

    let rpc_config = RpcConfig {
        allowed_keylist_path: String::from("blah/blah"),
        signing_priv_key_path: String::from("blah/blah"),
        recv_buffer_size: (1 << 15),
        channel_depth: 32,
    };

    let consensus_config = ConsensusConfig {
        node_list: vec![
            String::from("node1"),
            String::from("node2"),
            String::from("node3"),
        ],
        learner_list: vec![String::from("node4"), String::from("node5")],
        max_backlog_batch_size: 1000,
        signature_max_delay_blocks: 128,
        signature_max_delay_ms: 100,
        num_crypto_workers: 128,
        view_timeout_ms: 150,
        batch_max_delay_ms: 10,
        commit_index_gap_soft: 256,
        commit_index_gap_hard: 512,

        #[cfg(feature = "storage")]
        log_storage_config: crate::config::StorageConfig::RocksDB(RocksDBConfig::default()),

        #[cfg(feature = "platforms")]
        liveness_u: 1,
    };

    let app_config = AppConfig {
        logger_stats_report_ms: 100,
        checkpoint_interval_ms: 60000,
    };

    let evil_config = EvilConfig {
        simulate_byzantine_behavior: true,
        byzantine_start_block: 20000,
    };

    let config = Config {
        net_config,
        rpc_config,
        consensus_config,
        app_config,

        #[cfg(feature = "evil")]
        evil_config,
    };

    let s = config.serialize();
    println!("{}", s);

    let config2 = Config::deserialize(&s);
    let nc2 = config2.net_config;
    assert!(config.net_config.name.eq(&nc2.name));
    assert!(config.net_config.addr.eq(&nc2.addr));
    for (name, node_config) in config.net_config.nodes.into_iter() {
        let opt = nc2.nodes.get(&name);
        assert!(opt.is_some());
        let val = opt.unwrap();
        assert!(val.addr.eq(&node_config.addr));
    }
}

#[test]
fn test_clientconfig_serialize() {
    let mut net_config = ClientNetConfig {
        name: "client1".to_string(),
        tls_root_ca_cert_path: String::from("blah"),
        nodes: HashMap::new(),
        client_max_retry: 10,
    };

    for n in 0..5 {
        let mut name = "node".to_string();
        name.push_str(n.to_string().as_str());
        let mut addr = "127.0.0.1:300".to_string();
        addr.push_str(n.to_string().as_str());
        net_config.nodes.insert(
            name,
            NodeNetInfo {
                addr: addr.to_owned(),
                domain: String::from("blah.com"),
            },
        );
    }

    let rpc_config = ClientRpcConfig {
        signing_priv_key_path: String::from("/tmp/test.pem"),
    };

    let config = ClientConfig {
        net_config,
        rpc_config,
        workload_config: WorkloadConfig {
            num_clients: 100,
            duration: 60,
            max_concurrent_requests: 10,
            request_config: crate::config::RequestConfig::KVReadWriteUniform(KVReadWriteUniform {
                num_keys: 1000,
                val_size: 10000,
                read_ratio: 0.1,
                write_byz_commit_ratio: 0.5,
            }),
        },
        full_duplex: false,
    };
    let s = config.serialize();
    println!("{}", s);

    // let config2 = Config::deserialize(&s);
    // let nc2 = config2.net_config;
    // assert!(config.net_config.name.eq(&nc2.name));
    // assert!(config.net_config.addr.eq(&nc2.addr));
    // for (name, node_config) in config.net_config.nodes.into_iter() {
    //     let opt = nc2.nodes.get(&name);
    //     assert!(opt.is_some());
    //     let val = opt.unwrap();
    //     assert!(val.addr.eq(&node_config.addr));
    // }
}

#[test]
fn test_crossbeam_lock_less() {
    if !AtomicConfig::is_lock_free() {
        panic!("AtomicConfig is not lock free");
    }
}

#[tokio::test]
async fn test_atomic_config_access() {
    let mut net_config = NetConfig {
        name: "node1".to_string(),
        addr: "0.0.0.0:3001".to_string(),
        tls_cert_path: String::from("blah"),
        tls_key_path: String::from("blah"),
        tls_root_ca_cert_path: String::from("blah"),
        nodes: HashMap::new(),
        client_max_retry: 10,
    };

    for n in 0..5 {
        let mut name = "node".to_string();
        name.push_str(n.to_string().as_str());
        let mut addr = "127.0.0.1:300".to_string();
        addr.push_str(n.to_string().as_str());
        net_config.nodes.insert(
            name,
            NodeNetInfo {
                addr: addr.to_owned(),
                domain: String::from("blah.com"),
            },
        );
    }

    let rpc_config = RpcConfig {
        allowed_keylist_path: String::from("blah/blah"),
        signing_priv_key_path: String::from("blah/blah"),
        recv_buffer_size: (1 << 15),
        channel_depth: 32,
    };

    let consensus_config = ConsensusConfig {
        node_list: vec![
            String::from("node1"),
            String::from("node2"),
            String::from("node3"),
        ],
        learner_list: vec![String::from("node4"), String::from("node5")],
        max_backlog_batch_size: 1000,
        signature_max_delay_blocks: 128,
        signature_max_delay_ms: 100,
        num_crypto_workers: 128,
        view_timeout_ms: 150,
        batch_max_delay_ms: 10,
        commit_index_gap_soft: 256,
        commit_index_gap_hard: 512,

        #[cfg(feature = "storage")]
        log_storage_config: crate::config::StorageConfig::RocksDB(RocksDBConfig::default()),

        #[cfg(feature = "platforms")]
        liveness_u: 1,
    };

    let app_config = AppConfig {
        logger_stats_report_ms: 100,
        checkpoint_interval_ms: 60000,
    };

    let evil_config = EvilConfig {
        simulate_byzantine_behavior: true,
        byzantine_start_block: 20000,
    };

    let config = Config {
        net_config,
        rpc_config,
        consensus_config,
        app_config,

        #[cfg(feature = "evil")]
        evil_config,
    };

    let atomic_config = AtomicConfig::new(config);
    let atomic_config2 = atomic_config.clone();

    unsafe {
        let ptr1 = atomic_config.0.as_ptr().as_ref().unwrap();
        let ptr2 = atomic_config2.0.as_ptr().as_ref().unwrap();
        println!(
            "{:?}\n{:?}",
            std::ptr::addr_of!(ptr1),
            std::ptr::addr_of!(ptr2)
        );
    }

    let handle1 = tokio::spawn(async move {
        let mut got_different = false;
        for _ in 0..100 {
            let cfg = atomic_config.get();
            println!("{}", cfg.net_config.name);
            if !cfg.net_config.name.eq("node1") {
                got_different = true;
            }
            sleep(Duration::from_millis(1)).await;
        }

        assert!(got_different);
    });

    let handle2 = tokio::spawn(async move {
        for i in 0..100 {
            let mut cfg = atomic_config2.get();
            let cfg = Arc::make_mut(&mut cfg);
            cfg.net_config.name = format!("node{}", i);

            atomic_config2.set_checked(cfg.clone());
            sleep(Duration::from_millis(1)).await;
        }
    });

    let _ = join!(handle1, handle2);
}
