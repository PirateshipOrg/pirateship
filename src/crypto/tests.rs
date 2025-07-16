// Copyright (c) Shubham Mishra. All rights reserved.
// Licensed under the MIT License.

use prost::Message;

use crate::config::{AtomicConfig, Config};

use super::{AtomicKeyStore, CryptoService, KeyStore};

/// The tests needs a config directory.
/// Create it by running: sh scripts/gen_local_config.sh configs 7 scripts/local_template.json
#[test]
pub fn test_load_key() {
    KeyStore::new(
        &String::from("configs/signing_pub_keys.keylist"),
        &String::from("configs/node1_signing_privkey.pem"),
    );
}

#[test]
pub fn test_sign_and_verify() {
    let keys = KeyStore::new(
        &String::from("configs/signing_pub_keys.keylist"),
        &String::from("configs/node1_signing_privkey.pem"),
    );

    let message = String::from("I am become death, the destroyer of worlds!");
    let mut sig = keys.sign(message.as_bytes());
    if !keys.verify(&String::from("node1"), &sig, message.as_bytes()) {
        panic!("I should verify my signature!");
    }

    if keys.verify(&String::from("node2"), &sig, message.as_bytes()) {
        panic!("Node2's key should not verify my signature!");
    }

    sig[0] = !sig[0];

    if keys.verify(&String::from("node1"), &sig, message.as_bytes()) {
        panic!("I should not verify a forged signature!");
    }
}

#[test]
fn test_lock_free() {
    if !AtomicKeyStore::is_lock_free() {
        panic!("KeyStore is not lock free");
    }
}


#[tokio::test]
async fn test_crypto_service() {
    let cfg_path = "configs/node1_config.json";
    let cfg_contents = std::fs::read_to_string(cfg_path).expect("Invalid file path");

    let config = Config::deserialize(&cfg_contents);
    
    let key_store = KeyStore::new(
        &String::from("configs/signing_pub_keys.keylist"),
        &String::from("configs/node1_signing_privkey.pem"),
    );

    let mut crypto_service = CryptoService::new(8, AtomicKeyStore::new(key_store), AtomicConfig::new(config));
    crypto_service.run();

    let mut crypto = crypto_service.get_connector();
    let message = String::from("I am become death, the destroyer of worlds!");
    let bytes = message.encode_to_vec();
    let mut sig = crypto.sign(&bytes).await;

    if !crypto.verify(&bytes, &String::from("node1"), &sig).await {
        panic!("I should verify my signature!");
    }

    if crypto.verify(&bytes, &String::from("node2"), &sig).await {
        panic!("Node2's key should not verify my signature!");
    }

    sig[0] = !sig[0];

    if crypto.verify(&bytes, &String::from("node1"), &sig).await {
        panic!("I should not verify a forged signature!");
    }

    crypto.kill().await;
}