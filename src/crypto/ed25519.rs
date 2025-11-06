// Copyright (c) Shubham Mishra. All rights reserved.
// Licensed under the MIT License.

use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Read},
    path,
};

use ed25519_dalek::{
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    Signature, Signer, SigningKey, Verifier, VerifyingKey, SECRET_KEY_LENGTH, SIGNATURE_LENGTH,
};

use crate::utils::AtomicStruct;

/// KeyStore is an immutable struct.
/// It is initiated when called new.
/// This makes it easy to share among threads.
#[derive(Clone)]
pub struct KeyStore {
    pub pub_keys: HashMap<String, VerifyingKey>,
    pub priv_key: SigningKey,
}

impl KeyStore {
    pub fn get_pubkeys(pubkey_path: &String) -> HashMap<String, VerifyingKey> {
        let mut keys = HashMap::new();
        let key_path = path::Path::new(pubkey_path.as_str());
        if !key_path.exists() {
            panic!("Invalid Public Key Path: {}", pubkey_path);
        }
        let f = match File::open(key_path) {
            Ok(_f) => _f,
            Err(e) => {
                panic!("Problem reading cert file: {}", e);
            }
        };
        let keylist = BufReader::new(f);
        for line in keylist.lines() {
            match line {
                Ok(s) => {
                    // Format: name base64-encoded-key\n
                    let parts: Vec<_> = s.split(" ").collect();
                    let name = parts[0];
                    let key_pem = String::from("-----BEGIN PUBLIC KEY-----\n")
                        + parts[1]
                        + "\n-----END PUBLIC KEY-----\n";

                    let key =
                        VerifyingKey::from_public_key_pem(&key_pem).expect("Invalid PEM format");

                    keys.insert(String::from(name), key.to_owned());
                }
                Err(_) => {
                    break;
                }
            }
        }

        keys
    }
    pub fn get_privkeys(privkey_path: &String) -> SigningKey {
        let key_path = path::Path::new(privkey_path.as_str());
        if !key_path.exists() {
            panic!("Invalid Private Key Path: {}", privkey_path);
        }
        let f = match File::open(key_path) {
            Ok(_f) => _f,
            Err(e) => {
                panic!("Problem reading cert file: {}", e);
            }
        };
        let mut pem = BufReader::new(f);
        let mut key_str = String::new();
        pem.read_to_string(&mut key_str)
            .expect("Problem reading file");

        SigningKey::from_pkcs8_pem(key_str.as_str()).unwrap()
    }

    pub fn new(pubkey_path: &String, privkey_path: &String) -> KeyStore {
        KeyStore {
            pub_keys: KeyStore::get_pubkeys(pubkey_path),
            priv_key: KeyStore::get_privkeys(privkey_path),
        }
    }

    pub fn empty() -> KeyStore {
        KeyStore {
            pub_keys: HashMap::new(),
            priv_key: SigningKey::from_bytes(&[0u8; SECRET_KEY_LENGTH]),
        }
    }

    pub fn get_pubkey(&self, name: &String) -> Option<&VerifyingKey> {
        self.pub_keys.get(name)
    }

    pub fn get_privkey(&self) -> &SigningKey {
        &self.priv_key
    }

    pub fn sign(&self, data: &[u8]) -> [u8; SIGNATURE_LENGTH] {
        // Import the ed25519_dalek::Signer to avoid the .sign method to take a mutable ref
        let sig: Signature = self.priv_key.sign(data);
        sig.to_bytes()
    }

    pub fn verify(&self, name: &String, sig: &[u8; SIGNATURE_LENGTH], data: &[u8]) -> bool {
        let key = match self.get_pubkey(name) {
            Some(k) => k,
            None => {
                return false;
            }
        };

        key.verify(data, &Signature::from_bytes(sig)).is_ok()
    }
}

pub type AtomicKeyStore = AtomicStruct<KeyStore>;
