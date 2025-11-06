// Copyright (c) Shubham Mishra. All rights reserved.
// Licensed under the MIT License.

use sha2::{Digest, Sha512};

pub const DIGEST_LENGTH: usize = 64;

pub fn hash(data: &[u8]) -> Vec<u8> {
    Sha512::new()
        .chain_update(data)
        .finalize()
        .as_slice()
        .to_vec()

    // [0u8; DIGEST_LENGTH].to_vec()
}

pub fn cmp_hash(one: &Vec<u8>, two: &Vec<u8>) -> bool {
    one.as_slice() == two.as_slice()
    // true
}

pub type HashType = Vec<u8>;

pub fn default_hash() -> HashType {
    vec![0u8; DIGEST_LENGTH]
}
