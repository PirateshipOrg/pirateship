// Copyright (c) Shubham Mishra. All rights reserved.
// Licensed under the MIT License.

pub mod utils;
pub mod config;
// pub mod consensus;
pub mod consensus;
pub mod crypto;
pub mod rpc;
// pub mod execution;
pub mod proto;
pub mod peerreview;

pub mod client;

#[macro_export]
macro_rules! get_tx_list {
    ($block: expr) => {
        &match &$block.tx.as_ref().unwrap() {
            crate::proto::consensus::proto_block::Tx::TxList(l) => l,
            crate::proto::consensus::proto_block::Tx::TxListHash(_) => panic!("Incomplete block"),
        }.tx_list
    };
}

