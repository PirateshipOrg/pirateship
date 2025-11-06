
use pft::proto::{client::ProtoClientRequest, consensus::ProtoBlock, execution::{ProtoTransaction, ProtoTransactionOp, ProtoTransactionPhase}};
use prost::Message;

fn get_small_tx_msg() -> ProtoClientRequest {
    ProtoClientRequest {
        tx: Some(ProtoTransaction{
            on_receive: None,
            on_crash_commit: Some(ProtoTransactionPhase {
                ops: vec![ProtoTransactionOp {
                    op_type: pft::proto::execution::ProtoTransactionOpType::Noop.into(),
                    operands: vec![vec![2u8; 2]],
                }],
            }),
            on_byzantine_commit: None,
            is_reconfiguration: false,
            is_2pc: false,
        }),
        origin: String::from("client1"),
        // sig: vec![0u8; SIGNATURE_LENGTH],
        sig: vec![rand::random(); 1],
        client_tag: 0
    }
}

fn get_large_tx_msg() -> ProtoClientRequest {
    ProtoClientRequest {
        tx: Some(ProtoTransaction{
            on_receive: None,
            on_crash_commit: Some(ProtoTransactionPhase {
                ops: vec![ProtoTransactionOp {
                    op_type: pft::proto::execution::ProtoTransactionOpType::Write.into(),
                    operands: vec![
                        format!("crash_commit_{}", rand::random::<u64>()).into_bytes(),
                        format!("Tx:{}:{}", rand::random::<u64>(), rand::random::<u64>()).into_bytes()
                    ],
                    // operands: Vec::new(),
                }],
            }),
            // on_crash_commit: None,
            on_byzantine_commit: None,
            is_reconfiguration: false,
            is_2pc: false,
        }),
        origin: String::from("client1"),
        // sig: vec![0u8; SIGNATURE_LENGTH],
        sig: vec![0u8; 1],
        client_tag: 0,
    }
}

const SAMPLES: usize = 10000;
fn main() {
    let mut large_lens = Vec::new();
    let mut large_blocks = Vec::new();
    for i in 0..SAMPLES {
        let tx = get_large_tx_msg();
        let v = tx.encode_to_vec();
        large_lens.push(v.len());
        let block = ProtoBlock {
            tx_list: vec![tx.tx.unwrap()],
            n: i as u64,
            parent: vec![0u8; 32],
            view: 1,
            qc: Vec::new(),
            fork_validation: Vec::new(),
            view_is_stable: true,
            config_num: 0,
            sig: Some(pft::proto::consensus::proto_block::Sig::ProposerSig(vec![0u8; 64])),
        };
        large_blocks.push(block);
    }

    let mean_large_len = large_lens.iter().sum::<usize>() as f64 / SAMPLES as f64;

    println!("Mean large length: {} KiB Total: {} KiB", mean_large_len / 1024.0, mean_large_len * SAMPLES as f64 / 1024.0);
    
    // Calculate total size of all blocks
    let total_large_blocks_size: usize = large_blocks.iter().map(|b| b.encode_to_vec().len()).sum();
    println!("Large blocks total size: {} KiB", total_large_blocks_size as f64 / 1024.0);
    
    let mut small_blocks = Vec::new();
    let mut small_lens = Vec::new();
    for i in 0..SAMPLES {
        let tx = get_small_tx_msg();
        let v = tx.encode_to_vec();
        small_lens.push(v.len());
        let block = ProtoBlock {
            tx_list: vec![tx.tx.unwrap()],
            n: i as u64,
            parent: vec![0u8; 32],
            view: 1,
            qc: Vec::new(),
            fork_validation: Vec::new(),
            view_is_stable: true,
            config_num: 0,
            sig: Some(pft::proto::consensus::proto_block::Sig::ProposerSig(vec![0u8; 64])),
        };
        small_blocks.push(block);
    }

    let mean_small_len = small_lens.iter().sum::<usize>() as f64 / SAMPLES as f64;

    println!("Mean small length: {} KiB Total {} KiB", mean_small_len / 1024.0, mean_small_len * SAMPLES as f64 / 1024.0);
    
    // Calculate total size of all blocks
    let total_small_blocks_size: usize = small_blocks.iter().map(|b| b.encode_to_vec().len()).sum();
    println!("Small blocks total size: {} KiB", total_small_blocks_size as f64 / 1024.0);

    let tx = get_small_tx_msg();

    let tx_ser = tx.tx.unwrap().encode_to_vec();
    println!("Small tx serialized size: {}", tx_ser.len());

}