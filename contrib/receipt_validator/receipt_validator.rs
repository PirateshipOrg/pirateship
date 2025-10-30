use clap::{Arg, Command};
use ed25519_dalek::SIGNATURE_LENGTH;
use pft::crypto::{hash_proto_block_ser, HashType, KeyStore, MerkleInclusionProof};
use pft::proto::client::ProtoTransactionReceipt;
use pft::proto::consensus::{proto_block, ProtoBlock, ProtoQuorumCertificate};
use pft::utils::{unwrap_merkle_root,BLOCK_OFFSET};
use prost::bytes::BytesMut;
use prost::Message;
use std::fs;
use std::path::Path;
use scitt_cose::extract_receipt_from_statement;

mod json2proto;

fn hash_proto_block(block: &ProtoBlock) -> Result<HashType, String> {
    //
    // Serialized format: signature || block_size || parent_hash || block
    //
    let mut block = block.clone();
    let parent = block.parent;
    block.parent = vec![];

    let sig = block.sig.take();
    block.sig = None;
    let sig = match &sig {
        Some(proto_block::Sig::ProposerSig(sig)) => sig.as_slice(),
        Some(proto_block::Sig::NoSig(_)) => &[0u8; SIGNATURE_LENGTH],
        None => &[0u8; SIGNATURE_LENGTH],
    };

    let block_size = block.encoded_len();
    let mut bytes = BytesMut::with_capacity(BLOCK_OFFSET + block_size);
    bytes.extend_from_slice(sig);
    bytes.extend_from_slice(&block_size.to_be_bytes());
    bytes.extend_from_slice(&parent);
    block.encode(&mut bytes).unwrap();

    Ok(hash_proto_block_ser(&bytes))
}

fn validate_chain(chain: &Vec<ProtoBlock>) -> Result<(), String> {
    if chain.is_empty() {
        return Err("Chain is empty".to_string());
    }

    for i in 1..chain.len() {
        let parent = &chain[i - 1];
        let block = &chain[i];

        if parent.n + 1 != block.n {
            return Err(format!(
                "Blocks are not sequential: {} {}",
                parent.n, block.n
            ));
        }

        let parent_hash = hash_proto_block(parent)?;
        if parent_hash != block.parent {
            return Err(format!("Parent hash mismatch at block {}", block.n));
        }
    }

    Ok(())
}

fn validate_qcs(
    chain: &Vec<ProtoBlock>,
    qcs: &Vec<ProtoQuorumCertificate>,
    keystore: &KeyStore,
    n_nodes: usize,
) -> Result<usize, String> {
    if qcs.is_empty() {
        return Err("No quorum certificates provided".to_string());
    }

    let chain_start = chain.first().ok_or("Chain is empty")?.n;

    let mut counts_for = 0;
    for qc in qcs {
        if qc.n < chain_start {
            return Err(format!(
                "QC block number {} is less than chain start {}",
                qc.n, chain_start
            ));
        }
        if qc.n - chain_start >= chain.len() as u64 {
            return Err(format!("QC block number {} is out of chain bounds", qc.n));
        }
        let referencing_block = &chain[(qc.n - chain_start) as usize];
        assert_eq!(
            referencing_block.n, qc.n,
            "QC block number does not match referencing block number"
        );

        if qc.digest != hash_proto_block(referencing_block)? {
            return Err(format!("QC digest does not match block {} hash", qc.n));
        }

        for sig in &qc.sig {
            let sig_arr = sig.sig.as_slice()
                .try_into()
                .map_err(|_| "Invalid signature length".to_string())?;
            if !keystore.verify(&sig.name, &sig_arr, &qc.digest) {
                return Err(format!(
                    "Invalid signature for node {} in QC {}",
                    &sig.name, qc.n
                ));
            }
        }

        counts_for += if qc.sig.len() == n_nodes {
            2 // fast audit
        } else {
            1
        };
    }

    Ok(counts_for)
}

fn validate_cose_receipt(
    data: &[u8],
    tx_digest: &[u8],
    keystore: &KeyStore,
    n_nodes: usize,
    tx_n: usize,
) -> Result<(), String> {
    let receipt = extract_receipt_from_statement(&data)
        .map_err(|e| format!("Failed to extract receipt: {}", e))?;
    validate_ps_receipt(&receipt, tx_digest, keystore, n_nodes, tx_n)
}

fn validate_ps_receipt(
    data: &[u8],
    tx_digest: &[u8],
    keystore: &KeyStore,
    n_nodes: usize,
    tx_n: usize,
) -> Result<(), String> {
    let receipt = ProtoTransactionReceipt::decode(data).expect("Failed to decode PS receipt");

    let proof = MerkleInclusionProof::new(receipt.proof, receipt.k);
    if !proof.validate(
        &tx_digest.to_vec(),
        tx_n,
        unwrap_merkle_root(receipt.chain.first().ok_or("chain is empty")?),
    ) {
        return Err("Invalid PS receipt: Merkle proof validation failed".to_string());
    }

    if let Err(e) = validate_chain(&receipt.chain) {
        return Err(format!("Invalid PS receipt: {}", e));
    }

    match validate_qcs(&receipt.chain, &receipt.qcs, keystore, n_nodes) {
        Ok(counts_for) => {
            println!(
                "PS receipt validated with {} quorum certificates",
                counts_for
            );
        }
        Err(e) => return Err(format!("Invalid PS receipt: {}", e)),
    }

    Ok(())
}

fn main() {
    let matches = Command::new("receipt-validator")
        .about("Validates COSE or PS (binary) receipts")
        .version("0.1.0")
        .arg(
            Arg::new("txid")
                .help("Transaction ID (block:tx_n) to validate the receipt against")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("receipt")
                .help("Path to the receipt file")
                .required(true)
                .index(2),
        )
        .arg(
            Arg::new("hash")
                .help("Path to a file with the hash of the request that generated the receipt")
                .required(true)
                .index(3),
        )
        .arg(
            Arg::new("keylist")
                .help("Path to the keylist file")
                .required(true)
                .index(4),
        )
        .arg(
            Arg::new("type")
                .short('t')
                .long("type")
                .help("Receipt type: 'cose' or 'ps' (default: ps)")
                .value_parser(["cose", "ps"])
                .default_value("ps"),
        )
        .arg(
            Arg::new("num-nodes")
                .short('n')
                .long("num-nodes")
                .help("Number of Pirateship nodes")
                .value_parser(clap::value_parser!(u32).range(1..=100))
                .default_value("7"),
        )
        .get_matches();

    let txid = matches.get_one::<String>("txid").unwrap();
    let tx_n = txid
        .split(':')
        .nth(1)
        .and_then(|s| s.parse::<usize>().ok())
        .expect("Invalid transaction ID format, expected block:tx_n");

    let receipt_path = matches.get_one::<String>("receipt").unwrap();
    let receipt_data = if Path::new(receipt_path).exists() {
        match fs::read(receipt_path) {
            Ok(data) => data,
            Err(e) => {
                eprintln!("Error reading receipt file '{}': {}", receipt_path, e);
                std::process::exit(1);
            }
        }
    } else {
        eprintln!("Error: Receipt file '{}' does not exist", receipt_path);
        std::process::exit(1);
    };

    let hash_path = matches.get_one::<String>("hash").unwrap();
    let hash_data = if Path::new(hash_path).exists() {
        match fs::read(hash_path) {
            Ok(data) => data,
            Err(e) => {
                eprintln!("Error reading hash file '{}': {}", hash_path, e);
                std::process::exit(1);
            }
        }
    } else {
        eprintln!("Error: Hash file '{}' does not exist", hash_path);
        std::process::exit(1);
    };

    let keylist_path = matches.get_one::<String>("keylist").unwrap();
    let keystore = if Path::new(keylist_path).exists() {
        let mut keystore = KeyStore::empty();
        keystore.pub_keys = KeyStore::get_pubkeys(keylist_path);
        keystore
    } else {
        eprintln!("Error: Keylist file '{}' does not exist", keylist_path);
        std::process::exit(1);
    };

    let n_nodes = *matches.get_one::<u32>("num-nodes").unwrap() as usize;

    let receipt_type = matches.get_one::<String>("type").unwrap();
    let res = match receipt_type.as_str() {
        "cose" => {
            println!("Processing COSE receipt: {}", receipt_path);
            println!("Using keylist: {}", keylist_path);
            validate_cose_receipt(&receipt_data, &hash_data, &keystore, n_nodes, tx_n)
        }
        "ps" => {
            println!("Processing PS (binary) receipt: {}", receipt_path);
            println!("Using keylist: {}", keylist_path);
            validate_ps_receipt(&receipt_data, &hash_data, &keystore, n_nodes, tx_n)
        }
        _ => unreachable!("Invalid receipt type"),
    };

    match res {
        Ok(()) => println!("Receipt validation successful"),
        Err(e) => eprintln!("Receipt validation failed: {}", e),
    }
}
