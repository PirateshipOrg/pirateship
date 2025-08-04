use std::io::{Error, ErrorKind};

use bytes::BytesMut;
use ed25519_dalek::SIGNATURE_LENGTH;
use prost::{DecodeError, Message};

use crate::{crypto::{HashType, DIGEST_LENGTH}, proto::consensus::{DefferedSignature, ProtoBlock, ProtoTransactionList}};

pub const USIZE_LENGTH: usize = std::mem::size_of::<usize>();
pub const BLOCK_OFFSET: usize = SIGNATURE_LENGTH + DIGEST_LENGTH*2 + USIZE_LENGTH;
pub const PARENT_OFFSET: usize = SIGNATURE_LENGTH + USIZE_LENGTH;

pub fn serialize_proto_block_nascent(block: &ProtoBlock, merkle_root: &HashType) -> Result<(Vec<u8>, usize), Error> {
    //
    // Serialized format: signature || block_size || parent_hash || merkle_root || block || txs
    //
    if block.parent.len() != 0
    || (block.sig != None
        && block.sig != Some(crate::proto::consensus::proto_block::Sig::NoSig(DefferedSignature{})))
    {
        return Err(Error::new(ErrorKind::InvalidData, "Invalid new block"));
    }

    let mut detached_block = block.clone();
    let detached_txs = ProtoTransactionList{
        tx_list: detached_block.tx_list
    };
    detached_block.tx_list = Vec::new();
    detached_block.parent.clear();

    let detached_block_size = detached_block.encoded_len();

    let mut bytes = BytesMut::with_capacity(BLOCK_OFFSET + detached_block_size + detached_txs.encoded_len());
    bytes.extend_from_slice(&[0u8; SIGNATURE_LENGTH]);
    bytes.extend_from_slice(&detached_block_size.to_be_bytes());
    bytes.extend_from_slice(&[0u8; DIGEST_LENGTH]);
    bytes.extend_from_slice(merkle_root);
    detached_block.encode(&mut bytes).unwrap();
    detached_txs.encode(&mut bytes).unwrap();

    Ok((bytes.to_vec(), detached_block_size))
}

pub fn serialize_proto_block_prefilled(mut block: ProtoBlock, merkle_root: &HashType) -> Vec<u8> {
    //
    // Serialized format: signature || block_size || parent_hash || merkle_root || block || txs
    //
    let mut bytes = BytesMut::with_capacity(DIGEST_LENGTH + SIGNATURE_LENGTH + block.encoded_len());
    match &block.sig {
        Some(crate::proto::consensus::proto_block::Sig::ProposerSig(sig)) => {
            bytes.extend_from_slice(sig);
        },
        Some(crate::proto::consensus::proto_block::Sig::NoSig(_)) => {
            bytes.extend_from_slice(&[0u8; SIGNATURE_LENGTH]);
        },
        None => {
            bytes.extend_from_slice(&[0u8; SIGNATURE_LENGTH]);
        }
    }
    let detached_txs = ProtoTransactionList{
        tx_list: block.tx_list
    };
    block.tx_list = Vec::new();

    let parent = block.parent;
    block.parent = Vec::new();
    bytes.extend_from_slice(&block.encoded_len().to_be_bytes());
    bytes.extend_from_slice(&parent);
    bytes.extend_from_slice(merkle_root);
    
    block.parent.clear();
    block.sig = None;

    block.encode(&mut bytes).unwrap();
    let block_size = bytes.len() - BLOCK_OFFSET;
    detached_txs.encode(&mut bytes).unwrap();
    let mut bytes_vec = bytes.to_vec();
    bytes_vec[SIGNATURE_LENGTH..SIGNATURE_LENGTH + USIZE_LENGTH].copy_from_slice(&block_size.to_be_bytes());

    bytes_vec
}

pub fn update_parent_hash_in_proto_block_ser(block: &mut Vec<u8>, parent_hash: &HashType) {
    block[PARENT_OFFSET..PARENT_OFFSET+DIGEST_LENGTH].copy_from_slice(parent_hash);
}

pub fn get_parent_hash_in_proto_block_ser(block: &Vec<u8>) -> Option<HashType> {
    if block.len() < PARENT_OFFSET + DIGEST_LENGTH {
        return None;
    }
    Some(block[PARENT_OFFSET..PARENT_OFFSET+DIGEST_LENGTH].to_vec())
}

pub fn update_signature_in_proto_block_ser(block: &mut Vec<u8>, signature: &[u8; SIGNATURE_LENGTH]) {
    block[..SIGNATURE_LENGTH].copy_from_slice(signature);
}

pub fn get_block_size_from_ser(data: &[u8]) -> usize {
    return usize::from_be_bytes(data[SIGNATURE_LENGTH..SIGNATURE_LENGTH + USIZE_LENGTH].try_into().unwrap());
}

pub fn deserialize_proto_block(bytes: &[u8]) -> Result<ProtoBlock, DecodeError> {
    if bytes.len() < DIGEST_LENGTH + SIGNATURE_LENGTH {
        return Err(DecodeError::new("Invalid block length"));
    }
    
    let block_size = get_block_size_from_ser(bytes);
    let mut block = ProtoBlock::decode(&bytes[BLOCK_OFFSET..BLOCK_OFFSET + block_size]).unwrap();
    let txs = ProtoTransactionList::decode(&bytes[BLOCK_OFFSET + block_size..]).unwrap();

    block.parent = bytes[PARENT_OFFSET..PARENT_OFFSET + DIGEST_LENGTH].to_vec();
    block.tx_list = txs.tx_list;

    let sig = &bytes[..SIGNATURE_LENGTH];
    let sig_is_null = sig.iter().all(|&x| x == 0);
    if sig_is_null {
        block.sig = Some(crate::proto::consensus::proto_block::Sig::NoSig(DefferedSignature{}));
    } else {
        block.sig = Some(crate::proto::consensus::proto_block::Sig::ProposerSig(sig.to_vec()));
    }

    Ok(block)
}

#[cfg(test)]
mod test {
    use rand::{thread_rng, Rng};
    use crate::{crypto::hash, proto::{consensus::ProtoBlock, execution::{ProtoTransaction, ProtoTransactionOp, ProtoTransactionPhase}}, utils::BLOCK_OFFSET};

    #[test]
    fn test_proto_block_serde() {
        let mut block = ProtoBlock::default();
        let mut tx = Vec::with_capacity(1000);
        for _ in 0..1000 {
            let mut rng = thread_rng();
            tx.push(ProtoTransaction {
                on_receive: None,
                on_crash_commit: Some(ProtoTransactionPhase {
                    ops: vec![ProtoTransactionOp {
                        op_type: crate::proto::execution::ProtoTransactionOpType::Noop as i32,
                        operands: vec![vec![rng.gen(); 512]],
                    }],
                }),
                on_byzantine_commit: None,
                is_reconfiguration: false,
                is_2pc: false,
            });
        }
        block.tx_list = tx;

        let merkle_tree = crate::crypto::MerkleTree::from_block(&block);
        let (ser, _) = super::serialize_proto_block_nascent(&block, &merkle_tree.root()).unwrap();

        let block2 = super::deserialize_proto_block(&ser).unwrap();
        let merkle_tree2 = crate::crypto::MerkleTree::from_block(&block2);
        let ser2 = super::serialize_proto_block_prefilled(block2.clone(), &merkle_tree2.root());

        assert_eq!(block.n, block2.n);
        assert_eq!(merkle_tree.root(), merkle_tree2.root());
        assert_eq!(ser.len(), ser2.len());

        let hsh1 = hash(ser.as_slice());
        let hsh2 = hash(ser2.as_slice());

        assert_eq!(hsh1, hsh2);
    }
}