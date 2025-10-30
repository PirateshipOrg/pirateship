use std::io::{Error, ErrorKind};

use bytes::BytesMut;
use ed25519_dalek::SIGNATURE_LENGTH;
use prost::{DecodeError, Message};

use crate::{crypto::{HashType, DIGEST_LENGTH}, proto::consensus::{DefferedSignature, ProtoBlock}};

#[cfg(feature = "receipts")]
use crate::{
    proto::consensus::{proto_block, ProtoTransactionList},
    utils::unwrap_and_take_tx_list,
};

#[cfg(feature = "receipts")]
pub const USIZE_LENGTH: usize = std::mem::size_of::<usize>();
#[cfg(feature = "receipts")]
pub const BLOCK_OFFSET: usize = SIGNATURE_LENGTH + USIZE_LENGTH + DIGEST_LENGTH;
#[cfg(feature = "receipts")]
pub const PARENT_OFFSET: usize = SIGNATURE_LENGTH + USIZE_LENGTH;

#[cfg(not(feature = "receipts"))]
pub const BLOCK_OFFSET: usize = SIGNATURE_LENGTH + DIGEST_LENGTH;
#[cfg(not(feature = "receipts"))]
pub const PARENT_OFFSET: usize = SIGNATURE_LENGTH;

#[cfg(feature = "receipts")]
pub fn serialize_proto_block_nascent(block: &ProtoBlock, merkle_root: &HashType) -> Result<(Vec<u8>, usize), Error> {
    //
    // Serialized format: signature || block_size || parent_hash || block || txs
    //
    if block.parent.len() != 0
    || (block.sig != None
        && block.sig != Some(crate::proto::consensus::proto_block::Sig::NoSig(DefferedSignature{})))
    {
        return Err(Error::new(ErrorKind::InvalidData, "Invalid new block"));
    }

    let mut detached_block = block.clone();
    let detached_txs = ProtoTransactionList{
        tx_list: unwrap_and_take_tx_list(&mut detached_block)
    };
    detached_block.payload = Some(proto_block::Payload::MerkleRoot(merkle_root.to_vec()));
    detached_block.parent.clear();

    let detached_block_size = detached_block.encoded_len();

    let mut bytes = BytesMut::with_capacity(BLOCK_OFFSET + detached_block_size + detached_txs.encoded_len());
    bytes.extend_from_slice(&[0u8; SIGNATURE_LENGTH]);
    bytes.extend_from_slice(&detached_block_size.to_be_bytes());
    bytes.extend_from_slice(&[0u8; DIGEST_LENGTH]);
    detached_block.encode(&mut bytes).unwrap();
    detached_txs.encode(&mut bytes).unwrap();

    Ok((bytes.to_vec(), detached_block_size))
}

#[cfg(feature = "receipts")]
pub fn serialize_proto_block_prefilled(mut block: ProtoBlock, merkle_root: &HashType) -> Vec<u8> {
    //
    // Serialized format: signature || block_size || parent_hash || block || txs
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
        tx_list: unwrap_and_take_tx_list(&mut block)
    };
    block.sig = None;
    block.payload = Some(proto_block::Payload::MerkleRoot(merkle_root.to_vec()));

    let parent = block.parent;
    block.parent = Vec::new();
    bytes.extend_from_slice(&block.encoded_len().to_be_bytes());
    bytes.extend_from_slice(&parent);
    
    block.parent.clear();

    block.encode(&mut bytes).unwrap();
    detached_txs.encode(&mut bytes).unwrap();

    bytes.to_vec()
}

#[cfg(feature = "receipts")]
pub fn get_block_size_from_ser(data: &[u8]) -> usize {
    return usize::from_be_bytes(data[SIGNATURE_LENGTH..SIGNATURE_LENGTH + USIZE_LENGTH].try_into().unwrap());
}

#[cfg(feature = "receipts")]
pub fn deserialize_proto_block(bytes: &[u8]) -> Result<ProtoBlock, DecodeError> {
    if bytes.len() < DIGEST_LENGTH + SIGNATURE_LENGTH {
        return Err(DecodeError::new("Invalid block length"));
    }
    
    let block_size = get_block_size_from_ser(bytes);
    let mut block = ProtoBlock::decode(&bytes[BLOCK_OFFSET..BLOCK_OFFSET + block_size]).unwrap();
    let txs = ProtoTransactionList::decode(&bytes[BLOCK_OFFSET + block_size..]).unwrap();

    block.parent = bytes[PARENT_OFFSET..PARENT_OFFSET + DIGEST_LENGTH].to_vec();
    block.payload = Some(proto_block::Payload::TxList(txs));

    let sig = &bytes[..SIGNATURE_LENGTH];
    let sig_is_null = sig.iter().all(|&x| x == 0);
    if sig_is_null {
        block.sig = Some(proto_block::Sig::NoSig(DefferedSignature{}));
    } else {
        block.sig = Some(proto_block::Sig::ProposerSig(sig.to_vec()));
    }

    Ok(block)
}

#[cfg(not(feature = "receipts"))]
pub fn serialize_proto_block_nascent(block: &ProtoBlock) -> Result<Vec<u8>, Error> {
    let mut bytes = BytesMut::with_capacity(DIGEST_LENGTH + SIGNATURE_LENGTH + block.encoded_len());
    // Serialized format: signature || parent_hash || block
    bytes.extend_from_slice(&[0u8; SIGNATURE_LENGTH]);
    bytes.extend_from_slice(&[0u8; DIGEST_LENGTH]);
    
    if block.parent.len() != 0
    || (block.sig != None
        && block.sig != Some(crate::proto::consensus::proto_block::Sig::NoSig(DefferedSignature{})))
    {
        return Err(Error::new(ErrorKind::InvalidData, "Invalid new block"));
    }
    
    block.encode(&mut bytes).unwrap();

    Ok(bytes.to_vec())
}

#[cfg(not(feature = "receipts"))]
pub fn serialize_proto_block_prefilled(mut block: ProtoBlock) -> Vec<u8> {
    let mut bytes = BytesMut::with_capacity(DIGEST_LENGTH + SIGNATURE_LENGTH + block.encoded_len());
    // Serialized format: signature || parent_hash || block
 
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

    bytes.extend_from_slice(&block.parent);
    
    block.parent.clear();
    block.sig = None; // Some(crate::proto::consensus::proto_block::Sig::NoSig(DefferedSignature{}));

    block.encode(&mut bytes).unwrap();

    bytes.to_vec()
}

#[cfg(not(feature = "receipts"))]
pub fn deserialize_proto_block(bytes: &[u8]) -> Result<ProtoBlock, DecodeError> {
    if bytes.len() < DIGEST_LENGTH + SIGNATURE_LENGTH {
        return Err(DecodeError::new("Invalid block length"));
    }
    let mut block = ProtoBlock::decode(&bytes[DIGEST_LENGTH+SIGNATURE_LENGTH..]).unwrap();

    block.parent = bytes[SIGNATURE_LENGTH..SIGNATURE_LENGTH+DIGEST_LENGTH].to_vec();

    let sig = &bytes[..SIGNATURE_LENGTH];
    let sig_is_null = sig.iter().all(|&x| x == 0);
    if sig_is_null {
        block.sig = Some(crate::proto::consensus::proto_block::Sig::NoSig(DefferedSignature{}));
    } else {
        block.sig = Some(crate::proto::consensus::proto_block::Sig::ProposerSig(sig.to_vec()));
    }

    Ok(block)
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

#[cfg(test)]
mod test {
    use rand::{thread_rng, Rng};
    use crate::{crypto::hash, proto::{consensus::{proto_block, ProtoBlock, ProtoTransactionList}, execution::{ProtoTransaction, ProtoTransactionOp, ProtoTransactionPhase}}};

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
        block.payload = Some(proto_block::Payload::TxList(ProtoTransactionList { tx_list: tx }));

        #[allow(unused_mut)]
        let mut ser;

        #[cfg(feature = "receipts")] {
            let merkle_tree = crate::crypto::MerkleTree::from_block(&block);
            (ser, _) = super::serialize_proto_block_nascent(&block, &merkle_tree.root()).unwrap();
        }
        #[cfg(not(feature = "receipts"))] {
            ser = super::serialize_proto_block_nascent(&block).unwrap();
        }

        let block2 = super::deserialize_proto_block(&ser).unwrap();

        #[allow(unused_mut)]
        let mut ser2;
        #[cfg(feature = "receipts")] {
            let merkle_tree2 = crate::crypto::MerkleTree::from_block(&block2);
            ser2 = super::serialize_proto_block_prefilled(block2.clone(), &merkle_tree2.root());
        }
        #[cfg(not(feature = "receipts"))] {
            ser2 = super::serialize_proto_block_prefilled(block2.clone());
        }

        assert_eq!(block.n, block2.n);
        assert_eq!(ser.len(), ser2.len());

        let hsh1 = hash(ser.as_slice());
        let hsh2 = hash(ser2.as_slice());

        assert_eq!(hsh1, hsh2);
    }
}