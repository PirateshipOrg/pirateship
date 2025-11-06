use std::io::{Error, ErrorKind};

use bytes::BytesMut;
use ed25519_dalek::SIGNATURE_LENGTH;
use prost::{DecodeError, EncodeError, Message};

use crate::{
    crypto::{HashType, DIGEST_LENGTH},
    proto::consensus::{DefferedSignature, ProtoBlock},
};

pub fn serialize_proto_block_nascent(block: &ProtoBlock) -> Result<Vec<u8>, Error> {
    let mut bytes = BytesMut::with_capacity(DIGEST_LENGTH + SIGNATURE_LENGTH + block.encoded_len());
    // Serialized format: signature || parent_hash || block
    bytes.extend_from_slice(&[0u8; SIGNATURE_LENGTH]);
    bytes.extend_from_slice(&[0u8; DIGEST_LENGTH]);

    if block.parent.len() != 0
        || (block.sig != None
            && block.sig
                != Some(crate::proto::consensus::proto_block::Sig::NoSig(
                    DefferedSignature {},
                )))
    {
        return Err(Error::new(ErrorKind::InvalidData, "Invalid new block"));
    }

    // block.parent.clear();
    // block.sig = Some(crate::proto::consensus::proto_block::Sig::NoSig(DefferedSignature{}));

    block.encode(&mut bytes).unwrap();
    // bytes.extend_from_slice(&bitcode::encode(block));

    Ok(bytes.to_vec())
}

pub fn serialize_proto_block_prefilled(mut block: ProtoBlock) -> Vec<u8> {
    let mut bytes = BytesMut::with_capacity(DIGEST_LENGTH + SIGNATURE_LENGTH + block.encoded_len());
    // Serialized format: signature || parent_hash || block

    match &block.sig {
        Some(crate::proto::consensus::proto_block::Sig::ProposerSig(sig)) => {
            bytes.extend_from_slice(sig);
        }
        Some(crate::proto::consensus::proto_block::Sig::NoSig(_)) => {
            bytes.extend_from_slice(&[0u8; SIGNATURE_LENGTH]);
        }
        None => {
            bytes.extend_from_slice(&[0u8; SIGNATURE_LENGTH]);
        }
    }

    bytes.extend_from_slice(&block.parent);

    block.parent.clear();
    block.sig = None; // Some(crate::proto::consensus::proto_block::Sig::NoSig(DefferedSignature{}));

    block.encode(&mut bytes).unwrap();
    // bytes.extend_from_slice(&bitcode::encode(block));

    bytes.to_vec()
}

pub fn update_parent_hash_in_proto_block_ser(block: &mut Vec<u8>, parent_hash: &HashType) {
    block[SIGNATURE_LENGTH..SIGNATURE_LENGTH + DIGEST_LENGTH].copy_from_slice(parent_hash);
}

pub fn get_parent_hash_in_proto_block_ser(block: &Vec<u8>) -> Option<HashType> {
    if block.len() < DIGEST_LENGTH + SIGNATURE_LENGTH {
        return None;
    }
    Some(block[SIGNATURE_LENGTH..SIGNATURE_LENGTH + DIGEST_LENGTH].to_vec())
}

pub fn update_signature_in_proto_block_ser(
    block: &mut Vec<u8>,
    signature: &[u8; SIGNATURE_LENGTH],
) {
    block[..SIGNATURE_LENGTH].copy_from_slice(signature);
}

pub fn deserialize_proto_block(bytes: &[u8]) -> Result<ProtoBlock, DecodeError> {
    if bytes.len() < DIGEST_LENGTH + SIGNATURE_LENGTH {
        return Err(DecodeError::new("Invalid block length"));
    }

    // let mut block = ProtoBlock::default();

    // block.merge(&bytes[DIGEST_LENGTH+SIGNATURE_LENGTH..])?;
    let mut block = ProtoBlock::decode(&bytes[DIGEST_LENGTH + SIGNATURE_LENGTH..]).unwrap();

    block.parent = bytes[SIGNATURE_LENGTH..SIGNATURE_LENGTH + DIGEST_LENGTH].to_vec();

    let sig = &bytes[..SIGNATURE_LENGTH];
    let sig_is_null = sig.iter().all(|&x| x == 0);
    if sig_is_null {
        block.sig = Some(crate::proto::consensus::proto_block::Sig::NoSig(
            DefferedSignature {},
        ));
    } else {
        block.sig = Some(crate::proto::consensus::proto_block::Sig::ProposerSig(
            sig.to_vec(),
        ));
    }

    Ok(block)
}

#[cfg(test)]
mod test {
    use rand::{thread_rng, Rng};

    use crate::{
        crypto::hash,
        proto::{
            consensus::ProtoBlock,
            execution::{ProtoTransaction, ProtoTransactionOp, ProtoTransactionPhase},
        },
    };

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

        let ser = super::serialize_proto_block_nascent(&block).unwrap();

        let block2 = super::deserialize_proto_block(&ser).unwrap();

        assert_eq!(block.n, block2.n);

        let ser2 = super::serialize_proto_block_prefilled(block2);
        println!("Serialized sizes: {} {}", ser.len(), ser2.len());

        let hsh1 = hash(ser.as_slice());
        let hsh2 = hash(ser2.as_slice());

        assert_eq!(hsh1, hsh2);
    }
}
