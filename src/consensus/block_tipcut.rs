/// Module for shared behavior between blocks and tipcuts in consensus layer.
///
use crate::{
    crypto::{CachedBlock, CachedTipCut},
    proto::consensus::{ProtoForkValidation, ProtoQuorumCertificate, ProtoTipCutValidation},
};

#[derive(Clone, Debug)]
pub enum BlockOrTipCut {
    Block(CachedBlock),
    #[cfg(feature = "dag")]
    TipCut(CachedTipCut),
}

impl BlockOrTipCut {
    pub fn is_block(&self) -> bool {
        match &self {
            BlockOrTipCut::Block(_) => true,
            #[cfg(feature = "dag")]
            BlockOrTipCut::TipCut(_) => false,
        }
    }

    pub fn is_tipcut(&self) -> bool {
        match &self {
            BlockOrTipCut::Block(_) => false,
            #[cfg(feature = "dag")]
            BlockOrTipCut::TipCut(_) => true,
        }
    }

    pub fn n(&self) -> u64 {
        match &self {
            BlockOrTipCut::Block(block) => block.block.n,
            #[cfg(feature = "dag")]
            BlockOrTipCut::TipCut(tc) => tc.tipcut.n,
        }
    }

    pub fn parent(&self) -> Vec<u8> {
        match &self {
            BlockOrTipCut::Block(block) => block.block.parent.clone(),
            #[cfg(feature = "dag")]
            BlockOrTipCut::TipCut(tc) => tc.tipcut.parent.clone(),
        }
    }

    pub fn view(&self) -> u64 {
        match &self {
            BlockOrTipCut::Block(block) => block.block.view,
            #[cfg(feature = "dag")]
            BlockOrTipCut::TipCut(tc) => tc.tipcut.view,
        }
    }

    pub fn view_is_stable(&self) -> bool {
        match &self {
            BlockOrTipCut::Block(block) => block.block.view_is_stable,
            #[cfg(feature = "dag")]
            BlockOrTipCut::TipCut(tc) => tc.tipcut.view_is_stable,
        }
    }

    pub fn config_num(&self) -> u64 {
        match &self {
            BlockOrTipCut::Block(block) => block.block.config_num,
            #[cfg(feature = "dag")]
            BlockOrTipCut::TipCut(tc) => tc.tipcut.config_num,
        }
    }

    pub fn qc(&self) -> Vec<ProtoQuorumCertificate> {
        match &self {
            BlockOrTipCut::Block(block) => block.block.qc.clone(),
            #[cfg(feature = "dag")]
            BlockOrTipCut::TipCut(tc) => tc.tipcut.qc.clone(),
        }
    }

    #[cfg(not(feature = "dag"))]
    pub fn validation(&self) -> Vec<ProtoForkValidation> {
        match &self {
            BlockOrTipCut::Block(block) => block.block.fork_validation.clone(),
            _ => vec![],
        }
    }

    #[cfg(feature = "dag")]
    pub fn validation(&self) -> Vec<ProtoTipCutValidation> {
        match &self {
            BlockOrTipCut::Block(_) => vec![],
            BlockOrTipCut::TipCut(tc) => tc.tipcut.tc_validation.clone(),
        }
    }

    pub fn ser(&self) -> Vec<u8> {
        match &self {
            BlockOrTipCut::Block(block) => block.block_ser.clone(),
            #[cfg(feature = "dag")]
            BlockOrTipCut::TipCut(tc) => tc.tipcut_ser.clone(),
        }
    }

    pub fn digest(&self) -> Vec<u8> {
        match &self {
            BlockOrTipCut::Block(block) => block.block_hash.clone(),
            #[cfg(feature = "dag")]
            BlockOrTipCut::TipCut(tc) => tc.tipcut_hash.clone(),
        }
    }
}
