/// Module for shared behavior between blocks and tipcuts in consensus layer.
/// Essentially just an enum wrapper around CachedBlock and CachedTipCut.
use crate::{
    crypto::CachedBlock,
    proto::consensus::{ProtoForkValidation, ProtoQuorumCertificate, ProtoTipCutValidation},
};

#[cfg(feature = "dag")]
use crate::crypto::CachedTipCut;

#[derive(Clone, Debug)]
pub enum BlockOrTipCut {
    Block(CachedBlock),
    #[cfg(feature = "dag")]
    TipCut(CachedTipCut),
}

impl BlockOrTipCut {
    /// Returns true if this is a block, false if tip cut
    pub fn is_block(&self) -> bool {
        match &self {
            BlockOrTipCut::Block(_) => true,
            #[cfg(feature = "dag")]
            BlockOrTipCut::TipCut(_) => false,
        }
    }

    /// Returns true if this is a tip cut, false if block
    pub fn is_tipcut(&self) -> bool {
        match &self {
            BlockOrTipCut::Block(_) => false,
            #[cfg(feature = "dag")]
            BlockOrTipCut::TipCut(_) => true,
        }
    }

    /// Returns the block number / tip cut number
    pub fn n(&self) -> u64 {
        match &self {
            BlockOrTipCut::Block(block) => block.block.n,
            #[cfg(feature = "dag")]
            BlockOrTipCut::TipCut(tc) => tc.tipcut.n,
        }
    }

    /// Returns the parent hash of the block or tip cut
    pub fn parent(&self) -> Vec<u8> {
        match &self {
            BlockOrTipCut::Block(block) => block.block.parent.clone(),
            #[cfg(feature = "dag")]
            BlockOrTipCut::TipCut(tc) => tc.tipcut.parent.clone(),
        }
    }

    /// Returns the view number of the block or tip cut
    pub fn view(&self) -> u64 {
        match &self {
            BlockOrTipCut::Block(block) => block.block.view,
            #[cfg(feature = "dag")]
            BlockOrTipCut::TipCut(tc) => tc.tipcut.view,
        }
    }

    /// Returns whether the view is stable for the block or tip cut
    pub fn view_is_stable(&self) -> bool {
        match &self {
            BlockOrTipCut::Block(block) => block.block.view_is_stable,
            #[cfg(feature = "dag")]
            BlockOrTipCut::TipCut(tc) => tc.tipcut.view_is_stable,
        }
    }

    /// Returns the config number of the block or tip cut
    pub fn config_num(&self) -> u64 {
        match &self {
            BlockOrTipCut::Block(block) => block.block.config_num,
            #[cfg(feature = "dag")]
            BlockOrTipCut::TipCut(tc) => tc.tipcut.config_num,
        }
    }

    /// Returns the quorum certificates of the block or tip cut
    pub fn qc(&self) -> Vec<ProtoQuorumCertificate> {
        match &self {
            BlockOrTipCut::Block(block) => block.block.qc.clone(),
            #[cfg(feature = "dag")]
            BlockOrTipCut::TipCut(tc) => tc.tipcut.qc.clone(),
        }
    }

    /// Returns the fork validations of the block
    #[cfg(not(feature = "dag"))]
    pub fn validation(&self) -> Vec<ProtoForkValidation> {
        match &self {
            BlockOrTipCut::Block(block) => block.block.fork_validation.clone(),
            _ => vec![],
        }
    }

    /// Returns the tip cut validations of the tip cut
    #[cfg(feature = "dag")]
    pub fn validation(&self) -> Vec<ProtoTipCutValidation> {
        match &self {
            BlockOrTipCut::Block(_) => vec![],
            BlockOrTipCut::TipCut(tc) => tc.tipcut.tc_validation.clone(),
        }
    }

    /// Returns the proposer signature of the block or tip cut, if any
    pub fn sig(&self) -> Option<&Vec<u8>> {
        match &self {
            BlockOrTipCut::Block(block) => match &block.block.sig {
                Some(crate::proto::consensus::proto_block::Sig::ProposerSig(sig)) => Some(sig),
                _ => None,
            },
            #[cfg(feature = "dag")]
            BlockOrTipCut::TipCut(tc) => match &tc.tipcut.sig {
                Some(crate::proto::consensus::proto_tip_cut::Sig::ProposerSig(sig)) => Some(sig),
                _ => None,
            },
        }
    }

    /// Returns the serialized bytes of the block or tip cut
    pub fn ser(&self) -> Vec<u8> {
        match &self {
            BlockOrTipCut::Block(block) => block.block_ser.clone(),
            #[cfg(feature = "dag")]
            BlockOrTipCut::TipCut(tc) => tc.tipcut_ser.clone(),
        }
    }

    /// Returns the digest (hash) of the block or tip cut
    pub fn digest(&self) -> Vec<u8> {
        match &self {
            BlockOrTipCut::Block(block) => block.block_hash.clone(),
            #[cfg(feature = "dag")]
            BlockOrTipCut::TipCut(tc) => tc.tipcut_hash.clone(),
        }
    }
}
