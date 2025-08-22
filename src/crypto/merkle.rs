use bytes::BytesMut;
use prost::Message;

use crate::{
    crypto::{default_hash, hash, HashType, Sha},
    proto::consensus::ProtoBlock, utils::unwrap_tx_list,
};

#[allow(unused_imports)]
use sha2::{Digest, Sha256, Sha512};

#[derive(Clone, Debug)]
pub struct MerkleInclusionProof(Vec<HashType>);

impl MerkleInclusionProof {
    pub fn validate(self, leaf: &HashType, index: usize, root: &HashType) -> bool {
        let mut current_hash = leaf.clone();
        let mut index = index;
        for sibling in self.0.iter() {
            let mut hasher = Sha::new();
            if index % 2 == 0 {
                hasher.update(&current_hash);
                hasher.update(&sibling);
            } else {
                hasher.update(&sibling);
                hasher.update(&current_hash);
            }
            current_hash = hasher.finalize().to_vec();
            index /= 2;
        }
        current_hash == *root
    }

    pub fn as_vec(self) -> Vec<HashType> {
        self.0
    }

    pub fn default() -> Self {
        MerkleInclusionProof(vec![])
    }

    pub fn new(proof: Vec<HashType>) -> Self {
        MerkleInclusionProof(proof)
    }
}

#[derive(Clone, Debug)]
pub struct MerkleTree {
    root: HashType,
    tree: Vec<HashType>,
    n_leaves: usize,
    n_padded_leaves: usize,
}

impl MerkleTree {
    pub fn new(leaves: Vec<HashType>) -> Self {
        let n_leaves = leaves.len();
        let n_padded_leaves = n_leaves.next_power_of_two();
        let mut padded_leaves = leaves;
        if n_leaves < n_padded_leaves {
            padded_leaves
                .extend(std::iter::repeat(default_hash()).take(n_padded_leaves - n_leaves));
        }
        let mut tree = Vec::with_capacity(padded_leaves.len() * 2); // upper bound
        tree.extend(padded_leaves.iter().cloned());

        let mut level_start = 0;
        let mut level_size = padded_leaves.len();

        while level_size > 1 {
            let mut current_level_size = 0;
            let mut i = 0;
            while i < level_size {
                let mut hasher = Sha::new();
                hasher.update(&tree[level_start + i]);
                hasher.update(&tree[level_start + i + 1]);
                tree.push(hasher.finalize().to_vec());
                i += 2;
                current_level_size += 1;
            }
            level_start += level_size;
            level_size = current_level_size;
        }

        let root = tree.last().cloned().unwrap_or(default_hash());

        Self {
            root,
            tree,
            n_leaves,
            n_padded_leaves,
        }
    }

    pub fn from_block(block: &ProtoBlock) -> Self {
        let tx_list = unwrap_tx_list(block);
        let mut leaves = Vec::with_capacity(tx_list.len());
        for tx in tx_list {
            let mut buf = BytesMut::with_capacity(tx.encoded_len());
            tx.encode(&mut buf).unwrap();
            leaves.push(hash(&buf));
        }

        MerkleTree::new(leaves)
    }

    pub fn generate_inclusion_proof(&self, block_n: usize) -> MerkleInclusionProof {
        assert!(block_n < self.n_leaves, "block_n out of bounds {} {}", block_n, self.n_leaves);
        let mut proof = Vec::new();

        let mut current_index = block_n;
        let mut level_start = 0;
        let mut level_size = self.n_padded_leaves;

        while level_size > 1 {
            let sibling_index = if current_index % 2 == 0 {
                Some(current_index + 1)
            } else {
                Some(current_index - 1)
            };
            if let Some(sib_idx) = sibling_index {
                if sib_idx < level_size {
                    proof.push(self.tree[level_start + sib_idx].clone());
                }
            }
            current_index /= 2;
            level_start += level_size;
            level_size /= 2;
        }

        MerkleInclusionProof::new(proof)
    }

    /// benchmarks show that this is actually slightly slower than calling `generate_inclusion_proof` N times... left it for future reference
    pub fn generate_all_inclusion_proofs(&self) -> Vec<MerkleInclusionProof> {
        let mut proofs: Vec<Vec<HashType>> = vec![vec![]; self.n_leaves];
        
        let h = (self.n_padded_leaves as f64).log2() as usize;
        let mut level_start = 0;
        let mut level_size = self.n_padded_leaves;
        
        for level in 0..h {
            for i in 0..level_size {
            let sibling_index = i ^ 1; // Flip last bit to get sibling
            if sibling_index < level_size {
                let sibling_hash = &self.tree[level_start + sibling_index];
                
                // Determine which leaf indices this node contributes to
                let group_size = 1 << level;
                let base_leaf_index = (i / 2) * group_size * 2;
                
                for offset in 0..group_size {
                    let leaf_index = base_leaf_index + offset + (i % 2) * group_size;
                    if leaf_index < self.n_leaves {
                        proofs[leaf_index].push(sibling_hash.clone());
                    }
                }
            }
            }
            level_start += level_size;
            level_size /= 2;
        }
        
        proofs.into_iter().map(|proof| MerkleInclusionProof::new(proof)).collect()
    }

    pub fn root(&self) -> &HashType {
        &self.root
    }

    pub fn leaves(&self) -> &[HashType] {
        &self.tree[..self.n_leaves]
    }

    pub fn n_leaves(&self) -> usize {
        self.n_leaves
    }
}

#[test]
fn test_merkle_tree_generate_inclusion_proof() {
    let num_leaves = 1337;
    let mut data = Vec::with_capacity(num_leaves);
    let mut rng = rand::thread_rng();

    for _ in 0..num_leaves {
        let leaf: Vec<u8> = (0..32).map(|_| rand::Rng::gen(&mut rng)).collect();
        data.push(leaf);
    }

    let tree = MerkleTree::new(data.clone());

    for (index, leaf) in data.iter().enumerate() {
        let proof = tree.generate_inclusion_proof(index);
        assert!(
            proof.validate(leaf, index, &tree.root()),
            "Proof should verify for leaf at index {}",
            index
        );
    }
}


#[test]
fn test_merkle_tree_generate_all_inclusion_proofs() {
    let num_leaves = 1337;
    let mut data = Vec::with_capacity(num_leaves);
    let mut rng = rand::thread_rng();

    for _ in 0..num_leaves {
        let leaf: Vec<u8> = (0..32).map(|_| rand::Rng::gen(&mut rng)).collect();
        data.push(leaf);
    }

    let tree = MerkleTree::new(data.clone());
    let proofs = tree.generate_all_inclusion_proofs();

    for (index, (leaf, proof)) in data.iter().zip(proofs).enumerate() {
        assert!(
            proof.validate(leaf, index, &tree.root()),
            "Proof should verify for leaf at index {}",
            index
        );
    }
}