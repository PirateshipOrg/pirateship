use bytes::BytesMut;
use prost::Message;

use crate::{
    crypto::{default_hash, hash, HashType, Sha},
    proto::consensus::ProtoBlock, utils::unwrap_tx_list,
};

#[allow(unused_imports)]
use sha2::{Digest, Sha256, Sha512};

#[derive(Clone, Debug)]
pub struct MerkleInclusionProof(Vec<HashType>, usize);

impl MerkleInclusionProof {
    pub fn validate(self, leaf: &HashType, mut index: usize, root: &HashType) -> bool {
        let mut current_hash = leaf.clone();
        let mut level_size = self.1;
        let mut proof_iter = self.0.iter();
        while level_size > 1 {
            if index % 2 != 0 || index + 1 < level_size { // has sibling
                let sibling = match proof_iter.next() {
                    Some(s) => s,
                    None => return false,
                };
                let mut hasher = Sha::new();
                if index % 2 == 0 {
                    hasher.update(&current_hash);
                    hasher.update(sibling);
                } else {
                    hasher.update(sibling);
                    hasher.update(&current_hash);
                }
                current_hash = hasher.finalize().to_vec();
            }
            index /= 2;
            level_size = level_size / 2 + (level_size % 2);
        }
        current_hash == *root
    }

    pub fn as_vec(self) -> Vec<HashType> {
        self.0
    }

    pub fn k(&self) -> usize {
        self.1
    }

    pub fn default() -> Self {
        MerkleInclusionProof(vec![], 0)
    }

    pub fn new(proof: Vec<HashType>, k: usize) -> Self {
        MerkleInclusionProof(proof, k)
    }
}

#[derive(Clone, Debug)]
pub struct MerkleTree {
    root: HashType,
    tree: Vec<HashType>,
    n_leaves: usize,
}

impl MerkleTree {
    pub fn new(leaves: Vec<HashType>) -> Self {
        let n_leaves = leaves.len();
        let mut tree = Vec::with_capacity(n_leaves * 2); // upper bound
        tree.extend(leaves.iter().cloned());
    
        let mut level_start = 0;
        let mut level_size = n_leaves;
    
        while level_size > 1 {
            let mut current_level_size = 0;
            let mut i = 0;
            while i + 1 < level_size {
                let mut hasher = Sha::new();
                hasher.update(&tree[level_start + i]);
                hasher.update(&tree[level_start + i + 1]);
                tree.push(hasher.finalize().to_vec());
                i += 2;
                current_level_size += 1;
            }
    
            // push overhang up the tree
            if i < level_size {
                tree.push(tree[level_start + i].clone());
                current_level_size += 1;
            }
    
            level_start += level_size;
            level_size = current_level_size;
        }
    
        let root = tree.last().cloned().unwrap_or_else(default_hash);
    
        Self {
            root,
            tree,
            n_leaves,
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
        let mut level_size = self.n_leaves;

        while level_size > 1 {
            let sibling_index = if current_index % 2 == 0 {
                if current_index + 1 < level_size {
                    Some(current_index + 1)
                } else {
                    None
                }
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
            level_size = level_size / 2 + (level_size % 2);
        }
    
        MerkleInclusionProof::new(proof, self.n_leaves)
    }

    /// benchmarks show that this is actually slightly slower than calling `generate_inclusion_proof` N times... left it for future reference
    pub fn generate_all_inclusion_proofs(&self) -> Vec<MerkleInclusionProof> {
        let mut proofs: Vec<Vec<HashType>> = vec![vec![]; self.n_leaves];
    
        let mut level_start = 0;
        let mut level_size = self.n_leaves;
        let mut index_map: Vec<Vec<usize>> = (0..self.n_leaves).map(|i| vec![i]).collect();
    
        while level_size > 1 {
            let mut next_index_map = Vec::new();
            let mut i = 0;
    
            while i + 1 < level_size {
                let left_idx = i;
                let right_idx = i + 1;
    
                let left_leaves = &index_map[left_idx];
                let right_leaves = &index_map[right_idx];
    
                for &leaf_idx in left_leaves {
                    proofs[leaf_idx].push(self.tree[level_start + right_idx].clone());
                }
                for &leaf_idx in right_leaves {
                    proofs[leaf_idx].push(self.tree[level_start + left_idx].clone());
                }
    
                let mut combined = left_leaves.clone();
                combined.extend(right_leaves.iter().cloned());
                next_index_map.push(combined);
    
                i += 2;
            }
    
            if i < level_size {
                next_index_map.push(index_map[i].clone());
            }
    
            level_start += level_size;
            level_size = next_index_map.len();
            index_map = next_index_map;
        }
    
        proofs.into_iter().map(|x| MerkleInclusionProof::new(x, self.n_leaves)).collect()
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
