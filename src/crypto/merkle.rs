use bytes::BytesMut;
use prost::Message;

use crate::{
    crypto::{default_hash, hash, HashType, Sha},
    proto::consensus::ProtoBlock,
};

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
            let mut next_level = Vec::with_capacity(level_size / 2);
            let mut i = 0;
            while i < level_size {
                let mut hasher = Sha::new();
                hasher.update(&tree[level_start + i]);
                hasher.update(&tree[level_start + i + 1]);
                next_level.push(hasher.finalize().to_vec());
                i += 2;
            }
            tree.extend(next_level.iter().cloned());
            level_start += level_size;
            level_size = next_level.len();
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
        let mut leaves = Vec::with_capacity(block.tx_list.len());
        for tx in &block.tx_list {
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

        MerkleInclusionProof(proof)
    }

    pub fn root(&self) -> &HashType {
        &self.root
    }

    pub fn leaves(&self) -> &[HashType] {
        &self.tree[..self.n_leaves]
    }
}

#[test]
fn test_merkle_tree_proof() {
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
