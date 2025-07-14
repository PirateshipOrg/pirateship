use criterion::{criterion_group, criterion_main, Criterion};
use rand::Rng;
use pft::crypto::merkle::MerkleTree;

fn criterion_benchmark(c: &mut Criterion) {
    let num_leaves = 1337;
    let mut data = Vec::with_capacity(num_leaves);
    let mut rng = rand::thread_rng();
    for _ in 0..num_leaves {
        let leaf: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        data.push(leaf);
    }
    let tree = MerkleTree::new(data.clone());
    let mut group = c.benchmark_group("merkle_proof");

    group.bench_function("generate_all_inclusion_proofs", |b| {
        b.iter(|| {
            let _proofs = tree.generate_all_inclusion_proofs();
        })
    });

    group.bench_function("generate_inclusion_proof", |b| {
        b.iter(|| {
            for index in 0..data.len() {
                let _proof = tree.generate_inclusion_proof(index);
            }
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
