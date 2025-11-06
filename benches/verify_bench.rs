use criterion::{criterion_group, criterion_main, Criterion};
use ed25519_dalek::{Signature, SigningKey, SECRET_KEY_LENGTH};
use pft::crypto::KeyStore;
use rand::prelude::*;

fn __bench_verify(data: &Vec<u8>, sig: &Signature, keys: &KeyStore) -> bool {
    keys.priv_key.verify(&data, sig).is_ok()
}

fn criterion_benchmark(c: &mut Criterion) {
    let sizes = [2, 16, 64, 256, 1024, 4096];
    let mut data = Vec::new();
    let mut rng = thread_rng();
    for sz in sizes {
        let mut v = vec![0u8; sz];
        rng.fill_bytes(&mut v);
        data.push(v);
    }

    let mut keys = KeyStore::empty();
    let mut key_buff = [0u8; SECRET_KEY_LENGTH];
    rng.fill_bytes(&mut key_buff);
    keys.priv_key = SigningKey::from_bytes(&key_buff);

    let mut sigs = Vec::new();
    for buff in &data {
        let sig: Signature = keys.sign(buff.as_slice()).into();
        sigs.push(sig);
    }

    let mut bad_sigs = Vec::<Signature>::new();
    for sig in &sigs {
        let mut bad_sig = sig.clone().to_bytes();
        bad_sig[2] = !bad_sig[2];
        bad_sig[10] = !bad_sig[2];
        bad_sig[15] = !bad_sig[15];
        bad_sigs.push(bad_sig.into());
    }

    let mut group = c.benchmark_group("verify");

    for i in 0..sizes.len() {
        group.bench_function(format!("verify {} good", sizes[i]), |b| {
            b.iter(|| __bench_verify(&data[i], &sigs[i], &keys))
        });
        group.bench_function(format!("verify {} bad", sizes[i]), |b| {
            b.iter(|| __bench_verify(&data[i], &bad_sigs[i], &keys))
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
