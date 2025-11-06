// use pft::crypto::KeyStore;
// use ed25519_dalek::{SigningKey, SECRET_KEY_LENGTH, SIGNATURE_LENGTH};
// use criterion::{criterion_group, criterion_main, Criterion};
// use rand::prelude::*;

// fn __bench_sign(data: &Vec<u8>, keys: &KeyStore) -> [u8; SIGNATURE_LENGTH] {
//     keys.sign(data.as_slice())
// }

// fn criterion_benchmark(c: &mut Criterion) {
//     let sizes = [2, 16, 64, 256, 1024, 4096];
//     let mut data = Vec::new();
//     let mut rng = thread_rng();
//     for sz in sizes {
//         let mut v = vec![0u8; sz];
//         rng.fill_bytes(&mut v);
//         data.push(v);
//     }

//     let mut keys = KeyStore::empty();
//     let mut key_buff = [0u8; SECRET_KEY_LENGTH];
//     rng.fill_bytes(&mut key_buff);
//     keys.priv_key = SigningKey::from_bytes(&key_buff);

//     let mut group = c.benchmark_group("sign");

//     for i in 0..sizes.len() {
//         group.bench_function(format!("sign {}", sizes[i]), |b| b.iter(|| __bench_sign(&data[i], &keys)));
//     }
// }

// criterion_group!(benches, criterion_benchmark);
// criterion_main!(benches);
