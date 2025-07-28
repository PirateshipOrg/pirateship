use criterion::{criterion_group, criterion_main, Criterion};

static COSE_CLAIM: &[u8] = include_bytes!("assets/claim.cose");

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("validate_scitt_cose_signed_statement", |b| {
        b.iter(|| {
            let _ = scitt_cose::validate_scitt_cose_signed_statement(COSE_CLAIM);
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
