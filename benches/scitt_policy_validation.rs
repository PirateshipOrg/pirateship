use criterion::{criterion_group, criterion_main, Criterion};

static POLICY: &str = include_str!("assets/policy.js");
static COSE_CLAIM: &[u8] = include_bytes!("assets/claim.cose");

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("policy_validation", |b| {
        let runtime = rquickjs::Runtime::new().unwrap();
        let policy = POLICY.as_bytes();
        let headers = scitt_cose::validate_scitt_cose_signed_statement(COSE_CLAIM)
            .expect("Failed to parse COSE claim");
        let phdr = headers.phdr;
        b.iter(|| {
            pft::consensus::engines::scitt::apply_policy_to_claim(&runtime, policy, &phdr);
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
