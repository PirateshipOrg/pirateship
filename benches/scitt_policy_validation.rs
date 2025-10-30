use criterion::{criterion_group, criterion_main, Criterion};

#[cfg(feature = "policy_validation")]
static POLICY: &str = include_str!("assets/policy.js");
#[cfg(feature = "policy_validation")]
static COSE_CLAIM: &[u8] = include_bytes!("assets/claim.cose");

fn criterion_benchmark(c: &mut Criterion) {
    #[cfg(feature = "policy_validation")] {
        c.bench_function("policy_validation", |b| {
            let runtime = rquickjs::Runtime::new().unwrap();
            let policy = POLICY.as_bytes();
            let headers = scitt_cose::validate_scitt_cose_signed_statement(COSE_CLAIM)
                .expect("Failed to parse COSE claim");
            let phdr = headers.phdr;
            b.iter(|| {
                let _ = pft::consensus::engines::scitt::apply_policy_to_claim(&runtime, policy, &phdr);
            })
        });

        let runtime = rquickjs::Runtime::new().unwrap();
        let policy = POLICY.as_bytes();
        let headers = scitt_cose::validate_scitt_cose_signed_statement(COSE_CLAIM)
            .expect("Failed to parse COSE claim");
        let phdr = headers.phdr;
        let guard = pprof::ProfilerGuard::new(100).unwrap();
        for _ in 0..10000 {
            let _ = pft::consensus::engines::scitt::apply_policy_to_claim(&runtime, policy, &phdr);
        }
        if let Ok(report) = guard.report().build() {
            let file = std::fs::File::create("benches/profiling/policy_validation.svg").unwrap();
            report.flamegraph(file).unwrap();
        }
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
