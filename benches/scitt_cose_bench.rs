use criterion::{criterion_group, criterion_main, Criterion};

#[cfg(feature = "policy_validation")]
static COSE_CLAIM: &[u8] = include_bytes!("assets/claim.cose");

fn criterion_benchmark(c: &mut Criterion) {

    #[cfg(feature = "policy_validation")] {
        c.bench_function("cose_validation", |b| {
            b.iter(|| {
                let _ = scitt_cose::validate_scitt_cose_signed_statement(COSE_CLAIM);
            })
        });

        let guard = pprof::ProfilerGuard::new(100).unwrap();
        for _ in 0..10000 {
            let _ = scitt_cose::validate_scitt_cose_signed_statement(COSE_CLAIM);
        }
        if let Ok(report) = guard.report().build() {
            let file = std::fs::File::create("benches/profiling/cose_validation.svg").unwrap();
            report.flamegraph(file).unwrap();
        } else {
            eprintln!("Failed to generate flamegraph report");
        }
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
