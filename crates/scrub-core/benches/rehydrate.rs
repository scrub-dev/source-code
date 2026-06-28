//! Hot-path benchmarks (DESIGN §4): mask throughput and streaming rehydration,
//! including the worst case of single-byte chunks.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use scrub_core::config::Config;
use scrub_core::detect::Detector;
use scrub_core::mask::{mask, MaskStyle};
use scrub_core::rehydrate::Rehydrator;
use scrub_core::vault::Vault;

fn detector() -> Detector {
    let cfg = Config::from_yaml(
        r#"
glossary:
  - { term: "Project Hufflepuff", type: CODENAME, priority: 100 }
rules:
  - { name: email, type: EMAIL, pattern: '[\w.]+@[\w.]+', priority: 50 }
"#,
    )
    .unwrap();
    Detector::from_config(&cfg).unwrap()
}

/// ~1 KiB of realistic prompt text with a handful of maskable spans.
fn corpus() -> Vec<u8> {
    let unit = "Hi, please email john@acme.com and jane.doe@example.org about \
                Project Hufflepuff. Repeat: john@acme.com. ";
    unit.repeat(8).into_bytes()
}

/// A detector with many regex rules — exercises the single-pass meta engine.
fn many_rule_detector() -> Detector {
    let mut yaml = String::from("rules:\n");
    yaml.push_str("  - { name: email, type: EMAIL, pattern: '[\\w.]+@[\\w.]+', priority: 50 }\n");
    // 24 distinct secret-key-shaped patterns.
    for i in 0..24 {
        yaml.push_str(&format!(
            "  - {{ name: k{i}, type: SECRET, pattern: 'K{i:02}[0-9A-Za-z]{{12}}', priority: 80 }}\n"
        ));
    }
    Detector::from_config(&Config::from_yaml(&yaml).unwrap()).unwrap()
}

fn bench_mask(c: &mut Criterion) {
    let input = corpus();
    let mut g = c.benchmark_group("mask");
    g.throughput(Throughput::Bytes(input.len() as u64));

    let det = detector();
    g.bench_function("egress", |b| {
        b.iter(|| {
            let v = Vault::new();
            black_box(mask(black_box(&input), &det, &v, MaskStyle::TypedSentinel))
        })
    });

    // Cost should be roughly flat vs. the 2-rule case: all rules match in one pass.
    let det_many = many_rule_detector();
    g.bench_function("egress_25_rules", |b| {
        b.iter(|| {
            let v = Vault::new();
            black_box(mask(
                black_box(&input),
                &det_many,
                &v,
                MaskStyle::TypedSentinel,
            ))
        })
    });
    g.finish();
}

fn bench_rehydrate(c: &mut Criterion) {
    let det = detector();
    let input = corpus();
    let v = Vault::new();
    let masked = mask(&input, &det, &v, MaskStyle::TypedSentinel);

    let mut g = c.benchmark_group("rehydrate");
    g.throughput(Throughput::Bytes(masked.len() as u64));

    g.bench_function("one_shot", |b| {
        b.iter(|| {
            let mut r = Rehydrator::new();
            let mut out = r.push(black_box(&masked), &v);
            out.extend_from_slice(&r.finish());
            black_box(out)
        })
    });

    // Worst case for the state machine: every byte is its own chunk.
    g.bench_function("byte_chunks", |b| {
        b.iter(|| {
            let mut r = Rehydrator::new();
            let mut out = Vec::new();
            for byte in &masked {
                out.extend_from_slice(&r.push(std::slice::from_ref(byte), &v));
            }
            out.extend_from_slice(&r.finish());
            black_box(out)
        })
    });

    g.finish();
}

criterion_group!(benches, bench_mask, bench_rehydrate);
criterion_main!(benches);
