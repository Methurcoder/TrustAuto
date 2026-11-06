//! Measures the latency and size targets with the embedded model and a facts
//! snapshot: a lab machine's files by default, or a live snapshot.
//!
//!   trustauto-bench [FACTS_JSON [USAGE_JSON]]

use std::time::{Duration, Instant};
use trustauto::engine::{decide, Scorer};
use trustauto::facts::{Machine, Snapshot};
use trustauto::index::Index;
use trustauto::policy::{Mode, Policy};
use trustauto::request::{Context, Request};
use trustauto::risk::{embedded_model, Risk};

const POLICY: &str = include_str!("../../config/policy.toml");
const LAB: &str = "ml/truth/experiment_5/round4_evaluation/reproduction/data";

fn measure(rounds: usize, mut f: impl FnMut()) -> (Duration, Duration) {
    let mut samples = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let start = Instant::now();
        f();
        samples.push(start.elapsed());
    }
    samples.sort();
    (samples[rounds / 2], samples[rounds * 99 / 100])
}

fn show(name: &str, target_us: u128, (p50, p99): (Duration, Duration)) {
    let verdict = if p99.as_micros() < target_us { "ok" } else { "MISSED" };
    println!(
        "{name:<38} p50 {:>9.2} us   p99 {:>9.2} us   target < {target_us} us   {verdict}",
        p50.as_secs_f64() * 1e6,
        p99.as_secs_f64() * 1e6,
    );
}

fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let snapshot_text = match args.as_slice() {
        [facts, usage] => (read(facts), Some(read(usage))),
        [snapshot] => (read(snapshot), None),
        _ => (read(&format!("{LAB}/facts_deb137.json")), Some(read(&format!("{LAB}/usage_deb137.json")))),
    };
    let load = || match &snapshot_text {
        (facts, Some(usage)) => Snapshot::from_lab(facts, usage).expect("snapshot"),
        (snapshot, None) => Snapshot::parse(snapshot).expect("snapshot"),
    };
    let mut policy = Policy::parse(POLICY).expect("sample policy");
    // Decisions read the index trustauto-facts builds from the snapshot.
    let index_text = serde_json::to_string(&Index::build(&Machine::new(&load()), 0)).expect("index");
    let read_index = || Risk::from_index(embedded_model().expect("model"), Index::parse(&index_text).expect("index"));
    let risk = read_index();

    let hit = Request {
        bin: "/usr/bin/systemctl".to_string(),
        args: vec!["restart".to_string(), "cron".to_string()],
        ctx: Context::quiet(),
    };
    let package = Request {
        bin: "/usr/bin/apt".to_string(),
        args: vec!["purge".to_string(), "openssh-server".to_string()],
        ctx: Context::quiet(),
    };
    let miss = Request {
        bin: "/usr/bin/unknown-tool".to_string(),
        args: (0..20).map(|i| format!("--flag-{i}=value")).collect(),
        ctx: Context::quiet(),
    };

    println!("rules: {}, snapshot: {} KiB, index: {} KiB", policy.rules.len(), snapshot_text.0.len() / 1024, index_text.len() / 1024);
    policy.mode = Mode::Rule;
    show("rule: matching request", 100, measure(20_000, || {
        std::hint::black_box(decide(&policy, None, &hit));
    }));
    show("rule: no match, 20 arguments", 100, measure(20_000, || {
        std::hint::black_box(decide(&policy, None, &miss));
    }));
    show("model: unit features + score", 10_000, measure(200, || {
        std::hint::black_box(risk.score(&hit));
    }));
    show("model: package features + score", 10_000, measure(200, || {
        std::hint::black_box(risk.score(&package));
    }));
    policy.mode = Mode::Hybrid;
    show("hybrid: decision", 10_000, measure(200, || {
        std::hint::black_box(decide(&policy, Some(&risk as &dyn Scorer), &hit));
    }));
    show("model parse (per invocation)", 10_000, measure(50, || {
        std::hint::black_box(embedded_model().expect("model"));
    }));
    let (p50, p99) = measure(20, || {
        std::hint::black_box(read_index());
    });
    println!(
        "{:<38} p50 {:>9.2} us   p99 {:>9.2} us   (model + index parse, per invocation)",
        "facts load",
        p50.as_secs_f64() * 1e6,
        p99.as_secs_f64() * 1e6,
    );
}
