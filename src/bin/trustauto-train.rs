//! Trains the risk model. Runs anywhere, including macOS: the model file is
//! little-endian and portable, and the output is reproducible for a given seed.
//!
//!   trustauto-train --dataset FILE [--out ml/model.bin] [--eval-only]
//!                   [--test FILE]... [--scores FILE]
//!
//! Dataset: one `label<TAB>command` per line, with label 0 (routine) or 1 (needs
//! a human). `#` starts a comment. Commands are split on whitespace, or on the
//! unit separator (0x1f) when present, which preserves arguments with spaces.
//!
//! With `--test`, those files replace the internal splits. `--scores` prints the
//! score of every command in a file, to see what the model actually gets wrong.

use std::collections::BTreeSet;
use std::process::exit;
use trustauto::ml::{encode, for_each_feature, sigmoid, Model, DIM};
use trustauto::request::basename;

const EPOCHS: usize = 40;
const LEARNING_RATE: f32 = 0.1;
const L2: f32 = 1e-5;
const SEED: u64 = 0x5452_5553_5441_5554;

#[derive(Debug, Clone)]
struct Sample {
    name: String,
    args: Vec<String>,
    label: f32,
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            items.swap(i, (self.next() % (i as u64 + 1)) as usize);
        }
    }
}

fn parse_dataset(text: &str) -> Result<Vec<Sample>, String> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let bad = |why: &str| format!("line {}: {why}", n + 1);
        let (label, command) = line.split_once('\t').ok_or_else(|| bad("missing tab"))?;
        let label = match label {
            "0" => 0.0,
            "1" => 1.0,
            _ => return Err(bad("label must be 0 or 1")),
        };
        let mut words: Box<dyn Iterator<Item = String>> = if command.contains('\x1f') {
            Box::new(command.split('\x1f').map(str::to_string))
        } else {
            Box::new(command.split_whitespace().map(str::to_string))
        };
        let name = words.next().filter(|n| !n.is_empty()).ok_or_else(|| bad("empty command"))?;
        out.push(Sample {
            name,
            args: words.collect(),
            label,
        });
    }
    Ok(out)
}

/// Plain SGD on log loss. Class weights offset an unbalanced dataset.
fn train(samples: &[Sample]) -> (f32, Vec<f32>) {
    let mut weights = vec![0.0f32; DIM];
    let mut bias = 0.0f32;
    let positives = samples.iter().filter(|s| s.label > 0.5).count().max(1) as f32;
    let negatives = (samples.len() as f32 - positives).max(1.0);
    let total = samples.len() as f32;
    let weight_pos = total / (2.0 * positives);
    let weight_neg = total / (2.0 * negatives);

    let mut rng = Rng(SEED);
    let mut order: Vec<usize> = (0..samples.len()).collect();
    for epoch in 0..EPOCHS {
        rng.shuffle(&mut order);
        let rate = LEARNING_RATE / (1.0 + epoch as f32 * 0.05);
        for &i in &order {
            let sample = &samples[i];
            let mut z = bias;
            for_each_feature(&sample.name, &sample.args, |j, v| z += weights[j] * v);
            let class_weight = if sample.label > 0.5 { weight_pos } else { weight_neg };
            let gradient = (sigmoid(z) - sample.label) * class_weight;
            bias -= rate * gradient;
            for_each_feature(&sample.name, &sample.args, |j, v| {
                weights[j] -= rate * (gradient * v + L2 * weights[j]);
            });
        }
    }
    (bias, weights)
}

#[derive(Default)]
struct Metrics {
    risky: usize,
    routine: usize,
    risky_auto: usize,
    routine_auto: usize,
    correct: usize,
}

fn evaluate(model: &Model, samples: &[Sample], low: f32) -> Metrics {
    let mut m = Metrics::default();
    for s in samples {
        let p = sigmoid(model.logit(&s.name, &s.args));
        let auto = p < low;
        if s.label > 0.5 {
            m.risky += 1;
            m.risky_auto += auto as usize;
        } else {
            m.routine += 1;
            m.routine_auto += auto as usize;
        }
        m.correct += ((p >= 0.5) == (s.label > 0.5)) as usize;
    }
    m
}

fn pct(n: usize, of: usize) -> f64 {
    if of == 0 {
        0.0
    } else {
        100.0 * n as f64 / of as f64
    }
}

/// The two numbers that matter: how often a risky command would skip the human
/// (the security cost), and how often a routine one would (the usability gain).
fn report(title: &str, m: &Metrics, low: f32) {
    println!(
        "{title}: accuracy {:.1}%, risky auto-allowed below {low}: {}/{} ({:.1}%), routine auto-allowed: {}/{} ({:.1}%)",
        pct(m.correct, m.risky + m.routine),
        m.risky_auto,
        m.risky,
        pct(m.risky_auto, m.risky),
        m.routine_auto,
        m.routine,
        pct(m.routine_auto, m.routine),
    );
}

/// Probability that a random risky command outscores a random routine one.
/// Independent of any threshold, and 0.5 means the model has learned nothing.
fn auc(scored: &[(f32, bool)]) -> f64 {
    let mut sorted = scored.to_vec();
    sorted.sort_by(|a, b| a.0.total_cmp(&b.0));
    let (mut rank_sum, mut i) = (0.0f64, 0usize);
    while i < sorted.len() {
        let mut j = i;
        while j < sorted.len() && sorted[j].0 == sorted[i].0 {
            j += 1;
        }
        let rank = (i + j + 1) as f64 / 2.0;
        rank_sum += rank * sorted[i..j].iter().filter(|s| s.1).count() as f64;
        i = j;
    }
    let pos = sorted.iter().filter(|s| s.1).count() as f64;
    let neg = sorted.len() as f64 - pos;
    if pos == 0.0 || neg == 0.0 {
        return f64::NAN;
    }
    (rank_sum - pos * (pos + 1.0) / 2.0) / (pos * neg)
}

fn report_test(title: &str, model: &Model, samples: &[Sample]) {
    let scored: Vec<(f32, bool)> = samples
        .iter()
        .map(|s| (sigmoid(model.logit(&s.name, &s.args)), s.label > 0.5))
        .collect();
    let m = evaluate(model, samples, 0.5);
    println!(
        "\n{title}: {} risky, {} routine, AUC {:.3}, accuracy at 0.5: {:.1}%",
        m.risky,
        m.routine,
        auc(&scored),
        pct(m.correct, m.risky + m.routine)
    );
    println!("  threshold   risky auto-allowed   routine auto-allowed");
    for low in [0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.15, 0.3, 0.5, 0.6] {
        let m = evaluate(model, samples, low);
        println!(
            "  {low:<9}   {:>5}/{:<5} {:>5.1}%   {:>5}/{:<5} {:>5.1}%",
            m.risky_auto,
            m.risky,
            pct(m.risky_auto, m.risky),
            m.routine_auto,
            m.routine,
            pct(m.routine_auto, m.routine),
        );
    }
}

fn print_scores(model: &Model, samples: &[Sample]) {
    let mut rows: Vec<(f32, &Sample)> = samples
        .iter()
        .map(|s| (sigmoid(model.logit(&s.name, &s.args)), s))
        .collect();
    rows.sort_by(|a, b| a.0.total_cmp(&b.0));
    println!();
    for (p, s) in rows {
        println!("  {p:.3}  label={}  {} {}", s.label as u8, s.name, s.args.join(" "));
    }
}

fn load_or_exit(path: &str) -> Vec<Sample> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("{path}: {e}");
        exit(1)
    });
    parse_dataset(&text).unwrap_or_else(|e| {
        eprintln!("{path}: {e}");
        exit(1)
    })
}

fn add(total: &mut Metrics, m: Metrics) {
    total.risky += m.risky;
    total.routine += m.routine;
    total.risky_auto += m.risky_auto;
    total.routine_auto += m.routine_auto;
    total.correct += m.correct;
}

fn fit_and_score(train_set: &[Sample], test_set: &[Sample], low: f32) -> Metrics {
    let (bias, weights) = train(train_set);
    let bytes = encode(bias, &weights);
    let model = Model::parse(&bytes).expect("just encoded");
    evaluate(&model, test_set, low)
}

/// Random split: optimistic, since near-duplicates land on both sides.
fn holdout(samples: &[Sample], low: f32) -> Metrics {
    let mut shuffled = samples.to_vec();
    Rng(SEED ^ 1).shuffle(&mut shuffled);
    let cut = shuffled.len() / 5;
    let (test_set, train_set) = shuffled.split_at(cut);
    fit_and_score(train_set, test_set, low)
}

/// Holds out one program at a time: how the model does on commands it has never
/// seen, which is the case "unknown operation" is really about.
fn leave_one_binary_out(samples: &[Sample], low: f32) -> Metrics {
    let names: BTreeSet<&str> = samples.iter().map(|s| basename(&s.name)).collect();
    let mut total = Metrics::default();
    for name in names {
        let (test_set, train_set): (Vec<Sample>, Vec<Sample>) = samples
            .iter()
            .cloned()
            .partition(|s| basename(&s.name) == name);
        if train_set.is_empty() {
            continue;
        }
        add(&mut total, fit_and_score(&train_set, &test_set, low));
    }
    total
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut dataset = None;
    let mut out = "ml/model.bin".to_string();
    let mut low = 0.15f32;
    let mut eval_only = false;
    let mut tests = Vec::new();
    let mut scores = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--dataset" => {
                i += 1;
                dataset = args.get(i).cloned();
            }
            "--out" => {
                i += 1;
                out = args.get(i).cloned().unwrap_or(out);
            }
            "--low" => {
                i += 1;
                low = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(low);
            }
            "--eval-only" => eval_only = true,
            "--test" => {
                i += 1;
                tests.extend(args.get(i).cloned());
            }
            "--scores" => {
                i += 1;
                scores = args.get(i).cloned();
            }
            other => {
                eprintln!("unknown option {other}");
                exit(2);
            }
        }
        i += 1;
    }
    let Some(dataset) = dataset else {
        eprintln!("usage: trustauto-train --dataset FILE [--out FILE] [--low 0.15] [--eval-only]");
        exit(2)
    };

    let samples = load_or_exit(&dataset);
    let risky = samples.iter().filter(|s| s.label > 0.5).count();
    if risky == 0 || risky == samples.len() || samples.len() < 10 {
        eprintln!("the dataset needs at least 10 samples covering both labels");
        exit(1);
    }
    println!(
        "{} samples ({} risky, {} routine)",
        samples.len(),
        risky,
        samples.len() - risky
    );

    if tests.is_empty() {
        report("random 80/20 holdout ", &holdout(&samples, low), low);
        report("leave-one-binary-out ", &leave_one_binary_out(&samples, low), low);
        if eval_only {
            return;
        }
    }

    let (bias, weights) = train(&samples);
    let bytes = encode(bias, &weights);
    if !tests.is_empty() {
        let model = Model::parse(&bytes).expect("just encoded");
        report_test("training data (fit check)", &model, &samples);
        for path in &tests {
            report_test(path, &model, &load_or_exit(path));
        }
        if let Some(path) = &scores {
            print_scores(&model, &load_or_exit(path));
        }
        if eval_only {
            return;
        }
    }
    std::fs::write(&out, &bytes).unwrap_or_else(|e| {
        eprintln!("{out}: {e}");
        exit(1)
    });
    let model = Model::parse(&bytes).expect("just encoded");
    println!(
        "wrote {out} ({} KiB, checksum {:016x}); rebuild to embed it",
        bytes.len() / 1024,
        model.checksum()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dataset_errors_name_the_line() {
        assert!(parse_dataset("0\tapt update\n1\n").unwrap_err().contains("line 2"));
        assert!(parse_dataset("2\tapt update").unwrap_err().contains("label"));
        assert_eq!(parse_dataset("# c\n\n0\tapt update\n").unwrap().len(), 1);
    }

    #[test]
    fn separator_preserves_arguments_with_spaces() {
        let rows = parse_dataset("1\tawk\x1fBEGIN {x}\x1f-f\n").unwrap();
        assert_eq!(rows[0].name, "awk");
        assert_eq!(rows[0].args, vec!["BEGIN {x}".to_string(), "-f".to_string()]);
    }

    #[test]
    fn auc_ranks_correctly() {
        assert_eq!(auc(&[(0.1, false), (0.9, true)]), 1.0);
        assert_eq!(auc(&[(0.9, false), (0.1, true)]), 0.0);
        assert_eq!(auc(&[(0.5, false), (0.5, true)]), 0.5);
        assert!(auc(&[(0.5, true)]).is_nan());
    }

    #[test]
    fn training_is_deterministic_and_learns_a_separable_toy_problem() {
        // A synthetic check of the optimizer only, not a real dataset.
        let mut text = String::new();
        for i in 0..20 {
            text.push_str(&format!("0\ttoola read item{i}\n1\ttoolb wipe item{i}\n"));
        }
        let samples = parse_dataset(&text).unwrap();
        let (bias, weights) = train(&samples);
        let (bias2, weights2) = train(&samples);
        assert_eq!(bias, bias2);
        assert_eq!(weights, weights2);
        let bytes = encode(bias, &weights);
        let model = Model::parse(&bytes).unwrap();
        let m = evaluate(&model, &samples, 0.5);
        assert_eq!(m.correct, samples.len());
    }
}
