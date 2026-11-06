//! The Rust port against the Python training code, on the four lab machines.
//! `ml/release/out/golden.json` holds features and scores that
//! `ml/release/export_facts_model.py` computed with the original source.

use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use trustauto::facts::{features, Machine, Snapshot};
use trustauto::index::Index;
use trustauto::risk::embedded_model;

const GOLDEN: &str = "ml/release/out/golden.json";
const LAB: &str = "ml/truth/experiment_5/round4_evaluation/reproduction/data";

fn golden() -> Option<Value> {
    let text = std::fs::read_to_string(GOLDEN).ok()?;
    Some(serde_json::from_str(&text).unwrap())
}

fn machine(name: &str) -> Machine {
    let facts = std::fs::read_to_string(Path::new(LAB).join(format!("facts_{name}.json"))).unwrap();
    let usage = std::fs::read_to_string(Path::new(LAB).join(format!("usage_{name}.json"))).unwrap();
    Machine::new(&Snapshot::from_lab(&facts, &usage).unwrap())
}

fn row_x(row: &Value) -> BTreeMap<String, f64> {
    row["x"].as_object().unwrap().iter().map(|(k, v)| (k.clone(), v.as_f64().unwrap())).collect()
}

fn row_words(row: &Value) -> Vec<String> {
    row["words"].as_array().unwrap().iter().map(|w| w.as_str().unwrap().to_string()).collect()
}

fn argv(row: &Value) -> Vec<String> {
    row["argv"].as_array().unwrap().iter().map(|w| w.as_str().unwrap().to_string()).collect()
}

#[test]
fn transformer_matches_pytorch_on_python_features() {
    let Some(g) = golden() else { return eprintln!("skipped: {GOLDEN} missing") };
    let model = embedded_model().unwrap();
    assert!((model.threshold() as f64 - g["threshold"].as_f64().unwrap()).abs() < 1e-7);
    let mut worst = 0f64;
    for row in g["rows"].as_array().unwrap() {
        let risk = model.risk_of(&row_x(row), &row_words(row)) as f64;
        worst = worst.max((risk - row["score"].as_f64().unwrap()).abs());
        let program = trustauto::facts::stem(row["argv"][0].as_str().unwrap()).to_string();
        assert_eq!(model.is_known(&program), row["known"].as_bool().unwrap(), "{program}");
    }
    assert!(worst < 1e-4, "largest score difference {worst}");
}

#[test]
fn features_match_python_on_every_lab_machine() {
    let Some(g) = golden() else { return eprintln!("skipped: {GOLDEN} missing") };
    let rows = g["rows"].as_array().unwrap();
    let mut machines: HashMap<String, Machine> = HashMap::new();
    let model = embedded_model().unwrap();
    let (mut checked, mut differing) = (0, Vec::new());
    let mut worst_score = 0f64;
    for row in rows {
        let name = row["machine"].as_str().unwrap().to_string();
        let m = machines.entry(name.clone()).or_insert_with(|| machine(&name));
        let mode = row["target_mode"].as_u64().map(|v| v as u32);
        let (x, words) = features(&argv(row), mode, m);
        assert_eq!(words, row_words(row), "{name} {:?}", argv(row));
        let expected = row_x(row);
        let keys: Vec<&String> = expected.keys().chain(x.keys()).collect();
        let bad: Vec<String> = keys
            .into_iter()
            .filter(|k| (x.get(*k).copied().unwrap_or(f64::NAN) - expected.get(*k).copied().unwrap_or(f64::NAN)).abs() > 1e-9)
            .map(|k| format!("{k}: rust {:?} python {:?}", x.get(k), expected.get(k)))
            .collect();
        if !bad.is_empty() {
            differing.push(format!("{name} {:?}: {}", argv(row), bad.join(", ")));
        }
        let risk = model.risk_of(&x, &words) as f64;
        worst_score = worst_score.max((risk - row["score"].as_f64().unwrap()).abs());
        checked += 1;
    }
    for d in differing.iter().take(20) {
        eprintln!("{d}");
    }
    eprintln!("{checked} rows, {} differ, largest score difference {worst_score}", differing.len());
    assert!(differing.is_empty(), "{} of {checked} rows differ", differing.len());
    assert!(worst_score < 1e-4);
}

#[test]
fn the_saved_index_gives_the_same_features_as_the_machine() {
    let Some(g) = golden() else { return eprintln!("skipped: {GOLDEN} missing") };
    let rows = g["rows"].as_array().unwrap();
    let mut pairs: HashMap<String, (Machine, Index)> = HashMap::new();
    let mut checked = 0;
    for row in rows {
        let name = row["machine"].as_str().unwrap().to_string();
        let (m, index) = pairs.entry(name.clone()).or_insert_with(|| {
            let m = machine(&name);
            // Through the file format, as decisions read it.
            let text = serde_json::to_string(&Index::build(&m, 1)).unwrap();
            (m, Index::parse(&text).unwrap())
        });
        let mode = row["target_mode"].as_u64().map(|v| v as u32);
        let from_machine = features(&argv(row), mode, &*m);
        let from_index = features(&argv(row), mode, &*index);
        assert_eq!(from_index, from_machine, "{name} {:?}", argv(row));
        checked += 1;
    }
    eprintln!("{checked} rows, all equal");
}
