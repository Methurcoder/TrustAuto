//! The facts Transformer from round 4 of experiment 5, evaluated without PyTorch.
//!
//! Model file "TAFT": magic, u32 version, u32 header length, JSON header,
//! little-endian f32 tensors, u64 FNV-1a of everything before it. Written by
//! `ml/release/export_facts_model.py`. The forward pass is PyTorch's
//! `TransformerEncoderLayer` in eval mode (post-norm, ReLU, no dropout).

use crate::facts::{features, stem, Facts};
use crate::fnv1a64;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};

const MAGIC: &[u8; 4] = b"TAFT";
const VERSION: u32 = 1;
const EPS: f32 = 1e-5;

#[derive(Deserialize)]
struct TensorInfo {
    seed: usize,
    name: String,
    shape: Vec<usize>,
    offset: usize,
    len: usize,
}

#[derive(Deserialize)]
struct Header {
    names: Vec<String>,
    words: Vec<String>,
    mean: Vec<f64>,
    std: Vec<f64>,
    max_words: usize,
    width: usize,
    heads: usize,
    layers: usize,
    seeds: usize,
    threshold: f32,
    known_programs: Vec<String>,
    tensors: Vec<TensorInfo>,
}

struct Linear {
    w: Vec<f32>,
    b: Vec<f32>,
    rows: usize,
    cols: usize,
}

impl Linear {
    fn apply(&self, x: &[f32], out: &mut [f32]) {
        for r in 0..self.rows {
            let row = &self.w[r * self.cols..(r + 1) * self.cols];
            out[r] = self.b[r] + row.iter().zip(x).map(|(w, v)| w * v).sum::<f32>();
        }
    }
}

struct Norm {
    w: Vec<f32>,
    b: Vec<f32>,
}

impl Norm {
    fn apply(&self, x: &mut [f32]) {
        let n = x.len() as f32;
        let mean = x.iter().sum::<f32>() / n;
        let var = x.iter().map(|v| (v - mean) * (v - mean)).sum::<f32>() / n;
        let inv = 1.0 / (var + EPS).sqrt();
        for (i, v) in x.iter_mut().enumerate() {
            *v = (*v - mean) * inv * self.w[i] + self.b[i];
        }
    }
}

struct Layer {
    in_proj: Linear,
    out_proj: Linear,
    linear1: Linear,
    linear2: Linear,
    norm1: Norm,
    norm2: Norm,
}

struct Net {
    number_id: Vec<f32>,
    number_scale: Vec<f32>,
    word: Vec<f32>,
    cls: Vec<f32>,
    layers: Vec<Layer>,
    head: Linear,
}

pub struct FactsModel {
    names: Vec<String>,
    word_ids: HashMap<String, usize>,
    mean: Vec<f64>,
    std: Vec<f64>,
    max_words: usize,
    width: usize,
    heads: usize,
    nets: Vec<Net>,
    threshold: f32,
    known: HashSet<String>,
    checksum: u64,
}

/// A score and what it rests on.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Score {
    /// Mean probability of "needs a human" over the seeds.
    pub risk: f32,
    /// The program had at least three allowed rows in training.
    pub known: bool,
}

impl FactsModel {
    pub fn parse(bytes: &[u8]) -> Result<FactsModel, String> {
        if bytes.len() < 20 || &bytes[..4] != MAGIC {
            return Err("bad model magic".to_string());
        }
        let (body, tail) = bytes.split_at(bytes.len() - 8);
        let checksum = fnv1a64(body);
        if checksum.to_le_bytes() != *tail {
            return Err("model checksum mismatch".to_string());
        }
        let u32_at = |i: usize| u32::from_le_bytes(body[i..i + 4].try_into().unwrap());
        if u32_at(4) != VERSION {
            return Err("unsupported model version".to_string());
        }
        let header_len = u32_at(8) as usize;
        let header_end = 12usize.checked_add(header_len).filter(|e| *e <= body.len()).ok_or("model header out of range")?;
        let h: Header = serde_json::from_slice(&body[12..header_end]).map_err(|e| format!("bad model header: {e}"))?;
        let data = &body[header_end..];
        if data.len() % 4 != 0 {
            return Err("model tensor data is not f32".to_string());
        }
        let floats: Vec<f32> = data.chunks_exact(4).map(|c| f32::from_le_bytes(c.try_into().unwrap())).collect();
        let d = h.width;
        if h.heads == 0 || d % h.heads != 0 || h.names.len() != h.mean.len() || h.names.len() != h.std.len() {
            return Err("inconsistent model header".to_string());
        }
        let mut by_seed: Vec<HashMap<&str, &TensorInfo>> = (0..h.seeds).map(|_| HashMap::new()).collect();
        for t in &h.tensors {
            let fits = t.shape.iter().product::<usize>() == t.len && t.offset.checked_add(t.len).is_some_and(|e| e <= floats.len());
            if t.seed >= h.seeds || !fits {
                return Err(format!("bad tensor {}", t.name));
            }
            by_seed[t.seed].insert(t.name.as_str(), t);
        }
        let numbers = h.names.len();
        let vocabulary = h.words.len() + 1;
        let mut nets = Vec::new();
        for tensors in &by_seed {
            let take = |name: &str, shape: &[usize]| -> Result<Vec<f32>, String> {
                let t = tensors.get(name).ok_or_else(|| format!("missing tensor {name}"))?;
                if t.shape != shape {
                    return Err(format!("tensor {name} has shape {:?}, expected {shape:?}", t.shape));
                }
                Ok(floats[t.offset..t.offset + t.len].to_vec())
            };
            let linear = |prefix: &str, rows: usize, cols: usize| -> Result<Linear, String> {
                Ok(Linear { w: take(&format!("{prefix}.weight"), &[rows, cols])?, b: take(&format!("{prefix}.bias"), &[rows])?, rows, cols })
            };
            let norm = |prefix: &str| -> Result<Norm, String> {
                Ok(Norm { w: take(&format!("{prefix}.weight"), &[d])?, b: take(&format!("{prefix}.bias"), &[d])? })
            };
            let mut layers = Vec::new();
            for i in 0..h.layers {
                let p = format!("body.layers.{i}");
                layers.push(Layer {
                    in_proj: Linear {
                        w: take(&format!("{p}.self_attn.in_proj_weight"), &[3 * d, d])?,
                        b: take(&format!("{p}.self_attn.in_proj_bias"), &[3 * d])?,
                        rows: 3 * d,
                        cols: d,
                    },
                    out_proj: linear(&format!("{p}.self_attn.out_proj"), d, d)?,
                    linear1: linear(&format!("{p}.linear1"), 2 * d, d)?,
                    linear2: linear(&format!("{p}.linear2"), d, 2 * d)?,
                    norm1: norm(&format!("{p}.norm1"))?,
                    norm2: norm(&format!("{p}.norm2"))?,
                });
            }
            nets.push(Net {
                number_id: take("number_id", &[numbers, d])?,
                number_scale: take("number_scale", &[numbers, d])?,
                word: take("word.weight", &[vocabulary, d])?,
                cls: take("cls", &[1, 1, d])?,
                layers,
                head: linear("head", 1, d)?,
            });
        }
        if nets.is_empty() {
            return Err("model has no networks".to_string());
        }
        Ok(FactsModel {
            word_ids: h.words.iter().enumerate().map(|(i, w)| (w.clone(), i + 1)).collect(),
            names: h.names,
            mean: h.mean,
            std: h.std,
            max_words: h.max_words,
            width: d,
            heads: h.heads,
            nets,
            threshold: h.threshold,
            known: h.known_programs.into_iter().collect(),
            checksum,
        })
    }

    pub fn checksum(&self) -> u64 {
        self.checksum
    }

    /// Below this, the training rows let through at most 1.8% of the settled
    /// risky rows, scored out of fold.
    pub fn threshold(&self) -> f32 {
        self.threshold
    }

    pub fn is_known(&self, program: &str) -> bool {
        self.known.contains(program)
    }

    pub fn known_programs(&self) -> impl Iterator<Item = &String> {
        self.known.iter()
    }

    /// The probability from features already computed.
    pub fn risk_of(&self, x: &BTreeMap<String, f64>, words: &[String]) -> f32 {
        // Normalized in f64 like the NumPy original, then cast.
        let values: Vec<f32> = self
            .names
            .iter()
            .enumerate()
            .map(|(i, k)| ((x.get(k).copied().unwrap_or(0.0) - self.mean[i]) / self.std[i]) as f32)
            .collect();
        let ids: Vec<usize> = words.iter().filter_map(|w| self.word_ids.get(w).copied()).take(self.max_words).collect();
        let total: f32 = self.nets.iter().map(|net| sigmoid(self.logit(net, &values, &ids))).sum();
        total / self.nets.len() as f32
    }

    pub fn score(&self, argv: &[String], target_mode: Option<u32>, machine: &dyn Facts) -> Score {
        let (x, words) = features(argv, target_mode, machine);
        Score { risk: self.risk_of(&x, &words), known: self.is_known(stem(&argv[0])) }
    }

    fn logit(&self, net: &Net, values: &[f32], ids: &[usize]) -> f32 {
        let d = self.width;
        // Tokens: CLS, one per number, then max_words word slots (padding is masked).
        let numbers = values.len();
        let n = 1 + numbers + self.max_words;
        let mut x = vec![0f32; n * d];
        x[..d].copy_from_slice(&net.cls);
        for (i, v) in values.iter().enumerate() {
            let row = &mut x[(1 + i) * d..(2 + i) * d];
            for j in 0..d {
                row[j] = net.number_id[i * d + j] + v * net.number_scale[i * d + j];
            }
        }
        let mut live = vec![true; n];
        for slot in 0..self.max_words {
            let at = 1 + numbers + slot;
            match ids.get(slot) {
                Some(id) => x[at * d..(at + 1) * d].copy_from_slice(&net.word[id * d..(id + 1) * d]),
                None => live[at] = false,
            }
        }
        let last = net.layers.len().saturating_sub(1);
        for (i, layer) in net.layers.iter().enumerate() {
            // Only the CLS row of the last layer reaches the head.
            x = self.layer(layer, &x, &live, n, if i == last { 1 } else { n });
        }
        let mut out = [0f32; 1];
        net.head.apply(&x[..d], &mut out);
        out[0]
    }

    /// One encoder layer. Every token is a key and value; only the first
    /// `queries` rows are computed.
    fn layer(&self, l: &Layer, x: &[f32], live: &[bool], n: usize, queries: usize) -> Vec<f32> {
        let d = self.width;
        let heads = self.heads;
        let hd = d / heads;
        let scale = 1.0 / (hd as f32).sqrt();
        let mut qkv = vec![0f32; n * 3 * d];
        for t in 0..n {
            l.in_proj.apply(&x[t * d..(t + 1) * d], &mut qkv[t * 3 * d..(t + 1) * 3 * d]);
        }
        let mut attended = vec![0f32; queries * d];
        let mut weights = vec![0f32; n];
        for h in 0..heads {
            for t in 0..queries {
                let q = &qkv[t * 3 * d + h * hd..t * 3 * d + (h + 1) * hd];
                let mut top = f32::NEG_INFINITY;
                for s in 0..n {
                    weights[s] = if live[s] {
                        let k = &qkv[s * 3 * d + d + h * hd..s * 3 * d + d + (h + 1) * hd];
                        q.iter().zip(k).map(|(a, b)| a * b).sum::<f32>() * scale
                    } else {
                        f32::NEG_INFINITY
                    };
                    top = top.max(weights[s]);
                }
                let mut total = 0f32;
                for w in weights.iter_mut() {
                    *w = if w.is_finite() { (*w - top).exp() } else { 0.0 };
                    total += *w;
                }
                let out = &mut attended[t * d + h * hd..t * d + (h + 1) * hd];
                for s in 0..n {
                    if weights[s] == 0.0 {
                        continue;
                    }
                    let v = &qkv[s * 3 * d + 2 * d + h * hd..s * 3 * d + 2 * d + (h + 1) * hd];
                    let w = weights[s] / total;
                    for j in 0..hd {
                        out[j] += w * v[j];
                    }
                }
            }
        }
        let mut y = vec![0f32; queries * d];
        let mut tmp = vec![0f32; d];
        let mut hidden = vec![0f32; 2 * d];
        for t in 0..queries {
            l.out_proj.apply(&attended[t * d..(t + 1) * d], &mut tmp);
            let row = &mut y[t * d..(t + 1) * d];
            for j in 0..d {
                row[j] = x[t * d + j] + tmp[j];
            }
            l.norm1.apply(row);
            l.linear1.apply(row, &mut hidden);
            for v in hidden.iter_mut() {
                *v = v.max(0.0);
            }
            l.linear2.apply(&hidden, &mut tmp);
            for j in 0..d {
                row[j] += tmp[j];
            }
            l.norm2.apply(row);
        }
        y
    }
}

pub fn sigmoid(z: f32) -> f32 {
    1.0 / (1.0 + (-z).exp())
}

pub fn logit(p: f32) -> f32 {
    (p / (1.0 - p)).ln()
}
