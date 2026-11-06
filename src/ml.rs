//! The text-only risk model of experiments 1 and 2: hashed-feature logistic
//! regression over the command line. Kept for `trustauto-train`, which
//! reproduces those experiments. The engine uses `risk` (the facts Transformer)
//! instead.
//!
//! Model file: "TAML", u32 version, u32 dim, f32 bias, dim * f32 weights,
//! u64 FNV-1a of everything before it. All little-endian.

use crate::fnv1a64;
use crate::request::basename;

pub const DIM: usize = 1 << 16;
const MAGIC: &[u8; 4] = b"TAML";
const VERSION: u32 = 1;
const HEADER: usize = 16;
const MAX_ARGS: usize = 64;
const MAX_TOKEN: usize = 256;
const MAX_NAME_PARTS: usize = 8;
const MAX_NAME_GRAMS: usize = 32;

fn clip(s: &str) -> &[u8] {
    let b = s.as_bytes();
    &b[..b.len().min(MAX_TOKEN)]
}

fn hash_parts(parts: &[&[u8]]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for part in parts {
        for b in *part {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h ^= 0xff;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn emit(parts: &[&[u8]], f: &mut impl FnMut(usize, f32)) {
    let h = hash_parts(parts);
    let sign = if h >> 63 == 0 { 1.0 } else { -1.0 };
    f((h as usize) & (DIM - 1), sign);
}

/// The pieces of a package or service name, tied to the action on it. These let
/// the model say something about a name it never saw: `libpam-foo` looks like
/// other `libpam` packages, and removing one is different from installing one.
fn emit_name_features(verb: &[u8], arg: &str, f: &mut impl FnMut(usize, f32)) {
    let stem = arg
        .strip_suffix(".service")
        .or_else(|| arg.strip_suffix(".socket"))
        .unwrap_or(arg);
    let bytes = clip(stem);
    for part in stem
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|p| !p.is_empty())
        .take(MAX_NAME_PARTS)
    {
        emit(&[b"part", verb, clip(part)], f);
    }
    for len in 3..=5 {
        if bytes.len() >= len {
            emit(&[b"prefix", verb, &bytes[..len]], f);
        }
    }
    for gram in bytes.windows(3).take(MAX_NAME_GRAMS) {
        emit(&[b"gram", verb, gram], f);
    }
    // The whole name, without the unit suffix, so `ssh` and `ssh.service` agree.
    emit(&[b"name", verb, bytes], f);
}

/// Calls `f(bucket, value)` for each feature of a command.
pub fn for_each_feature(name: &str, args: &[String], mut f: impl FnMut(usize, f32)) {
    let bin = clip(basename(name));
    let name_bytes: &[u8] = bin;
    emit(&[b"bin", bin], &mut f);

    let mut prev: &[u8] = b"^";
    let mut first_word = true;
    let mut verb: &[u8] = b"";
    let mut path_args = 0u32;
    for arg in args.iter().take(MAX_ARGS) {
        let token = clip(arg);
        emit(&[b"arg", token], &mut f);
        emit(&[b"pair", name_bytes, token], &mut f);
        emit(&[b"bigram", prev, token], &mut f);
        prev = token;

        if arg.starts_with("--") {
            let flag = arg.split('=').next().unwrap_or(arg);
            emit(&[b"flag", clip(flag)], &mut f);
            emit(&[b"binflag", name_bytes, clip(flag)], &mut f);
        } else if let Some(shorts) = arg.strip_prefix('-') {
            for c in shorts.bytes().take(16) {
                emit(&[b"short", &[c]], &mut f);
                emit(&[b"binshort", name_bytes, &[c]], &mut f);
            }
        } else if first_word {
            first_word = false;
            verb = token;
            emit(&[b"sub", name_bytes, token], &mut f);
        } else {
            emit_name_features(verb, arg, &mut f);
        }

        if arg.contains('=') {
            emit(&[b"shape", b"eq"], &mut f);
        }
        if arg == "/" {
            emit(&[b"shape", b"root"], &mut f);
        }
        if arg.contains('*') || arg.contains('?') {
            emit(&[b"shape", b"glob"], &mut f);
        }
        if arg.chars().any(|c| ";|&$`<>".contains(c)) {
            emit(&[b"shape", b"meta"], &mut f);
        }

        let value = arg.rsplit('=').next().unwrap_or(arg);
        if value.starts_with('/') {
            path_args += 1;
            let mut comps = value[1..].splitn(3, '/');
            if let Some(top) = comps.next() {
                emit(&[b"p1", clip(top)], &mut f);
                if let Some(second) = comps.next() {
                    emit(&[b"p2", clip(top), clip(second)], &mut f);
                }
            }
        }
    }
    if path_args > 0 {
        emit(&[b"shape", b"path"], &mut f);
    }
    if args.len() > MAX_ARGS {
        emit(&[b"shape", b"long"], &mut f);
    }
    let bucket: &[u8] = match args.len() {
        0 => b"0",
        1 => b"1",
        2 => b"2",
        3..=5 => b"few",
        _ => b"many",
    };
    emit(&[b"nargs", bucket], &mut f);
}

#[derive(Debug, Clone, Copy)]
pub struct Model<'a> {
    bias: f32,
    weights: &'a [u8],
    checksum: u64,
}

impl<'a> Model<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Model<'a>, String> {
        let expected = HEADER + DIM * 4 + 8;
        if bytes.len() != expected {
            return Err(format!("model size {} != {expected}", bytes.len()));
        }
        if &bytes[..4] != MAGIC {
            return Err("bad model magic".to_string());
        }
        let u32_at = |i: usize| u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap());
        if u32_at(4) != VERSION || u32_at(8) as usize != DIM {
            return Err("unsupported model version or dimension".to_string());
        }
        let (body, tail) = bytes.split_at(expected - 8);
        let checksum = fnv1a64(body);
        if checksum.to_le_bytes() != *tail {
            return Err("model checksum mismatch".to_string());
        }
        Ok(Model {
            bias: f32::from_le_bytes(bytes[12..16].try_into().unwrap()),
            weights: &bytes[HEADER..HEADER + DIM * 4],
            checksum,
        })
    }

    pub fn checksum(&self) -> u64 {
        self.checksum
    }

    fn weight(&self, i: usize) -> f32 {
        let at = i * 4;
        f32::from_le_bytes(self.weights[at..at + 4].try_into().unwrap())
    }

    /// Log-odds of "this command needs a human", from the command text alone.
    pub fn logit(&self, name: &str, args: &[String]) -> f32 {
        let mut z = self.bias;
        for_each_feature(name, args, |i, v| z += self.weight(i) * v);
        z
    }

}

pub fn sigmoid(z: f32) -> f32 {
    1.0 / (1.0 + (-z).exp())
}

pub fn encode(bias: f32, weights: &[f32]) -> Vec<u8> {
    assert_eq!(weights.len(), DIM);
    let mut out = Vec::with_capacity(HEADER + DIM * 4 + 8);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&(DIM as u32).to_le_bytes());
    out.extend_from_slice(&bias.to_le_bytes());
    for w in weights {
        out.extend_from_slice(&w.to_le_bytes());
    }
    let checksum = fnv1a64(&out);
    out.extend_from_slice(&checksum.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(args: &[&str]) -> Vec<String> {
        args.iter().map(|a| a.to_string()).collect()
    }

    #[test]
    fn roundtrip_and_tamper_detection() {
        let mut bytes = encode(-3.0, &vec![0.0; DIM]);
        let model = Model::parse(&bytes).unwrap();
        assert!((model.logit("x", &[]) + 3.0).abs() < 1e-6);
        bytes[100] ^= 1;
        assert!(Model::parse(&bytes).is_err());
        assert!(Model::parse(&bytes[..100]).is_err());
    }

    #[test]
    fn features_are_bounded_for_huge_input() {
        let args: Vec<String> = (0..100_000).map(|i| format!("-{}", "x".repeat(i % 300))).collect();
        let mut n = 0usize;
        for_each_feature("tool", &args, |_, _| n += 1);
        assert!(n < 4000, "{n}");
    }

    #[test]
    fn name_features_are_bounded() {
        let args: Vec<String> = (0..100_000).map(|_| "a-b".repeat(1000)).collect();
        let mut n = 0usize;
        for_each_feature("tool", &args, |_, _| n += 1);
        assert!(n < 8000, "{n}");
    }

    #[test]
    fn unit_suffix_does_not_change_name_features() {
        let collect = |unit: &str| {
            let mut v = Vec::new();
            emit_name_features(b"stop", unit, &mut |i, _| v.push(i));
            v
        };
        assert_eq!(collect("ssh"), collect("ssh.service"));
        assert_eq!(collect("ssh"), collect("ssh.socket"));
    }

    #[test]
    fn distinct_commands_have_distinct_features() {
        let collect = |args: Vec<String>| {
            let mut v = Vec::new();
            for_each_feature("apt", &args, |i, _| v.push(i));
            v
        };
        assert_ne!(collect(s(&["install", "htop"])), collect(s(&["remove", "htop"])));
    }

}
