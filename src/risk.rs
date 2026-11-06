//! The risk model as the engine uses it: the embedded facts Transformer plus
//! this machine's facts snapshot, and the context signals that can only raise
//! the score.

use crate::analyze::{changes_things, is_opaque, SBIN_DIRS};
use crate::facts::{Facts, Machine, Snapshot};
use crate::index::{Index, INDEX_PATH};
use crate::paths::{verify_trusted_file, SECURE_PATH};
use crate::request::{Context, Request};
use crate::transformer::{logit, sigmoid, FactsModel, Score};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

static EMBEDDED: &[u8] = include_bytes!("../ml/facts_model.bin");

/// A snapshot older than this no longer describes the machine.
pub const MAX_SNAPSHOT_AGE_SECS: u64 = 8 * 24 * 3600;

// Hand-set log-odds for context signals. The training data has no context, and
// these only ever push the score upward.
const PENALTY_NO_TTY: f32 = 1.0;
const PENALTY_SSH: f32 = 0.5;
const PENALTY_CWD: f32 = 1.0;
const PENALTY_ENV: f32 = 1.0;

pub fn context_penalty(ctx: &Context) -> f32 {
    let mut p = 0.0;
    if !ctx.has_tty {
        p += PENALTY_NO_TTY;
    }
    if ctx.ssh_session {
        p += PENALTY_SSH;
    }
    if ctx.cwd_unsafe {
        p += PENALTY_CWD;
    }
    if ctx.suspicious_env {
        p += PENALTY_ENV;
    }
    p
}

pub fn embedded_model() -> Result<FactsModel, String> {
    FactsModel::parse(EMBEDDED)
}

pub struct Risk {
    pub model: FactsModel,
    pub machine: Box<dyn Facts>,
    pub collected_at: u64,
}

impl Risk {
    /// From a snapshot, building every index: slow, for training and measuring.
    pub fn new(model: FactsModel, snapshot: &Snapshot) -> Risk {
        Risk { model, machine: Box::new(Machine::new(snapshot)), collected_at: snapshot.collected_at }
    }

    /// From the index `trustauto-facts` saved: what a decision uses.
    pub fn from_index(model: FactsModel, index: Index) -> Risk {
        let collected_at = index.collected_at;
        Risk { model, machine: Box::new(index), collected_at }
    }

    /// The embedded model and the machine's facts index. `trusted` requires the
    /// index to be root-owned with a root-only directory chain, as the broker
    /// must; the front end only uses its answer to explain and show settings.
    pub fn load(trusted: bool) -> Result<Risk, String> {
        let path = Path::new(INDEX_PATH);
        if trusted {
            verify_trusted_file(path)?;
        }
        let meta = std::fs::metadata(path).map_err(|e| format!("{INDEX_PATH}: {e} (run trustauto-facts collect as root)"))?;
        let text = std::fs::read_to_string(path).map_err(|e| format!("{INDEX_PATH}: {e}"))?;
        let index = Index::parse(&text)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let written = (meta.mtime().max(0) as u64).max(index.collected_at);
        if index.collected_at == 0 || now.saturating_sub(written) > MAX_SNAPSHOT_AGE_SECS {
            return Err(format!("{INDEX_PATH} is older than 8 days (run trustauto-facts collect as root)"));
        }
        Ok(Risk::from_index(embedded_model()?, index))
    }

    pub fn checksum(&self) -> u64 {
        self.model.checksum()
    }

    pub fn threshold(&self) -> f32 {
        self.model.threshold()
    }

    /// The score of a request, with context signals added in log-odds.
    pub fn score(&self, req: &Request) -> Score {
        let mut argv = Vec::with_capacity(req.args.len() + 1);
        argv.push(req.basename().to_string());
        argv.extend(req.args.iter().cloned());
        let s = self.model.score(&argv, target_mode(&argv), self.machine.as_ref());
        let penalty = context_penalty(&req.ctx);
        let risk = if penalty > 0.0 { sigmoid(logit(s.risk) + penalty) } else { s.risk };
        Score { risk, known: s.known }
    }
}

/// Extra commands the shell integration routes through TrustAuto in ML-only
/// mode: programs the model knows that administer the system. Opaque programs
/// are left out, since ML-only mode never elevates them anyway.
pub fn ml_wrapper_names(model: &FactsModel) -> Vec<String> {
    let mut names: Vec<String> = model
        .known_programs()
        .filter(|name| !is_opaque(name))
        .filter(|name| {
            SECURE_PATH.iter().any(|dir| {
                let path = Path::new(dir).join(name.as_str());
                path.is_file() && (changes_things(name) || SBIN_DIRS.iter().any(|s| format!("{dir}/").ends_with(s)))
            })
        })
        .cloned()
        .collect();
    names.sort();
    names
}

/// The permission bits of what the command acts on, as the lab recorded them:
/// the first path argument, or, for a command that creates it, its directory.
pub fn target_mode(argv: &[String]) -> Option<u32> {
    let first = argv[1..].iter().find(|a| !a.starts_with('-') && a.starts_with('/'))?;
    let path = Path::new(first);
    if let Ok(meta) = path.symlink_metadata() {
        return Some(meta.mode() & 0o7777);
    }
    if matches!(argv[0].as_str(), "touch" | "mkdir" | "tee") {
        return path.parent().and_then(|d| d.symlink_metadata().ok()).map(|m| m.mode() & 0o7777);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_model_parses() {
        let m = embedded_model().unwrap();
        assert!(m.threshold() > 0.0 && m.threshold() < 1.0);
        assert!(m.is_known("systemctl"));
    }

    #[test]
    fn context_only_raises_risk() {
        assert_eq!(context_penalty(&Context::quiet()), 0.0);
        let noisy = Context { has_tty: false, ssh_session: true, cwd_unsafe: true, suspicious_env: true };
        assert!(context_penalty(&noisy) > 0.0);
    }

    #[test]
    fn target_mode_uses_the_parent_for_new_files() {
        let dir = std::env::temp_dir();
        let new = dir.join(format!("ta-missing-{}", std::process::id()));
        let argv = |cmd: &str| vec![cmd.to_string(), new.to_str().unwrap().to_string()];
        assert!(target_mode(&argv("touch")).is_some());
        assert_eq!(target_mode(&argv("cat")), None);
        assert_eq!(target_mode(&["useradd".to_string(), "x".to_string()]), None);
    }
}
