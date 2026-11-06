//! The operator's policy file. This is the independent authorization layer:
//! it defines the only commands that can ever be elevated without an approver.
//! Any invalid input rejects the whole file, and the broker then elevates nothing.

use crate::analyze::is_shell_equivalent;
use crate::fnv1a64;
use crate::paths::verify_trusted_file;
use crate::request::{basename, Request};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::Path;

const MAX_ARG_LEN: usize = 256;

/// Broad directories where a `{path:...}` capability would mean little.
const FORBIDDEN_PATH_PREFIXES: &[&str] = &[
    "/", "/tmp", "/var", "/var/tmp", "/home", "/root", "/etc", "/usr", "/dev", "/dev/shm", "/run",
    "/proc", "/sys", "/boot",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Rule,
    Ml,
    Hybrid,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Rule => "rule",
            Mode::Ml => "ml",
            Mode::Hybrid => "hybrid",
        }
    }

    pub fn from_name(s: &str) -> Option<Mode> {
        match s {
            "rule" => Some(Mode::Rule),
            "ml" => Some(Mode::Ml),
            "hybrid" => Some(Mode::Hybrid),
            _ => None,
        }
    }
}

/// `allow`: elevate on rule match. `envelope`: may elevate only with a low ML
/// score. `ask`: always needs an approver. `deny`: never runs. `user`: runs
/// without privileges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Envelope,
    Ask,
    Deny,
    User,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct MlConfig {
    /// A stricter cap on the model's own threshold. A request scored below
    /// both may elevate. Unset uses the model's threshold alone.
    pub low: Option<f32>,
    /// At or above this score, even an `allow` rule needs an approver in hybrid mode.
    pub high: f32,
    /// ML-only mode: let the model judge programs it had too few allowed
    /// training rows for. High risk; off unless the operator chose it.
    pub judge_unknown: bool,
}

impl Default for MlConfig {
    fn default() -> Self {
        MlConfig { low: None, high: 0.6, judge_unknown: false }
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NetworkConfig {
    /// A command that may talk to other machines never elevates without an approver.
    pub ask: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig { ask: true }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ApprovalConfig {
    pub approvers: Vec<String>,
    pub attempts: u32,
}

impl Default for ApprovalConfig {
    fn default() -> Self {
        ApprovalConfig {
            approvers: Vec::new(),
            attempts: 3,
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    version: u32,
    mode: Mode,
    #[serde(default = "default_true")]
    require_tty: bool,
    #[serde(default)]
    ml: MlConfig,
    #[serde(default)]
    network: NetworkConfig,
    #[serde(default)]
    approval: ApprovalConfig,
    #[serde(default, rename = "rule")]
    rules: Vec<RawRule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    id: String,
    action: Action,
    bin: String,
    args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pat {
    Lit(String),
    OneOf(Vec<String>),
    Word,
    Pkg,
    Unit,
    Int,
    Path(String),
    /// Anything at all. Only `deny`, `ask` and `user` rules may use it.
    Any,
}

impl Pat {
    fn matches(&self, arg: &str) -> bool {
        match self {
            Pat::Lit(l) => l == arg,
            Pat::OneOf(set) => set.iter().any(|s| s == arg),
            Pat::Word => is_word(arg),
            Pat::Pkg => is_pkg(arg),
            Pat::Unit => is_unit(arg),
            Pat::Int => !arg.is_empty() && arg.len() <= 18 && arg.bytes().all(|b| b.is_ascii_digit()),
            Pat::Path(prefix) => is_path_under(prefix, arg),
            Pat::Any => true,
        }
    }
}

fn first_is(arg: &str, pred: impl Fn(u8) -> bool) -> bool {
    arg.as_bytes().first().is_some_and(|b| pred(*b))
}

/// None of the typed patterns can match a leading `-`, which blocks option
/// injection such as `apt-get -o APT::Update::Pre-Invoke::=/bin/sh`.
fn is_word(arg: &str) -> bool {
    arg.len() <= MAX_ARG_LEN
        && first_is(arg, |b| b.is_ascii_alphanumeric() || b == b'_')
        && arg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:@+-".contains(&b))
}

/// Package names. Excluded on purpose, since apt gives each its own meaning:
/// `/` is a local file, `=` a version pin, `.` a regex, a trailing `-` removes.
fn is_pkg(arg: &str) -> bool {
    arg.len() <= 128
        && first_is(arg, |b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && !arg.ends_with('-')
        && arg
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"+-".contains(&b))
}

/// systemd unit names, without the glob characters systemctl would expand.
fn is_unit(arg: &str) -> bool {
    arg.len() <= MAX_ARG_LEN
        && first_is(arg, |b| b.is_ascii_alphanumeric() || b == b'_')
        && arg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b":_.@\\-".contains(&b))
}

/// The path must lie under the prefix both as written and after resolving
/// symlinks, so it has to exist.
fn is_path_under(prefix: &str, arg: &str) -> bool {
    if arg.len() > 4096 || !arg.starts_with('/') || arg.chars().any(char::is_control) {
        return false;
    }
    if arg.split('/').skip(1).any(|c| c.is_empty() || c == "." || c == "..") {
        return false;
    }
    if !under(prefix, arg) {
        return false;
    }
    match std::fs::canonicalize(arg) {
        Ok(real) => real.to_str().is_some_and(|r| under(prefix, r)),
        Err(_) => false,
    }
}

fn under(prefix: &str, path: &str) -> bool {
    path.strip_prefix(prefix).is_some_and(|rest| rest.starts_with('/'))
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub action: Action,
    pub bin: String,
    fixed: Vec<Pat>,
    /// Repeating final pattern and the minimum number of repeats.
    tail: Option<(Pat, usize)>,
}

impl Rule {
    pub fn matches(&self, req: &Request) -> bool {
        if self.bin != req.bin || req.args.len() < self.fixed.len() {
            return false;
        }
        let (head, rest) = req.args.split_at(self.fixed.len());
        if !self.fixed.iter().zip(head).all(|(p, a)| p.matches(a)) {
            return false;
        }
        match &self.tail {
            None => rest.is_empty(),
            Some((pat, min)) => rest.len() >= *min && rest.iter().all(|a| pat.matches(a)),
        }
    }
}

/// A parsed pattern: `literal`, `{type}`, `{type}+` or `{type}*`.
fn parse_pattern(raw: &str, is_last: bool) -> Result<(Pat, Option<usize>), String> {
    if !raw.starts_with('{') {
        if raw.contains('{') || raw.contains('}') {
            return Err(format!("malformed pattern `{raw}`"));
        }
        return Ok((Pat::Lit(raw.to_string()), None));
    }
    let (body, repeat) = if let Some(b) = raw.strip_suffix("}+") {
        (b, Some(1))
    } else if let Some(b) = raw.strip_suffix("}*") {
        (b, Some(0))
    } else if let Some(b) = raw.strip_suffix('}') {
        (b, None)
    } else {
        return Err(format!("malformed pattern `{raw}`"));
    };
    if repeat.is_some() && !is_last {
        return Err(format!("`{raw}`: only the last pattern may repeat"));
    }
    let body = &body[1..];
    let pat = match body.split_once(':') {
        None => match body {
            "word" => Pat::Word,
            "pkg" => Pat::Pkg,
            "unit" => Pat::Unit,
            "int" => Pat::Int,
            "any" => Pat::Any,
            _ => return Err(format!("unknown pattern `{raw}`")),
        },
        Some(("opt", set)) => {
            let items: Vec<String> = set.split('|').map(str::to_string).collect();
            if items.iter().any(String::is_empty) {
                return Err(format!("`{raw}`: empty alternative"));
            }
            Pat::OneOf(items)
        }
        Some(("path", prefix)) => {
            let prefix = prefix.trim_end_matches('/');
            let prefix = if prefix.is_empty() { "/" } else { prefix };
            if !prefix.starts_with('/') || prefix.split('/').any(|c| c == "..") {
                return Err(format!("`{raw}`: prefix must be absolute"));
            }
            if FORBIDDEN_PATH_PREFIXES.contains(&prefix) {
                return Err(format!("`{raw}`: prefix is too broad"));
            }
            Pat::Path(prefix.to_string())
        }
        _ => return Err(format!("unknown pattern `{raw}`")),
    };
    Ok((pat, repeat))
}

fn build_rule(raw: RawRule) -> Result<Rule, String> {
    let ctx = |msg: String| format!("rule `{}`: {msg}", raw.id);
    if raw.id.is_empty() {
        return Err("rule with empty id".to_string());
    }
    if !raw.bin.starts_with('/') || raw.bin.split('/').any(|c| c == "..") {
        return Err(ctx(format!("bin `{}` must be an absolute path", raw.bin)));
    }

    // Requests are compared by canonical path, so a rule on /bin/x must also
    // apply on a merged-usr system where the real file is /usr/bin/x.
    let real = std::fs::canonicalize(&raw.bin)
        .ok()
        .and_then(|p| p.to_str().map(str::to_string));
    let bin = match &real {
        Some(r) if basename(r) == basename(&raw.bin) => r.clone(),
        _ => raw.bin.clone(),
    };

    let elevating = matches!(raw.action, Action::Allow | Action::Envelope);
    if elevating {
        let real_name = real.as_deref().map(basename).unwrap_or("");
        if is_shell_equivalent(basename(&raw.bin)) || is_shell_equivalent(real_name) {
            return Err(ctx(format!(
                "{} can run arbitrary code as root and cannot be auto-elevated; use `ask`",
                raw.bin
            )));
        }
    }

    let mut fixed = Vec::with_capacity(raw.args.len());
    let mut tail = None;
    let count = raw.args.len();
    for (i, item) in raw.args.iter().enumerate() {
        let (pat, repeat) = parse_pattern(item, i + 1 == count).map_err(&ctx)?;
        if elevating && pat == Pat::Any {
            return Err(ctx(
                "`{any}` would let any argument reach a root process; use a typed pattern"
                    .to_string(),
            ));
        }
        match repeat {
            Some(min) => tail = Some((pat, min)),
            None => fixed.push(pat),
        }
    }
    Ok(Rule {
        id: raw.id,
        action: raw.action,
        bin,
        fixed,
        tail,
    })
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub mode: Mode,
    pub require_tty: bool,
    pub ml: MlConfig,
    pub network: NetworkConfig,
    pub approval: ApprovalConfig,
    pub rules: Vec<Rule>,
    /// Identifies the exact policy text in audit records.
    pub fingerprint: u64,
}

/// The rule that decides each action class for one request.
#[derive(Debug, Default, Clone, Copy)]
pub struct Matches<'a> {
    pub deny: Option<&'a Rule>,
    pub ask: Option<&'a Rule>,
    pub allow: Option<&'a Rule>,
    pub envelope: Option<&'a Rule>,
    pub user: Option<&'a Rule>,
}

impl Policy {
    pub fn parse(text: &str) -> Result<Policy, String> {
        let raw: RawPolicy = toml::from_str(text).map_err(|e| e.to_string())?;
        if raw.version != 1 {
            return Err(format!("unsupported policy version {}", raw.version));
        }
        let MlConfig { low, high, .. } = raw.ml;
        // The negated forms also reject NaN.
        if !(0.0..=1.0).contains(&high) || low.is_some_and(|low| !(0.0..=1.0).contains(&low) || !(low <= high)) {
            return Err("ml thresholds must satisfy 0 <= low <= high <= 1".to_string());
        }
        if raw.approval.attempts == 0 || raw.approval.attempts > 10 {
            return Err("approval.attempts must be between 1 and 10".to_string());
        }
        let mut seen = BTreeSet::new();
        let mut rules = Vec::with_capacity(raw.rules.len());
        for rule in raw.rules {
            if !seen.insert(rule.id.clone()) {
                return Err(format!("duplicate rule id `{}`", rule.id));
            }
            rules.push(build_rule(rule)?);
        }
        Ok(Policy {
            mode: raw.mode,
            require_tty: raw.require_tty,
            ml: raw.ml,
            network: raw.network,
            approval: raw.approval,
            rules,
            fingerprint: fnv1a64(text.as_bytes()),
        })
    }

    pub fn load(path: &Path) -> Result<Policy, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Policy::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Loads a policy only if no non-root user could have changed it.
    pub fn load_trusted(path: &Path) -> Result<Policy, String> {
        verify_trusted_file(path)?;
        Policy::load(path)
    }

    pub fn match_rules(&self, req: &Request) -> Matches<'_> {
        let mut m = Matches::default();
        for rule in &self.rules {
            if !rule.matches(req) {
                continue;
            }
            let slot = match rule.action {
                Action::Deny => &mut m.deny,
                Action::Ask => &mut m.ask,
                Action::Allow => &mut m.allow,
                Action::Envelope => &mut m.envelope,
                Action::User => &mut m.user,
            };
            slot.get_or_insert(rule);
        }
        m
    }

    /// Command names the shell integration should route through TrustAuto.
    /// Deny rules are left out: wrapping `rm` to deny it would also block a
    /// user's ordinary, unprivileged `rm`.
    pub fn wrapper_names(&self) -> Vec<String> {
        let names: BTreeSet<&str> = self
            .rules
            .iter()
            .filter(|r| r.action != Action::Deny)
            .map(|r| basename(&r.bin))
            .collect();
        names.into_iter().map(str::to_string).collect()
    }
}

/// The policy text with a new mode and, if given, `ml.judge_unknown`. Only those
/// lines change, so comments and rules stay as the operator wrote them. The
/// result must parse, or nothing is returned.
pub fn with_mode(text: &str, mode: Mode, judge_unknown: Option<bool>) -> Result<String, String> {
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let header = |l: &str| l.trim_start().starts_with('[');
    let key_is = |l: &str, key: &str| {
        let t = l.trim_start();
        t.strip_prefix(key).is_some_and(|rest| rest.trim_start().starts_with('='))
    };
    let top_end = lines.iter().position(|l| header(l)).unwrap_or(lines.len());
    let new_mode = format!("mode = \"{}\"", mode.as_str());
    match lines[..top_end].iter().position(|l| key_is(l, "mode")) {
        Some(i) => lines[i] = new_mode,
        None => lines.insert(top_end, new_mode),
    }
    if let Some(judge) = judge_unknown {
        let setting = format!("judge_unknown = {judge}");
        let ml = lines.iter().position(|l| l.trim() == "[ml]");
        match ml {
            Some(start) => {
                let end = lines[start + 1..].iter().position(|l| header(l)).map_or(lines.len(), |i| start + 1 + i);
                match lines[start + 1..end].iter().position(|l| key_is(l, "judge_unknown")) {
                    Some(i) => lines[start + 1 + i] = setting,
                    None => lines.insert(start + 1, setting),
                }
            }
            None => {
                lines.push(String::new());
                lines.push("[ml]".to_string());
                lines.push(setting);
            }
        }
    }
    let mut out = lines.join("\n");
    out.push('\n');
    let parsed = Policy::parse(&out)?;
    if parsed.mode != mode || judge_unknown.is_some_and(|j| parsed.ml.judge_unknown != j) {
        return Err("could not change the mode in this policy file".to_string());
    }
    Ok(out)
}

#[cfg(test)]
mod mode_tests {
    use super::*;

    const SAMPLE: &str = include_str!("../config/policy.toml");

    #[test]
    fn with_mode_changes_only_the_mode_and_judge_lines() {
        let out = with_mode(SAMPLE, Mode::Ml, Some(true)).unwrap();
        let p = Policy::parse(&out).unwrap();
        assert_eq!(p.mode, Mode::Ml);
        assert!(p.ml.judge_unknown);
        assert_eq!(p.rules.len(), Policy::parse(SAMPLE).unwrap().rules.len());
        let changed = SAMPLE.lines().zip(out.lines()).filter(|(a, b)| a != b).count();
        assert_eq!(changed, 2);
        assert!(out.contains("# Change it with: sudo trustauto mode"));
        let back = with_mode(&out, Mode::Rule, None).unwrap();
        assert_eq!(Policy::parse(&back).unwrap().mode, Mode::Rule);
        assert!(Policy::parse(&back).unwrap().ml.judge_unknown, "judge_unknown is kept when not given");
    }

    #[test]
    fn with_mode_adds_missing_lines() {
        let out = with_mode("version = 1\nmode = \"rule\"\n", Mode::Ml, Some(false)).unwrap();
        let p = Policy::parse(&out).unwrap();
        assert_eq!(p.mode, Mode::Ml);
        assert!(!p.ml.judge_unknown);
        let out = with_mode("version = 1\nmode = \"rule\"\n[ml]\nhigh = 0.5\n", Mode::Ml, Some(true)).unwrap();
        assert!(Policy::parse(&out).unwrap().ml.judge_unknown);
        assert!((Policy::parse(&out).unwrap().ml.high - 0.5).abs() < 1e-6);
    }

    #[test]
    fn with_mode_refuses_a_broken_file() {
        assert!(with_mode("version = 1\nmode = \"rule\"\nnonsense\n", Mode::Ml, None).is_err());
    }
}

