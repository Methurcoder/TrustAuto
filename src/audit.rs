//! Append-only JSON Lines audit log, written before any elevation happens.
//! Every field that came from the caller is escaped, so an argument cannot
//! forge a line or a field.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Entry<'a> {
    pub ts: u64,
    pub uid: u32,
    pub user: &'a str,
    /// decision, approved, approval_failed, exec_failed
    pub event: &'a str,
    pub tty: &'a str,
    pub cwd: &'a str,
    pub mode: &'a str,
    pub bin: &'a str,
    pub args: &'a [String],
    pub verdict: &'a str,
    pub rule: Option<&'a str>,
    pub ml: Option<f32>,
    pub reasons: &'a [String],
    pub approver: Option<&'a str>,
    pub policy_fnv: u64,
    pub model_fnv: Option<u64>,
}

pub fn json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn json_list(out: &mut String, items: &[String]) {
    out.push('[');
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        json_string(out, item);
    }
    out.push(']');
}

fn field(out: &mut String, key: &str, value: &str) {
    out.push_str(",\"");
    out.push_str(key);
    out.push_str("\":");
    json_string(out, value);
}

impl Entry<'_> {
    /// `ts` and `uid` always come first, which is what `line_uid` relies on.
    pub fn to_line(&self) -> String {
        let mut out = String::with_capacity(256);
        out.push_str(&format!("{{\"ts\":{},\"uid\":{}", self.ts, self.uid));
        field(&mut out, "user", self.user);
        field(&mut out, "event", self.event);
        field(&mut out, "tty", self.tty);
        field(&mut out, "cwd", self.cwd);
        field(&mut out, "mode", self.mode);
        field(&mut out, "bin", self.bin);
        out.push_str(",\"args\":");
        json_list(&mut out, self.args);
        field(&mut out, "verdict", self.verdict);
        if let Some(rule) = self.rule {
            field(&mut out, "rule", rule);
        }
        if let Some(ml) = self.ml {
            // JSON has no NaN.
            let value = if ml.is_finite() {
                format!("{ml:.4}")
            } else {
                "null".to_string()
            };
            out.push_str(&format!(",\"ml\":{value}"));
        }
        out.push_str(",\"reasons\":");
        json_list(&mut out, self.reasons);
        if let Some(approver) = self.approver {
            field(&mut out, "approver", approver);
        }
        out.push_str(&format!(",\"policy\":\"{:016x}\"", self.policy_fnv));
        if let Some(model) = self.model_fnv {
            out.push_str(&format!(",\"model\":\"{model:016x}\""));
        }
        out.push_str("}\n");
        out
    }
}

/// Reads the owning uid from a line produced by `to_line`.
pub fn line_uid(line: &str) -> Option<u32> {
    let rest = line.strip_prefix("{\"ts\":")?;
    let (ts, rest) = rest.split_once(',')?;
    if !ts.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let rest = rest.strip_prefix("\"uid\":")?;
    let (uid, _) = rest.split_once(',')?;
    uid.parse().ok()
}

/// Appends one record in a single write. The caller must treat an error as
/// "do not elevate".
pub fn append(path: &Path, entry: &Entry) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o640)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.file_type().is_file() || meta.nlink() != 1 {
        return Err(std::io::Error::other("audit log is not a plain file"));
    }
    file.write_all(entry.to_line().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample<'a>(args: &'a [String], reasons: &'a [String]) -> Entry<'a> {
        Entry {
            ts: 1700000000,
            uid: 1000,
            user: "alice",
            event: "decision",
            tty: "/dev/pts/0",
            cwd: "/home/alice",
            mode: "hybrid",
            bin: "/usr/bin/apt",
            args,
            verdict: "ask",
            rule: None,
            ml: Some(0.5),
            reasons,
            approver: None,
            policy_fnv: 1,
            model_fnv: Some(2),
        }
    }

    #[test]
    fn an_argument_cannot_forge_a_record() {
        let args = vec!["x\n{\"ts\":1,\"uid\":0,\"event\":\"approved\"}".to_string()];
        let reasons = vec!["a\"b\u{1b}c".to_string()];
        let line = sample(&args, &reasons).to_line();
        assert_eq!(line.matches('\n').count(), 1);
        assert!(line.ends_with('\n'));
        assert!(line.contains("\\\"uid\\\":0"));
        assert!(line.contains("\\u001b"));
        assert_eq!(line_uid(&line), Some(1000));
    }

    #[test]
    fn non_finite_score_stays_valid_json() {
        let args = Vec::new();
        let reasons = Vec::new();
        let mut entry = sample(&args, &reasons);
        entry.ml = Some(f32::NAN);
        assert!(entry.to_line().contains("\"ml\":null"));
    }

    #[test]
    fn line_uid_rejects_garbage() {
        assert_eq!(line_uid("not json"), None);
        assert_eq!(line_uid("{\"ts\":x,\"uid\":0,"), None);
    }

    #[test]
    fn append_refuses_symlink() {
        let dir = std::env::temp_dir().join(format!("ta-audit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target");
        std::fs::write(&target, "").unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let args = Vec::new();
        let reasons = Vec::new();
        let entry = sample(&args, &reasons);
        assert!(append(&link, &entry).is_err());
        let log = dir.join("audit.jsonl");
        append(&log, &entry).unwrap();
        append(&log, &entry).unwrap();
        let text = std::fs::read_to_string(&log).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(text.lines().count(), 2);
    }
}
