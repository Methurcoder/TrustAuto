//! A parsed elevation request: the resolved binary, its exact argv and the
//! environment signals around it. Elevation works on argv, never a shell string.

use std::ffi::OsString;
use std::os::unix::fs::MetadataExt;

/// Environment names that change how programs load code or read config.
const SUSPICIOUS_ENV: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "BASH_ENV",
    "ENV",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PERL5LIB",
    "PERL5OPT",
    "RUBYLIB",
    "RUBYOPT",
    "NODE_OPTIONS",
    "GCONV_PATH",
    "IFS",
];

/// Signals about where the request came from. All of them can only raise risk.
/// Their absence proves nothing, since the caller controls the environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context {
    pub has_tty: bool,
    pub ssh_session: bool,
    pub cwd_unsafe: bool,
    pub suspicious_env: bool,
}

impl Context {
    /// The context with no risk signals set.
    pub fn quiet() -> Self {
        Context {
            has_tty: true,
            ssh_session: false,
            cwd_unsafe: false,
            suspicious_env: false,
        }
    }

    pub fn capture(env: &[(OsString, OsString)]) -> Self {
        let has = |name: &str| env.iter().any(|(k, _)| k == name);
        let path_unsafe = env.iter().any(|(k, v)| {
            k == "PATH"
                && v.to_string_lossy()
                    .split(':')
                    .any(|part| !part.starts_with('/'))
        });
        let cwd_unsafe = std::fs::metadata(".")
            .map(|m| m.mode() & 0o002 != 0)
            .unwrap_or(true);
        Context {
            has_tty: unsafe { libc::isatty(0) == 1 },
            ssh_session: has("SSH_CONNECTION") || has("SSH_TTY"),
            cwd_unsafe,
            suspicious_env: path_unsafe || SUSPICIOUS_ENV.iter().any(|n| has(n)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Canonical absolute path of the binary.
    pub bin: String,
    pub args: Vec<String>,
    pub ctx: Context,
}

impl Request {
    pub fn basename(&self) -> &str {
        basename(&self.bin)
    }

    pub fn display(&self) -> String {
        display_command(&self.bin, &self.args)
    }
}

pub fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Renders untrusted text so it cannot rewrite the terminal or hide its content.
pub fn escape_display(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let invisible = matches!(c as u32,
            0x200B..=0x200F | 0x2028..=0x202E | 0x2060..=0x2069 | 0xFEFF);
        if c.is_control() || invisible {
            out.extend(c.escape_unicode());
        } else if c == '\\' {
            out.push_str("\\\\");
        } else {
            out.push(c);
        }
    }
    out
}

/// A one-line command for approval prompts. Quotes arguments so that word
/// boundaries stay visible.
pub fn display_command(bin: &str, args: &[String]) -> String {
    let mut out = escape_display(bin);
    for arg in args {
        out.push(' ');
        let needs_quotes = arg.is_empty()
            || arg
                .chars()
                .any(|c| c.is_whitespace() || "'\"$`;|&<>()*?[]{}#~!".contains(c));
        if needs_quotes {
            out.push('\'');
            out.push_str(&escape_display(arg).replace('\'', "'\\''"));
            out.push('\'');
        } else {
            out.push_str(&escape_display(arg));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_hides_nothing() {
        assert_eq!(escape_display("a\x1b[2Kb"), "a\\u{1b}[2Kb");
        assert_eq!(escape_display("a\nb"), "a\\u{a}b");
        assert_eq!(escape_display("x\u{202e}y"), "x\\u{202e}y");
        assert_eq!(escape_display("日本語"), "日本語");
    }

    #[test]
    fn display_keeps_word_boundaries() {
        let args = vec!["a b".to_string(), "".to_string(), "c".to_string()];
        assert_eq!(display_command("/bin/x", &args), "/bin/x 'a b' '' c");
    }

    #[test]
    fn capture_flags_relative_path_entries() {
        let env = vec![(OsString::from("PATH"), OsString::from("/usr/bin::.")) ];
        assert!(Context::capture(&env).suspicious_env);
        let env = vec![(OsString::from("PATH"), OsString::from("/usr/bin:/bin"))];
        assert!(!Context::capture(&env).suspicious_env);
    }
}
