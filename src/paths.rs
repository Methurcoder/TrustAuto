//! Fixed locations and trusted path resolution. None of this reads the caller's
//! PATH or any other caller-controlled setting.

use crate::request::basename;
use std::fmt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub const POLICY_PATH: &str = "/etc/trustauto/policy.toml";
pub const AUDIT_PATH: &str = "/var/log/trustauto/audit.jsonl";
pub const BROKER_PATH: &str = "/usr/lib/trustauto/trustauto-broker";
pub const GROUP_NAME: &str = "trustauto";
pub const PAM_SERVICE: &str = "trustauto";

pub const SECURE_PATH: &[&str] = &[
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
];
pub const SECURE_PATH_ENV: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    NotFound(String),
    RelativePath(String),
    /// A symlink to a differently named binary. Multi-call programs choose
    /// their behaviour from argv[0], so a rule on the real name would not
    /// describe what actually runs.
    Alias { requested: String, real: String },
    Untrusted(String),
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResolveError::NotFound(n) => write!(f, "{n}: not found in the secure path"),
            ResolveError::RelativePath(n) => {
                write!(f, "{n}: relative paths cannot be elevated")
            }
            ResolveError::Alias { requested, real } => write!(
                f,
                "{requested} is an alias of {real}: call the real name explicitly"
            ),
            ResolveError::Untrusted(why) => write!(f, "untrusted binary: {why}"),
        }
    }
}

/// Resolves a command to a canonical, root-controlled executable.
pub fn resolve_binary(name: &str) -> Result<String, ResolveError> {
    let found: PathBuf = if name.contains('/') {
        if !name.starts_with('/') {
            return Err(ResolveError::RelativePath(name.to_string()));
        }
        PathBuf::from(name)
    } else {
        if name.is_empty() {
            return Err(ResolveError::NotFound(name.to_string()));
        }
        SECURE_PATH
            .iter()
            .map(|dir| Path::new(dir).join(name))
            .find(|p| p.is_file())
            .ok_or_else(|| ResolveError::NotFound(name.to_string()))?
    };

    let canonical = found
        .canonicalize()
        .map_err(|_| ResolveError::NotFound(name.to_string()))?;
    let canonical = canonical
        .to_str()
        .ok_or_else(|| ResolveError::Untrusted("path is not valid UTF-8".to_string()))?
        .to_string();

    if basename(&canonical) != basename(name) {
        return Err(ResolveError::Alias {
            requested: name.to_string(),
            real: canonical,
        });
    }
    verify_trusted_file(Path::new(&canonical)).map_err(ResolveError::Untrusted)?;
    let mode = std::fs::metadata(&canonical)
        .map_err(|e| ResolveError::Untrusted(e.to_string()))?
        .mode();
    if mode & 0o111 == 0 {
        return Err(ResolveError::Untrusted(format!(
            "{canonical} is not executable"
        )));
    }
    Ok(canonical)
}

fn writable_by_others(meta: &std::fs::Metadata) -> bool {
    let mode = meta.mode();
    mode & 0o002 != 0 || (mode & 0o020 != 0 && meta.gid() != 0)
}

/// Requires a root-owned regular file whose whole directory chain only root
/// can modify. With that chain in place, a non-root caller cannot swap the file
/// between this check and its use.
pub fn verify_trusted_file(path: &Path) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.file_type().is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if meta.uid() != 0 || writable_by_others(&meta) {
        return Err(format!(
            "{} must be owned by root and not writable by others",
            path.display()
        ));
    }
    let mut dir = path.parent();
    while let Some(d) = dir {
        let meta = std::fs::symlink_metadata(d).map_err(|e| format!("{}: {e}", d.display()))?;
        if meta.file_type().is_symlink() {
            return Err(format!("{} is a symlink", d.display()));
        }
        if meta.uid() != 0 || writable_by_others(&meta) {
            return Err(format!(
                "{} must be owned by root and not writable by others",
                d.display()
            ));
        }
        dir = d.parent();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_relative_names_with_slash() {
        assert!(matches!(
            resolve_binary("./x"),
            Err(ResolveError::RelativePath(_))
        ));
        assert!(matches!(
            resolve_binary("bin/x"),
            Err(ResolveError::RelativePath(_))
        ));
    }

    #[test]
    fn rejects_missing() {
        assert!(matches!(
            resolve_binary("trustauto-does-not-exist"),
            Err(ResolveError::NotFound(_))
        ));
        assert!(matches!(resolve_binary(""), Err(ResolveError::NotFound(_))));
    }

    #[test]
    fn rejects_user_owned_binary() {
        let dir = std::env::temp_dir().join(format!("ta-path-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("tool");
        std::fs::write(&file, "#!/bin/sh\n").unwrap();
        let got = resolve_binary(file.to_str().unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
        // When the suite runs as root the file is root-owned, but the temp
        // directory is still world-writable through its parent.
        assert!(matches!(got, Err(ResolveError::Untrusted(_))), "{got:?}");
    }

    #[test]
    fn accepts_system_binary() {
        assert!(resolve_binary("/bin/ls").is_ok() || resolve_binary("/usr/bin/ls").is_ok());
    }

    #[test]
    fn rejects_symlink_alias() {
        let dir = std::env::temp_dir().join(format!("ta-alias-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let link = dir.join("innocent");
        std::os::unix::fs::symlink("/bin/ls", &link).unwrap();
        let got = resolve_binary(link.to_str().unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(matches!(got, Err(ResolveError::Alias { .. })), "{got:?}");
    }
}
