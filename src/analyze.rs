//! Static checks on a request. These lists catch mistakes and known bypasses,
//! but they are not the security boundary and cannot be complete. The boundary
//! is the default-deny typed rule match in `policy`.

use crate::request::Request;

/// Programs that can run arbitrary code or overwrite arbitrary files as root,
/// so an automatic rule on them amounts to giving away a root shell.
const SHELL_EQUIVALENT: &[&str] = &[
    // Shells and interpreters
    "sh", "bash", "dash", "zsh", "ksh", "mksh", "fish", "csh", "tcsh", "ash", "busybox", "awk",
    "gawk", "mawk", "nawk", "sed", "gsed", "tclsh", "expect", "deno", "bun", "m4",
    // Editors and pagers with shell escapes
    "vi", "vim", "vim.basic", "vim.tiny", "nvim", "view", "nano", "emacs", "ed", "ex", "less",
    "more", "most", "man", "pager",
    // Elevation and process launchers
    "sudo", "su", "doas", "pkexec", "env", "nice", "ionice", "nohup", "setsid", "timeout", "time",
    "xargs", "watch", "strace", "ltrace", "gdb", "script", "screen", "tmux", "chroot", "unshare",
    "nsenter", "systemd-run", "systemd-nspawn", "run-parts", "start-stop-daemon", "capsh", "setpriv",
    "trustauto", "trustauto-broker",
    // File writers and permission changers
    "cp", "mv", "dd", "tee", "install", "ln", "rsync", "chmod", "chown", "chgrp", "setfacl",
    "setcap", "truncate", "mount", "umount", "tar", "cpio", "zip", "unzip", "find",
    // Network tools that can launch commands or fetch files into place
    "ssh", "scp", "sftp", "nc", "ncat", "netcat", "socat", "curl", "wget", "ftp", "telnet",
    // Build tools and package managers that run project code
    "git", "make", "cmake", "gcc", "g++", "cc", "c++", "clang", "ld", "cargo", "go", "rustc", "pip",
    "pip3", "npm", "npx", "yarn", "pnpm", "gem", "dpkg", "rpm", "docker", "podman", "lxc",
    // Account and system-execution configuration
    "visudo", "passwd", "chpasswd", "useradd", "usermod", "userdel", "groupadd", "groupmod",
    "crontab", "at", "batch", "insmod", "modprobe", "rmmod", "kexec", "sysctl",
];

/// Language runtimes commonly installed under a versioned name.
const VERSIONED_RUNTIMES: &[&str] = &["python", "pypy", "perl", "ruby", "lua", "php", "node", "nodejs"];

pub fn is_shell_equivalent(name: &str) -> bool {
    if SHELL_EQUIVALENT.contains(&name) {
        return true;
    }
    VERSIONED_RUNTIMES.iter().any(|runtime| {
        name.strip_prefix(runtime)
            .is_some_and(|v| v.bytes().all(|b| b.is_ascii_digit() || b == b'.'))
    })
}

const SENSITIVE_PATHS: &[&str] = &[
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/passwd",
    "/etc/group",
    "/etc/pam.d",
    "/etc/ssh",
    "/etc/cron",
    "/etc/systemd",
    "/etc/ld.so",
    "/etc/trustauto",
    "/usr/lib/trustauto",
    "/var/log/trustauto",
    "/root",
    "/boot",
    "/dev/sd",
    "/dev/nvme",
    "/dev/vd",
    "/dev/mem",
    "/proc/sys",
    "/sys/",
    "/.ssh",
];

const EXECUTION_TOKENS: &[&str] = &[
    "-exec",
    "-execdir",
    "-ok",
    "--checkpoint-action",
    "--to-command",
    "--use-compress-program",
    "--rsh-command",
    "--rcfile",
    "--init-file",
    "--command",
    "core.pager",
    "core.sshcommand",
    "pre-invoke",
    "post-invoke",
    "dpkg::",
    "ld_preload",
];

/// Reasons this request must not elevate automatically, even when a rule
/// allows it. A broken rule can therefore fall back to Ask, never to more access.
pub fn hard_guard(req: &Request) -> Vec<String> {
    let mut reasons = Vec::new();
    if is_shell_equivalent(req.basename()) {
        reasons.push(format!("{} can run arbitrary code as root", req.basename()));
    }
    for arg in &req.args {
        if let Some(path) = SENSITIVE_PATHS.iter().find(|p| arg.contains(**p)) {
            reasons.push(format!("argument touches sensitive path {path}"));
        }
        let lower = arg.to_ascii_lowercase();
        // Options must match as whole options, so a package like `foo-ok` is unaffected.
        let found = EXECUTION_TOKENS.iter().find(|t| {
            if t.starts_with('-') {
                lower.strip_prefix(**t).is_some_and(|r| r.is_empty() || r.starts_with('='))
            } else {
                lower.contains(**t)
            }
        });
        if let Some(tok) = found {
            reasons.push(format!("argument contains execution option {tok}"));
        }
        if arg.chars().any(|c| ";|&$`<>\n\r".contains(c) || c.is_control()) {
            reasons.push("argument contains shell metacharacters".to_string());
        }
    }
    reasons
}

/// Programs whose effect the lab could not observe, so the model never learned
/// them: they run other code, edit interactively, reach other machines, or act
/// on the kernel, boot or block devices. ML-only mode never elevates them.
const OPAQUE: &[&str] = &[
    "sh", "bash", "dash", "zsh", "ksh", "mksh", "fish", "csh", "tcsh", "ash", "busybox", "awk", "gawk",
    "mawk", "nawk", "sed", "gsed", "tclsh", "expect", "deno", "bun", "m4", "vi", "vim", "vim.basic",
    "vim.tiny", "nvim", "view", "nano", "emacs", "ed", "ex", "less", "more", "most", "man", "pager",
    "sudo", "su", "doas", "pkexec", "env", "nice", "ionice", "nohup", "setsid", "timeout", "time",
    "xargs", "watch", "strace", "ltrace", "gdb", "script", "screen", "tmux", "chroot", "unshare",
    "nsenter", "systemd-run", "systemd-nspawn", "run-parts", "start-stop-daemon", "capsh", "setpriv",
    "trustauto", "trustauto-broker", "ssh", "scp", "sftp", "nc", "ncat", "netcat", "socat", "curl",
    "wget", "ftp", "telnet", "git", "make", "cmake", "gcc", "g++", "cc", "c++", "clang", "ld", "cargo",
    "go", "rustc", "pip", "pip3", "npm", "npx", "yarn", "pnpm", "gem", "docker", "podman", "lxc",
    "visudo", "crontab", "at", "batch", "insmod", "modprobe", "rmmod", "kexec", "mount", "umount",
    "fstrim", "fdisk", "sfdisk", "gdisk", "parted", "wipefs", "losetup", "cryptsetup", "dd",
    "grub-install", "update-grub", "update-initramfs", "efibootmgr", "vipw", "vigr", "sudoedit", "edquota",
    "select-editor", "dpkg-reconfigure",
];

pub fn is_opaque(name: &str) -> bool {
    OPAQUE.contains(&name)
        || name.starts_with("mkfs")
        || name.starts_with("mkswap")
        || VERSIONED_RUNTIMES.iter().any(|runtime| {
            name.strip_prefix(runtime)
                .is_some_and(|v| v.bytes().all(|b| b.is_ascii_digit() || b == b'.'))
        })
}

/// What ML-only mode keeps from `hard_guard`: everything except the file tools
/// the model was trained on (`cp`, `chmod`, `tee`, ...).
pub fn ml_alone_guard(req: &Request) -> Vec<String> {
    let mut reasons = Vec::new();
    if is_opaque(req.basename()) {
        reasons.push(format!("{} runs code or reaches places the model was never trained on", req.basename()));
    }
    if req.basename() == "systemctl" && req.args.iter().any(|a| a == "edit") {
        reasons.push("systemctl edit opens an editor as root".to_string());
    }
    reasons.extend(hard_guard(req).into_iter().filter(|r| !r.ends_with("can run arbitrary code as root")));
    reasons
}

/// Subcommands that fetch over the network.
const NETWORK_VERBS: &[(&str, &[&str])] = &[
    ("apt", &["update", "upgrade", "dist-upgrade", "full-upgrade", "install", "reinstall", "download", "source", "build-dep", "changelog"]),
    ("apt-get", &["update", "upgrade", "dist-upgrade", "full-upgrade", "install", "reinstall", "download", "source", "build-dep", "changelog"]),
    ("aptitude", &["update", "upgrade", "safe-upgrade", "full-upgrade", "install", "reinstall", "download"]),
    ("snap", &["install", "refresh", "download", "find"]),
    ("flatpak", &["install", "update", "remote-add", "search"]),
    ("pip", &["install", "download"]),
    ("pip3", &["install", "download"]),
    ("npm", &["install", "i", "ci", "add", "update", "publish"]),
    ("yarn", &["install", "add", "upgrade", "publish"]),
    ("pnpm", &["install", "i", "add", "update", "publish"]),
    ("gem", &["install", "update", "push"]),
    ("cargo", &["install", "update", "fetch", "publish"]),
    ("go", &["get", "install", "mod"]),
    ("git", &["clone", "fetch", "pull", "push", "ls-remote", "submodule", "remote"]),
    ("docker", &["pull", "push", "login", "search", "run", "build"]),
    ("podman", &["pull", "push", "login", "search", "run", "build"]),
    ("fwupdmgr", &["refresh", "update", "get-updates"]),
    ("apt-key", &["adv"]),
];

/// Programs whose job is to talk to other machines.
const NETWORK_PROGRAMS: &[&str] = &[
    "curl", "wget", "ssh", "scp", "sftp", "rsync", "nc", "ncat", "netcat", "socat", "telnet", "ftp",
    "lftp", "ping", "ping6", "traceroute", "tracepath", "mtr", "dig", "nslookup", "host", "whois", "nmap",
    "ntpdate", "add-apt-repository", "sendmail", "mail", "mailx", "mutt", "certbot", "freshclam",
];

const NETWORK_FLAGS: &[&str] = &["--recv-keys", "--receive-keys", "--refresh-keys", "--search-keys", "--send-keys", "--keyserver"];

/// Why this command may send or fetch data over the network, if it may.
pub fn network_reason(req: &Request) -> Option<String> {
    let name = req.basename();
    if NETWORK_PROGRAMS.contains(&name) {
        return Some(format!("{name} talks to other machines"));
    }
    let verb = req.args.iter().find(|a| !a.starts_with('-'));
    if let (Some((_, verbs)), Some(verb)) = (NETWORK_VERBS.iter().find(|(p, _)| *p == name), verb) {
        if verbs.contains(&verb.as_str()) {
            return Some(format!("`{name} {verb}` downloads or uploads over the network"));
        }
    }
    for arg in &req.args {
        let lower = arg.to_ascii_lowercase();
        let flag = lower.split('=').next().unwrap_or("");
        if lower.contains("://") || lower.starts_with("git@") || NETWORK_FLAGS.contains(&flag) || is_remote_spec(arg) {
            return Some("an argument names a remote location".to_string());
        }
    }
    None
}

/// `user@host:path`, as scp and rsync write it.
fn is_remote_spec(arg: &str) -> bool {
    let Some((left, _)) = arg.split_once(':') else { return false };
    let Some((user, host)) = left.split_once('@') else { return false };
    let ok = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    ok(user) && ok(host) && !arg.starts_with('-')
}

/// Programs whose job is to change something, from the training code's lists
/// (`ALWAYS_CHANGES`, `CHANGING_ACTIONS`, `CHANGING_FLAGS` in train_actions.py).
const ALWAYS_CHANGES: &[&str] = &[
    "pkill", "killall", "kill", "chpasswd", "chgpasswd", "newusers", "sulogin", "rm", "truncate", "mv", "chmod",
    "chown", "chgrp", "ln", "mkdir", "touch", "tee", "update-rc.d", "kernel-install", "phpenmod", "phpdismod",
    "mkhomedir_helper", "hardlink", "locale-gen", "zforce", "mariadb-install-db", "nft", "systemd-firstboot",
    "systemd-sysusers", "systemd-tmpfiles", "redis-server", "mosquitto", "eject", "service", "cp", "rmdir",
    "useradd", "usermod", "userdel", "groupadd", "groupmod", "groupdel", "passwd", "hostname", "setcap",
];
const CHANGING_ACTIONS: &[(&str, &[&str])] = &[
    ("systemctl", &["start", "stop", "restart", "reload", "enable", "disable", "mask", "unmask", "kill", "isolate", "log-level", "daemon-reload", "poweroff", "reboot", "halt", "set-default", "edit"]),
    ("apt", &["install", "remove", "purge", "upgrade", "dist-upgrade", "full-upgrade", "autoremove", "update", "reinstall"]),
    ("apt-get", &["install", "remove", "purge", "upgrade", "dist-upgrade", "full-upgrade", "autoremove", "update", "reinstall", "clean"]),
    ("apachectl", &["start", "stop", "restart", "graceful"]),
    ("apache2ctl", &["start", "stop", "restart", "graceful"]),
    ("postfix", &["start", "stop", "reload"]),
    ("apt-mark", &["hold", "unhold", "auto", "manual"]),
    ("systemd-sysext", &["merge", "unmerge", "refresh"]),
    ("systemd-cryptsetup", &["attach", "detach"]),
    ("ip", &["add", "del", "delete", "set", "flush", "change", "replace"]),
];
const CHANGING_FLAGS: &[(&str, &[&str])] = &[
    ("sysctl", &["-w", "--write"]),
    ("faillock", &["--reset"]),
    ("nginx", &["-s"]),
    ("ldconfig", &["-n"]),
    ("update-alternatives", &["--remove", "--remove-all", "--install", "--set", "--auto"]),
];
const INFORMATION_FLAGS: &[&str] = &["--help", "--version", "--list", "--dry-run", "--cat-config"];

/// Whether the command's job is to change something on the machine.
pub fn asks_for_change(name: &str, args: &[String]) -> bool {
    if args.iter().any(|a| INFORMATION_FLAGS.contains(&a.as_str())) {
        return false;
    }
    if ALWAYS_CHANGES.contains(&name) {
        return true;
    }
    if let Some((_, verbs)) = CHANGING_ACTIONS.iter().find(|(p, _)| *p == name) {
        // `ip` puts its verb after the object (`ip link set`), so any word counts.
        return args.iter().filter(|a| !a.starts_with('-')).take(if name == "ip" { 3 } else { 1 }).any(|a| verbs.contains(&a.as_str()));
    }
    if let Some((_, flags)) = CHANGING_FLAGS.iter().find(|(p, _)| *p == name) {
        return args.iter().any(|a| flags.contains(&a.split('=').next().unwrap_or("")));
    }
    matches!(name, "hostnamectl" | "timedatectl" | "localectl")
        && args.iter().find(|a| !a.starts_with('-')).is_some_and(|a| a.starts_with("set-"))
}

/// Programs whose job is to change something, whatever the arguments.
pub fn changes_things(name: &str) -> bool {
    ALWAYS_CHANGES.contains(&name)
        || CHANGING_ACTIONS.iter().any(|(p, _)| *p == name)
        || CHANGING_FLAGS.iter().any(|(p, _)| *p == name)
        || matches!(name, "hostnamectl" | "timedatectl" | "localectl")
}

pub const SBIN_DIRS: &[&str] = &["/usr/sbin/", "/sbin/", "/usr/local/sbin/"];

/// Whether the command plausibly needs root: a system-administration program,
/// a change to the system, or a path the caller cannot read (or write, for a
/// change). Checked with the caller's real uid, so the setuid broker gives the
/// same answer as the front end. A heuristic: it only decides whether ML-only
/// mode is consulted at all; everything it lets through still faces the model.
pub fn needs_root(req: &Request) -> bool {
    let name = req.basename();
    if SBIN_DIRS.iter().any(|d| req.bin.starts_with(d)) {
        return true;
    }
    let changes = asks_for_change(name, &req.args);
    let paths: Vec<&String> = req.args.iter().filter(|a| a.starts_with('/')).collect();
    if changes && paths.is_empty() {
        return true;
    }
    paths.iter().any(|p| {
        let path = std::path::Path::new(p.as_str());
        let parent_writable = || path.parent().is_none_or(|d| can(d, libc::W_OK));
        if path.symlink_metadata().is_ok() {
            !can(path, libc::R_OK) || changes && (!can(path, libc::W_OK) || !parent_writable())
        } else {
            changes && !parent_writable()
        }
    })
}

fn can(path: &std::path::Path, mode: libc::c_int) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else { return false };
    unsafe { libc::access(c.as_ptr(), mode) == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::Context;

    fn req(bin: &str, args: &[&str]) -> Request {
        Request {
            bin: bin.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            ctx: Context::quiet(),
        }
    }

    #[test]
    fn versioned_runtimes_are_shell_equivalent() {
        for name in ["python", "python3", "python3.12", "perl5.38", "node", "lua5.4"] {
            assert!(is_shell_equivalent(name), "{name}");
        }
        for name in ["pythonista", "apt", "systemctl", "journalctl", "nodeinfo"] {
            assert!(!is_shell_equivalent(name), "{name}");
        }
    }

    #[test]
    fn guard_flags_known_bypasses() {
        assert!(hard_guard(&req("/usr/bin/apt", &["update"])).is_empty());
        for r in [
            req("/usr/bin/bash", &[]),
            req("/usr/bin/tool", &["/etc/shadow"]),
            req("/usr/bin/tool", &["--file=/etc/sudoers.d/x"]),
            req("/usr/bin/apt-get", &["-o", "APT::Update::Pre-Invoke::=/bin/sh"]),
            req("/usr/bin/tool", &["--checkpoint-action=exec=sh"]),
            req("/usr/bin/tool", &["a;id"]),
            req("/usr/bin/tool", &["a\nb"]),
        ] {
            assert!(!hard_guard(&r).is_empty(), "{r:?}");
        }
    }
    #[test]
    fn network_commands_are_recognised() {
        for r in [
            req("/usr/bin/apt", &["update"]),
            req("/usr/bin/apt-get", &["-y", "install", "htop"]),
            req("/usr/bin/curl", &["example.com"]),
            req("/usr/bin/tool", &["https://example.com/x"]),
            req("/usr/bin/rsync", &["-a", "dir", "me@host:backup"]),
            req("/usr/bin/gpg", &["--recv-keys", "ABC"]),
        ] {
            assert!(network_reason(&r).is_some(), "{r:?}");
        }
        for r in [
            req("/usr/bin/apt", &["list", "--installed"]),
            req("/usr/bin/systemctl", &["restart", "nginx"]),
            req("/usr/bin/cp", &["a:b", "c"]),
        ] {
            assert!(network_reason(&r).is_none(), "{r:?}");
        }
    }

    #[test]
    fn ml_alone_keeps_file_tools_but_not_interpreters() {
        assert!(ml_alone_guard(&req("/usr/bin/chmod", &["644", "/srv/site/index.html"])).is_empty());
        assert!(!ml_alone_guard(&req("/usr/bin/python3", &["x.py"])).is_empty());
        assert!(!ml_alone_guard(&req("/usr/sbin/mkfs.ext4", &["/tmp/img"])).is_empty());
        assert!(!ml_alone_guard(&req("/usr/bin/chmod", &["644", "/etc/shadow"])).is_empty());
    }

    #[test]
    fn changes_follow_the_training_lists() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(asks_for_change("systemctl", &a(&["restart", "nginx"])));
        assert!(!asks_for_change("systemctl", &a(&["status", "nginx"])));
        assert!(asks_for_change("rm", &a(&["x"])));
        assert!(!asks_for_change("rm", &a(&["--help"])));
        assert!(asks_for_change("hostnamectl", &a(&["set-hostname", "x"])));
        assert!(asks_for_change("ip", &a(&["link", "set", "lo", "down"])));
        assert!(!asks_for_change("ip", &a(&["addr", "show"])));
    }

    #[test]
    fn needs_root_spares_the_callers_own_files() {
        let dir = std::env::temp_dir().join(format!("ta-need-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mine = dir.join("f");
        std::fs::write(&mine, "x").unwrap();
        let mine = mine.to_str().unwrap();
        assert!(!needs_root(&req("/usr/bin/cp", &[mine, "/tmp/ta-copy-test"])));
        assert!(!needs_root(&req("/usr/bin/cat", &[mine])));
        assert!(needs_root(&req("/usr/bin/systemctl", &["restart", "nginx"])));
        assert!(needs_root(&req("/usr/sbin/useradd", &["x"])));
        if unsafe { libc::geteuid() } != 0 {
            assert!(needs_root(&req("/usr/bin/touch", &["/etc/ta-new"])));
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
