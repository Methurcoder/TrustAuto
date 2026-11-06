//! Process-level hardening and identity handling for the setuid broker.

use crate::paths::SECURE_PATH_ENV;
use std::ffi::{CStr, CString, OsString};
use std::io;

const NAME_BUF: usize = 16 * 1024;

pub struct Identity {
    pub uid: u32,
    pub euid: u32,
    gid: u32,
    groups: Vec<u32>,
}

impl Identity {
    pub fn capture() -> Identity {
        let mut groups = vec![0 as libc::gid_t; 4096];
        let n = unsafe { libc::getgroups(groups.len() as libc::c_int, groups.as_mut_ptr()) };
        groups.truncate(n.max(0) as usize);
        Identity {
            uid: unsafe { libc::getuid() },
            euid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getgid() },
            groups,
        }
    }

    pub fn in_group(&self, gid: u32) -> bool {
        self.gid == gid || self.groups.contains(&gid)
    }
}

/// Closes everything above stderr. Never needs the fd table to be readable, and
/// works even when the caller set RLIMIT_NOFILE low.
pub fn close_inherited_fds() {
    let rc = unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) };
    if rc != 0 {
        for fd in 3..65536 {
            unsafe { libc::close(fd) };
        }
    }
}

/// Sets real, effective and saved ids to root. Afterwards the caller's uid no
/// longer matches, so it cannot send this process signals.
pub fn become_root() -> io::Result<()> {
    let groups: [libc::gid_t; 1] = [0];
    let checks = unsafe {
        [
            libc::setgroups(1, groups.as_ptr()),
            libc::setresgid(0, 0, 0),
            libc::setresuid(0, 0, 0),
        ]
    };
    if checks.iter().any(|rc| *rc != 0) {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::getuid() != 0 || libc::geteuid() != 0 || libc::getgid() != 0 } {
        return Err(io::Error::other("identity change did not take effect"));
    }
    Ok(())
}

pub fn reset_signals() {
    unsafe {
        for sig in 1..=64 {
            libc::signal(sig, libc::SIG_DFL);
        }
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigprocmask(libc::SIG_SETMASK, &set, std::ptr::null_mut());
    }
}

/// Undoes what the caller could set up to make a root process misbehave: a tiny
/// RLIMIT_FSIZE that truncates the audit log, blocked signals, a strange umask.
pub fn reset_process_state() -> io::Result<()> {
    let inf = libc::RLIM_INFINITY;
    let limits = [
        (libc::RLIMIT_CORE, 0, 0),
        (libc::RLIMIT_FSIZE, inf, inf),
        (libc::RLIMIT_CPU, inf, inf),
        (libc::RLIMIT_DATA, inf, inf),
        (libc::RLIMIT_AS, inf, inf),
        (libc::RLIMIT_NPROC, inf, inf),
        (libc::RLIMIT_MEMLOCK, 64 * 1024 * 1024, 64 * 1024 * 1024),
        (libc::RLIMIT_NOFILE, 4096, 4096),
        (libc::RLIMIT_STACK, 8 * 1024 * 1024, inf),
    ];
    for (resource, soft, hard) in limits {
        let limit = libc::rlimit {
            rlim_cur: soft,
            rlim_max: hard,
        };
        if unsafe { libc::setrlimit(resource, &limit) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    unsafe {
        libc::umask(0o022);
        // Password handling must not end up in a core dump or be ptrace-readable.
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        libc::prctl(libc::PR_SET_PDEATHSIG, 0, 0, 0, 0);
    }
    reset_signals();
    Ok(())
}

pub fn username_of(uid: u32) -> Option<String> {
    let mut buf = vec![0u8; NAME_BUF];
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            &mut pwd,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    let name = unsafe { CStr::from_ptr(pwd.pw_name) };
    name.to_str().ok().map(str::to_string)
}

pub fn gid_of(group: &str) -> Option<u32> {
    let name = CString::new(group).ok()?;
    let mut buf = vec![0u8; NAME_BUF];
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::group = std::ptr::null_mut();
    let rc = unsafe {
        libc::getgrnam_r(
            name.as_ptr(),
            &mut grp,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    Some(grp.gr_gid)
}

pub fn tty_name() -> Option<String> {
    let mut buf = [0u8; 256];
    let rc = unsafe { libc::ttyname_r(0, buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if rc != 0 {
        return None;
    }
    CStr::from_bytes_until_nul(&buf)
        .ok()?
        .to_str()
        .ok()
        .map(str::to_string)
}

fn safe_env_value(value: &str, extra: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
}

/// Builds the child's environment from nothing. Pagers and editors point at
/// harmless programs, because an interactive `!sh` in a root pager is a root shell.
pub fn elevated_env(env: &[(OsString, OsString)], caller: &str) -> Vec<CString> {
    let mut out: Vec<String> = vec![
        format!("PATH={SECURE_PATH_ENV}"),
        "HOME=/root".to_string(),
        "USER=root".to_string(),
        "LOGNAME=root".to_string(),
        "PAGER=cat".to_string(),
        "SYSTEMD_PAGER=cat".to_string(),
        "SYSTEMD_PAGERSECURE=1".to_string(),
        "LESSSECURE=1".to_string(),
        "EDITOR=/bin/false".to_string(),
        "VISUAL=/bin/false".to_string(),
        "SYSTEMD_EDITOR=/bin/false".to_string(),
        format!("TRUSTAUTO_USER={caller}"),
    ];
    for (key, value) in env {
        let (Some(key), Some(value)) = (key.to_str(), value.to_str()) else {
            continue;
        };
        let keep = match key {
            "TERM" => safe_env_value(value, b"_.+-"),
            "LANG" | "LANGUAGE" | "LC_ALL" | "LC_CTYPE" | "LC_MESSAGES" | "LC_TIME"
            | "LC_NUMERIC" | "LC_COLLATE" | "LC_MONETARY" => safe_env_value(value, b"_.@-"),
            _ => false,
        };
        if keep {
            out.push(format!("{key}={value}"));
        }
    }
    out.into_iter().filter_map(|e| CString::new(e).ok()).collect()
}

/// Replaces this process. Only returns on failure.
pub fn exec(path: &CStr, argv: &[CString], envp: &[CString]) -> io::Error {
    let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let mut envp_ptrs: Vec<*const libc::c_char> = envp.iter().map(|e| e.as_ptr()).collect();
    envp_ptrs.push(std::ptr::null());
    unsafe { libc::execve(path.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr()) };
    io::Error::last_os_error()
}
