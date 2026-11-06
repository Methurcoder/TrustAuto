//! The per-user `trustauto on` / `trustauto off` switch. It is a preference, not a
//! security limit: only the front end reads it, and the broker never does, because
//! the user can change it at any time. It is read on every run, so it needs no daemon
//! and takes effect in shells that are already open.

use std::ffi::CStr;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

const HOME_BUF: usize = 16 * 1024;

/// From the account database, so the setting stays the same whatever HOME says.
pub fn home_of(uid: u32) -> Option<PathBuf> {
    let mut buf = vec![0u8; HOME_BUF];
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
    let home = unsafe { CStr::from_ptr(pwd.pw_dir) };
    home.to_str().ok().map(PathBuf::from)
}

pub fn marker_in(home: &Path) -> PathBuf {
    home.join(".config/trustauto/off")
}

/// Anything but a clean "no marker" counts as off: a user who asked for no elevation
/// must not get it back because their home directory could not be read.
pub fn is_off(marker: Option<&Path>) -> bool {
    match marker {
        None => true,
        Some(path) => match fs::symlink_metadata(path) {
            Ok(_) => true,
            Err(e) => e.kind() != ErrorKind::NotFound,
        },
    }
}

pub fn turn_off(marker: &Path) -> std::io::Result<()> {
    if let Some(dir) = marker.parent() {
        fs::create_dir_all(dir)?;
    }
    fs::write(marker, "")
}

pub fn turn_on(marker: &Path) -> std::io::Result<()> {
    match fs::remove_file(marker) {
        Err(e) if e.kind() != ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ta-switch-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn on_and_off_round_trip() {
        let dir = temp("trip");
        let marker = marker_in(&dir);
        assert!(!is_off(Some(&marker)));
        turn_off(&marker).unwrap();
        turn_off(&marker).unwrap();
        assert!(is_off(Some(&marker)));
        turn_on(&marker).unwrap();
        turn_on(&marker).unwrap();
        assert!(!is_off(Some(&marker)));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_dangling_symlink_still_counts_as_off() {
        let dir = temp("link");
        let marker = dir.join("off");
        std::os::unix::fs::symlink(dir.join("missing"), &marker).unwrap();
        assert!(is_off(Some(&marker)));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_unknown_state_counts_as_off() {
        assert!(is_off(None));
        let dir = temp("notdir");
        let file = dir.join("file");
        fs::write(&file, "").unwrap();
        // A path through a regular file is an error other than "not found" on Linux,
        // and "not found" nowhere means elevation the user turned off comes back.
        let through = file.join("off");
        assert_eq!(
            is_off(Some(&through)),
            fs::symlink_metadata(&through).unwrap_err().kind() != ErrorKind::NotFound
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_account_database_knows_the_current_user() {
        let uid = unsafe { libc::getuid() };
        assert!(home_of(uid).is_some());
    }
}
