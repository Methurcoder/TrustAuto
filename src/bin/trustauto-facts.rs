//! Collects the machine facts the risk model reads, as root. Run by the
//! installer, a daily timer and an apt hook; only reads the system.
//!
//!   trustauto-facts collect [--out PATH] [--root DIR]

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::exit;
use trustauto::collect::collect;
use trustauto::facts::{Machine, SNAPSHOT_PATH};
use trustauto::index::Index;
use trustauto::paths::GROUP_NAME;

const USAGE: &str = "usage: trustauto-facts collect [--out PATH] [--root DIR]";

fn die(message: &str) -> ! {
    eprintln!("trustauto-facts: {message}");
    exit(1)
}

/// The trustauto group may read the facts: `trustauto explain` and `setting` use
/// them. Everyone else may not, since they list processes.
fn group_id() -> Option<libc::gid_t> {
    let name = std::ffi::CString::new(GROUP_NAME).ok()?;
    let group = unsafe { libc::getgrnam(name.as_ptr()) };
    (!group.is_null()).then(|| unsafe { (*group).gr_gid })
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) != Some("collect") {
        die(USAGE);
    }
    let mut out = PathBuf::from(SNAPSHOT_PATH);
    let mut root = PathBuf::from("/");
    let mut i = 1;
    while i < args.len() {
        let value = args.get(i + 1).unwrap_or_else(|| die(USAGE));
        match args[i].as_str() {
            "--out" => out = PathBuf::from(value),
            "--root" => root = PathBuf::from(value),
            _ => die(USAGE),
        }
        i += 2;
    }
    if unsafe { libc::geteuid() } != 0 {
        die("run as root: process maps and socket owners are only visible to root");
    }
    let started = std::time::Instant::now();
    let snapshot = collect(&root).unwrap_or_else(|e| die(&e));
    let text = serde_json::to_string(&snapshot).unwrap_or_else(|e| die(&e.to_string()));

    // What decisions read: every index built once, here, instead of per decision.
    let index = Index::build(&Machine::new(&snapshot), snapshot.collected_at);
    let index_text = serde_json::to_string(&index).unwrap_or_else(|e| die(&e.to_string()));
    let index_out = out.with_extension("index.json");

    let dir = out.parent().unwrap_or(Path::new("/"));
    if let Err(e) = std::fs::create_dir_all(dir) {
        die(&format!("{}: {e}", dir.display()));
    }
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755));
    write_atomically(&out, &text);
    write_atomically(&index_out, &index_text);
    println!(
        "{}: {} packages, {} units, {} processes, {} links, {} files with libraries, {} KiB, index {} KiB, {:.1} s",
        out.display(),
        snapshot.lists.len(),
        snapshot.units.len(),
        snapshot.procs.len(),
        snapshot.usage.links.len(),
        snapshot.usage.needed.len(),
        text.len() / 1024,
        index_text.len() / 1024,
        started.elapsed().as_secs_f64()
    );
}

/// Written next to the target and renamed over it, so a reader never sees half a
/// file, then readable by root and the trustauto group only.
fn write_atomically(out: &Path, text: &str) {
    let mut temp = out.as_os_str().to_owned();
    temp.push(".new");
    let temp = PathBuf::from(temp);
    let _ = std::fs::remove_file(&temp);
    let written = (|| -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        if let Some(gid) = group_id() {
            std::os::unix::fs::chown(&temp, Some(0), Some(gid))?;
            std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o640))?;
        }
        std::fs::rename(&temp, out)
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&temp);
        die(&format!("cannot write {}: {e}", out.display()));
    }
}
