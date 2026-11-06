//! Collects a facts snapshot on the live machine, the way the lab collected it
//! (`truth_lab.collect_facts` and `collect_usage.py`). Only reads; run as root
//! so that every process's maps and `ss -p` owners are visible.

use crate::facts::{Proc, Snapshot, UsageData, SNAPSHOT_VERSION};
use indexmap::IndexMap;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

const TOP_LEVELS: &[&str] = &["usr", "etc", "opt", "lib", "lib64", "bin", "sbin", "var/lib/dpkg/info"];
const SKIP: &[&str] = &[
    "/usr/share/doc/", "/usr/share/man/", "/usr/share/locale/", "/usr/share/info/", "/usr/include/",
    "/usr/share/zoneinfo/", "/usr/share/i18n/", "/usr/share/perl/", "/usr/lib/python3", "/usr/share/mime/",
];
const COMMAND_DIRS: &[&str] = &["/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/usr/local/sbin/", "/usr/games/", "/bin/", "/sbin/"];
const UNIT_DIRS: &[&str] = &["/usr/lib/systemd/system/", "/lib/systemd/system/", "/etc/systemd/system/"];
const TEXT_LIMIT: usize = 512 * 1024;
const UNIT_TEXT_CHARS: usize = 4000;

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn run(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .output()
        .map(|o| lossy(&o.stdout))
        .unwrap_or_default()
}

fn starts_with_any(s: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|p| s.starts_with(p))
}

pub fn collect(root: &Path) -> Result<Snapshot, String> {
    let status = fs::read(root.join("var/lib/dpkg/status")).map_err(|e| format!("cannot read dpkg status: {e}"))?;
    let collected_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Ok(Snapshot {
        version: SNAPSHOT_VERSION,
        collected_at,
        status: lossy(&status),
        lists: package_lists(root),
        units: units(),
        procs: procs(),
        pam: pam(root),
        ss: run("ss", &["-ltnupH"]),
        usage: usage(root),
    })
}

fn package_lists(root: &Path) -> IndexMap<String, Vec<String>> {
    let mut lists = BTreeMap::new();
    let Ok(dir) = fs::read_dir(root.join("var/lib/dpkg/info")) else { return IndexMap::new() };
    for entry in dir.flatten() {
        let file = entry.file_name().to_string_lossy().into_owned();
        let Some(stem) = file.strip_suffix(".list") else { continue };
        let name = stem.split(':').next().unwrap_or(stem).to_string();
        let Ok(bytes) = fs::read(entry.path()) else { continue };
        let files = lossy(&bytes)
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !root.join(l.trim_start_matches('/')).is_dir())
            .map(str::to_string)
            .collect();
        lists.insert(name, files);
    }
    lists.into_iter().collect()
}

fn procs() -> Vec<Proc> {
    let mut found = Vec::new();
    let Ok(dir) = fs::read_dir("/proc") else { return found };
    for entry in dir.flatten() {
        let pid = entry.file_name().to_string_lossy().into_owned();
        if pid.is_empty() || !pid.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(exe) = fs::read_link(format!("/proc/{pid}/exe")) else { continue };
        let Ok(maps) = fs::read(format!("/proc/{pid}/maps")) else { continue };
        let mut paths = BTreeSet::new();
        for line in lossy(&maps).lines() {
            if let Some(path) = sixth_field(line) {
                if path.starts_with('/') {
                    paths.insert(path.to_string());
                }
            }
        }
        found.push(Proc { exe: exe.to_string_lossy().into_owned(), maps: paths.into_iter().collect() });
    }
    found
}

/// Python's `line.split(None, 5)[5].strip()`.
fn sixth_field(line: &str) -> Option<&str> {
    let mut rest = line;
    for _ in 0..5 {
        rest = rest.trim_start();
        let end = rest.find(char::is_whitespace)?;
        rest = &rest[end..];
    }
    let field = rest.trim();
    (!field.is_empty()).then_some(field)
}

fn pam(root: &Path) -> IndexMap<String, String> {
    let mut found = BTreeMap::new();
    if let Ok(dir) = fs::read_dir(root.join("etc/pam.d")) {
        for entry in dir.flatten() {
            if let Ok(bytes) = fs::read(entry.path()) {
                found.insert(entry.file_name().to_string_lossy().into_owned(), lossy(&bytes));
            }
        }
    }
    found.into_iter().collect()
}

fn units() -> IndexMap<String, IndexMap<String, String>> {
    let listing = run("systemctl", &["list-unit-files", "--type=service", "--no-legend", "--no-pager"]);
    let names: BTreeSet<String> = listing
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|u| !u.contains('@'))
        .filter_map(|u| u.strip_suffix(".service"))
        .map(str::to_string)
        .collect();
    let mut units = IndexMap::new();
    for unit in names {
        let shown = run("systemctl", &["show", &unit]);
        let mut props: IndexMap<String, String> = shown
            .lines()
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let path = props.get("FragmentPath").cloned().unwrap_or_default();
        let text = if path.is_empty() {
            String::new()
        } else {
            fs::read(&path).map(|b| lossy(&b).chars().take(UNIT_TEXT_CHARS).collect()).unwrap_or_default()
        };
        props.insert("_text".to_string(), text);
        units.insert(unit, props);
    }
    units
}

struct Entry {
    path: String,
    full: std::path::PathBuf,
    mode: u32,
    size: u64,
}

/// Every file under the top-level folders, never following a symlink.
fn walk(root: &Path, links: &mut IndexMap<String, String>, entries: &mut Vec<Entry>) {
    fn visit(root: &Path, dir: &Path, links: &mut IndexMap<String, String>, entries: &mut Vec<Entry>) {
        let Ok(read) = fs::read_dir(dir) else { return };
        let mut items: Vec<_> = read.flatten().collect();
        items.sort_by_key(|e| e.file_name());
        for item in items {
            let full = item.path();
            let Ok(meta) = fs::symlink_metadata(&full) else { continue };
            let Ok(rel) = full.strip_prefix(root) else { continue };
            let Some(rel) = rel.to_str() else { continue };
            let path = format!("/{rel}");
            let kind = meta.file_type();
            if kind.is_dir() {
                visit(root, &full, links, entries);
            } else if kind.is_symlink() {
                // Like os.walk: a link to a folder is listed as a folder and not entered.
                if fs::metadata(&full).is_ok_and(|m| m.is_dir()) {
                    continue;
                }
                if let Ok(target) = fs::read_link(&full) {
                    links.insert(path, target.to_string_lossy().into_owned());
                }
            } else if kind.is_file() {
                entries.push(Entry { path, full, mode: meta.permissions().mode(), size: meta.len() });
            }
        }
    }
    for top in TOP_LEVELS {
        let start = root.join(top);
        match fs::symlink_metadata(&start) {
            Ok(m) if m.is_dir() => visit(root, &start, links, entries),
            _ => {}
        }
    }
}

fn is_scanned(path: &str, mode: u32) -> bool {
    if starts_with_any(path, SKIP) {
        return false;
    }
    starts_with_any(path, &["/etc/", "/var/lib/dpkg/info/", "/usr/lib/systemd/", "/lib/systemd/"]) || mode & 0o111 != 0
}

fn usage(root: &Path) -> UsageData {
    let mut links = IndexMap::new();
    let mut entries = Vec::new();
    walk(root, &mut links, &mut entries);
    let mut names: HashSet<String> = HashSet::new();
    for path in entries.iter().map(|e| &e.path).chain(links.keys()) {
        let base = path.rsplit('/').next().unwrap_or(path);
        if starts_with_any(path, COMMAND_DIRS) {
            names.insert(base.to_string());
        }
        if starts_with_any(path, UNIT_DIRS) {
            if let Some(unit) = base.strip_suffix(".service") {
                names.insert(base.to_string());
                names.insert(unit.to_string());
            }
        }
    }
    let known_paths: HashSet<&str> = entries.iter().map(|e| e.path.as_str()).chain(links.keys().map(String::as_str)).collect();

    let mut needed = IndexMap::new();
    let mut interp = IndexMap::new();
    let mut refs = IndexMap::new();
    for e in &entries {
        if starts_with_any(&e.path, SKIP) || e.size < 4 {
            continue;
        }
        let scanned = is_scanned(&e.path, e.mode);
        let Ok(mut file) = fs::File::open(&e.full) else { continue };
        let mut head = Vec::new();
        let limit = if scanned { TEXT_LIMIT } else { 4 };
        if (&mut file).take(limit as u64).read_to_end(&mut head).is_err() {
            continue;
        }
        if head.starts_with(b"\x7fELF") {
            let libraries = elf_needed(&mut file).unwrap_or_default();
            if !libraries.is_empty() {
                needed.insert(e.path.clone(), libraries);
            }
            continue;
        }
        if !scanned || head[..head.len().min(8192)].contains(&0) {
            continue;
        }
        if let Some(line) = head.strip_prefix(b"#!") {
            let line = line.split(|b| *b == b'\n').next().unwrap_or(b"");
            let words: Vec<String> = line
                .split(|b| b" \t\n\r\x0b\x0c".contains(b))
                .filter(|w| !w.is_empty())
                .take(2)
                .map(lossy)
                .collect();
            if !words.is_empty() {
                interp.insert(e.path.clone(), words);
            }
        }
        let own = e.path.rsplit('/').next().unwrap_or("");
        let mut found: BTreeSet<String> = BTreeSet::new();
        for w in word_runs(&head) {
            if let Ok(w) = std::str::from_utf8(w) {
                if names.contains(w) {
                    found.insert(w.to_string());
                }
            }
        }
        for p in path_runs(&head) {
            if let Ok(p) = std::str::from_utf8(p) {
                if known_paths.contains(p) {
                    found.insert(p.to_string());
                }
            }
        }
        found.remove(own);
        if !found.is_empty() {
            refs.insert(e.path.clone(), found.into_iter().collect());
        }
    }
    UsageData { links, needed, interp, refs }
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"_.+-".contains(&b)
}

/// `re.findall(rb"[A-Za-z0-9_.+-]{2,}", head)`
pub fn word_runs(head: &[u8]) -> Vec<&[u8]> {
    head.split(|b| !is_word_byte(*b)).filter(|w| w.len() >= 2).collect()
}

/// `re.findall(rb"/[A-Za-z0-9_.+/-]{2,}", head)`
pub fn path_runs(head: &[u8]) -> Vec<&[u8]> {
    let mut found = Vec::new();
    let mut i = 0;
    while i < head.len() {
        if head[i] == b'/' {
            let mut j = i + 1;
            while j < head.len() && (is_word_byte(head[j]) || head[j] == b'/') {
                j += 1;
            }
            if j - i - 1 >= 2 {
                found.push(&head[i..j]);
                i = j;
                continue;
            }
        }
        i += 1;
    }
    found
}

/// DT_NEEDED entries of an ELF file, read through its section headers.
pub fn elf_needed<R: Read + Seek>(file: &mut R) -> Option<Vec<String>> {
    let mut ident = [0u8; 64];
    file.seek(SeekFrom::Start(0)).ok()?;
    file.read_exact(&mut ident[..52]).ok()?;
    let wide = match ident[4] {
        1 => false,
        2 => {
            file.read_exact(&mut ident[52..64]).ok()?;
            true
        }
        _ => return None,
    };
    let little = match ident[5] {
        1 => true,
        2 => false,
        _ => return None,
    };
    let u16_at = |b: &[u8], i: usize| {
        let v = [b[i], b[i + 1]];
        if little { u16::from_le_bytes(v) } else { u16::from_be_bytes(v) }
    };
    let u32_at = |b: &[u8], i: usize| {
        let v = [b[i], b[i + 1], b[i + 2], b[i + 3]];
        if little { u32::from_le_bytes(v) } else { u32::from_be_bytes(v) }
    };
    let u64_at = |b: &[u8], i: usize| {
        let v: [u8; 8] = b[i..i + 8].try_into().unwrap();
        if little { u64::from_le_bytes(v) } else { u64::from_be_bytes(v) }
    };
    let word = |b: &[u8], i: usize| if wide { u64_at(b, i) } else { u32_at(b, i) as u64 };
    let (shoff, shentsize, shnum) = if wide {
        (u64_at(&ident, 0x28), u16_at(&ident, 0x3a) as u64, u16_at(&ident, 0x3c) as u64)
    } else {
        (u32_at(&ident, 0x20) as u64, u16_at(&ident, 0x2e) as u64, u16_at(&ident, 0x30) as u64)
    };
    let min_entry = if wide { 64 } else { 40 };
    if shoff == 0 || shnum == 0 || shnum > 4096 || shentsize < min_entry {
        return None;
    }
    let mut table = vec![0u8; (shentsize * shnum) as usize];
    file.seek(SeekFrom::Start(shoff)).ok()?;
    file.read_exact(&mut table).ok()?;
    // (type, offset, size, link)
    let section = |i: u64| {
        let s = &table[(i * shentsize) as usize..];
        if wide {
            (u32_at(s, 4), u64_at(s, 0x18), u64_at(s, 0x20), u32_at(s, 0x28))
        } else {
            (u32_at(s, 4), u32_at(s, 0x10) as u64, u32_at(s, 0x14) as u64, u32_at(s, 0x18))
        }
    };
    const SHT_DYNAMIC: u32 = 6;
    const DT_NEEDED: u64 = 1;
    const MAX_SECTION: u64 = 16 << 20;
    let mut read_at = |offset: u64, size: u64| -> Option<Vec<u8>> {
        if size > MAX_SECTION {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        file.seek(SeekFrom::Start(offset)).ok()?;
        file.read_exact(&mut buf).ok()?;
        Some(buf)
    };
    for i in 0..shnum {
        let (kind, offset, size, link) = section(i);
        if kind != SHT_DYNAMIC || link as u64 >= shnum {
            continue;
        }
        let (_, str_off, str_size, _) = section(link as u64);
        let dynamic = read_at(offset, size)?;
        let strings = read_at(str_off, str_size)?;
        let entry = if wide { 16 } else { 8 };
        let mut found = Vec::new();
        for e in dynamic.chunks_exact(entry) {
            let tag = word(e, 0);
            if tag == 0 {
                break;
            }
            if tag == DT_NEEDED {
                let at = word(e, entry / 2) as usize;
                let end = strings.get(at..)?.iter().position(|b| *b == 0)?;
                found.push(lossy(&strings[at..at + end]));
            }
        }
        return Some(found);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_match_the_python_regexes() {
        let head = b"#!/bin/sh\nexec /usr/sbin/cron -f a /x //y ssh.service";
        let words: Vec<&[u8]> = word_runs(head);
        assert!(words.contains(&&b"cron"[..]) && words.contains(&&b"ssh.service"[..]) && !words.contains(&&b"a"[..]));
        let paths: Vec<&[u8]> = path_runs(head);
        assert_eq!(paths, vec![&b"/bin/sh"[..], &b"/usr/sbin/cron"[..], &b"//y"[..]]);
    }

    #[test]
    fn sixth_field_keeps_inner_spaces() {
        assert_eq!(sixth_field("7f-7f r-xp 0 08:01 12  /usr/lib/a b.so "), Some("/usr/lib/a b.so"));
        assert_eq!(sixth_field("7f-7f r-xp 0 00:00 0 "), None);
    }

    /// A minimal 64-bit little-endian ELF with a .dynamic and a .dynstr section.
    fn tiny_elf() -> Vec<u8> {
        let strings = b"\0libc.so.6\0libm.so.6\0";
        let mut dynamic = Vec::new();
        for (tag, val) in [(1u64, 1u64), (1, 11), (0, 0)] {
            dynamic.extend_from_slice(&tag.to_le_bytes());
            dynamic.extend_from_slice(&val.to_le_bytes());
        }
        let str_off = 64u64;
        let dyn_off = str_off + strings.len() as u64;
        let sh_off = dyn_off + dynamic.len() as u64;
        let mut f = vec![0u8; 64];
        f[..4].copy_from_slice(b"\x7fELF");
        f[4] = 2;
        f[5] = 1;
        f[0x28..0x30].copy_from_slice(&sh_off.to_le_bytes());
        f[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes());
        f[0x3c..0x3e].copy_from_slice(&3u16.to_le_bytes());
        f.extend_from_slice(strings);
        f.extend_from_slice(&dynamic);
        let mut section = |kind: u32, off: u64, size: u64, link: u32| {
            let mut s = vec![0u8; 64];
            s[4..8].copy_from_slice(&kind.to_le_bytes());
            s[0x18..0x20].copy_from_slice(&off.to_le_bytes());
            s[0x20..0x28].copy_from_slice(&size.to_le_bytes());
            s[0x28..0x2c].copy_from_slice(&link.to_le_bytes());
            f.extend_from_slice(&s);
        };
        section(0, 0, 0, 0);
        section(3, str_off, strings.len() as u64, 0);
        section(6, dyn_off, dynamic.len() as u64, 1);
        f
    }

    #[test]
    fn elf_needed_reads_dynamic_section() {
        let mut cursor = std::io::Cursor::new(tiny_elf());
        assert_eq!(elf_needed(&mut cursor), Some(vec!["libc.so.6".to_string(), "libm.so.6".to_string()]));
        let mut broken = std::io::Cursor::new(tiny_elf()[..80].to_vec());
        assert_eq!(elf_needed(&mut broken), None);
    }
}
