//! Facts about this machine that a decision may read before a command runs, and
//! the numbers and words the risk model was trained on.
//!
//! This is a line-by-line port of the training code in
//! `ml/truth/experiment_5/round4_evaluation/reproduction/source` (`train_live.py`,
//! `train_usage.py` and `features` in `train_actions.py`). The model only means
//! something on inputs computed exactly as in training, so `tests/facts_parity.rs`
//! compares this port with the Python values on all four lab machines.
//! Where Python iterates a set of strings, its order is random per process; the
//! one place that order changes a result (`closure`) uses sorted order here.

use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::OnceLock;

pub const SNAPSHOT_PATH: &str = "/var/lib/trustauto/facts.json";
pub const SNAPSHOT_VERSION: u32 = 1;

/// One running process: its executable and the files it has mapped.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Proc {
    pub exe: String,
    pub maps: Vec<String>,
}

/// Who uses what on the machine, as `ml/truth/collect_usage.py` records it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UsageData {
    pub links: IndexMap<String, String>,
    pub needed: IndexMap<String, Vec<String>>,
    pub interp: IndexMap<String, Vec<String>>,
    pub refs: IndexMap<String, Vec<String>>,
}

/// The facts file. Field names and meaning follow the lab's `facts_NAME.json`
/// plus `usage_NAME.json`, so a snapshot of a lab machine and of a live one are
/// read by the same code.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Snapshot {
    #[serde(default)]
    pub version: u32,
    /// Unix seconds when it was collected. Zero for lab files.
    #[serde(default)]
    pub collected_at: u64,
    pub status: String,
    pub lists: IndexMap<String, Vec<String>>,
    pub units: IndexMap<String, IndexMap<String, String>>,
    pub procs: Vec<Proc>,
    pub pam: IndexMap<String, String>,
    pub ss: String,
    #[serde(default)]
    pub usage: UsageData,
}

impl Snapshot {
    pub fn parse(text: &str) -> Result<Snapshot, String> {
        serde_json::from_str(text).map_err(|e| format!("bad facts file: {e}"))
    }

    /// A lab machine: `facts_NAME.json` and `usage_NAME.json`.
    pub fn from_lab(facts: &str, usage: &str) -> Result<Snapshot, String> {
        let mut s = Snapshot::parse(facts)?;
        s.usage = serde_json::from_str(usage).map_err(|e| format!("bad usage file: {e}"))?;
        Ok(s)
    }
}

type Fields = HashMap<String, String>;

pub(crate) const COMMAND_DIRS: &[&str] = &["/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/usr/local/sbin/", "/usr/games/"];
const SERVICE_LINKS: &[&str] = &["RequiredBy", "RequisiteOf", "BoundBy", "ConsistsOf"];
const LOCATIONS: &[&str] = &[
    "/etc/", "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/share/", "/var/lib/", "/var/www/", "/boot/", "/root/",
    "/home/", "/tmp/", "/srv/", "/dev/", "/proc/", "/sys/",
];
const CHANGING_WORDS: &[&str] = &["-r", "-R", "--recursive", "-f", "--force", "-i", "--in-place", "-y", "--yes", "-a", "--append"];

fn log(n: f64) -> f64 {
    n.ln_1p()
}

pub(crate) fn logn(n: usize) -> f64 {
    log(n as f64)
}

pub(crate) fn starts_with_any(s: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|p| s.starts_with(p))
}

/// Python's `str.split()` with no argument.
fn words(s: &str) -> impl Iterator<Item = &str> {
    s.split_whitespace()
}

/// `/bin/x` and `/usr/bin/x` are one file on a merged-/usr system.
pub fn norm(path: &str) -> String {
    for old in ["/bin/", "/sbin/", "/lib/", "/lib64/"] {
        if path.starts_with(old) {
            return format!("/usr{path}");
        }
    }
    path.to_string()
}

fn resolve(link: &str, target: &str) -> String {
    if target.starts_with('/') {
        return norm(target);
    }
    let mut parts: Vec<&str> = link.split('/').collect();
    parts.pop();
    for piece in target.split('/') {
        if piece == ".." {
            parts.pop();
        } else if !piece.is_empty() && piece != "." {
            parts.push(piece);
        }
    }
    norm(&parts.join("/"))
}

fn base_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn parse_status(text: &str) -> HashMap<String, Fields> {
    let mut packages = HashMap::new();
    for block in text.split("\n\n") {
        let mut fields: Fields = HashMap::new();
        let mut key: Option<String> = None;
        for line in block.lines() {
            match &key {
                Some(k) if line.starts_with(' ') && !k.is_empty() => {
                    let entry = fields.entry(k.clone()).or_default();
                    entry.push(' ');
                    entry.push_str(line.trim());
                }
                _ => {
                    if let Some((k, v)) = line.split_once(':') {
                        fields.insert(k.to_string(), v.trim().to_string());
                        key = Some(k.to_string());
                    }
                }
            }
        }
        if fields.get("Status").map(String::as_str) == Some("install ok installed") {
            if let Some(name) = fields.get("Package").cloned() {
                packages.insert(name, fields);
            }
        }
    }
    packages
}

/// Hard dependencies as lists of alternative package names.
fn clauses(fields: &Fields) -> Vec<Vec<String>> {
    let parts: Vec<&str> = ["Depends", "Pre-Depends"]
        .iter()
        .filter_map(|k| fields.get(*k).map(String::as_str).filter(|v| !v.is_empty()))
        .collect();
    let text = parts.join(", ");
    text.split(',')
        .filter(|c| !c.trim().is_empty())
        .map(|c| c.split('|').map(|alt| bare_name(alt).to_string()).collect())
        .collect()
}

fn bare_name(item: &str) -> &str {
    let item = item.split('(').next().unwrap_or("");
    item.split(':').next().unwrap_or("").trim()
}

/// `users:(("name",pid=123` in `ss -p` output: the first process of each socket.
fn listeners(ss: &str) -> Vec<(String, String)> {
    const OPEN: &str = "users:((\"";
    let mut found = Vec::new();
    let mut at = 0;
    while let Some(i) = ss[at..].find(OPEN) {
        let start = at + i + OPEN.len();
        let rest = &ss[start..];
        let matched = rest.find('"').and_then(|q| {
            let name = &rest[..q];
            let after = rest[q..].strip_prefix("\",pid=")?;
            let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
            (!name.is_empty() && !digits.is_empty()).then(|| (name.to_string(), digits, start + q + 6))
        });
        match matched {
            Some((name, pid, end)) => {
                at = end + pid.len();
                found.push((name, pid));
            }
            None => at = at + i + 1,
        }
    }
    found
}

fn exec_paths(value: &str) -> impl Iterator<Item = &str> {
    static PATH: OnceLock<Regex> = OnceLock::new();
    PATH.get_or_init(|| Regex::new(r"path=(\S+)").unwrap())
        .captures_iter(value)
        .map(|c| c.get(1).unwrap().as_str())
}

/// The machine with every index the features need. Building it takes about 0.3 s
/// on an ordinary Ubuntu install, so `trustauto-facts` builds it once when it
/// collects and saves the answers as an `Index`; decisions read that instead.
pub struct Machine {
    pub(crate) packages: HashMap<String, Fields>,
    lists: IndexMap<String, Vec<String>>,
    pub(crate) units: IndexMap<String, IndexMap<String, String>>,
    procs: Vec<Proc>,
    pam: String,
    listeners: Vec<(String, String)>,
    owner: HashMap<String, String>,
    providers: HashMap<String, BTreeSet<String>>,
    needs: HashMap<String, Vec<Vec<String>>>,
    pub(crate) rdeps: HashMap<String, BTreeSet<String>>,
    pub(crate) owned_by: HashMap<String, String>,
    pub(crate) paths: Vec<String>,
    pub(crate) strong_users: HashMap<String, HashSet<String>>,
    pub(crate) text_users: HashMap<String, HashSet<String>>,
    names_used: HashMap<String, usize>,
    programs: HashSet<String>,
    unit_files: IndexMap<String, HashSet<String>>,
    proc_exes: Vec<String>,
    pub(crate) mapped: HashSet<String>,
}

impl Machine {
    pub fn new(s: &Snapshot) -> Machine {
        let packages = parse_status(&s.status);
        let mut owner = HashMap::new();
        for (name, files) in &s.lists {
            for f in files {
                owner.insert(f.clone(), name.clone());
            }
        }
        let mut providers: HashMap<String, BTreeSet<String>> = HashMap::new();
        for (package, fields) in &packages {
            providers.entry(package.clone()).or_default().insert(package.clone());
            for item in fields.get("Provides").map(String::as_str).unwrap_or("").split(',') {
                let item = bare_name(item);
                if !item.is_empty() {
                    providers.entry(item.to_string()).or_default().insert(package.clone());
                }
            }
        }
        let needs: HashMap<String, Vec<Vec<String>>> =
            packages.iter().map(|(n, f)| (n.clone(), clauses(f))).collect();
        let mut rdeps: HashMap<String, BTreeSet<String>> = HashMap::new();
        for (package, needed) in &needs {
            for clause in needed {
                for alt in clause {
                    for provider in providers.get(alt).into_iter().flatten() {
                        rdeps.entry(provider.clone()).or_default().insert(package.clone());
                    }
                }
            }
        }

        // train_usage.Usage
        let u = &s.usage;
        let mut owned_by = HashMap::new();
        for (name, files) in &s.lists {
            for f in files {
                owned_by.insert(norm(f), name.clone());
            }
        }
        let mut by_base: HashMap<String, HashSet<String>> = HashMap::new();
        let mut strong_users: HashMap<String, HashSet<String>> = HashMap::new();
        for path in owned_by.keys() {
            by_base.entry(base_name(path).to_string()).or_default().insert(path.clone());
        }
        for (link, target) in &u.links {
            let link_n = norm(link);
            by_base.entry(base_name(&link_n).to_string()).or_default().insert(link_n.clone());
            strong_users.entry(resolve(&link_n, target)).or_default().insert(link_n);
        }
        let mut commands: HashMap<String, HashSet<String>> = HashMap::new();
        let link_paths: HashSet<String> = u.links.keys().map(|p| norm(p)).collect();
        for path in owned_by.keys().chain(link_paths.iter()) {
            if starts_with_any(path, COMMAND_DIRS) {
                commands.entry(base_name(path).to_string()).or_default().insert(path.clone());
            }
        }
        for (user, libraries) in &u.needed {
            for library in libraries {
                for path in by_base.get(library).into_iter().flatten() {
                    strong_users.entry(path.clone()).or_default().insert(norm(user));
                }
            }
        }
        for (user, ws) in &u.interp {
            let Some(first) = ws.first() else { continue };
            let first = norm(first);
            if first.ends_with("/env") && ws.len() > 1 {
                for path in commands.get(&ws[1]).into_iter().flatten() {
                    strong_users.entry(path.clone()).or_default().insert(norm(user));
                }
            } else {
                strong_users.entry(first).or_default().insert(norm(user));
            }
        }
        let mut names_used: HashMap<String, usize> = HashMap::new();
        let mut text_users: HashMap<String, HashSet<String>> = HashMap::new();
        for (user, ws) in &u.refs {
            let user = norm(user);
            for word in ws {
                *names_used.entry(word.clone()).or_default() += 1;
                let targets: Vec<String> = if word.starts_with('/') {
                    vec![norm(word)]
                } else {
                    commands.get(word).into_iter().flatten().cloned().collect()
                };
                for path in targets {
                    text_users.entry(path).or_default().insert(user.clone());
                }
            }
        }
        let programs = owned_by.keys().filter(|p| starts_with_any(p, COMMAND_DIRS)).cloned().collect();
        let mut unit_files = IndexMap::new();
        for (unit, props) in &s.units {
            let mut found = HashSet::new();
            for (key, value) in props {
                if key.starts_with("Exec") && !key.ends_with("Ex") {
                    found.extend(exec_paths(value).map(norm));
                }
            }
            unit_files.insert(unit.clone(), found);
        }
        let proc_exes = s.procs.iter().map(|p| norm(&p.exe)).collect();
        let mapped = s
            .procs
            .iter()
            .flat_map(|p| std::iter::once(&p.exe).chain(p.maps.iter()))
            .map(|p| norm(p))
            .collect();
        let mut paths: Vec<String> = owned_by.keys().cloned().collect();
        paths.sort();

        Machine {
            packages,
            lists: s.lists.clone(),
            units: s.units.clone(),
            procs: s.procs.clone(),
            pam: s.pam.values().cloned().collect::<Vec<_>>().join("\n"),
            listeners: listeners(&s.ss),
            owner,
            providers,
            needs,
            rdeps,
            owned_by,
            paths,
            strong_users,
            text_users,
            names_used,
            programs,
            unit_files,
            proc_exes,
            mapped,
        }
    }

    fn props(&self, unit: &str) -> &IndexMap<String, String> {
        static EMPTY: OnceLock<IndexMap<String, String>> = OnceLock::new();
        self.units.get(unit).unwrap_or_else(|| EMPTY.get_or_init(IndexMap::new))
    }

    fn prop<'a>(&'a self, unit: &str, key: &str) -> &'a str {
        self.props(unit).get(key).map(String::as_str).unwrap_or("")
    }

    fn closure(&self, package: &str) -> BTreeSet<String> {
        let mut gone = BTreeSet::from([package.to_string()]);
        let mut frontier = vec![package.to_string()];
        while let Some(current) = frontier.pop() {
            for dependent in self.rdeps.get(&current).into_iter().flatten() {
                if gone.contains(dependent) {
                    continue;
                }
                for clause in &self.needs[dependent] {
                    let providers: BTreeSet<&String> =
                        clause.iter().flat_map(|a| self.providers.get(a).into_iter().flatten()).collect();
                    if !providers.is_empty() && providers.iter().all(|p| gone.contains(*p)) {
                        gone.insert(dependent.clone());
                        frontier.push(dependent.clone());
                        break;
                    }
                }
            }
        }
        gone
    }

    fn unit_owner(&self, unit: &str) -> Option<&str> {
        let path = self.prop(unit, "FragmentPath");
        for candidate in [path.to_string(), path.replace("/usr/lib/", "/lib/"), path.replace("/lib/", "/usr/lib/")] {
            if let Some(o) = self.owner.get(&candidate) {
                return Some(o);
            }
        }
        None
    }

    pub(crate) fn field<'a>(&'a self, package: &str, key: &str) -> Option<&'a str> {
        self.packages.get(package).and_then(|f| f.get(key)).map(String::as_str)
    }

    fn strong_reach(&self, start: &HashSet<String>) -> HashSet<String> {
        let mut seen = start.clone();
        let mut frontier: Vec<String> = start.iter().cloned().collect();
        while let Some(current) = frontier.pop() {
            for user in self.strong_users.get(&current).into_iter().flatten() {
                if seen.insert(user.clone()) {
                    frontier.push(user.clone());
                }
            }
        }
        seen
    }

    fn under(&self, path: &str) -> &[String] {
        let trimmed = path.trim_end_matches('/');
        let low = format!("{trimmed}/");
        let high = format!("{trimmed}0");
        let at = self.paths.partition_point(|p| p.as_str() < low.as_str());
        let end = self.paths.partition_point(|p| p.as_str() < high.as_str());
        &self.paths[at..end.max(at)]
    }

}

/// What `features` reads about the machine. `Machine` computes it from a
/// snapshot; `Index` looks up what `trustauto-facts` computed when it collected.
pub trait Facts {
    fn path_facts(&self, path: &str, prefix: &str, x: &mut BTreeMap<String, f64>);
    fn has_unit(&self, name: &str) -> bool;
    fn has_package(&self, name: &str) -> bool;
    fn service_features(&self, unit: &str, x: &mut BTreeMap<String, f64>);
    fn remove_features(&self, package: &str, x: &mut BTreeMap<String, f64>);
}

impl Facts for Machine {
    /// `train_live.remove_features` without `root_is_owner`.
    fn remove_features(&self, package: &str, x: &mut BTreeMap<String, f64>) {
        let names = self.closure(package);
        let files: Vec<&String> = names.iter().flat_map(|n| self.lists.get(n).into_iter().flatten()).collect();
        let owned: HashSet<&str> = files.iter().map(|f| f.as_str()).collect();
        let fields: Vec<Option<&Fields>> = names.iter().map(|n| self.packages.get(n)).collect();
        fn get<'a>(f: &Option<&'a Fields>, k: &str) -> Option<&'a str> {
            f.and_then(|f| f.get(k)).map(String::as_str)
        }
        let running = self.procs.iter().filter(|p| owned.contains(p.exe.as_str())).count();
        let mapping: Vec<&Proc> = self
            .procs
            .iter()
            .filter(|p| owned.contains(p.exe.as_str()) || p.maps.iter().any(|m| owned.contains(m.as_str())))
            .collect();
        let exes: HashSet<&str> = mapping.iter().map(|p| p.exe.as_str()).collect();
        let in_owned = |u: &IndexMap<String, String>| u.get("FragmentPath").is_some_and(|f| owned.contains(f.as_str()));
        let active = self.units.values().filter(|p| in_owned(p) && p.get("ActiveState").map(String::as_str) == Some("active")).count();
        let enabled = self.units.values().filter(|p| in_owned(p) && p.get("UnitFileState").map(String::as_str) == Some("enabled")).count();
        let modules: HashSet<&str> = files.iter().filter(|f| f.contains("/security/pam_")).map(|f| base_name(f)).collect();
        let size: f64 = fields
            .iter()
            .map(|f| get(f, "Installed-Size").filter(|s| !s.is_empty()).and_then(|s| s.parse::<i64>().ok()).unwrap_or(0) as f64)
            .sum();
        let count = |k: &str, v: &str| fields.iter().filter(|f| get(f, k) == Some(v)).count();
        static PROGRAM: OnceLock<Regex> = OnceLock::new();
        static SHARED: OnceLock<Regex> = OnceLock::new();
        let program = PROGRAM.get_or_init(|| Regex::new(r"^/(usr/)?s?bin/").unwrap());
        let shared = SHARED.get_or_init(|| Regex::new(r"\.so(\.|$)").unwrap());
        let mut put = |k: &str, v: f64| {
            x.insert(format!("package_{k}"), v);
        };
        put("svc", 0.0);
        put("closure", logn(names.len()));
        put("direct_rdeps", logn(self.rdeps.get(package).map_or(0, |s| s.len())));
        put("files", logn(files.len()));
        put("size", log(size));
        put("essential", count("Essential", "yes") as f64);
        put("required", logn(count("Priority", "required")));
        put("important", logn(count("Priority", "important")));
        put("standard", logn(count("Priority", "standard")));
        put("unit_files", logn(files.iter().filter(|f| f.contains("/systemd/system/")).count()));
        put("generators", files.iter().filter(|f| f.contains("/system-generators/")).count() as f64);
        put("programs", logn(files.iter().filter(|f| program.is_match(f)).count()));
        put("shared_libs", logn(files.iter().filter(|f| shared.is_match(f)).count()));
        put("running_exes", logn(running));
        put("mapping_procs", logn(mapping.len()));
        put("mapping_exes", logn(exes.len()));
        put("mapping_share", mapping.len() as f64 / self.procs.len().max(1) as f64);
        put("listeners", logn(self.listeners.iter().filter(|(n, _)| exes.iter().any(|e| e.contains(n.as_str()))).count()));
        put("active_units", logn(active));
        put("enabled_units", logn(enabled));
        put("pam_modules_in_use", logn(modules.iter().filter(|m| self.pam.contains(*m)).count()));
        put("pam_files", logn(files.iter().filter(|f| f.starts_with("/etc/pam.d/")).count()));

        // train_usage.Usage.remove_features
        let owned: HashSet<String> = files.iter().map(|f| norm(f)).collect();
        let strong = self.strong_reach(&owned);
        let outside: HashSet<&String> = strong.iter().filter(|p| !owned.contains(*p)).collect();
        let direct: HashSet<&String> = owned
            .iter()
            .flat_map(|p| self.strong_users.get(p).into_iter().flatten())
            .filter(|u| !owned.contains(*u))
            .collect();
        let text: HashSet<&String> = strong
            .iter()
            .flat_map(|p| self.text_users.get(p).into_iter().flatten())
            .filter(|u| !strong.contains(*u))
            .collect();
        let referenced = owned
            .iter()
            .filter(|p| self.text_users.get(*p).is_some_and(|us| us.iter().any(|u| !owned.contains(u))))
            .count();
        let active_units: Vec<&String> =
            self.units.iter().filter(|(_, p)| p.get("ActiveState").map(String::as_str) == Some("active")).map(|(u, _)| u).collect();
        let enabled_units: Vec<&String> =
            self.units.iter().filter(|(_, p)| p.get("UnitFileState").map(String::as_str) == Some("enabled")).map(|(u, _)| u).collect();
        let reached = |units: &[&String], seen: &dyn Fn(&String) -> bool| {
            units.iter().filter(|u| self.unit_files.get(u.as_str()).is_some_and(|fs| fs.iter().any(seen))).count()
        };
        let in_strong = |p: &String| strong.contains(p);
        let in_hit = |p: &String| strong.contains(p) || text.contains(p);
        let procs = self.proc_exes.iter().filter(|e| strong.contains(*e)).count();
        let listener_names: HashSet<&str> = self.listeners.iter().map(|(n, _)| n.as_str()).collect();
        let mut needed_providers: HashSet<&String> = HashSet::new();
        for n in &names {
            for clause in self.needs.get(n).into_iter().flatten() {
                for alt in clause {
                    needed_providers.extend(self.providers.get(alt).into_iter().flatten());
                }
            }
        }
        needed_providers.retain(|q| !names.contains(*q));
        let active_owners: HashSet<&str> = active_units.iter().filter_map(|u| self.unit_owner(u)).collect();
        let extends = needed_providers.iter().filter(|q| active_owners.contains(q.as_str())).count();
        let outside_programs = outside.iter().filter(|p| self.programs.contains(**p)).count();
        let count_text = |f: &dyn Fn(&str) -> bool| text.iter().filter(|p| f(p)).count();
        let mut put = |k: &str, v: f64| {
            x.insert(format!("package_{k}"), v);
        };
        put("u_extends_active", logn(extends));
        put("u_installs", 0.0);
        put("u_outside", logn(outside.len()));
        put("u_programs", logn(outside_programs));
        put("u_programs_share", outside_programs as f64 / self.programs.len().max(1) as f64);
        put("u_direct", logn(direct.len()));
        put("u_text_scripts", logn(count_text(&|p| starts_with_any(p, COMMAND_DIRS) || p.contains("/lib/"))));
        put("u_text_etc", logn(count_text(&|p| p.starts_with("/etc/"))));
        put("u_text_maint", logn(count_text(&|p| p.starts_with("/var/lib/dpkg/info/"))));
        put("u_text_units", logn(count_text(&|p| p.contains("/systemd/system/"))));
        put("u_units_active", logn(reached(&active_units, &in_strong)));
        put("u_units_active_text", logn(reached(&active_units, &in_hit)));
        put("u_units_active_share", reached(&active_units, &in_strong) as f64 / active_units.len().max(1) as f64);
        put("u_units_enabled", logn(reached(&enabled_units, &in_strong)));
        put("u_procs", logn(procs));
        put("u_procs_share", procs as f64 / self.proc_exes.len().max(1) as f64);
        put(
            "u_listeners",
            logn(listener_names
                .iter()
                .filter(|n| self.proc_exes.iter().any(|e| strong.contains(e) && e.ends_with(&format!("/{n}"))))
                .count()),
        );
        put("u_referenced", logn(referenced));
        put("u_package_share", names.len() as f64 / self.packages.len().max(1) as f64);
        put("u_unused", if outside.is_empty() && text.is_empty() { 1.0 } else { 0.0 });
    }

    /// `train_live.service_features(m, "stop", unit)` without `restart`, then
    /// `train_usage.Usage.service_features`.
    fn service_features(&self, unit: &str, x: &mut BTreeMap<String, f64>) {
        let p = self.props(unit);
        let get = |k: &str| p.get(k).map(String::as_str);
        let is = |k: &str, v: &str| f64::from(u8::from(get(k) == Some(v)));
        let not_none = |k: &str| f64::from(u8::from(get(k).unwrap_or("none") != "none"));
        let count = |k: &str| words(get(k).unwrap_or("")).count();
        let text = get("_text").unwrap_or("");
        let pid = get("MainPID").unwrap_or("0");
        let number = |k: &str| {
            let v = get(k).unwrap_or("0");
            if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) {
                v.parse::<f64>().unwrap_or(0.0)
            } else {
                0.0
            }
        };
        let mut put = |k: &str, v: f64| {
            x.insert(format!("unit_{k}"), v);
        };
        put("svc", 1.0);
        put("active", is("ActiveState", "active"));
        put("enabled", is("UnitFileState", "enabled"));
        put("loaded", is("LoadState", "loaded"));
        put("oneshot", is("Type", "oneshot"));
        put("refuse_stop", is("RefuseManualStop", "yes"));
        put("refuse_start", is("RefuseManualStart", "yes"));
        put("no_default_deps", is("DefaultDependencies", "no"));
        put("success_action", not_none("SuccessAction"));
        put("failure_action", not_none("FailureAction"));
        put("job_action", not_none("JobTimeoutAction"));
        put("isolate", is("AllowIsolate", "yes"));
        put("conflicts", logn(count("Conflicts")));
        put("conflicts_shutdown", f64::from(u8::from(words(get("Conflicts").unwrap_or("")).any(|w| w == "shutdown.target"))));
        put("required_by", logn(count("RequiredBy") + count("RequisiteOf")));
        put("wanted_by", logn(count("WantedBy")));
        put("before", logn(count("Before")));
        put("after", logn(count("After")));
        put("has_main_pid", f64::from(u8::from(pid != "0")));
        put("listens", f64::from(u8::from(self.listeners.iter().any(|(_, q)| q == pid))));
        put("tasks", log(number("TasksCurrent")));
        put("triggered", f64::from(u8::from(!get("TriggeredBy").unwrap_or("").is_empty())));
        put("exec_systemctl", f64::from(u8::from(text.contains("systemctl"))));

        let mut depends: HashSet<String> = HashSet::new();
        let mut frontier = vec![unit.to_string()];
        while let Some(current) = frontier.pop() {
            let props = self.props(&current);
            for key in SERVICE_LINKS {
                for word in words(props.get(*key).map(String::as_str).unwrap_or("")) {
                    if let Some(name) = word.strip_suffix(".service") {
                        if depends.insert(name.to_string()) {
                            frontier.push(name.to_string());
                        }
                    }
                }
            }
        }
        let active = |names: &mut dyn Iterator<Item = &String>| names.filter(|n| self.prop(n, "ActiveState") == "active").count();
        let me = format!("{unit}.service");
        let after: Vec<&String> =
            self.units.iter().filter(|(n, q)| *n != unit && words(q.get("After").map(String::as_str).unwrap_or("")).any(|w| w == me)).map(|(n, _)| n).collect();
        let owner = self.unit_owner(unit);
        static PROGRAM: OnceLock<Regex> = OnceLock::new();
        let program = PROGRAM.get_or_init(|| Regex::new(r"^/(usr/)?s?bin/").unwrap());
        let programs: HashSet<&str> = owner
            .map(|o| self.lists.get(o).into_iter().flatten().filter(|f| program.is_match(f)).map(|f| base_name(f)).collect())
            .unwrap_or_default();
        let exes = self.unit_files.get(unit);
        let empty = HashSet::new();
        let exes = exes.unwrap_or(&empty);
        let exec_lines = p.iter().filter(|(k, v)| k.starts_with("Exec") && !k.ends_with("Ex") && v.contains("path=")).count();
        let shared = self.unit_files.iter().filter(|(n, other)| *n != unit && !exes.is_disjoint(other)).count();
        let mut put = |k: &str, v: f64| {
            x.insert(format!("unit_{k}"), v);
        };
        put("s_required_active", logn(active(&mut depends.iter())));
        put("s_required", logn(depends.len()));
        put("s_after_active", logn(active(&mut after.iter().copied())));
        put("s_after", logn(after.len()));
        put("s_owner_listens", f64::from(u8::from(self.listeners.iter().any(|(n, _)| programs.contains(n.as_str())))));
        put(
            "s_owner_units_active",
            match owner {
                Some(o) => logn(self.units.iter().filter(|(n, q)| self.unit_owner(n) == Some(o) && q.get("ActiveState").map(String::as_str) == Some("active")).count()),
                None => 0.0,
            },
        );
        put("s_named_by", logn(self.names_used.get(unit).copied().unwrap_or(0) + self.names_used.get(&me).copied().unwrap_or(0)));
        put("s_memory", log(number("MemoryCurrent")));
        put("s_cpu", log(number("CPUUsageNSec")));
        put("s_running", is("SubState", "running"));
        put("s_remain", is("RemainAfterExit", "yes"));
        put("s_restarts_itself", f64::from(u8::from(get("Restart").unwrap_or("no") != "no")));
        put("s_exec_lines", logn(exec_lines));
        put("s_shared_exe", logn(shared));
    }

    fn path_facts(&self, path: &str, prefix: &str, x: &mut BTreeMap<String, f64>) {
        let path = norm(path);
        let inside = self.under(&path);
        let owner = self
            .owned_by
            .get(&path)
            .filter(|o| !o.is_empty())
            .or_else(|| inside.first().map(|p| &self.owned_by[p]))
            .filter(|o| !o.is_empty());
        let mut touched: HashSet<&String> = inside.iter().collect();
        touched.insert(&path);
        let union = |m: &HashMap<String, HashSet<String>>| {
            touched.iter().flat_map(|p| m.get(*p).into_iter().flatten()).collect::<HashSet<_>>().len()
        };
        let mut put = |k: &str, v: f64| {
            x.insert(format!("{prefix}{k}"), v);
        };
        put("p_known", f64::from(u8::from(owner.is_some())));
        put("p_files_inside", logn(inside.len()));
        put("p_programs_inside", logn(inside.iter().filter(|p| starts_with_any(p, COMMAND_DIRS)).count()));
        put("p_strong_users", logn(union(&self.strong_users)));
        put("p_text_users", logn(union(&self.text_users)));
        put("p_mapped", logn(touched.iter().filter(|p| self.mapped.contains(**p)).count()));
        let field = |k: &str| owner.and_then(|o| self.field(o, k));
        put("p_owner_essential", f64::from(u8::from(field("Essential") == Some("yes"))));
        put("p_owner_required", f64::from(u8::from(field("Priority") == Some("required"))));
        put("p_owner_rdeps", owner.map_or(0.0, |o| logn(self.rdeps.get(o).map_or(0, |s| s.len()))));
    }

    fn has_unit(&self, name: &str) -> bool {
        self.units.contains_key(name)
    }

    fn has_package(&self, name: &str) -> bool {
        self.packages.contains_key(name)
    }
}

/// The program a command runs, as training named it.
pub fn stem(argv0: &str) -> &str {
    let name = base_name(argv0);
    if name == "apt-get" {
        "apt"
    } else {
        name
    }
}

struct Patterns {
    setuid: Regex,
    world_write: Regex,
    owner: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        setuid: Regex::new(r"^[ugoa]*[+=][rwxXt]*s|^[2-7][0-7]{3}$").unwrap(),
        world_write: Regex::new(r"^(o|a|[ugo]*o[ugo]*)[+=][rxXst]*w|^[0-7]{0,2}[0-7][2367]$").unwrap(),
        owner: Regex::new(r"^[A-Za-z_][\w.-]*(:[\w.-]*)?$|^:[\w.-]+$").unwrap(),
    })
}

/// Numbers and words about a command, from its arguments, its target's mode
/// bits and the machine. `train_actions.features`.
pub fn features(argv: &[String], target_mode: Option<u32>, m: &dyn Facts) -> (BTreeMap<String, f64>, Vec<String>) {
    let args = &argv[1..];
    let flags: Vec<&String> = args.iter().filter(|a| a.starts_with('-')).collect();
    let plain: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    let paths: Vec<&String> = plain.iter().copied().filter(|a| a.starts_with('/')).collect();
    let pat = patterns();
    let b = |v: bool| f64::from(u8::from(v));
    let mode = target_mode.unwrap_or(0);
    let has = target_mode.is_some();
    let mut x = BTreeMap::new();
    x.insert("n_args".into(), logn(args.len()));
    x.insert("n_flags".into(), logn(flags.len()));
    x.insert("n_paths".into(), logn(paths.len()));
    x.insert("changing_words".into(), args.iter().filter(|a| CHANGING_WORDS.contains(&a.as_str())).count() as f64);
    x.insert("arg_setuid".into(), b(plain.iter().any(|a| pat.setuid.is_match(a))));
    x.insert("arg_world_write".into(), b(plain.iter().any(|a| pat.world_write.is_match(a))));
    x.insert("arg_owner_not_root".into(), b(plain.iter().take(1).any(|a| pat.owner.is_match(a) && !a.starts_with("root"))));
    x.insert("absent_target".into(), b(!has));
    x.insert("target_private".into(), b(has && mode & 0o004 == 0));
    x.insert("mode_setuid".into(), b(mode & 0o6000 != 0));
    x.insert("mode_other_read".into(), b(mode & 0o004 != 0));
    x.insert("mode_other_write".into(), b(mode & 0o002 != 0));
    x.insert("mode_group_write".into(), b(mode & 0o020 != 0));
    x.insert("mode_exec".into(), b(mode & 0o111 != 0));
    for place in LOCATIONS {
        let name = format!("in{}", place.trim_end_matches('/').replace('/', "_"));
        x.insert(name, b(paths.iter().any(|p| p.starts_with(place))));
    }
    let program = stem(&argv[0]);
    let mut ws = vec![format!("program={program}")];
    ws.extend(flags.iter().map(|a| format!("flag={}", a.split('=').next().unwrap_or(""))));
    if let Some(first) = plain.first() {
        if !first.starts_with('/') {
            ws.push(format!("action={program}:{first}"));
        }
    }
    ws.extend(paths.iter().map(|p| format!("place={}", p.split('/').take(4).collect::<Vec<_>>().join("/"))));
    if let Some(last) = paths.last() {
        m.path_facts(last, "", &mut x);
        let trimmed = last.trim_end_matches('/');
        let parent = trimmed.rsplit_once('/').map_or("", |(p, _)| p);
        m.path_facts(if parent.is_empty() { "/" } else { parent }, "d_", &mut x);
    }
    for word in &plain {
        let name = word.strip_suffix(".service").unwrap_or(word);
        if m.has_unit(name) {
            m.service_features(name, &mut x);
            break;
        }
        if m.has_package(name) {
            m.remove_features(name, &mut x);
            break;
        }
    }
    (x, ws)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn norm_and_resolve_follow_merged_usr() {
        assert_eq!(norm("/bin/sh"), "/usr/bin/sh");
        assert_eq!(norm("/etc/x"), "/etc/x");
        assert_eq!(resolve("/usr/bin/vi", "/etc/alternatives/vi"), "/etc/alternatives/vi");
        assert_eq!(resolve("/usr/lib/x/libfoo.so", "../libbar.so"), "/usr/lib/libbar.so");
        assert_eq!(resolve("/bin/sh", "dash"), "/usr/bin/dash");
    }

    #[test]
    fn listeners_take_the_first_process_of_each_socket() {
        let ss = r#"tcp LISTEN 0 4096 0.0.0.0:22 users:(("sshd",pid=612,fd=3),("sshd",pid=1,fd=3))
udp UNCONN 0 0 x users:(("systemd-resolve",pid=40,fd=12))
bad users:(("",pid=1)) users:(("noquote,pid=1"#;
        assert_eq!(
            listeners(ss),
            vec![("sshd".to_string(), "612".to_string()), ("systemd-resolve".to_string(), "40".to_string())]
        );
    }

    #[test]
    fn status_keeps_installed_packages_and_continuations() {
        let text = "Package: a\nStatus: install ok installed\nDepends: b (>= 1), c | d:any\nDescription: x\n more\n\nPackage: z\nStatus: deinstall ok config-files\n";
        let p = parse_status(text);
        assert_eq!(p.len(), 1);
        assert_eq!(p["a"]["Description"], "x more");
        assert_eq!(clauses(&p["a"]), vec![vec!["b".to_string()], vec!["c".to_string(), "d".to_string()]]);
    }

    #[test]
    fn stem_names_apt_get_apt() {
        assert_eq!(stem("/usr/bin/apt-get"), "apt");
        assert_eq!(stem("cp"), "cp");
    }
}
