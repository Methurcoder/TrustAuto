//! The answers to everything `features` asks about the machine, computed by
//! `trustauto-facts` when it collects, so that a decision only looks them up.
//!
//! Package and unit features depend only on the name, so every one is computed in
//! advance. Path features depend on the path a command names, so the paths they
//! can touch are kept sorted, with the users of each as numbers, and counted per
//! request exactly as `Machine::path_facts` does. `tests/facts_parity.rs` checks
//! that both give the same features on every lab row.

use crate::facts::{logn, norm, starts_with_any, Facts, Machine, COMMAND_DIRS};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

pub const INDEX_PATH: &str = "/var/lib/trustauto/facts.index.json";
pub const INDEX_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
pub struct Index {
    pub version: u32,
    /// Unix seconds when the facts it was built from were collected.
    pub collected_at: u64,
    /// `remove_features` of every installed package.
    packages: BTreeMap<String, BTreeMap<String, f64>>,
    /// `service_features` of every unit.
    units: BTreeMap<String, BTreeMap<String, f64>>,
    paths: Paths,
}

/// Every path a path feature can touch, in sorted order. The paths sit in one
/// string, and the users of each path are numbers in one list, so reading the
/// index makes a handful of allocations rather than one per path.
#[derive(Debug, Serialize, Deserialize)]
struct Paths {
    text: String,
    /// Where each path starts in `text`, plus its end.
    starts: Vec<u32>,
    /// 1 when a package owns the path (`Machine::paths`).
    owned: Vec<u8>,
    /// 1 when a running process has it mapped.
    mapped: Vec<u8>,
    /// Into `owners`, or -1.
    owner: Vec<i32>,
    owners: Vec<Owner>,
    /// `strong_users` and `text_users` of path i: `strong[strong_at[i]..strong_at[i + 1]]`.
    strong_at: Vec<u32>,
    strong: Vec<u32>,
    text_at: Vec<u32>,
    text_users: Vec<u32>,
}

/// What the path features need about the package that owns a path.
#[derive(Debug, Serialize, Deserialize)]
struct Owner {
    essential: bool,
    required: bool,
    rdeps: u32,
}

impl Index {
    pub fn build(m: &Machine, collected_at: u64) -> Index {
        // About 12 s for 800 packages on one core, since each walks who uses its
        // files. They are independent, so they are spread over the cores; the
        // heavy shared libraries sort together, hence every n-th name per thread.
        let names: Vec<&String> = m.packages.keys().collect();
        let threads = std::thread::available_parallelism().map_or(1, |n| n.get()).min(8);
        let packages: BTreeMap<String, BTreeMap<String, f64>> = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..threads)
                .map(|k| {
                    let names = &names;
                    scope.spawn(move || {
                        names
                            .iter()
                            .skip(k)
                            .step_by(threads)
                            .map(|name| {
                                let mut x = BTreeMap::new();
                                m.remove_features(name, &mut x);
                                ((*name).clone(), x)
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            workers.into_iter().flat_map(|w| w.join().expect("package features")).collect()
        });
        let mut units = BTreeMap::new();
        for name in m.units.keys() {
            let mut x = BTreeMap::new();
            m.service_features(name, &mut x);
            units.insert(name.clone(), x);
        }
        Index { version: INDEX_VERSION, collected_at, packages, units, paths: Paths::build(m) }
    }

    pub fn parse(text: &str) -> Result<Index, String> {
        let index: Index = serde_json::from_str(text).map_err(|e| format!("bad facts index: {e}"))?;
        if index.version != INDEX_VERSION {
            return Err(format!("facts index version {} is not {INDEX_VERSION}", index.version));
        }
        index.paths.check()?;
        Ok(index)
    }
}

impl Paths {
    fn build(m: &Machine) -> Paths {
        let all: BTreeSet<&str> = m
            .paths
            .iter()
            .chain(m.strong_users.keys())
            .chain(m.text_users.keys())
            .chain(m.mapped.iter())
            .map(String::as_str)
            .collect();
        let mut users: HashMap<&str, u32> = HashMap::new();
        fn id<'m>(users: &mut HashMap<&'m str, u32>, user: &'m str) -> u32 {
            let next = users.len() as u32;
            *users.entry(user).or_insert(next)
        }
        let mut owner_ids: HashMap<&str, i32> = HashMap::new();
        let mut p = Paths {
            text: String::new(),
            starts: Vec::with_capacity(all.len() + 1),
            owned: Vec::with_capacity(all.len()),
            mapped: Vec::with_capacity(all.len()),
            owner: Vec::with_capacity(all.len()),
            owners: Vec::new(),
            strong_at: vec![0],
            strong: Vec::new(),
            text_at: vec![0],
            text_users: Vec::new(),
        };
        for path in all {
            p.starts.push(p.text.len() as u32);
            p.text.push_str(path);
            let owned_by = m.owned_by.get(path);
            p.owned.push(u8::from(owned_by.is_some()));
            p.mapped.push(u8::from(m.mapped.contains(path)));
            let owner = owned_by.filter(|o| !o.is_empty()).map(|o| {
                *owner_ids.entry(o.as_str()).or_insert_with(|| {
                    p.owners.push(Owner {
                        essential: m.field(o, "Essential") == Some("yes"),
                        required: m.field(o, "Priority") == Some("required"),
                        rdeps: m.rdeps.get(o).map_or(0, |s| s.len() as u32),
                    });
                    p.owners.len() as i32 - 1
                })
            });
            p.owner.push(owner.unwrap_or(-1));
            p.strong.extend(m.strong_users.get(path).into_iter().flatten().map(|u| id(&mut users, u)));
            p.strong_at.push(p.strong.len() as u32);
            p.text_users.extend(m.text_users.get(path).into_iter().flatten().map(|u| id(&mut users, u)));
            p.text_at.push(p.text_users.len() as u32);
        }
        p.starts.push(p.text.len() as u32);
        p
    }

    /// A damaged index must fail to load, never index out of bounds later.
    fn check(&self) -> Result<(), String> {
        let n = self.owned.len();
        let sorted = |at: &[u32], len: usize| at.len() == n + 1 && at.windows(2).all(|w| w[0] <= w[1]) && at[n] as usize == len;
        let ok = sorted(&self.starts, self.text.len())
            && self.starts.iter().all(|&s| self.text.is_char_boundary(s as usize))
            && self.mapped.len() == n
            && self.owner.len() == n
            && self.owner.iter().all(|&o| o >= -1 && (o as i64) < self.owners.len() as i64)
            && sorted(&self.strong_at, self.strong.len())
            && sorted(&self.text_at, self.text_users.len())
            && (0..n.saturating_sub(1)).all(|i| self.path(i) < self.path(i + 1));
        if ok { Ok(()) } else { Err("bad facts index: inconsistent path table".to_string()) }
    }

    fn len(&self) -> usize {
        self.owned.len()
    }

    fn path(&self, i: usize) -> &str {
        &self.text[self.starts[i] as usize..self.starts[i + 1] as usize]
    }

    fn find(&self, path: &str) -> Option<usize> {
        let i = self.first_at_least(path);
        (i < self.len() && self.path(i) == path).then_some(i)
    }

    fn first_at_least(&self, s: &str) -> usize {
        let (mut low, mut high) = (0, self.len());
        while low < high {
            let mid = (low + high) / 2;
            if self.path(mid) < s {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        low
    }

    /// The owned paths below `path`, as `Machine::under` finds them.
    fn under(&self, path: &str) -> Vec<usize> {
        let trimmed = path.trim_end_matches('/');
        let at = self.first_at_least(&format!("{trimmed}/"));
        let end = self.first_at_least(&format!("{trimmed}0"));
        (at..end.max(at)).filter(|&i| self.owned[i] == 1).collect()
    }

    fn owner_of(&self, i: usize) -> Option<&Owner> {
        usize::try_from(self.owner[i]).ok().map(|o| &self.owners[o])
    }

    fn strong_of(&self, i: usize) -> &[u32] {
        &self.strong[self.strong_at[i] as usize..self.strong_at[i + 1] as usize]
    }

    fn text_of(&self, i: usize) -> &[u32] {
        &self.text_users[self.text_at[i] as usize..self.text_at[i + 1] as usize]
    }
}

impl Facts for Index {
    fn path_facts(&self, path: &str, prefix: &str, x: &mut BTreeMap<String, f64>) {
        let p = &self.paths;
        let path = norm(path);
        let inside = p.under(&path);
        let me = p.find(&path);
        let owner = me
            .filter(|&i| p.owned[i] == 1)
            .and_then(|i| p.owner_of(i))
            .or_else(|| inside.first().and_then(|&i| p.owner_of(i)));
        let mut touched: HashSet<usize> = inside.iter().copied().collect();
        touched.extend(me);
        let union = |of: fn(&Paths, usize) -> &[u32]| touched.iter().flat_map(|&i| of(p, i)).collect::<HashSet<_>>().len();
        let mut put = |k: &str, v: f64| {
            x.insert(format!("{prefix}{k}"), v);
        };
        put("p_known", f64::from(u8::from(owner.is_some())));
        put("p_files_inside", logn(inside.len()));
        put("p_programs_inside", logn(inside.iter().filter(|&&i| starts_with_any(p.path(i), COMMAND_DIRS)).count()));
        put("p_strong_users", logn(union(Paths::strong_of)));
        put("p_text_users", logn(union(Paths::text_of)));
        put("p_mapped", logn(touched.iter().filter(|&&i| p.mapped[i] == 1).count()));
        put("p_owner_essential", f64::from(u8::from(owner.is_some_and(|o| o.essential))));
        put("p_owner_required", f64::from(u8::from(owner.is_some_and(|o| o.required))));
        put("p_owner_rdeps", owner.map_or(0.0, |o| logn(o.rdeps as usize)));
    }

    fn has_unit(&self, name: &str) -> bool {
        self.units.contains_key(name)
    }

    fn has_package(&self, name: &str) -> bool {
        self.packages.contains_key(name)
    }

    fn service_features(&self, unit: &str, x: &mut BTreeMap<String, f64>) {
        x.extend(self.units.get(unit).into_iter().flatten().map(|(k, v)| (k.clone(), *v)));
    }

    fn remove_features(&self, package: &str, x: &mut BTreeMap<String, f64>) {
        x.extend(self.packages.get(package).into_iter().flatten().map(|(k, v)| (k.clone(), *v)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::Snapshot;
    use serde_json::{json, Value};

    fn saved() -> Value {
        let mut s = Snapshot::default();
        s.lists.insert("p".into(), vec!["/usr/bin/a".into(), "/usr/bin/b".into()]);
        serde_json::to_value(Index::build(&Machine::new(&s), 1)).unwrap()
    }

    #[test]
    fn a_saved_index_reads_back() {
        let index = Index::parse(&saved().to_string()).unwrap();
        let mut x = BTreeMap::new();
        index.path_facts("/usr/bin", "", &mut x);
        assert_eq!(x["p_files_inside"], logn(2));
    }

    #[test]
    fn a_damaged_or_foreign_index_does_not_load() {
        let mut v = saved();
        v["version"] = json!(INDEX_VERSION + 1);
        assert!(Index::parse(&v.to_string()).is_err());
        let mut v = saved();
        v["paths"]["starts"] = json!([0, 999, 999]);
        assert!(Index::parse(&v.to_string()).is_err());
        let mut v = saved();
        v["paths"]["owner"] = json!([7, 7]);
        assert!(Index::parse(&v.to_string()).is_err());
        let mut v = saved();
        let text = v["paths"]["text"].as_str().unwrap().to_string();
        v["paths"]["text"] = json!(text.chars().rev().collect::<String>());
        assert!(Index::parse(&v.to_string()).is_err());
    }
}
