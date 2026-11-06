#!/usr/bin/env python3
"""Tests whether ML alone can approve commands, on machines and packages it never saw.

The features name no capability and no package. They only describe what a command
would take away from this machine: running programs, listening sockets, enabled units,
login modules. That is what makes unseen kinds of damage possible to catch at all.

Fixed before any result of this experiment was looked at:

- Damage: any check that passed on the untouched machine fails afterwards, role probes
  included. Stopping a database counts, even when that is exactly what was asked.
- Independence: all cases of a source package are one group, across machines. The count
  that matters is groups, not rows.
- Every row is scored by a model that saw neither its machine nor its group.
- The threshold is chosen inside the training part only: it lets through at most 1% of
  the risky rows there, scored out of fold.
- Pass: risky auto under 1% (95% upper bound, by group) and harmless auto at least 70%.

Changed after the label counts were seen and before any model score was: the refusal
check only knew the wording of the newest apt, so 318 refusals by older apt versions read
as inconclusive and would have added refused packages to the risky groups. When apt
refuses, nothing happens, so the row says nothing about damage either way. Such rows are
dropped from training and scoring unless a check still failed. --refused shows what the
other two treatments would have given.

  train_live.py DATA_DIR MACHINE [MACHINE...] [--final MACHINE] [--refused drop|harmless|inconclusive]

--final opens a machine built after the method was frozen. Use it once.
"""
import collections
import hashlib
import json
import math
import re
import sys

import numpy as np
from sklearn.ensemble import GradientBoostingClassifier

from train_facts import clauses, rule_of_three

TREES = 150
DEPTH = 3
RISKY_BUDGET = 0.01
ROUTINE_TARGET = 0.70
FOLDS = 5
REFUSALS = ("conflicting assignments", "generated breaks")


def parse_status(text):
    packages = {}
    for block in text.split("\n\n"):
        fields, key = {}, None
        for line in block.splitlines():
            if line.startswith(" ") and key:
                fields[key] += " " + line.strip()
            elif ":" in line:
                key, value = line.split(":", 1)
                fields[key] = value.strip()
        if fields.get("Status") == "install ok installed":
            packages[fields["Package"]] = fields
    return packages


class Machine:
    def __init__(self, name, facts):
        self.name = name
        self.packages = parse_status(facts["status"])
        self.lists = facts["lists"]
        self.units = facts["units"]
        self.procs = facts["procs"]
        self.baseline = {k for k, v in facts["checks"].items() if v}
        self.pam = "\n".join(facts["pam"].values())
        self.listeners = re.findall(r'users:\(\("([^"]+)",pid=(\d+)', facts["ss"])
        self.owner = {f: n for n, files in self.lists.items() for f in files}
        self.providers = collections.defaultdict(set)
        for package, fields in self.packages.items():
            self.providers[package].add(package)
            for item in fields.get("Provides", "").split(","):
                item = item.split("(")[0].split(":")[0].strip()
                if item:
                    self.providers[item].add(package)
        self.needs = {n: clauses(f) for n, f in self.packages.items()}
        self.rdeps = collections.defaultdict(set)
        for package, needed in self.needs.items():
            for clause in needed:
                for alt in clause:
                    for provider in self.providers.get(alt, ()):
                        self.rdeps[provider].add(package)

    def closure(self, package):
        gone, frontier = {package}, [package]
        while frontier:
            for dependent in self.rdeps.get(frontier.pop(), ()):
                if dependent in gone:
                    continue
                for clause in self.needs[dependent]:
                    providers = set().union(*(self.providers.get(a, set()) for a in clause))
                    if providers and providers <= gone:
                        gone.add(dependent)
                        frontier.append(dependent)
                        break
        return gone

    def source(self, package):
        fields = self.packages.get(package, {})
        return fields.get("Source", package).split(" ")[0]

    def unit_owner(self, unit):
        path = self.units.get(unit, {}).get("FragmentPath", "")
        for candidate in (path, path.replace("/usr/lib/", "/lib/"), path.replace("/lib/", "/usr/lib/")):
            if candidate in self.owner:
                return self.owner[candidate]
        return None

    def group(self, kind, name):
        if kind == "remove":
            return "src:" + self.source(name)
        owner = self.unit_owner(name)
        return "src:" + self.source(owner) if owner else "unit:" + name


def log(n):
    return math.log1p(n)


def remove_features(m, package):
    names = m.closure(package)
    files = [f for n in names for f in m.lists.get(n, [])]
    owned = set(files)
    fields = [m.packages.get(n, {}) for n in names]
    running = [p for p in m.procs if p["exe"] in owned]
    mapping = [p for p in m.procs if p["exe"] in owned or owned.intersection(p["maps"])]
    exes = {p["exe"] for p in mapping}
    active = [u for u, p in m.units.items() if p.get("FragmentPath") in owned and p.get("ActiveState") == "active"]
    enabled = [u for u, p in m.units.items() if p.get("FragmentPath") in owned and p.get("UnitFileState") == "enabled"]
    modules = {f.rsplit("/", 1)[1] for f in files if "/security/pam_" in f}
    return {
        "svc": 0.0, "closure": log(len(names)), "direct_rdeps": log(len(m.rdeps.get(package, ()))),
        "files": log(len(files)), "size": log(sum(int(f.get("Installed-Size", 0) or 0) for f in fields)),
        "essential": sum(f.get("Essential") == "yes" for f in fields), "required": log(sum(f.get("Priority") == "required" for f in fields)),
        "important": log(sum(f.get("Priority") == "important" for f in fields)),
        "standard": log(sum(f.get("Priority") == "standard" for f in fields)),
        "unit_files": log(sum("/systemd/system/" in f for f in files)),
        "generators": sum("/system-generators/" in f for f in files),
        "programs": log(sum(re.match(r"^/(usr/)?s?bin/", f) is not None for f in files)),
        "shared_libs": log(sum(re.search(r"\.so(\.|$)", f) is not None for f in files)),
        "running_exes": log(len(running)), "mapping_procs": log(len(mapping)), "mapping_exes": log(len(exes)),
        "mapping_share": len(mapping) / max(len(m.procs), 1),
        "listeners": log(sum(any(os_name in e for e in exes) for os_name, _ in m.listeners)),
        "active_units": log(len(active)), "enabled_units": log(len(enabled)),
        "pam_modules_in_use": log(sum(mod in m.pam for mod in modules)),
        "pam_files": log(sum(f.startswith("/etc/pam.d/") for f in files)),
        "root_is_owner": float(package in names and len(names) == 1),
    }


def service_features(m, verb, unit):
    p = m.units.get(unit, {})
    words = lambda key: p.get(key, "").split()
    text = p.get("_text", "")
    pid = p.get("MainPID", "0")
    return {
        "svc": 1.0, "restart": float(verb == "restart"), "active": float(p.get("ActiveState") == "active"),
        "enabled": float(p.get("UnitFileState") == "enabled"), "loaded": float(p.get("LoadState") == "loaded"),
        "oneshot": float(p.get("Type") == "oneshot"), "refuse_stop": float(p.get("RefuseManualStop") == "yes"),
        "refuse_start": float(p.get("RefuseManualStart") == "yes"),
        "no_default_deps": float(p.get("DefaultDependencies") == "no"),
        "success_action": float(p.get("SuccessAction", "none") != "none"),
        "failure_action": float(p.get("FailureAction", "none") != "none"),
        "job_action": float(p.get("JobTimeoutAction", "none") != "none"),
        "isolate": float(p.get("AllowIsolate") == "yes"),
        "conflicts": log(len(words("Conflicts"))), "conflicts_shutdown": float("shutdown.target" in words("Conflicts")),
        "required_by": log(len(words("RequiredBy")) + len(words("RequisiteOf"))), "wanted_by": log(len(words("WantedBy"))),
        "before": log(len(words("Before"))), "after": log(len(words("After"))),
        "has_main_pid": float(pid != "0"), "listens": float(any(pid == q for _, q in m.listeners)),
        "tasks": log(int(p.get("TasksCurrent", "0")) if p.get("TasksCurrent", "0").isdigit() else 0),
        "triggered": float(bool(p.get("TriggeredBy"))), "exec_systemctl": float("systemctl" in text),
    }


def load_machine(data, name):
    return Machine(name, json.load(open(f"{data}/facts_{name}.json")))


def load_rows(data, name, on_refusal="drop"):
    m = load_machine(data, name)
    confirmed = collections.defaultdict(list)
    for suffix in ("confirm1", "confirm2"):
        try:
            for line in open(f"{data}/{suffix}_{name}.jsonl"):
                row = json.loads(line)
                if "checks" in row:
                    confirmed[" ".join(row["case"])].append({k for k, v in row["checks"].items() if not v})
        except FileNotFoundError:
            pass
    rows = []
    for line in open(f"{data}/out_{name}.jsonl"):
        row = json.loads(line)
        if "error" in row:
            continue
        kind, target = row["case"]
        bad = {k for k, v in row["checks"].items() if not v} & m.baseline
        # Damage must repeat in every confirmation run. A one-off failure is load, not damage.
        for run in confirmed.get(f"{kind} {target}", ()):
            bad &= run
        action = row["action"]
        tail = action.get("tail", "")
        refused = kind == "remove" and action["rc"] != 0 and any(s in tail for s in REFUSALS)
        if refused and not bad and on_refusal == "drop":
            continue
        inconclusive = kind == "remove" and action["rc"] != 0 and (not refused or on_refusal == "inconclusive")
        rows.append({
            "key": f"{name}: {kind} {target}", "machine": name, "bad": sorted(bad), "risky": bool(bad),
            "inconclusive": inconclusive, "group": m.group(kind, target),
            "x": remove_features(m, target) if kind == "remove" else service_features(m, kind, target),
        })
    return rows


def to_matrix(rows, names):
    return np.array([[r["x"].get(k, 0.0) for k in names] for r in rows], dtype=float)


def new_model():
    return GradientBoostingClassifier(n_estimators=TREES, max_depth=DEPTH, learning_rate=0.05,
                                      subsample=0.8, random_state=1)


def fit(rows, names):
    return new_model().fit(to_matrix(rows, names), [r["risky"] for r in rows])


def fold_of(group):
    return int(hashlib.sha256(("trustauto-live:" + group).encode()).hexdigest(), 16) % FOLDS


def threshold_inside(train, names):
    """Lets through at most the risky budget of the training rows, scored out of fold."""
    scores = []
    for fold in range(FOLDS):
        model = fit([r for r in train if fold_of(r["group"]) != fold], names)
        held = [r for r in train if fold_of(r["group"]) == fold and r["risky"]]
        if held:
            scores += list(model.predict_proba(to_matrix(held, names))[:, 1])
    scores.sort()
    return scores[int(len(scores) * RISKY_BUDGET)]


def evaluate(title, rows):
    """Rows carry `score` and `limit`. An inconclusive row auto-allowed counts against the method."""
    groups = collections.defaultdict(lambda: [False, False])
    for r in rows:
        allowed = r["score"] < r["limit"]
        if r["risky"] or r["inconclusive"]:
            groups[r["group"]][0] = True
            groups[r["group"]][1] |= allowed
    risky_groups = len(groups)
    missed_groups = sum(v[1] for v in groups.values())
    risky = [r for r in rows if r["risky"] or r["inconclusive"]]
    safe = [r for r in rows if not (r["risky"] or r["inconclusive"])]
    missed = [r for r in risky if r["score"] < r["limit"]]
    allowed_safe = sum(r["score"] < r["limit"] for r in safe)
    bound = rule_of_three(missed_groups, risky_groups)
    routine = allowed_safe / max(len(safe), 1)
    verdict = "PASS" if bound < RISKY_BUDGET and routine >= ROUTINE_TARGET else "FAIL"
    print(f"{title}: {verdict}")
    print(f"  risky auto {len(missed)}/{len(risky)} rows, {missed_groups}/{risky_groups} groups (95% UB {bound:.1%})")
    print(f"  harmless auto {allowed_safe}/{len(safe)} ({routine:.1%})")
    for r in sorted(missed, key=lambda r: r["score"])[:15]:
        print(f"    missed {r['key']} {r['bad']} {r['score']:.4f}")


def main():
    args = sys.argv[1:]
    on_refusal = "drop"
    if "--refused" in args:
        at = args.index("--refused")
        on_refusal = args[at + 1]
        del args[at:at + 2]
    data = args[0]
    final = args[args.index("--final") + 1] if "--final" in args else None
    machines = [a for a in args[1:args.index("--final")] if a] if final else args[1:]
    per_machine = {m: load_rows(data, m, on_refusal) for m in machines}
    everything = [r for rows in per_machine.values() for r in rows]
    names = sorted({k for r in everything for k in r["x"]})
    train_ok = lambda r: not r["inconclusive"]
    print("rows", len(everything), "risky", sum(r["risky"] for r in everything),
          "inconclusive", sum(r["inconclusive"] for r in everything),
          "groups", len({r["group"] for r in everything}),
          "risky groups", len({r["group"] for r in everything if r["risky"]}))
    print("damage by check", collections.Counter(c for r in everything for c in r["bad"]).most_common())

    # Each machine in turn is held out, and so is every source package it contains.
    held_rows = []
    for held in machines:
        test = per_machine[held]
        test_groups = {r["group"] for r in test}
        train = [r for m in machines if m != held for r in per_machine[m]
                 if train_ok(r) and r["group"] not in test_groups]
        print(f"hold out {held}: train {len(train)} rows ({sum(r['risky'] for r in train)} risky), test {len(test)}")
        limit = threshold_inside(train, names)
        scores = fit(train, names).predict_proba(to_matrix(test, names))[:, 1]
        for r, s in zip(test, scores):
            held_rows.append({**r, "score": float(s), "limit": limit})
    evaluate("unseen machine and unseen packages", held_rows)
    for kind, wanted in (("remove", 0.0), ("stop/restart", 1.0)):
        evaluate(f"  of which {kind}", [r for r in held_rows if r["x"]["svc"] == wanted])

    if final:
        test = load_rows(data, final, on_refusal)
        known = {r["group"] for r in everything}
        train = [r for r in everything if train_ok(r)]
        limit = threshold_inside(train, names)
        scores = fit(train, names).predict_proba(to_matrix(test, names))[:, 1]
        rows = [{**r, "score": float(s), "limit": limit} for r, s in zip(test, scores)]
        evaluate(f"FINAL {final} (opened)", rows)
        evaluate(f"FINAL {final}, packages unseen in training", [r for r in rows if r["group"] not in known])


if __name__ == "__main__":
    main()
