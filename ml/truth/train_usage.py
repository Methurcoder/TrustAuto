#!/usr/bin/env python3
"""train_live.py, changed in three ways after its results were seen.

1. The features also know who uses what on the machine.
2. The model may not learn that more use makes a command safer (monotonic constraints). Four
   models were tried on the development machines, and this is the best of them by overall
   AUC. The choice is therefore optimistic on those machines.
3. systemd and every package on all the development machines stay in training, also when a
   machine holding them is tested. Holding them out left no base system to learn from, while
   a released model is trained on it. Their results say nothing about unseen kinds of damage,
   so they are printed apart from the rest.

The labels and the pass mark stay as train_live.py has them. The machines named on the
command line are development data. Only machines built after this method is frozen can test
it, and those go after --final, separated by commas. One machine has about 100 risky groups
and showing under 1% takes about 300, so a single final machine cannot pass.

Strong links (library needed, interpreter, symlink) are followed as far as they go. Names
found in text are noisy, so they count one step only. Like the features before them, these
name no capability and no package. What a removal takes away comes from apt's own plan, because
apt may install a replacement or drop more than the declared dependencies suggest.

  train_usage.py DATA_DIR MACHINE [MACHINE...] [--final MACHINE,MACHINE...]
"""
import collections
import json
import re
import sys

from sklearn.ensemble import HistGradientBoostingClassifier

import train_live as base

log = base.log
COMMAND_DIRS = ("/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/usr/local/sbin/", "/usr/games/")
SERVICE_LINKS = ("RequiredBy", "RequisiteOf", "BoundBy", "ConsistsOf")
ALWAYS_TRAINED = {"src:systemd"}
# More of these can make a command either safer or riskier, so they carry no constraint.
UNCONSTRAINED = {"svc", "restart", "root_is_owner", "oneshot", "refuse_stop", "refuse_start", "no_default_deps",
                 "triggered", "s_remain", "s_restarts_itself", "loaded", "after", "before", "wanted_by",
                 "u_installs", "isolate"}
SAFER_WITH_MORE = {"u_unused"}


def norm(path):
    for old in ("/bin/", "/sbin/", "/lib/", "/lib64/"):
        if path.startswith(old):
            return "/usr" + path
    return path


def resolve(link, target):
    if target.startswith("/"):
        return norm(target)
    parts = link.split("/")[:-1]
    for piece in target.split("/"):
        if piece == "..":
            parts = parts[:-1]
        elif piece not in ("", "."):
            parts.append(piece)
    return norm("/".join(parts))


class Usage:
    def __init__(self, machine, usage):
        self.m = machine
        self.by_base = collections.defaultdict(set)
        self.commands = collections.defaultdict(set)
        self.strong_users = collections.defaultdict(set)
        self.text_users = collections.defaultdict(set)
        self.owned_by = {norm(f): n for n, files in machine.lists.items() for f in files}
        for path in self.owned_by:
            self.by_base[path.rsplit("/", 1)[1]].add(path)
        for link, target in usage["links"].items():
            link = norm(link)
            self.by_base[link.rsplit("/", 1)[1]].add(link)
            self.strong_users[resolve(link, target)].add(link)
        for path in set(self.owned_by) | {norm(p) for p in usage["links"]}:
            if path.startswith(COMMAND_DIRS):
                self.commands[path.rsplit("/", 1)[1]].add(path)
        for user, libraries in usage["needed"].items():
            for library in libraries:
                for path in self.by_base.get(library, ()):
                    self.strong_users[path].add(norm(user))
        for user, words in usage["interp"].items():
            first = norm(words[0])
            if first.endswith("/env") and len(words) > 1:
                for path in self.commands.get(words[1], ()):
                    self.strong_users[path].add(norm(user))
            else:
                self.strong_users[first].add(norm(user))
        self.names_used = collections.Counter()
        for user, words in usage["refs"].items():
            user = norm(user)
            for word in words:
                self.names_used[word] += 1
                targets = {norm(word)} if word.startswith("/") else self.commands.get(word, ())
                for path in targets:
                    self.text_users[path].add(user)
        self.programs = {p for p in self.owned_by if p.startswith(COMMAND_DIRS)}
        self.unit_files = {}
        for unit, props in machine.units.items():
            found = set()
            for key, value in props.items():
                if key.startswith("Exec") and not key.endswith("Ex"):
                    found.update(norm(p) for p in re.findall(r"path=(\S+)", value))
            self.unit_files[unit] = found
        self.proc_exes = [norm(p["exe"]) for p in machine.procs]

    def strong_reach(self, start):
        seen, frontier = set(start), list(start)
        while frontier:
            for user in self.strong_users.get(frontier.pop(), ()):
                if user not in seen:
                    seen.add(user)
                    frontier.append(user)
        return seen

    def remove_features(self, package):
        m = self.m
        names = m.closure(package)
        owned = {norm(f) for n in names for f in m.lists.get(n, [])}
        strong = self.strong_reach(owned)
        outside = strong - owned
        direct = {u for p in owned for u in self.strong_users.get(p, ())} - owned
        text = {u for p in strong for u in self.text_users.get(p, ())} - strong
        referenced = {p for p in owned if self.text_users.get(p, set()) - owned}
        hit = strong | text
        active = [u for u, p in m.units.items() if p.get("ActiveState") == "active"]
        enabled = [u for u, p in m.units.items() if p.get("UnitFileState") == "enabled"]
        reached = lambda units, seen: sum(bool(self.unit_files.get(u, set()) & seen) for u in units)
        procs = sum(e in strong for e in self.proc_exes)
        listeners = {name for name, _ in m.listeners}
        needed_providers = {q for n in names for clause in m.needs.get(n, ()) for alt in clause
                            for q in m.providers.get(alt, ())} - names
        extends = sum(any(m.unit_owner(u) == q for u in active) for q in needed_providers)
        return {
            "u_extends_active": log(extends), "u_installs": log(len(m.plans.get(package, {}).get("installs", ()))),
            "u_outside": log(len(outside)), "u_programs": log(len(outside & self.programs)),
            "u_programs_share": len(outside & self.programs) / max(len(self.programs), 1),
            "u_direct": log(len(direct)),
            "u_text_scripts": log(sum(p.startswith(COMMAND_DIRS) or "/lib/" in p for p in text)),
            "u_text_etc": log(sum(p.startswith("/etc/") for p in text)),
            "u_text_maint": log(sum(p.startswith("/var/lib/dpkg/info/") for p in text)),
            "u_text_units": log(sum("/systemd/system/" in p for p in text)),
            "u_units_active": log(reached(active, strong)), "u_units_active_text": log(reached(active, hit)),
            "u_units_active_share": reached(active, strong) / max(len(active), 1),
            "u_units_enabled": log(reached(enabled, strong)),
            "u_procs": log(procs), "u_procs_share": procs / max(len(self.proc_exes), 1),
            "u_listeners": log(sum(any(e in strong and e.endswith("/" + n) for e in self.proc_exes) for n in listeners)),
            "u_referenced": log(len(referenced)),
            "u_package_share": len(names) / max(len(m.packages), 1),
            "u_unused": float(not outside and not text),
        }

    def service_features(self, unit):
        m = self.m
        p = m.units.get(unit, {})
        depends, frontier = set(), [unit]
        while frontier:
            current = m.units.get(frontier.pop(), {})
            for key in SERVICE_LINKS:
                for word in current.get(key, "").split():
                    if word.endswith(".service") and word[:-8] not in depends:
                        depends.add(word[:-8])
                        frontier.append(word[:-8])
        active = lambda names: sum(m.units.get(n, {}).get("ActiveState") == "active" for n in names)
        after = [n for n, q in m.units.items() if n != unit and unit + ".service" in q.get("After", "").split()]
        owner = m.unit_owner(unit)
        programs = {f.rsplit("/", 1)[1] for f in m.lists.get(owner, []) if re.match(r"^/(usr/)?s?bin/", f)} if owner else set()
        number = lambda key: int(p.get(key, "0")) if p.get(key, "0").isdigit() else 0
        exes = self.unit_files.get(unit, set())
        return {
            "s_required_active": log(active(depends)), "s_required": log(len(depends)),
            "s_after_active": log(active(after)), "s_after": log(len(after)),
            "s_owner_listens": float(any(n in programs for n, _ in m.listeners)),
            "s_owner_units_active": log(sum(m.unit_owner(n) == owner and q.get("ActiveState") == "active"
                                            for n, q in m.units.items())) if owner else 0.0,
            "s_named_by": log(self.names_used.get(unit, 0) + self.names_used.get(unit + ".service", 0)),
            "s_memory": log(number("MemoryCurrent")), "s_cpu": log(number("CPUUsageNSec")),
            "s_running": float(p.get("SubState") == "running"), "s_remain": float(p.get("RemainAfterExit") == "yes"),
            "s_restarts_itself": float(p.get("Restart", "no") != "no"),
            "s_exec_lines": log(sum(k.startswith("Exec") and not k.endswith("Ex") and "path=" in v for k, v in p.items())),
            "s_shared_exe": log(sum(bool(exes & other) for n, other in self.unit_files.items() if n != unit)),
        }


frozen_load_rows = base.load_rows
frozen_load_machine = base.load_machine


def load_machine(data, name):
    """The machine, with apt's own plan in place of the closure train_live.py works out."""
    m = frozen_load_machine(data, name)
    plans = json.load(open(f"{data}/plans_{name}.json"))
    estimate = m.closure
    m.plans = plans
    # When apt refuses it has no plan to read. Keep the estimate rather than assume nothing happens.
    m.closure = lambda p: ({p, *plans[p]["removes"]} if p in plans and plans[p]["rc"] == 0 else estimate(p))
    return m


def load_rows(data, name, on_refusal="drop"):
    base.load_machine = load_machine
    m = load_machine(data, name)
    usage = Usage(m, json.load(open(f"{data}/usage_{name}.json")))
    rows = frozen_load_rows(data, name, on_refusal)
    for r in rows:
        kind, target = r["key"].split(": ", 1)[1].split(" ", 1)
        r["x"] = {**r["x"], **(usage.remove_features(target) if kind == "remove" else usage.service_features(target))}
    return rows


def fit(rows, names):
    signs = [0 if n in UNCONSTRAINED else -1 if n in SAFER_WITH_MORE else 1 for n in names]
    model = HistGradientBoostingClassifier(max_iter=300, max_depth=4, learning_rate=0.05, min_samples_leaf=3,
                                           monotonic_cst=signs, random_state=1)
    return model.fit(base.to_matrix(rows, names), [r["risky"] for r in rows])


def threshold_inside(train, names):
    """Lets through at most the risky budget of the training rows, scored out of fold."""
    scores = []
    for fold in range(base.FOLDS):
        held = lambda r: r["group"] not in ALWAYS_TRAINED and base.fold_of(r["group"]) == fold
        risky = [r for r in train if held(r) and r["risky"]]
        if risky:
            model = fit([r for r in train if not held(r)], names)
            scores += list(model.predict_proba(base.to_matrix(risky, names))[:, 1])
    scores.sort()
    return scores[int(len(scores) * base.RISKY_BUDGET)]


def report(title, rows):
    base.evaluate(title, rows)
    base.evaluate(f"  {title}, remove", [r for r in rows if r["x"]["svc"] == 0.0])
    base.evaluate(f"  {title}, stop/restart", [r for r in rows if r["x"]["svc"] == 1.0])
    base.evaluate(f"  {title}, packages kept out of training", [r for r in rows if r["group"] not in ALWAYS_TRAINED])
    base.evaluate(f"  {title}, packages always in training", [r for r in rows if r["group"] in ALWAYS_TRAINED])


def main():
    args = sys.argv[1:]
    finals = []
    if "--final" in args:
        at = args.index("--final")
        finals = args[at + 1].split(",")
        del args[at:at + 2]
    data, machines = args[0], args[1:]
    per_machine = {m: load_rows(data, m) for m in machines}
    everything = [r for rows in per_machine.values() for r in rows]
    names = sorted({k for r in everything for k in r["x"]})
    ALWAYS_TRAINED.update(set.intersection(*({r["group"] for r in rows} for rows in per_machine.values())))
    print("rows", len(everything), "risky", sum(r["risky"] for r in everything),
          "inconclusive", sum(r["inconclusive"] for r in everything),
          "risky groups", len({r["group"] for r in everything if r["risky"]}),
          "groups always in training", len(ALWAYS_TRAINED))

    held_rows = []
    for held in machines:
        test = per_machine[held]
        kept_out = {r["group"] for r in test} - ALWAYS_TRAINED
        train = [r for m in machines if m != held for r in per_machine[m]
                 if not r["inconclusive"] and r["group"] not in kept_out]
        limit = threshold_inside(train, names)
        scores = fit(train, names).predict_proba(base.to_matrix(test, names))[:, 1]
        held_rows += [{**r, "score": float(s), "limit": limit} for r, s in zip(test, scores)]
    report("development: unseen machine, unseen package unless always in training", held_rows)

    if finals:
        train = [r for r in everything if not r["inconclusive"]]
        limit = threshold_inside(train, names)
        model = fit(train, names)
        known = {r["group"] for r in everything}
        opened = []
        for machine in finals:
            test = load_rows(data, machine)
            scores = model.predict_proba(base.to_matrix(test, names))[:, 1]
            opened += [{**r, "score": float(s), "limit": limit} for r, s in zip(test, scores)]
        report(f"FINAL {','.join(finals)} (opened)", opened)
        base.evaluate("FINAL, packages unseen in training", [r for r in opened if r["group"] not in known])


if __name__ == "__main__":
    main()
