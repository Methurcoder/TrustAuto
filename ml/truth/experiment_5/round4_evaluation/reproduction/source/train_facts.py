#!/usr/bin/env python3
"""Trains on observed damage, using facts about this machine instead of command text.

Inputs come from truth_lab.py and collect_facts.py. Cases are split by source package
or unit family, so near-identical cases never straddle the split. Thresholds come from
the validation part only. Pass --test once, after the method is fixed.

  train_facts.py DATA_DIR [--test] [--fresh]
"""
import collections
import hashlib
import json
import math
import random
import re
import sys

EPOCHS = 400
LEARNING_RATE = 0.05
L2 = 1e-3
ROUTINE_TARGET = 0.70

# Named from the checks in truth_lab.py, before any result was looked at.
CAPABILITIES = {
    "sshd": r"^/usr/sbin/sshd$",
    "sudo": r"^/usr/bin/sudo$",
    "apt": r"^/usr/bin/apt-get$",
    "dpkg": r"^/usr/bin/dpkg$",
    "sh": r"^/(usr/)?bin/(dash|sh)$",
    "bash": r"^/(usr/)?bin/bash$",
    "init": r"^/usr/lib/systemd/systemd$",
    "dbus": r"^/usr/bin/dbus-daemon$|^/usr/bin/dbus-broker$|^/usr/share/dbus-1/system\.conf$",
    "journal": r"^/usr/bin/journalctl$",
    "netplan": r"^/usr/sbin/netplan$",
    "networkd": r"^/usr/lib/systemd/systemd-networkd$",
    "lvm": r"^/usr/sbin/lvm$",
}
# Containers cannot observe these, so a clean result proves nothing about them.
BOOT_CHAIN = re.compile(
    r"^/boot/|^/usr/lib/modules/|^/usr/lib/firmware/|^/usr/share/initramfs-tools/"
    r"|^/usr/sbin/(update-initramfs|mkinitramfs|update-grub|grub-|mdadm|multipath|cryptsetup|dracut)"
    r"|^/usr/lib/grub/|^/usr/lib/shim/|^/usr/bin/dracut"
)


def parse_status(path):
    packages = {}
    for block in open(path, errors="replace").read().split("\n\n"):
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


def clauses(fields):
    """Hard dependencies as lists of alternative package names."""
    text = ", ".join(x for x in (fields.get("Depends"), fields.get("Pre-Depends")) if x)
    return [[alt.split("(")[0].split(":")[0].strip() for alt in c.split("|")]
            for c in text.split(",") if c.strip()]


class Machine:
    def __init__(self, status_path, facts_path):
        self.packages = parse_status(status_path)
        facts = json.load(open(facts_path))
        self.lists = facts["lists"]
        self.units = facts["units"]
        self.providers = collections.defaultdict(set)
        for name, fields in self.packages.items():
            self.providers[name].add(name)
            for item in fields.get("Provides", "").split(","):
                item = item.split("(")[0].split(":")[0].strip()
                if item:
                    self.providers[item].add(name)
        self.needs = {n: clauses(f) for n, f in self.packages.items()}
        self.rdeps = collections.defaultdict(set)
        for name, cs in self.needs.items():
            for clause in cs:
                for alt in clause:
                    for provider in self.providers.get(alt, ()):
                        self.rdeps[provider].add(name)

    def closure(self, package):
        """Everything that loses a hard dependency when the package goes."""
        gone, frontier = {package}, [package]
        while frontier:
            current = frontier.pop()
            for dependent in self.rdeps.get(current, ()):
                if dependent in gone:
                    continue
                for clause in self.needs[dependent]:
                    providers = set().union(*(self.providers.get(a, set()) for a in clause))
                    if providers and providers <= gone:
                        gone.add(dependent)
                        frontier.append(dependent)
                        break
        return gone

    def files(self, names):
        return [f for n in names for f in self.lists.get(n, [])]

    def group(self, kind, name):
        if kind == "remove":
            fields = self.packages.get(name, {})
            return "src:" + fields.get("Source", name).split(" ")[0]
        return "unit:" + name.split("-")[0].split("@")[0]


def remove_features(m, package):
    names = m.closure(package)
    files = m.files(names)
    fields = [m.packages.get(n, {}) for n in names]
    x = collections.OrderedDict()
    x["log_closure"] = math.log1p(len(names))
    x["log_direct_rdeps"] = math.log1p(len(m.rdeps.get(package, ())))
    x["log_files"] = math.log1p(len(files))
    x["log_size"] = math.log1p(sum(int(f.get("Installed-Size", 0) or 0) for f in fields))
    x["essential"] = sum(f.get("Essential") == "yes" for f in fields) > 0
    x["required"] = math.log1p(sum(f.get("Priority") == "required" for f in fields))
    x["important"] = math.log1p(sum(f.get("Priority") == "important" for f in fields))
    x["standard"] = math.log1p(sum(f.get("Priority") == "standard" for f in fields))
    x["units"] = math.log1p(sum(f.startswith("/usr/lib/systemd/system/") for f in files))
    x["generators"] = any("/system-generators/" in f for f in files)
    x["pam"] = any("/security/pam_" in f or f.startswith("/etc/pam.d/") for f in files)
    x["sbin"] = math.log1p(sum(f.startswith("/usr/sbin/") for f in files))
    x["shared_lib"] = any(re.search(r"\.so(\.|$)", f) for f in m.lists.get(package, []))
    for capability, pattern in CAPABILITIES.items():
        x["cap_" + capability] = any(re.search(pattern, f) for f in files)
    return x, any(BOOT_CHAIN.search(f) for f in files), names


def service_features(m, verb, unit):
    props = m.units.get(unit, {})
    text = props.get("_text", "")
    words = lambda key: props.get(key, "").split()
    x = collections.OrderedDict()
    x["log_closure"] = x["log_direct_rdeps"] = x["log_files"] = x["log_size"] = 0.0
    x["svc"] = 1.0
    x["restart"] = verb == "restart"
    x["active"] = props.get("ActiveState") == "active"
    x["enabled"] = props.get("UnitFileState") == "enabled"
    x["loaded"] = props.get("LoadState") == "loaded"
    x["oneshot"] = props.get("Type") == "oneshot"
    x["refuse_stop"] = props.get("RefuseManualStop") == "yes"
    x["refuse_start"] = props.get("RefuseManualStart") == "yes"
    x["no_default_deps"] = props.get("DefaultDependencies") == "no"
    x["success_action"] = props.get("SuccessAction", "none") != "none"
    x["failure_action"] = props.get("FailureAction", "none") != "none"
    x["job_action"] = props.get("JobTimeoutAction", "none") != "none"
    x["isolate"] = props.get("AllowIsolate") == "yes"
    x["conflicts_shutdown"] = "shutdown.target" in words("Conflicts")
    x["conflicts_targets"] = any(t in words("Conflicts") for t in
                                 ("multi-user.target", "basic.target", "sysinit.target", "rescue.target"))
    x["log_required_by"] = math.log1p(len(words("RequiredBy")) + len(words("RequisiteOf")))
    x["log_wanted_by"] = math.log1p(len(words("WantedBy")))
    x["before_login"] = any("ssh" in b or "getty" in b or "user@" in b for b in words("Before"))
    x["exec_systemctl"] = "systemctl" in text and "ExecStart" in text
    x["shutdown_like"] = any(a in text for a in ("halt", "reboot", "poweroff", "kexec", "exit.target"))
    return x, False, {unit}


def load_cases(data):
    """Returns observed outcomes, after confirmation reruns overrule single-run damage."""
    final = json.load(open(f"{data}/merged.json"))
    votes = collections.defaultdict(list)
    for name in ("confirm1", "confirm2", "confirm3"):
        try:
            for line in open(f"{data}/{name}.jsonl"):
                row = json.loads(line)
                votes[" ".join(row["case"])].append(sorted(k for k, v in row["checks"].items() if not v))
        except FileNotFoundError:
            pass
    for key, runs in votes.items():
        final[key]["bad"] = runs[0] if all(r == runs[0] for r in runs) and final[key]["bad"] else (
            sorted(set(final[key]["bad"]) & set().union(*runs)) if any(runs) else [])
    return final


def build(data):
    m = Machine(f"{data}/dpkg_status.txt", f"{data}/facts.json")
    rows = []
    for key, outcome in load_cases(data).items():
        kind, name = key.split(" ", 1)
        x, blind, names = (remove_features(m, name) if kind == "remove"
                           else service_features(m, kind, name))
        inconclusive = outcome["status"] in ("dpkg_error", "solver_timeout")
        rows.append({"key": key, "x": x, "blind": blind, "inconclusive": inconclusive,
                     "risky": bool(outcome["bad"]), "bad": outcome["bad"],
                     "group": m.group(kind, name), "closure": sorted(names)})
    names = sorted({k for r in rows for k in r["x"]})
    for r in rows:
        r["v"] = [float(r["x"].get(k, 0.0)) for k in names]
    return rows, names


def build_fresh(data, names):
    """Cases from a machine with other roles, scored by a method already frozen."""
    m = Machine(f"{data}/dpkg_status_fresh.txt", f"{data}/facts_fresh.json")
    votes = collections.defaultdict(list)
    for name in ("fresh_confirm1", "fresh_confirm2"):
        try:
            for line in open(f"{data}/{name}.jsonl"):
                row = json.loads(line)
                votes[" ".join(row["case"])].append([k for k, v in row["checks"].items() if not v])
        except FileNotFoundError:
            pass
    rows = []
    for line in open(f"{data}/fresh.jsonl"):
        row = json.loads(line)
        kind, name = row["case"]
        bad = sorted(k for k, v in row["checks"].items() if not v)
        # Damage counts only if every confirmation run saw it too.
        if bad and not all(votes.get(f"{kind} {name}", [bad])):
            bad = []
        action = row["action"]
        refused = kind == "remove" and action["rc"] != 0 and "conflicting assignments" in action.get("tail", "")
        x, blind, closure = remove_features(m, name) if kind == "remove" else service_features(m, kind, name)
        rows.append({"key": f"{kind} {name}", "x": x, "blind": blind, "risky": bool(bad), "bad": bad,
                     "inconclusive": kind == "remove" and action["rc"] != 0 and not refused,
                     "group": m.group(kind, name), "closure": sorted(closure),
                     "v": [float(x.get(k, 0.0)) for k in names]})
    return rows


def part_of(group):
    """Fixed before any training: the salt was not chosen by looking at outcomes."""
    h = int(hashlib.sha256(("trustauto-truth-1:" + group).encode()).hexdigest(), 16) % 100
    return "train" if h < 60 else "val" if h < 80 else "test"


def standardize(train):
    n = len(train[0]["v"])
    means = [sum(r["v"][i] for r in train) / len(train) for i in range(n)]
    stds = [max(1e-6, math.sqrt(sum((r["v"][i] - means[i]) ** 2 for r in train) / len(train))) for i in range(n)]
    return lambda v: [(a - b) / c for a, b, c in zip(v, means, stds)]


def train_lr(train, scale, seed=1, l2=L2):
    rng = random.Random(seed)
    data = [(scale(r["v"]), 1.0 if r["risky"] else 0.0) for r in train]
    pos = sum(y for _, y in data)
    weight = {1.0: len(data) / (2 * max(pos, 1)), 0.0: len(data) / (2 * max(len(data) - pos, 1))}
    w, b = [0.0] * len(data[0][0]), 0.0
    for epoch in range(EPOCHS):
        rng.shuffle(data)
        rate = LEARNING_RATE / (1 + epoch / 100)
        for v, y in data:
            p = 1 / (1 + math.exp(-max(-30, min(30, sum(a * c for a, c in zip(w, v)) + b))))
            g = (p - y) * weight[y]
            w = [a - rate * (g * c + l2 * a) for a, c in zip(w, v)]
            b -= rate * g
    return lambda r: 1 / (1 + math.exp(-max(-30, min(30, sum(a * c for a, c in zip(w, scale(r["v"]))) + b)))), w


def auc(rows, score):
    pos = [score(r) for r in rows if r["risky"]]
    neg = [score(r) for r in rows if not r["risky"]]
    if not pos or not neg:
        return float("nan")
    return sum((p > n) + 0.5 * (p == n) for p in pos for n in neg) / (len(pos) * len(neg))


def rule_of_three(misses, total):
    """Exact one-sided 95% upper bound, by bisection on the binomial tail."""
    if total == 0:
        return 1.0
    low, high = misses / total, 1.0
    for _ in range(60):
        mid = (low + high) / 2
        tail = sum(math.comb(total, k) * mid ** k * (1 - mid) ** (total - k) for k in range(misses + 1))
        low, high = (mid, high) if tail > 0.05 else (low, mid)
    return high


def report(title, rows, allow):
    """A gated or inconclusive row counts as risky if the method would still auto-allow it."""
    risky = [r for r in rows if r["risky"] or r["inconclusive"]]
    safe = [r for r in rows if not (r["risky"] or r["inconclusive"])]
    missed = [r for r in risky if allow(r)]
    allowed_safe = sum(allow(r) for r in safe)
    allowed = allowed_safe + len(missed)
    print(f"  {title}: risky auto {len(missed)}/{len(risky)}"
          f" (95% UB {rule_of_three(len(missed), len(risky)):.1%})"
          f", harmless auto {allowed_safe}/{len(safe)}"
          f", damage among auto {len(missed)}/{allowed} (95% UB {rule_of_three(len(missed), allowed):.1%})")
    for r in missed[:12]:
        print(f"     missed: {r['key']} {r['bad']}")


def kind_of(r):
    return "svc" if "svc" in r["x"] else "remove"


def fit(rows, l2):
    """One model per kind: damage from a removal and from a stopped unit share no cause."""
    models = {}
    for kind in ("remove", "svc"):
        members = [r for r in rows if kind_of(r) == kind]
        scale = standardize(members)
        models[kind] = train_lr(members, scale, l2=l2)
    return lambda r: models[kind_of(r)][0](r), models


def out_of_fold(rows, l2, folds=5):
    """Scores each row with a model that never saw its group."""
    scores = {}
    for fold in range(folds):
        held = lambda r: int(hashlib.sha256(r["group"].encode()).hexdigest(), 16) % folds == fold
        score, _ = fit([r for r in rows if not held(r)], l2)
        for r in rows:
            if held(r):
                scores[r["key"]] = score(r)
    return scores


def main():
    data, open_test = sys.argv[1], "--test" in sys.argv[2:]
    rows, names = build(data)
    parts = collections.defaultdict(list)
    for r in rows:
        parts[part_of(r["group"])].append(r)
    for part, members in sorted(parts.items()):
        print(part, len(members), "risky", sum(r["risky"] for r in members),
              "inconclusive", sum(r["inconclusive"] for r in members),
              "blind", sum(r["blind"] for r in members), "groups", len({r["group"] for r in members}))

    # Inconclusive outcomes teach nothing, and the boot gate decides blind rows anyway.
    usable = lambda r: not r["inconclusive"] and not r["blind"]
    dev = [r for r in parts["train"] + parts["val"] if usable(r)]
    best = None
    for l2 in (1e-3, 1e-2, 3e-2, 1e-1):
        oof = out_of_fold(dev, l2)
        for kind in ("remove", "svc"):
            members = [r for r in dev if kind_of(r) == kind]
            print(f"l2={l2} {kind}: out-of-fold AUC", round(auc(members, lambda r: oof[r["key"]]), 3))
        result = sum(auc([r for r in dev if kind_of(r) == k], lambda r: oof[r["key"]]) for k in ("remove", "svc"))
        if best is None or result > best[0]:
            best = (result, l2, oof)
    _, l2, oof = best
    print("chosen l2", l2)
    # Thresholds: the lowest out-of-fold score of any risky row of that kind.
    low = {k: min(oof[r["key"]] for r in dev if kind_of(r) == k and r["risky"]) for k in ("remove", "svc")}
    print("thresholds", {k: round(v, 5) for k, v in low.items()})
    for kind in ("remove", "svc"):
        members = [r for r in dev if kind_of(r) == kind]
        print(f"out-of-fold {kind}: harmless auto",
              sum(oof[r["key"]] < low[kind] for r in members if not r["risky"]), "/",
              sum(not r["risky"] for r in members), "risky total", sum(r["risky"] for r in members))
    score, _ = fit(dev, l2)
    for kind in ("remove", "svc"):
        hardest = sorted((r for r in dev if kind_of(r) == kind and r["risky"]), key=lambda r: oof[r["key"]])[:6]
        print(f"lowest-scored risky {kind}:", [(r["key"], round(oof[r["key"]], 3), r["bad"]) for r in hardest])

    gate = lambda r: not r["blind"]
    def rule(r):
        if kind_of(r) == "svc":
            x = r["x"]
            return x["active"] and x["enabled"] and not x["refuse_stop"] and not x["no_default_deps"]
        return gate(r) and not any(r["x"].get("cap_" + c) for c in CAPABILITIES)
    methods = [
        ("no check at all", lambda r: True),
        ("fact rule (no ML)", rule),
        ("ML alone", lambda r: score(r) < low[kind_of(r)]),
        ("boot gate + ML", lambda r: gate(r) and score(r) < low[kind_of(r)]),
        ("fact rule + ML", lambda r: rule(r) and score(r) < low[kind_of(r)]),
    ]
    print("out-of-fold on dev (ML scored by the fold that did not see the row):")
    for title, allow in methods:
        def oof_allow(r, allow=allow, title=title):
            if not title.endswith("ML") and title != "ML alone":
                return allow(r)
            return (rule(r) if title.startswith("fact") else gate(r) if title.startswith("boot") else True) \
                and oof[r["key"]] < low[kind_of(r)]
        for kind in ("remove", "svc"):
            report(f"{title} [{kind}]", [r for r in dev if kind_of(r) == kind], oof_allow)
    if "--fresh" in sys.argv[2:]:
        fresh = build_fresh(data, names)
        print("FRESH MACHINE (opened):", len(fresh), "risky", sum(r["risky"] for r in fresh),
              "inconclusive", sum(r["inconclusive"] for r in fresh), "blind", sum(r["blind"] for r in fresh))
        for title, allow in methods:
            for kind in ("remove", "svc"):
                report(f"{title} [{kind}]", [r for r in fresh if kind_of(r) == kind], allow)
        for r in fresh:
            if r["risky"] or r["inconclusive"]:
                print("  outcome:", r["key"], r["bad"], "blind" if r["blind"] else "", round(score(r), 4))
    if open_test:
        print("TEST (opened):")
        test = parts["test"]
        for kind in ("remove", "svc"):
            print(" ", kind, "AUC", round(auc([r for r in test if usable(r) and kind_of(r) == kind], score), 3))
        for title, allow in methods:
            for kind in ("remove", "svc"):
                report(f"{title} [{kind}]", [r for r in test if kind_of(r) == kind], allow)


if __name__ == "__main__":
    main()
