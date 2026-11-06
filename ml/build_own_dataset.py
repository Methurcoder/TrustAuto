#!/usr/bin/env python3
"""Builds the self-made dataset from Ubuntu package metadata. It covers only the
command forms the policy can send to the model, and asks: would a mistake here
cut off access or break the system?

  python3 -I ml/build_own_dataset.py --main MAIN_PACKAGES_GZ \
      --universe UNIVERSE_PACKAGES_GZ --contents CONTENTS_GZ --out ml/data/own

A package is critical when any of these holds, and labels.tsv records which:
  essential / priority   the archive marks it Essential, required or important
  minimal                ubuntu-minimal needs it, directly or indirectly
  rdeps                  at least RDEPS_CRITICAL packages depend on it
  function               it matches CRITICAL_BY_FUNCTION (boot, remote access,
                         networking, privilege, security logging)

Labels: removing a critical package is 1. Stopping or restarting a service that a
critical package ships is 1. Installing, starting, reloading and reading logs are 0.

Names are split as whole groups, so a test name never appears in training. Names
in the probe files are left out of every split, keeping those tests independent.
"""
import argparse
import collections
import gzip
import hashlib
import pathlib
import re

RDEPS_CRITICAL = 300
MAX_ROUTINE_MAIN = 3000
MAX_ROUTINE_UNIVERSE = 1500
MAX_KERNEL_PACKAGES = 40
FIXED_ROW_COPIES = 30
SEEDS = ["ubuntu-minimal"]
CRITICAL_BY_FUNCTION = re.compile(
    r"^("
    r"linux-(image|modules|generic|virtual|lowlatency)(-.*)?"  # kernel
    r"|grub.*|shim(-.*)?"  # boot
    r"|openssh-(server|sftp-server)"  # remote access
    r"|network-manager|netplan.*"  # networking
    r"|sudo(-ldap)?|polkitd|libpam.*|libnss.*"  # privilege
    r"|ubuntu-(minimal|standard|server|desktop|server-minimal|desktop-minimal)"  # base system
    r"|dbus(-.*)?"  # system bus
    r"|ufw|nftables|iptables|firewalld|apparmor|auditd|rsyslog|fail2ban"  # security and logging
    r")$"
)
# Generated language bindings would otherwise dominate the universe sample.
BORING_UNIVERSE = re.compile(r"^(librust-|golang-|node-|r-cran-|r-bioc-|ruby-|php-|libghc-|haskell-|lib.*-dev$)")
SERVICE_PATH = re.compile(r"^(?:usr/)?lib/systemd/system/([^/@]+)\.service$")
VALID_NAME = re.compile(r"^[a-z0-9][a-z0-9+-]*[a-z0-9+]$")
VALID_UNIT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9:_.-]*$")


def read_packages(path):
    packages = {}
    for block in gzip.open(path, "rt", errors="replace").read().split("\n\n"):
        fields = {}
        for line in block.splitlines():
            if line and not line[0].isspace() and ": " in line:
                key, value = line.split(": ", 1)
                fields[key] = value
        if "Package" in fields:
            packages[fields["Package"]] = fields
    return packages


def dependency_names(fields):
    """Names this package needs. Only the first alternative of each dependency counts."""
    names = []
    for key in ("Pre-Depends", "Depends"):
        for dep in filter(None, fields.get(key, "").split(",")):
            names.append(re.split(r"[ (:|]", dep.strip(), maxsplit=1)[0])
    return names


def closure(seeds, packages):
    seen, stack = set(), list(seeds)
    while stack:
        name = stack.pop()
        if name in seen or name not in packages:
            continue
        seen.add(name)
        stack.extend(dependency_names(packages[name]))
    return seen


def classify(main, universe):
    everything = {**universe, **main}
    rdeps = collections.Counter()
    for fields in everything.values():
        for name in set(dependency_names(fields)):
            rdeps[name] += 1
    minimal = closure(SEEDS, everything)
    reasons = {}
    for name, fields in everything.items():
        why = []
        if fields.get("Essential") == "yes":
            why.append("essential")
        if fields.get("Priority") in ("required", "important"):
            why.append("priority")
        if name in minimal:
            why.append("minimal")
        if rdeps[name] >= RDEPS_CRITICAL:
            why.append(f"rdeps={rdeps[name]}")
        if CRITICAL_BY_FUNCTION.match(name):
            why.append("function")
        if why:
            reasons[name] = ",".join(why)
    return reasons


def read_units(path, known):
    """Maps each service name to the package that ships it."""
    units = {}
    with gzip.open(path, "rt", errors="replace") as lines:
        for line in lines:
            if "systemd/system/" not in line:
                continue
            parts = line.rsplit(None, 1)
            if len(parts) != 2:
                continue
            match = SERVICE_PATH.match(parts[0].strip())
            if not match or not VALID_UNIT.match(match.group(1)):
                continue
            owner = parts[1].split(",")[0].rsplit("/", 1)[-1]
            if owner in known:
                units[match.group(1)] = owner
    return units


def stable(text):
    return hashlib.sha256(text.encode()).hexdigest()


def split_of(group):
    bucket = int(stable("split:" + group), 16) % 100
    return "train" if bucket < 70 else "val" if bucket < 85 else "test"


def read_probe_names(paths):
    names = set()
    for path in paths:
        for line in pathlib.Path(path).read_text().splitlines():
            if not line or line.startswith("#"):
                continue
            words = line.split("\t", 1)[1].split()
            if words[0] in ("apt", "apt-get") and len(words) > 2:
                names.update(words[2:])
            elif words[0] == "systemctl" and len(words) > 2:
                names.add(re.sub(r"\.(service|socket)$", "", words[2]))
            elif words[0] == "journalctl":
                names.add(words[2])
    return names


def main():
    parser = argparse.ArgumentParser()
    for name in ("main", "universe", "contents", "out"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--include-probe-names", action="store_true",
                        help="for the final model only: train on the probe names too")
    parser.add_argument("--probe", action="append", default=["ml/probe_envelope.tsv", "ml/probe_fresh.tsv"])
    options = parser.parse_args()

    main_packages = read_packages(options.main)
    universe_packages = read_packages(options.universe)
    known = {**universe_packages, **main_packages}
    reasons = classify(main_packages, universe_packages)
    units = read_units(options.contents, known)
    probe_names = read_probe_names(options.probe)

    # Only the exact probe names are held back. Their relatives stay, because a
    # new name in real use also tends to resemble known ones.
    held_back = set(probe_names)
    if options.include_probe_names:
        held_back = set()

    def usable(name):
        return VALID_NAME.match(name) and name not in held_back

    # Kernel flavors would otherwise be most of the critical class.
    kernels = sorted((n for n in reasons if usable(n) and n.startswith("linux-")), key=stable)
    dropped_kernels = set(kernels[MAX_KERNEL_PACKAGES:])
    critical = sorted(n for n in reasons if usable(n) and n not in dropped_kernels)
    routine_main = sorted(
        (n for n in main_packages if n not in reasons and usable(n)), key=stable
    )[:MAX_ROUTINE_MAIN]
    routine_universe = sorted(
        (n for n in universe_packages
         if n not in reasons and n not in main_packages and usable(n) and not BORING_UNIVERSE.match(n)),
        key=stable,
    )[:MAX_ROUTINE_UNIVERSE]
    names = critical + routine_main + routine_universe

    rows = {"train": [], "val": [], "test": []}
    by_split = collections.defaultdict(list)
    for name in names:
        part = split_of(name)
        by_split[part].append(name)
        label = int(name in reasons)
        rows[part] += [
            (label, f"apt remove {name}"),
            (label, f"apt-get remove {name}"),
            (0, f"apt install {name}"),
        ]

    # Several names at once: one critical name makes the whole command critical.
    for part, group in by_split.items():
        ordered = sorted(group, key=stable)
        for first, second in zip(ordered[::4], ordered[1::4]):
            label = int(first in reasons or second in reasons)
            rows[part] += [(label, f"apt remove {first} {second}"), (0, f"apt install {first} {second}")]

    unit_count = collections.Counter()
    for unit, owner in sorted(units.items()):
        if unit in held_back:
            continue
        part = split_of(owner)
        label = int(owner in reasons)
        unit_count[(part, label)] += 1
        rows[part] += [
            (label, f"systemctl stop {unit}"),
            (label, f"systemctl stop {unit}.service"),
            (label, f"systemctl restart {unit}"),
            (0, f"systemctl start {unit}"),
            (0, f"systemctl reload {unit}"),
            (0, f"journalctl -u {unit} --no-pager"),
        ]

    # Fixed forms with no name in them, so they cannot be split by name.
    fixed = ["apt update", "apt upgrade", "apt-get update", "apt-get upgrade",
             "systemctl daemon-reload", "dmesg", "ufw status"]
    rows["train"] += [(0, command) for command in fixed] * FIXED_ROW_COPIES

    out = pathlib.Path(options.out)
    out.mkdir(parents=True, exist_ok=True)
    for part, part_rows in rows.items():
        (out / f"{part}.tsv").write_text("".join(f"{label}\t{command}\n" for label, command in part_rows))
        risky = sum(label for label, _ in part_rows)
        print(f"{part:6} {len(part_rows):6} rows ({risky} risky, {len(part_rows) - risky} routine)")
    print(f"packages: {len(critical)} critical, {len(routine_main)} + {len(routine_universe)} routine")
    print("critical services per split:", {p: unit_count[(p, 1)] for p in rows})
    print("routine services per split:", {p: unit_count[(p, 0)] for p in rows})

    with open(out / "labels.tsv", "w") as f:
        for name, why in sorted(reasons.items()):
            f.write(f"{name}\t{why}\n")
    print("reasons:", dict(collections.Counter(p.split("=")[0] for v in reasons.values() for p in v.split(","))))

    # The simplest rival: look the name up in the same metadata, and treat an
    # unknown name as routine. Comparing it on the probes shows what ML adds.
    print("\nlist lookup on the probes (no model):")
    for path in options.probe:
        missed, flagged, risky_total, routine_total = [], [], 0, 0
        for line in pathlib.Path(path).read_text().splitlines():
            if not line or line.startswith("#"):
                continue
            label, command = line.split("\t", 1)
            words = command.split()
            verb = words[1] if len(words) > 1 else ""
            target = None
            if words[0] == "apt" and verb == "remove":
                predicted = any(w in reasons for w in words[2:])
            elif words[0] == "systemctl" and verb in ("stop", "restart"):
                target = re.sub(r"\.(service|socket)$", "", words[2])
                predicted = units.get(target) in reasons
            else:
                predicted = False
            if label == "1":
                risky_total += 1
                if not predicted:
                    missed.append(command)
            else:
                routine_total += 1
                if predicted:
                    flagged.append(command)
        print(f"  {path}: risky auto-allowed {len(missed)}/{risky_total}, "
              f"routine auto-allowed {routine_total - len(flagged)}/{routine_total}")
        for command in missed:
            print(f"    missed:  {command}")
        for command in flagged:
            print(f"    flagged: {command}")


if __name__ == "__main__":
    main()
