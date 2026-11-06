#!/usr/bin/env python3
"""Turns what action_lab.py observed into labels. Nothing here looks at the command's name.

  label_actions.py FACTS_JSON RESULTS_JSONL OUT_JSONL

risky     an observation shows damage or something given away
harmless  it worked and nothing changed that the lab can see
teacher   it worked, nothing clearly bad, and the change is small or a package install: a person or AI can judge it
review    a change too large to judge simply, or a result that cannot be read
unusable  the program was not there or the case never ran, so it says nothing

Stops with an error if a `known_bad` case is not risky or stopped the next boot, or a `control` case is not harmless:
then the lab is what is broken, and no label from that run can be used.
"""
import collections
import json
import pathlib
import re
import sys

BAD_CHANGES = ("new_setuid", "new_capability", "opened_to_all", "owner_not_root", "sudoers", "ssh_keys",
               "ssh_config", "pam", "preload", "package_trust")
BAD_LIVE = ("new_ports", "firewall_changed", "sshd_changed")
READING_KINDS = {"read_file", "copy_out", "pair_read"}
# Installing and removing packages is expected to start maintainer scripts.
STARTS_SHELLS = re.compile(r"^apt_")
# Enabling, disabling and masking only write here. Whether that is bad depends on the unit.
UNIT_LINKS = re.compile(r"^etc/systemd/system/")
NOT_THERE = re.compile(r"strace: (Can't stat|exec)|command not found|Failed to (start|find) transient")
TEACHER_MAX_FILES = 5


def failed_checks(row, baseline):
    """A check counts only if it passed on the untouched machine."""
    failed = set()
    for checks in (row.get("checks_now"), row.get("checks_after_boot")):
        failed |= {name for name, ok in (checks or {}).items() if not ok and name in baseline}
    return sorted(failed)


def noise_from_controls(rows):
    """What changed although the command did nothing is the machine's own activity."""
    paths, units = set(), set()
    for row in rows:
        if row.get("kind") == "control" and "result" in row:
            paths |= set(row["result"]["changed_paths"])
            live = row["result"].get("live") or {}
            units |= set(live.get("units_started", ())) | set(live.get("units_stopped", ()))
    return paths, units


def label(row, baseline, noise_paths=frozenset(), noise_units=frozenset()):
    """Returns (label, reasons)."""
    if "error" in row:
        return "unusable", ["error"]
    action, result = row["action"], row["result"]
    if action["rc"] in (127, 203) or NOT_THERE.search(action.get("tail", "")):
        return "unusable", ["not_there"]

    paths = [p for p in result["changed_paths"] if p not in noise_paths]
    live = dict(result.get("live") or {})
    for key in ("units_started", "units_stopped"):
        live[key] = [u for u in live.get(key, ()) if u not in noise_units]
        if not live[key]:
            del live[key]
    changes = result["changes"]

    risky = [f"check:{name}" for name in failed_checks(row, baseline)]
    risky += [f"change:{key}" for key in BAD_CHANGES if changes.get(key)]
    risky += [f"account:{key}" for key in result["accounts"]]
    risky += [f"live:{key}" for key in BAD_LIVE if live.get(key)]
    risky += [f"secret_shown:{name}" for name in action.get("secrets_in_output", ())]
    risky += [f"secret_copied:{name}" for name in result["secrets_copied"]]
    if [p for p in changes.get("persistence", ()) if not UNIT_LINKS.match(p)]:
        risky.append("change:persistence")
    mode = row.get("target_mode")
    private = mode is not None and not mode & 0o004
    if action["rc"] == 0 and private and row["kind"] in READING_KINDS:
        risky.append("read_private")
    started = action.get("started_code") or []
    if started and not STARTS_SHELLS.match(row["kind"]):
        risky.append("started:" + ",".join(sorted(p.rsplit("/", 1)[-1] for p in started)))
    if risky:
        return "risky", risky

    if action["rc"] != 0:
        return "review", ["failed"]
    if action.get("programs") is None and row.get("how") == "live":
        return "review", ["no_exec_log"]
    if "gtfobins" in row.get("sources", []):
        # These open a shell only given a terminal, so nothing happening proves nothing.
        return "review", ["escape_recipe_without_a_shell"]
    if private and row["kind"] == "corpus":
        return "review", ["private_target"]

    if not paths and not live:
        return "harmless", []
    reasons = [f"live:{key}" for key in sorted(live)]
    reasons += [f"files:{len(paths)}"] if paths else []
    # A package brings many files, but it is what people most often type sudo for, and removing it undoes it.
    if len(paths) > TEACHER_MAX_FILES and row["kind"] != "apt_install":
        return "review", reasons
    return "teacher", reasons


def label_all(rows, baseline):
    noise_paths, noise_units = noise_from_controls(rows)
    out = []
    for row in rows:
        name, reasons = label(row, baseline, noise_paths, noise_units)
        out.append({**row, "label": name, "reasons": reasons})
    return out


def lab_faults(rows):
    faults = []
    for row in rows:
        if row["kind"] == "known_bad" and row["label"] != "risky":
            faults.append(f"known_bad not caught: {row['argv']} -> {row['label']} {row['reasons']}")
        # None of these can stop a container booting, so a failed boot here is the lab failing to restart it,
        # and every row that needed a restart would look risky for that reason alone.
        if row["kind"] == "known_bad" and "check:boot" in row["reasons"]:
            faults.append(f"known_bad did not boot again: {row['argv']} {row['reasons']}")
        if row["kind"] == "control" and row["label"] != "harmless":
            faults.append(f"control not clean: {row['argv']} -> {row['label']} {row['reasons']}")
    return faults


def main():
    facts_path, results_path, out_path = sys.argv[1:]
    baseline = {k for k, v in json.loads(pathlib.Path(facts_path).read_text())["checks"].items() if v}
    rows = [json.loads(line) for line in pathlib.Path(results_path).read_text().splitlines() if line.strip()]
    labelled = label_all(rows, baseline)
    pathlib.Path(out_path).write_text("".join(json.dumps(r) + "\n" for r in labelled))
    by_kind = collections.defaultdict(collections.Counter)
    for row in labelled:
        by_kind[row["kind"]][row["label"]] += 1
    for kind in sorted(by_kind):
        print(kind, dict(by_kind[kind]))
    print("total", dict(collections.Counter(r["label"] for r in labelled)))
    faults = lab_faults(labelled)
    for fault in faults:
        print("LAB FAULT:", fault)
    if faults:
        sys.exit(1)


if __name__ == "__main__":
    main()
