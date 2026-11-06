#!/usr/bin/env python3
"""Reads the published command datasets into rows the comparison can train on. Nothing here runs a command.

  external_rows.py EXT_DIR OUT_JSONL

Only one plain command fits what TrustAuto sees, so pipes, redirections, substitutions, variables and non-POSIX shells are
left out, and a leading sudo and a trailing comment are removed. Wrappers like `env` and `nohup` are left out because their
label is about what they were told to run. These labels are other people's policies, not what the lab observed: they may
teach, but they never count as settled risky or harmless and are never tested on. A command with both labels in a source is
left out, and so is an allowed one that reaches what the lab treats as settled danger.
"""
import collections
import json
import pathlib
import re
import shlex
import sys

UNSUPPORTED = re.compile(r"[|;&<>`\n$]")
COMMENT = re.compile(r"\s+#.*$")
ASSIGNMENT = re.compile(r"^[A-Za-z_]\w*=")
WRAPPERS = {"env", "time", "nohup", "nice", "ionice", "timeout", "xargs", "command", "exec", "stdbuf", "setsid", "watch", "strace", "busybox"}
SETUID = re.compile(r"^[ugoa]*[+=][rwxXt]*s|^[2-7][0-7]{3}$")
WORLD_WRITE = re.compile(r"^(o|a|[ugo]*o[ugo]*)[+=][rxXst]*w|^[0-7]{0,2}[0-7][2367]$")
DANGER_PATH = re.compile(r"(^|/)(shadow|gshadow|sudoers(\.d)?|authorized_keys|ld\.so\.preload|id_rsa|id_ed25519|id_ecdsa|id_dsa|ssh_host_\w+_key)($|/)|/etc/pam\.d|/\.ssh/?$")
READS_ONLY = {"ls", "stat", "file", "chmod", "test", "du", "wc", "find"}
SHELLS = {"sh", "bash", "dash", "zsh", "fish", "ksh", "csh", "tcsh", "python", "python2", "python3", "perl", "ruby", "php", "node", "lua", "awk", "gawk", "mawk", "nawk"}
FILES = ("shellkeeper-data/train.jsonl", "shellkeeper-data/validation.jsonl", "shellkeeper-data/test.jsonl", "shellkeeper-data/test_new.jsonl", "shellkeeper-data/golden.jsonl")


def plain_argv(command):
    """The words of one plain command, or None."""
    command = COMMENT.sub("", command)
    if UNSUPPORTED.search(command):
        return None
    try:
        argv = shlex.split(command)
    except ValueError:
        return None
    while argv and argv[0] == "sudo":
        argv = argv[1:]
    if not argv or ASSIGNMENT.match(argv[0]) or argv[0].startswith("-") or argv[0] == "sudo" or argv[0].rsplit("/", 1)[-1] in WRAPPERS:
        return None
    return argv


def reaches_danger(argv):
    """Allowed by a dataset but settled danger in the lab: setuid, world-writable, shells and interpreters, private files."""
    name, args = argv[0].rsplit("/", 1)[-1], argv[1:]
    if name in SHELLS:
        return True
    if name == "chmod" and any(SETUID.match(a) or WORLD_WRITE.match(a) for a in args):
        return True
    return name not in READS_ONLY and any(DANGER_PATH.search(a) for a in args) or name == "chmod" and any(DANGER_PATH.search(a) for a in args) and not any(a in ("600", "400", "go-rwx", "u=rw,go=") for a in args)


def jsonl(path):
    return [json.loads(line) for line in pathlib.Path(path).read_text().splitlines() if line.strip()]


def shellkeeper_rows(top):
    for name in FILES:
        for row in jsonl(top / name):
            if row["shell"] != "powershell":
                yield row


def shellkeeper_cold(top):
    """No request and no earlier commands: the label of the others leans on context TrustAuto does not have."""
    for row in shellkeeper_rows(top):
        if not row["task"] and not row["history"]:
            yield row["command"], "allow" if row["label"] == "safe" else "deny", row["id"].rsplit("-", 1)[0]


def shellkeeper_all(top):
    """Every mode. A command whose label flips with context has both labels and drops out; near-miss variants stay."""
    for row in shellkeeper_rows(top):
        yield row["command"], "allow" if row["label"] == "safe" else "deny", row["id"].rsplit("-", 1)[0]


def cli_risk(top):
    """Safe and moderate or worse. `low` is a change that is quick to undo, which is the question being learned, so it is left out."""
    import pyarrow.parquet as pq
    for split in ("train", "validation", "test"):
        for row in pq.read_table(top / f"cli-command-risk/data/{split}.parquet").to_pylist():
            if row["risk_level"] == "safe":
                yield row["command"], "allow", row["derived_from"] or row["id"]
            elif row["risk_level"] in ("moderate", "high", "critical"):
                yield row["command"], "deny", row["derived_from"] or row["id"]


def shell_safety(top):
    """`ask` means someone should look, so it may not go ahead by itself."""
    for split in ("train", "validation", "test"):
        for row in jsonl(top / f"shell-safety-v1.1/{split}.jsonl"):
            if row["shell"] == "posix":
                yield row["command"], "allow" if row["label"] == "allow" else "deny", row["category"]


SOURCES = {"shellkeeper_cold": shellkeeper_cold, "shellkeeper_all": shellkeeper_all, "cli_risk": cli_risk, "shell_safety": shell_safety}


def rows_of(name, top):
    labels, family = collections.defaultdict(set), {}
    for command, label, group in SOURCES[name](top):
        argv = plain_argv(command)
        if argv:
            key = json.dumps(argv)
            labels[key].add(label)
            family.setdefault(key, group)
    single = [(json.loads(key), next(iter(found)), family[key]) for key, found in labels.items() if len(found) == 1]
    kept = [{"source": name, "argv": argv, "label": label, "family": group} for argv, label, group in single
            if not (label == "allow" and reaches_danger(argv))]
    return kept, sum(len(found) > 1 for found in labels.values()), len(single) - len(kept)


def main():
    top, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
    rows = []
    for name in SOURCES:
        found, both, danger = rows_of(name, top)
        counts = collections.Counter(r["label"] for r in found)
        print(name, "rows", len(found), dict(counts), "both labels dropped", both, "allowed but danger dropped", danger, "programs", len({r["argv"][0] for r in found}))
        rows += found
    out.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows))


if __name__ == "__main__":
    main()
