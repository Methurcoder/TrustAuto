#!/usr/bin/env python3
"""Builds a train/test split from public command corpora. Labels come from the
source alone, with no hand relabeling: 0 for NL2Bash and tldr-pages, 1 for
GTFOBins and Atomic Red Team. The commands are only parsed, never executed.

  python3 -I ml/build_dataset.py --nl2bash ALL_CM --tldr PAGES_DIR \
      --gtfobins BINS_DIR --atomic INDEX_YAML --out ml/data

Every source is normalized to what TrustAuto would really receive: one simple
command as argv, without sudo, redirections or shell syntax. Otherwise a model
could score well by recognizing a source's writing style instead of its risk.
"""
import argparse
import collections
import hashlib
import pathlib
import re
import shlex

import yaml

PER_BINARY_CAP = 150
UNSEEN_BINARY_PERCENT = 15
RANDOM_TEST_PERCENT = 20
SEPARATOR = "\x1f"

SHELL_WORDS = {
    "if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case", "esac",
    "function", "{", "}", "[", "[[", "]]", "test", "return", "exit", "export", "local", "unset",
    "set", "source", ".", "eval", "exec", "cd", "alias", "read", "wait", "trap", "shift", "!",
}
# Helper steps inside attack recipes. They say nothing about risk, so labeling
# them risky would only teach the model that `echo` is dangerous.
RECIPE_HELPERS = {
    "echo", "printf", "cat", "ls", "pwd", "sleep", "true", "false", "mkdir", "touch", "rm",
    "mktemp", "head", "tail", "grep", "wc", "sort", "uniq", "cut", "tr", "id", "whoami", "hostname",
    "uname", "date", "which", "command", "type", "basename", "dirname", "seq", "yes",
}
COMMAND_NAME = re.compile(r"^[A-Za-z0-9_.+/-]+$")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
TLDR_PLACEHOLDER = re.compile(r"\{\{(.*?)\}\}")
ATOMIC_INPUT = re.compile(r"#\{([^}]*)\}")
SUDO_VALUE_FLAGS = {"-u", "-g", "-h", "-p", "-C", "-r", "-t", "-U"}


def simple_commands(line):
    """Splits a shell line into argv lists, or returns nothing if it needs a real parser."""
    line = line.strip()
    if not line or line.startswith("#"):
        return []
    # Keep find's terminator as an argument, not a command separator.
    protected = line.replace("\\;", "__SEMI__")
    lexer = shlex.shlex(protected, posix=True, punctuation_chars=";|&<>()")
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        tokens = list(lexer)
    except ValueError:
        return []
    if any(set(t) <= set("()") and t for t in tokens) or any("$(" in t or "`" in t for t in tokens):
        return []

    commands, current, skip_next = [], [], False
    for token in tokens:
        if skip_next:
            skip_next = False
            continue
        if token and set(token) <= set("<>&") and ">" in token or token in ("<", "<<", "<<<"):
            skip_next = True
            continue
        if token and set(token) <= set(";|&"):
            commands.append(current)
            current = []
            continue
        current.append(token.replace("__SEMI__", ";"))
    commands.append(current)
    return [c for c in commands if c]


def clean_argv(argv):
    """Removes what never reaches TrustAuto: variable prefixes and sudo itself."""
    argv = list(argv)
    while argv and ASSIGNMENT.match(argv[0]):
        argv.pop(0)
    while argv and argv[0] == "sudo":
        argv.pop(0)
        while argv and argv[0].startswith("-"):
            flag = argv.pop(0)
            if flag in SUDO_VALUE_FLAGS and argv:
                argv.pop(0)
    while argv and ASSIGNMENT.match(argv[0]):
        argv.pop(0)
    if not argv:
        return None
    name = argv[0].rsplit("/", 1)[-1]
    if not COMMAND_NAME.match(name) or name in SHELL_WORDS or not name:
        return None
    args = [re.sub(r"[\t\r\n\x1f]+", " ", a) for a in argv[1:]]
    return [name] + args


def from_nl2bash(path):
    for line in pathlib.Path(path).read_text(errors="replace").splitlines():
        for argv in simple_commands(line):
            yield argv


def tldr_value(match):
    inner = match.group(1).strip()
    if inner.startswith("[") and inner.endswith("]"):
        return inner[1:-1].split("|")[-1]
    inner = inner.split("|")[0].replace("...", "").strip() or "value"
    if "path/to/" in inner and not inner.startswith("/"):
        inner = "/" + inner
    return re.sub(r"\s+", "_", inner)


def from_tldr(pages):
    for sub in ("common", "linux"):
        for page in sorted(pathlib.Path(pages, sub).glob("*.md")):
            for line in page.read_text(errors="replace").splitlines():
                if line.startswith("`") and line.endswith("`") and len(line) > 2:
                    command = TLDR_PLACEHOLDER.sub(tldr_value, line[1:-1])
                    for argv in simple_commands(command):
                        yield argv


def from_gtfobins(directory):
    for path in sorted(pathlib.Path(directory).iterdir()):
        if not path.is_file():
            continue
        try:
            docs = [d for d in yaml.safe_load_all(path.read_text(errors="replace")) if d]
        except yaml.YAMLError:
            continue
        for doc in docs:
            for kind, entries in (doc.get("functions") or {}).items():
                # `inherit` entries are plain commands that open a pager.
                if kind == "inherit":
                    continue
                for entry in entries or []:
                    for line in (entry.get("code") or "").splitlines():
                        for argv in simple_commands(line):
                            yield argv


def from_atomic(index):
    tree = yaml.safe_load(pathlib.Path(index).read_text(errors="replace"))
    for tactic in tree.values():
        for technique in (tactic or {}).values():
            for test in (technique or {}).get("atomic_tests", []) or []:
                executor = test.get("executor") or {}
                if executor.get("name") not in ("sh", "bash"):
                    continue
                command = ATOMIC_INPUT.sub(lambda m: "/path/to/" + m.group(1), executor.get("command") or "")
                for line in command.splitlines():
                    for argv in simple_commands(line):
                        yield argv


def percent(text):
    return int(hashlib.sha256(text.encode()).hexdigest(), 16) % 100


def main():
    parser = argparse.ArgumentParser()
    for name in ("nl2bash", "tldr", "gtfobins", "atomic", "out"):
        parser.add_argument("--" + name, required=True)
    options = parser.parse_args()

    sources = [
        ("nl2bash", 0, from_nl2bash(options.nl2bash)),
        ("tldr", 0, from_tldr(options.tldr)),
        ("gtfobins", 1, from_gtfobins(options.gtfobins)),
        ("atomic", 1, from_atomic(options.atomic)),
    ]
    labels = collections.defaultdict(set)
    origin = {}
    raw = collections.Counter()
    for source, label, commands in sources:
        for argv in commands:
            argv = clean_argv(argv)
            if not argv or (label == 1 and argv[0] in RECIPE_HELPERS):
                continue
            key = SEPARATOR.join(argv)
            labels[key].add(label)
            origin.setdefault((key, label), source)
            raw[source] += 1

    conflicts = {k for k, v in labels.items() if len(v) > 1}
    by_group = collections.defaultdict(list)
    for key, values in labels.items():
        if key not in conflicts:
            label = next(iter(values))
            by_group[(label, key.split(SEPARATOR)[0])].append(key)

    rows, capped = [], 0
    for (label, _), keys in sorted(by_group.items()):
        # A hash order keeps the cap deterministic without favoring any source.
        keys.sort(key=lambda k: hashlib.sha256(k.encode()).hexdigest())
        capped += max(0, len(keys) - PER_BINARY_CAP)
        rows += [(label, key) for key in keys[:PER_BINARY_CAP]]

    train, test_random, test_unseen = [], [], []
    for label, key in rows:
        if percent("bin:" + key.split(SEPARATOR)[0]) < UNSEEN_BINARY_PERCENT:
            test_unseen.append((label, key))
        elif percent("row:" + key) < RANDOM_TEST_PERCENT:
            test_random.append((label, key))
        else:
            train.append((label, key))

    out = pathlib.Path(options.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, part in (("train", train), ("test_random", test_random), ("test_unseen", test_unseen)):
        text = "".join(f"{label}\t{key}\n" for label, key in part)
        (out / f"{name}.tsv").write_text(text)
        pos = sum(1 for label, _ in part if label)
        print(f"{name:12} {len(part):6} rows ({pos} risky, {len(part) - pos} routine)")
    print("parsed per source:", dict(raw))
    print(f"dropped {len(conflicts)} commands with both labels, {capped} over the per-binary cap")


if __name__ == "__main__":
    main()
