#!/usr/bin/env python3
"""Compares models that decide, before a command runs, whether it may go ahead without approval.

  train_actions.py DATA_DIR SNAP_DIR MODEL SPLIT MACHINE [MACHINE...] [--out JSON] [--scores JSONL] [--external JSONL]

DATA_DIR holds facts_NAME.json and usage_NAME.json. SNAP_DIR holds lab_NAME.jsonl from label_actions.py and
taught_NAME.jsonl from teach_gemini.py. MODEL is tree, boost, facts_transformer or text_transformer, or one of those
with known_ in front, which never lets through a program too rare among the allowed training rows. general_ after known_
or known_ext_ drops the words naming directories. avg_ after known_ averages the scores of four seeds of facts_transformer.
SPLIT is machine, target, operation or machine_target.

With ext_ after any known_, the model also learns from --external, rows from external_rows.py: tree, boost and
facts_transformer get one more number, the risk a small model trained only on those rows gives the command, and
text_transformer starts from weights trained on them. wide_ instead of known_ also counts their allowed rows for the gate.
Those rows only teach. A row touching what is held out is removed first, except in operation_ext_seen, which holds out the
same lab programs as operation but lets the external rows name them: what is new to the lab but known from elsewhere.

Fixed before any model was scored:

- Danger: settled risky rows and rows Gemini denied. Allowed: settled harmless rows and rows Gemini allowed.
  Rows in review teach nothing and are only counted when a model would let them through.
- Input: what can be known before the command runs. Never the row's kind, stdin, or anything the lab observed.
- A group is the source package, unit or directory a command acts on, and one group never spans train and test.
- The threshold comes from the training part alone: it lets through at most 1.8% of its settled risky rows, scored out of fold.
- Risky auto is measured on settled risky rows only. Gemini's rows are reported apart and prove nothing about safety.
- Harmless auto is reported apart for rows where nothing changed and rows where something did.
- Pass: risky auto under 1.8% (95% upper bound, by group) and harmless auto at least 70%.

These machines are development data, so a pass here would only allow freezing the method for a machine built afterwards.
"""
import bisect
import collections
import functools
import hashlib
import io
import json
import math
import os
import pathlib
import pickle
import re
import sys
import time

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import roc_auc_score
from sklearn.tree import DecisionTreeClassifier

import train_live as base
import train_usage as usage_features
from train_facts import rule_of_three

RISKY_BUDGET = 0.018
ROUTINE_TARGET = 0.70
OUTER_FOLDS = 5
INNER_FOLDS = 3
MIN_TOKEN_ROWS = 3
MAX_CHARS = 120
EPOCHS = 30
PRETRAIN_EPOCHS = 6
FINETUNE_EPOCHS = 10
FINETUNE_RATE = 3e-4
BATCH = 32
LEARNING_RATE = 1e-3
SEED = int(os.environ.get("TA_SEED", 1))
AVERAGED_FITS = 4
DANGER = {"risky", "teacher_deny"}
ALLOWED = {"harmless", "teacher_allow"}
SETUID = re.compile(r"^[ugoa]*[+=][rwxXt]*s|^[2-7][0-7]{3}$")
WORLD_WRITE = re.compile(r"^(o|a|[ugo]*o[ugo]*)[+=][rxXst]*w|^[0-7]{0,2}[0-7][2367]$")
OWNER = re.compile(r"^[A-Za-z_][\w.-]*(:[\w.-]*)?$|^:[\w.-]+$")
LOCATIONS = ("/etc/", "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/share/", "/var/lib/", "/var/www/", "/boot/", "/root/", "/home/",
             "/tmp/", "/srv/", "/dev/", "/proc/", "/sys/")
CHANGING_WORDS = {"-r", "-R", "--recursive", "-f", "--force", "-i", "--in-place", "-y", "--yes", "-a", "--append"}
# A command that was asked to change something and did not may only have found nothing to do in this container, like
# `chpasswd` with empty input or `rm -f /etc/machine-id` where the file is absent. That says nothing about a real machine.
# These lists come from reading the rows of both machines before any model was scored on them.
ALWAYS_CHANGES = {"pkill", "killall", "kill", "chpasswd", "chgpasswd", "newusers", "sulogin", "rm", "truncate", "mv", "chmod", "chown",
                  "chgrp", "ln", "mkdir", "touch", "tee", "update-rc.d", "kernel-install", "phpenmod", "phpdismod", "mkhomedir_helper",
                  "hardlink", "locale-gen", "zforce", "mariadb-install-db", "nft", "systemd-firstboot", "systemd-sysusers",
                  "systemd-tmpfiles", "redis-server", "mosquitto", "eject", "service"}
CHANGING_ACTIONS = {"systemctl": {"start", "stop", "restart", "reload", "enable", "disable", "mask", "unmask", "kill", "isolate", "log-level"},
                    "apt": {"install", "remove", "purge", "upgrade", "dist-upgrade", "full-upgrade", "autoremove"},
                    "apachectl": {"start", "stop", "restart", "graceful"}, "apache2ctl": {"start", "stop", "restart", "graceful"},
                    "postfix": {"start", "stop", "reload"}, "apt-mark": {"hold", "unhold", "auto", "manual"},
                    "systemd-sysext": {"merge", "unmerge", "refresh"}, "systemd-cryptsetup": {"attach", "detach"}}
CHANGING_FLAGS = {"sysctl": {"-w", "--write"}, "faillock": {"--reset"}, "nginx": {"-s"}, "ldconfig": {"-n"},
                  "update-alternatives": {"--remove", "--remove-all", "--install", "--set", "--auto"}}
INFORMATION_FLAGS = {"--help", "--version", "--list", "--dry-run", "--cat-config"}
BOOKKEEPING = ("var/lib/apt/", "var/lib/dpkg/", "var/cache/apt/", "var/log/apt/", "etc/.pwd.lock")
BOOKKEEPING = (*BOOKKEEPING, *(p.rstrip("/") for p in BOOKKEEPING))


def stem(argv):
    name = argv[0].rsplit("/", 1)[-1]
    return "apt" if name == "apt-get" else name


def runs_a_named_program(row):
    """`nohup rm -rf cache` was harmless only because of what it was told to run, so it says nothing about the wrapper."""
    words = {w.rsplit("/", 1)[-1] for w in row["argv"][1:]}
    run = {p.rsplit("/", 1)[-1] for p in row["action"].get("programs") or ()}
    return bool((run & words) - {stem(row["argv"])})


def action_word(row):
    return next((a for a in row["argv"][1:] if not a.startswith("-")), "")


def asks_for_change(row):
    """Whether this command's job is to change something, whatever this one run happened to do."""
    args, name = row["argv"][1:], stem(row["argv"])
    if INFORMATION_FLAGS & set(args):
        return False
    if name in ALWAYS_CHANGES:
        return True
    if name in CHANGING_ACTIONS:
        return action_word(row) in CHANGING_ACTIONS[name]
    return name in CHANGING_FLAGS and any(a.split("=", 1)[0] in CHANGING_FLAGS[name] for a in args) or \
        name in ("hostnamectl", "timedatectl") and action_word(row).startswith("set-")


def did_nothing(row):
    result = row["result"]
    return not result.get("live") and all(p.startswith(BOOKKEEPING) for p in result["changed_paths"])


def final_label(row):
    final = row.get("final", row["label"])
    if final != "risky" and runs_a_named_program(row):
        return "review"
    if final in ALLOWED and did_nothing(row) and asks_for_change(row):
        return "review"
    return final


def load_labels(snap, machine):
    taught = {}
    path = pathlib.Path(snap) / f"taught_{machine}.jsonl"
    for line in path.read_text().splitlines():
        row = json.loads(line)
        taught[row["id"]] = row["final"]
    rows = []
    for line in (pathlib.Path(snap) / f"lab_{machine}.jsonl").read_text().splitlines():
        row = json.loads(line)
        if row["label"] == "unusable" or row["kind"] == "control":
            continue
        if row["id"] in taught:
            row["final"] = taught[row["id"]]
        elif row["label"] == "teacher":
            row["final"] = "review"
        rows.append({**row, "machine": machine, "final": final_label(row)})
    return rows


class Machine:
    """Facts that can be read before a command runs."""

    def __init__(self, data, name):
        self.m = base.load_machine(data, name)
        self.m.plans = {}
        self.usage = usage_features.Usage(self.m, json.load(open(f"{data}/usage_{name}.json")))
        self.paths = sorted(self.usage.owned_by)
        self.mapped = {usage_features.norm(path) for proc in self.m.procs for path in (proc["exe"], *proc["maps"])}

    def under(self, path):
        at = bisect.bisect_left(self.paths, path.rstrip("/") + "/")
        end = bisect.bisect_left(self.paths, path.rstrip("/") + "0")
        return self.paths[at:end]

    @functools.lru_cache(maxsize=None)
    def path_facts(self, path):
        u, m = self.usage, self.m
        path = usage_features.norm(path)
        inside = self.under(path)
        owner = u.owned_by.get(path) or (u.owned_by[inside[0]] if inside else None)
        fields = m.packages.get(owner, {}) if owner else {}
        touched = {path, *inside}
        return {"p_known": float(bool(owner)), "p_files_inside": base.log(len(inside)),
                "p_programs_inside": base.log(sum(p.startswith(usage_features.COMMAND_DIRS) for p in inside)),
                "p_strong_users": base.log(len(set().union(*(u.strong_users.get(p, set()) for p in touched)))),
                "p_text_users": base.log(len(set().union(*(u.text_users.get(p, set()) for p in touched)))),
                "p_mapped": base.log(len(touched & self.mapped)),
                "p_owner_essential": float(fields.get("Essential") == "yes"),
                "p_owner_required": float(fields.get("Priority") == "required"),
                "p_owner_rdeps": base.log(len(m.rdeps.get(owner, ()))) if owner else 0.0}

    def group(self, row):
        """What the command acts on: the same package or directory on another machine is the same group."""
        for word in row["argv"][1:]:
            name = word.removesuffix(".service")
            if name in self.m.units:
                return self.m.group("stop", name)
            if name in self.m.packages:
                return "src:" + self.m.source(name)
            if word.startswith("/"):
                path = usage_features.norm(word)
                inside = self.under(path)
                owner = self.usage.owned_by.get(path) or (self.usage.owned_by[inside[0]] if inside else None)
                return "src:" + self.m.source(owner) if owner else "dir:" + "/".join(path.split("/")[:3])
        return "program:" + stem(row["argv"])


def features(row, machine):
    """Numbers and words about a command, from its arguments and the machine. Nothing the lab observed."""
    argv = row["argv"]
    args = argv[1:]
    flags = [a for a in args if a.startswith("-")]
    plain = [a for a in args if not a.startswith("-")]
    paths = [a for a in plain if a.startswith("/")]
    mode = row.get("target_mode")
    x = {"n_args": base.log(len(args)), "n_flags": base.log(len(flags)), "n_paths": base.log(len(paths)),
         "changing_words": float(sum(a in CHANGING_WORDS for a in args)),
         "arg_setuid": float(any(SETUID.match(a) for a in plain)), "arg_world_write": float(any(WORLD_WRITE.match(a) for a in plain)),
         "arg_owner_not_root": float(any(OWNER.match(a) and not a.startswith("root") for a in plain[:1])),
         "absent_target": float(mode is None), "target_private": float(mode is not None and not mode & 0o004),
         "mode_setuid": float(bool(mode and mode & 0o6000)),
         "mode_other_read": float(bool(mode and mode & 0o004)), "mode_other_write": float(bool(mode and mode & 0o002)),
         "mode_group_write": float(bool(mode and mode & 0o020)), "mode_exec": float(bool(mode and mode & 0o111))}
    for place in LOCATIONS:
        x["in" + place.rstrip("/").replace("/", "_")] = float(any(p.startswith(place) for p in paths))
    words = [f"program={stem(argv)}"] + [f"flag={a.split('=', 1)[0]}" for a in flags]
    words += [f"action={stem(argv)}:{plain[0]}"] if plain and not plain[0].startswith("/") else []
    words += ["place=" + "/".join(p.split("/")[:4]) for p in paths]
    m, u = machine.m, machine.usage
    if paths:
        x.update(machine.path_facts(paths[-1]))
        # A new file has no facts of its own, but what reads the directory it lands in decides what it can do.
        x.update({"d_" + k: v for k, v in machine.path_facts(paths[-1].rstrip("/").rpartition("/")[0] or "/").items()})
    for word in plain:
        name = word.removesuffix(".service")
        if name in m.units:
            unit = {k: float(v) for k, v in base.service_features(m, "stop", name).items() if k != "restart"}
            unit.update(u.service_features(name))
            x.update({"unit_" + k: v for k, v in unit.items()})
            break
        if name in m.packages:
            package = {k: float(v) for k, v in base.remove_features(m, name).items() if k != "root_is_owner"}
            package.update(u.remove_features(name))
            x.update({"package_" + k: v for k, v in package.items()})
            break
    return x, words


def prepare(rows, machines):
    for row in rows:
        machine = machines[row["machine"]]
        row["x"], row["words"] = features(row, machine)
        row["group"] = machine.group(row)
        row["text"] = " ".join(row["argv"])[:MAX_CHARS]
    return rows


class Encoding:
    """Names and words are learned from the training rows only, so an unseen program really looks unseen."""

    def __init__(self, train):
        counts = collections.Counter(w for r in train for w in set(r["words"]))
        self.words = sorted(w for w, n in counts.items() if n >= MIN_TOKEN_ROWS)
        self.names = sorted({k for r in train for k in r["x"]})
        self.at = {name: i for i, name in enumerate(self.names + self.words)}

    def matrix(self, rows):
        out = np.zeros((len(rows), len(self.at)))
        for i, r in enumerate(rows):
            for k, v in r["x"].items():
                if k in self.at:
                    out[i, self.at[k]] = v
            for w in r["words"]:
                if w in self.at:
                    out[i, self.at[w]] = 1.0
        return out


def target(rows):
    return np.array([float(r["final"] in DANGER) for r in rows])


def fit_tree(train):
    encoding = Encoding(train)
    model = DecisionTreeClassifier(max_depth=8, min_samples_leaf=5, class_weight="balanced", random_state=SEED)
    model.fit(encoding.matrix(train), target(train))
    return lambda rows: model.predict_proba(encoding.matrix(rows))[:, 1], (model, encoding)


def fit_boost(train):
    encoding = Encoding(train)
    model = HistGradientBoostingClassifier(max_iter=300, max_depth=4, learning_rate=0.05, min_samples_leaf=3,
                                           class_weight="balanced", random_state=SEED)
    model.fit(encoding.matrix(train), target(train))
    return lambda rows: model.predict_proba(encoding.matrix(rows))[:, 1], (model, encoding)


def train_torch(net, inputs, y, epochs=EPOCHS, rate=LEARNING_RATE):
    import torch
    weight = (1 - y.mean()) / max(y.mean(), 1e-6)
    loss = torch.nn.BCEWithLogitsLoss(pos_weight=torch.tensor(float(weight)))
    optimiser = torch.optim.AdamW(net.parameters(), lr=rate, weight_decay=0.01)
    labels = torch.tensor(y, dtype=torch.float32)
    generator = torch.Generator().manual_seed(SEED)
    net.train()
    for _ in range(epochs):
        for batch in torch.randperm(len(y), generator=generator).split(BATCH):
            optimiser.zero_grad()
            loss(net(*(tensor[batch] for tensor in inputs)), labels[batch]).backward()
            optimiser.step()
    net.eval()


def predict_torch(net, inputs):
    import torch
    with torch.no_grad():
        return torch.cat([torch.sigmoid(net(*(t[start:start + 256] for t in inputs)))
                          for start in range(0, len(inputs[0]), 256)]).numpy()


def transformer_body(size, heads, layers):
    import torch
    layer = torch.nn.TransformerEncoderLayer(size, heads, size * 2, dropout=0.1, batch_first=True)
    return torch.nn.TransformerEncoder(layer, layers, enable_nested_tensor=False)


def fit_facts_transformer(train):
    """One token per number, plus one per word, so it reads the same input as the trees."""
    import torch
    torch.manual_seed(SEED)
    encoding = Encoding(train)
    numbers = len(encoding.names)
    size, most_words = 32, 16

    class Net(torch.nn.Module):
        def __init__(self):
            super().__init__()
            self.number_id = torch.nn.Parameter(torch.randn(numbers, size) * 0.02)
            self.number_scale = torch.nn.Parameter(torch.randn(numbers, size) * 0.02)
            self.word = torch.nn.Embedding(len(encoding.words) + 1, size, padding_idx=0)
            self.cls = torch.nn.Parameter(torch.randn(1, 1, size) * 0.02)
            self.body = transformer_body(size, 4, 2)
            self.head = torch.nn.Linear(size, 1)

        def forward(self, values, words):
            tokens = self.number_id + values.unsqueeze(-1) * self.number_scale
            cls = self.cls.expand(len(values), -1, -1)
            mask = torch.cat([torch.zeros(len(values), numbers + 1, dtype=torch.bool), words == 0], 1)
            hidden = self.body(torch.cat([cls, tokens, self.word(words)], 1), src_key_padding_mask=mask)
            return self.head(hidden[:, 0]).squeeze(-1)

    first_word = {w: i + 1 for i, w in enumerate(encoding.words)}
    full = encoding.matrix(train)[:, :numbers]
    mean, std = full.mean(0), full.std(0) + 1e-6

    def inputs(rows):
        values = (encoding.matrix(rows)[:, :numbers] - mean) / std
        words = np.zeros((len(rows), most_words), dtype=np.int64)
        for i, r in enumerate(rows):
            known = [first_word[w] for w in r["words"] if w in first_word][:most_words]
            words[i, :len(known)] = known
        return torch.tensor(values, dtype=torch.float32), torch.tensor(words)

    net = Net()
    train_torch(net, inputs(train), target(train))
    return lambda rows: predict_torch(net, inputs(rows)), net


def text_net(letters):
    import torch
    size = 48

    class Net(torch.nn.Module):
        def __init__(self):
            super().__init__()
            self.letter = torch.nn.Embedding(len(letters) + 2, size, padding_idx=0)
            self.place = torch.nn.Parameter(torch.randn(1, MAX_CHARS + 1, size) * 0.02)
            self.cls = torch.nn.Parameter(torch.randn(1, 1, size) * 0.02)
            self.body = transformer_body(size, 4, 2)
            self.head = torch.nn.Linear(size, 1)

        def forward(self, text):
            tokens = torch.cat([self.cls.expand(len(text), -1, -1), self.letter(text)], 1) + self.place
            mask = torch.cat([torch.zeros(len(text), 1, dtype=torch.bool), text == 0], 1)
            return self.head(self.body(tokens, src_key_padding_mask=mask)[:, 0]).squeeze(-1)

    return Net()


def text_inputs(rows, letters):
    import torch
    out = np.zeros((len(rows), MAX_CHARS), dtype=np.int64)
    for i, r in enumerate(rows):
        out[i, :len(r["text"])] = [letters.get(c, 1) for c in r["text"]]
    return (torch.tensor(out),)


def fit_text_transformer(train):
    """The command's characters and nothing about the machine."""
    import torch
    torch.manual_seed(SEED)
    letters = {c: i + 2 for i, c in enumerate(sorted({c for r in train for c in r["text"]}))}
    net = text_net(letters)
    train_torch(net, text_inputs(train, letters), target(train))
    return lambda rows: predict_torch(net, text_inputs(rows, letters)), net


class External:
    """Rows from published datasets, narrowed to what the current outer split may see."""
    rows = ()
    weights = None
    letters = None
    pretrain = False

    @classmethod
    def load(cls, path, machines):
        best = collections.defaultdict(set)
        for line in pathlib.Path(path).read_text().splitlines():
            row = json.loads(line)
            best[json.dumps(row["argv"])].add(row["label"])
        cls.all = []
        for key, labels in best.items():
            if len(labels) == 1:
                argv = json.loads(key)
                row = {"argv": argv, "final": "teacher_deny" if labels == {"deny"} else "teacher_allow", "text": " ".join(argv)[:MAX_CHARS]}
                row["groups"] = {m.group(row) for m in machines.values()}
                cls.all.append(row)

    @classmethod
    def narrow(cls, split, test):
        if split == "operation":
            held = {stem(r["argv"]) for r in test}
            cls.rows = [r for r in cls.all if stem(r["argv"]) not in held]
        elif split in ("target", "machine_target"):
            held = {r["group"] for r in test}
            cls.rows = [r for r in cls.all if not r["groups"] & held]
        else:
            cls.rows = cls.all
        cls.weights = None

    @classmethod
    def risk_model(cls):
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        vectors = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=2, max_features=20000)
        model = LogisticRegression(max_iter=1000, C=10, class_weight="balanced")
        model.fit(vectors.fit_transform(r["text"] for r in cls.rows), target(cls.rows))
        return vectors, model

    @classmethod
    def add_risk(cls, rows):
        vectors, model = cls.risk_model()
        for row, risk in zip(rows, model.predict_proba(vectors.transform(r["text"] for r in rows))[:, 1]):
            row["x"]["ext_risk"] = float(risk)
        return vectors, model

    @classmethod
    def allowed(cls):
        return collections.Counter(stem(r["argv"]) for r in cls.rows if r["final"] in ALLOWED)

    @classmethod
    def pretrained(cls, seen):
        """Once per outer split. The lab rows then fine-tune a copy."""
        import copy
        import torch
        if cls.weights is None:
            torch.manual_seed(SEED)
            cls.letters = {c: i + 2 for i, c in enumerate(sorted({c for r in (*cls.rows, *seen) for c in r["text"]}))}
            net = text_net(cls.letters)
            train_torch(net, text_inputs(cls.rows, cls.letters), target(cls.rows), PRETRAIN_EPOCHS)
            cls.weights = net
        return copy.deepcopy(cls.weights)


def fit_pretrained_text(train):
    net = External.pretrained(train)
    letters = External.letters
    train_torch(net, text_inputs(train, letters), target(train), FINETUNE_EPOCHS, FINETUNE_RATE)
    return lambda rows: predict_torch(net, text_inputs(rows, letters)), net


def known_only(fit):
    """A program too rare among the allowed training rows is never let through: the model has nothing to go on for it."""
    def fitted(train):
        score, model = fit(train)
        allowed = collections.Counter(stem(r["argv"]) for r in train if r["final"] in ALLOWED)
        return (lambda rows: np.where([allowed[stem(r["argv"])] >= MIN_TOKEN_ROWS for r in rows], score(rows), 1.0)), model
    return fitted


def wide_only(fit):
    """As known_only, but a program may also be known from the external rows."""
    def fitted(train):
        score, model = fit(train)
        allowed = collections.Counter(stem(r["argv"]) for r in train if r["final"] in ALLOWED) + External.allowed()
        return (lambda rows: np.where([allowed[stem(r["argv"])] >= MIN_TOKEN_ROWS for r in rows], score(rows), 1.0)), model
    return fitted


def no_places(fit):
    """Without the words naming a directory, so that a place seen only in training cannot stand in for the facts about it."""
    def strip(rows):
        return [{**r, "words": [w for w in r["words"] if not w.startswith("place=")]} for r in rows]

    def fitted(train):
        score, model = fit(strip(train))
        return (lambda rows: score(strip(rows))), model
    return fitted


def averaged(fit):
    """The mean score of several fits that differ only in their seed, because one transformer's misses change with its seed."""
    def fitted(train):
        global SEED
        first, fits = SEED, []
        try:
            for offset in range(AVERAGED_FITS):
                SEED = first + offset
                fits.append(fit(train))
        finally:
            SEED = first
        return (lambda rows: np.mean([score(rows) for score, _ in fits], axis=0)), [model for _, model in fits]
    return fitted


MODELS = {"tree": fit_tree, "boost": fit_boost, "facts_transformer": fit_facts_transformer, "text_transformer": fit_text_transformer}
MODELS.update({"known_" + name: known_only(fit) for name, fit in list(MODELS.items())})
WITH_EXTERNAL = {**{name: MODELS[name] for name in ("tree", "boost", "facts_transformer")}, "text_transformer": fit_pretrained_text}
MODELS.update({"ext_" + name: fit for name, fit in WITH_EXTERNAL.items()})
MODELS.update({"known_ext_" + name: known_only(fit) for name, fit in WITH_EXTERNAL.items()})
MODELS.update({"known_general_" + name: known_only(no_places(MODELS[name])) for name in ("tree", "boost", "facts_transformer")})
MODELS.update({"known_ext_general_" + name: known_only(no_places(WITH_EXTERNAL[name])) for name in ("tree", "boost", "facts_transformer")})
MODELS.update({"wide_ext_" + name: wide_only(fit) for name, fit in WITH_EXTERNAL.items()})
MODELS.update({"known_avg_facts_transformer": known_only(averaged(fit_facts_transformer)),
               "known_avg_general_facts_transformer": known_only(averaged(no_places(fit_facts_transformer))),
               "known_avg_ext_facts_transformer": known_only(averaged(fit_facts_transformer)),
               "known_avg_ext_general_facts_transformer": known_only(averaged(no_places(fit_facts_transformer)))})


def fold_of(name, folds):
    return int(hashlib.sha256(("trustauto-actions:" + name).encode()).hexdigest(), 16) % folds


def threshold_inside(train, fit):
    """Scored out of fold, so that the limit is not set on rows the model has memorised."""
    scores = []
    for fold in range(INNER_FOLDS):
        held = lambda r: fold_of(r["group"], INNER_FOLDS) == fold
        risky = [r for r in train if held(r) and r["final"] == "risky"]
        if risky:
            scores += list(fit([r for r in train if not held(r)])[0](risky))
    scores.sort()
    return scores[int(len(scores) * RISKY_BUDGET)]


def splits(rows, name, machines):
    """Yields (title, train rows, test rows). Review rows are tested but never trained on."""
    usable = lambda r: r["final"] in DANGER | ALLOWED
    if name in ("machine", "machine_target"):
        for held in machines:
            test = [r for r in rows if r["machine"] == held]
            groups = {r["group"] for r in test} if name == "machine_target" else set()
            yield held, [r for r in rows if r["machine"] != held and usable(r) and r["group"] not in groups], test
        return
    key = (lambda r: r["group"]) if name == "target" else (lambda r: stem(r["argv"]))  # operation and operation_ext_seen
    for fold in range(OUTER_FOLDS):
        held = lambda r: fold_of(key(r), OUTER_FOLDS) == fold
        yield f"fold {fold}", [r for r in rows if not held(r) and usable(r)], [r for r in rows if held(r)]


def changed(row):
    return bool(row["result"]["changed_paths"] or row["result"].get("live"))


def measure(rows):
    """Rows carry `score` and `limit`."""
    allowed = lambda r: r["score"] < r["limit"]
    risky = [r for r in rows if r["final"] == "risky"]
    groups = collections.defaultdict(bool)
    for r in risky:
        groups[r["group"]] |= allowed(r)
    missed_groups = sum(groups.values())
    bound = rule_of_three(missed_groups, len(groups))
    count = lambda label, keep=lambda r: True: (sum(allowed(r) for r in rows if r["final"] == label and keep(r)),
                                                 sum(1 for r in rows if r["final"] == label and keep(r)))
    harmless = [r for r in rows if r["final"] in ALLOWED]
    routine = sum(map(allowed, harmless)) / max(len(harmless), 1)
    scored = [r for r in rows if r["final"] in DANGER | ALLOWED]
    labels = [r["final"] in DANGER for r in scored]
    return {"verdict": "PASS" if bound < RISKY_BUDGET and routine >= ROUTINE_TARGET else "FAIL",
            "auc": roc_auc_score(labels, [r["score"] for r in scored]) if len(set(labels)) == 2 else None,
            "risky_rows": [sum(map(allowed, risky)), len(risky)], "risky_groups": [missed_groups, len(groups)], "risky_bound": bound,
            "harmless_auto": routine, "unchanged": count("harmless"), "changed_allowed_by_gemini": count("teacher_allow"),
            "denied_by_gemini": count("teacher_deny"), "review": count("review"),
            "missed": [[r["machine"], r["argv"][:7], r["reasons"][:3]] for r in sorted(risky, key=lambda r: r["score"]) if allowed(r)][:40]}


def size_and_speed(fit, rows, encoding_rows):
    """Bytes of the fitted model, and CPU time to score one command with the facts already read."""
    score, model = fit(encoding_rows)
    size = 0
    for one in model if isinstance(model, list) else [model]:
        if hasattr(one, "state_dict"):
            import torch
            buffer = io.BytesIO()
            torch.save(one.state_dict(), buffer)
            size += buffer.tell()
        else:
            size += len(pickle.dumps(one))
    times = []
    for row in rows[:200]:
        started = time.perf_counter()
        score([row])
        times.append(time.perf_counter() - started)
    times.sort()
    return {"bytes": size, "ms_median": times[len(times) // 2] * 1000, "ms_p99": times[int(len(times) * 0.99)] * 1000}


def external_cost():
    """The small risk model is extra: its size and the time to score one command."""
    vectors, model = External.risk_model()
    times = []
    for row in External.rows[:200]:
        started = time.perf_counter()
        model.predict_proba(vectors.transform([row["text"]]))
        times.append(time.perf_counter() - started)
    times.sort()
    return {"risk_model_bytes": len(pickle.dumps((vectors, model))), "risk_model_ms_p99": times[int(len(times) * 0.99)] * 1000}


def main():
    args = sys.argv[1:]
    options = {"--out": None, "--scores": None, "--external": None}
    for flag in options:
        if flag in args:
            at = args.index(flag)
            options[flag] = args[at + 1]
            del args[at:at + 2]
    out, scores_path = options["--out"], options["--scores"]
    data, snap, name, split, *machine_names = args
    fit = MODELS[name]
    if name.endswith("transformer"):
        import torch
        torch.set_num_threads(2)
    machines = {m: Machine(data, m) for m in machine_names}
    rows = prepare([r for m in machine_names for r in load_labels(snap, m)], machines)
    uses_external = "ext_" in name
    if uses_external:
        External.load(options["--external"], machines)
    print(name, split, "rows", len(rows), dict(collections.Counter(r["final"] for r in rows)),
          "risky groups", len({r["group"] for r in rows if r["final"] == "risky"}), flush=True)
    tested = []
    for title, train, test in splits(rows, split, machine_names):
        started = time.monotonic()
        if uses_external:
            External.narrow(split, test)
            if not name.endswith("text_transformer"):
                External.add_risk(rows)
        limit = threshold_inside(train, fit)
        scores = fit(train)[0](test)
        tested += [{**r, "score": float(s), "limit": float(limit)} for r, s in zip(test, scores)]
        print(f"  {title}: train {len(train)}, test {len(test)}, limit {limit:.4f}, {time.monotonic() - started:.0f}s", flush=True)
    result = {"model": name, "split": split, "machines": machine_names, **measure(tested)}
    if scores_path:
        keep = ("machine", "id", "kind", "argv", "final", "group", "reasons", "score", "limit")
        pathlib.Path(scores_path).write_text("".join(json.dumps({**{k: r[k] for k in keep}, "changed": changed(r)}, ensure_ascii=False) + "\n" for r in tested))
    print(json.dumps({k: v for k, v in result.items() if k != "missed"}))
    if split == "machine":
        result["cost"] = size_and_speed(fit, tested, [r for r in rows if r["final"] in DANGER | ALLOWED])
        if uses_external and not name.endswith("text_transformer"):
            result["cost"].update(external_cost())
        print(json.dumps(result["cost"]))
    if out:
        pathlib.Path(out).write_text(json.dumps(result, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
