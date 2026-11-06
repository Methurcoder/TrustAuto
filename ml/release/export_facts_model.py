#!/usr/bin/env python3
"""Train the release model and write it in the format the Rust CLI reads, plus golden vectors for parity tests.

  export_facts_model.py OUT_DIR

The method is round 4's known_avg_facts_transformer, unchanged: the original training source in
experiment_5/round4_evaluation/reproduction/source, four seeds averaged, a program too rare among the allowed
training rows is never let through, and the threshold comes from the training rows alone (out of fold, 1.8% of the
settled risky rows). The only difference is that all four development machines are training data, because nothing is
held out from a released model. Its quality is what round 4 measured, not anything this script prints.
"""
import collections
import hashlib
import json
import multiprocessing
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
REPRO = ROOT / "truth/experiment_5/round4_evaluation/reproduction"
MACHINES = ["deb137", "ubu2610", "ubu24", "deb14"]
SEEDS = 4


def setup():
    sys.path.insert(0, str(REPRO / "source"))
    import train_actions as ta
    import torch
    torch.set_num_threads(2)
    machines = {m: ta.Machine(REPRO / "data", m) for m in MACHINES}
    rows = ta.prepare([r for m in MACHINES for r in ta.load_labels(REPRO / "labels", m)], machines)
    return ta, rows


def fit_seeds(ta, train):
    fits = []
    for offset in range(SEEDS):
        ta.SEED = 1 + offset
        fits.append(ta.fit_facts_transformer(train))
    ta.SEED = 1
    return fits


def preprocessing(score):
    outer = dict(zip(score.__code__.co_freevars, [c.cell_contents for c in score.__closure__]))
    inputs = outer["inputs"]
    values = dict(zip(inputs.__code__.co_freevars, [c.cell_contents for c in inputs.__closure__]))
    return values["encoding"], values["mean"], values["std"]


def job(part):
    """One inner fold's out-of-fold risky scores, or the final fits."""
    ta, rows = setup()
    train = [r for r in rows if r["final"] in ta.DANGER | ta.ALLOWED]
    import numpy as np
    if part == "final":
        fits = fit_seeds(ta, train)
        encoding, mean, std = preprocessing(fits[0][0])
        for score, _ in fits[1:]:
            other, m2, s2 = preprocessing(score)
            assert other.names == encoding.names and other.words == encoding.words
            assert np.array_equal(m2, mean) and np.array_equal(s2, std)
        states = [{k: v.detach().numpy().tolist() for k, v in net.state_dict().items()} for _, net in fits]
        shapes = [{k: list(v.shape) for k, v in net.state_dict().items()} for _, net in fits]
        golden = pick_golden(ta, rows)
        scores = np.mean([score(golden) for score, _ in fits], axis=0)
        per_seed = [score(golden).tolist() for score, _ in fits]
        return {"names": encoding.names, "words": encoding.words, "mean": mean.tolist(), "std": std.tolist(),
                "states": states, "shapes": shapes,
                "golden": [{"machine": r["machine"], "id": r["id"], "argv": r["argv"], "target_mode": r.get("target_mode"),
                            "x": r["x"], "words": r["words"], "final": r["final"], "score": float(s),
                            "seed_scores": [p[i] for p in per_seed]} for i, (r, s) in enumerate(zip(golden, scores))]}
    held = lambda r: ta.fold_of(r["group"], ta.INNER_FOLDS) == part
    risky = [r for r in train if held(r) and r["final"] == "risky"]
    fits = fit_seeds(ta, [r for r in train if not held(r)])
    return {"fold": part, "scores": np.mean([score(risky) for score, _ in fits], axis=0).tolist() if risky else []}


def pick_golden(ta, rows):
    """Every unit and package row, every row with a path, and a spread of the rest, from all machines."""
    chosen = []
    for r in rows:
        x = r["x"]
        h = int(hashlib.sha256((r["machine"] + r["id"]).encode()).hexdigest(), 16)
        if any(k.startswith(("unit_", "package_")) for k in x) and h % 3 == 0 or "p_known" in x and h % 5 == 0 or h % 23 == 0:
            chosen.append(r)
    return chosen


def write_model(out, final, limit, known):
    """TAFT v1: magic, u32 version, u32 header length, JSON header, f32 tensors, u64 FNV-1a of everything before."""
    tensors, blob = [], bytearray()
    for seed, (state, shapes) in enumerate(zip(final["states"], final["shapes"])):
        for name, shape in shapes.items():
            flat = flatten(state[name])
            tensors.append({"seed": seed, "name": name, "shape": shape, "offset": len(blob) // 4, "len": len(flat)})
            blob += struct.pack(f"<{len(flat)}f", *flat)
    header = json.dumps({"names": final["names"], "words": final["words"], "mean": final["mean"], "std": final["std"],
                         "max_words": 16, "width": 32, "heads": 4, "layers": 2, "seeds": SEEDS, "threshold": limit,
                         "known_programs": sorted(known), "tensors": tensors,
                         "method": "round4 known_avg_facts_transformer, trained on deb137 ubu2610 ubu24 deb14"},
                        separators=(",", ":")).encode()
    body = b"TAFT" + struct.pack("<II", 1, len(header)) + header + bytes(blob)
    h = 0xcbf29ce484222325
    for b in body:
        h = ((h ^ b) * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    (out / "facts_model.bin").write_bytes(body + struct.pack("<Q", h))


def flatten(v):
    return [x for item in v for x in flatten(item)] if isinstance(v, list) else [v]


def main():
    out = pathlib.Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    ta, rows = setup()
    train = [r for r in rows if r["final"] in ta.DANGER | ta.ALLOWED]
    print("rows", len(rows), dict(collections.Counter(r["final"] for r in rows)), "train", len(train), flush=True)
    allowed = collections.Counter(ta.stem(r["argv"]) for r in train if r["final"] in ta.ALLOWED)
    known = {p for p, n in allowed.items() if n >= ta.MIN_TOKEN_ROWS}
    with multiprocessing.get_context("spawn").Pool(ta.INNER_FOLDS + 1) as pool:
        results = pool.map(job, [*range(ta.INNER_FOLDS), "final"])
    folds, final = results[:-1], results[-1]
    # known_only gives 1.0 to rare programs, so the risky rows it scores count at 1.0 like in threshold_inside.
    scores = []
    for fold in folds:
        held_risky = [r for r in train if ta.fold_of(r["group"], ta.INNER_FOLDS) == fold["fold"] and r["final"] == "risky"]
        inner_train = [r for r in train if ta.fold_of(r["group"], ta.INNER_FOLDS) != fold["fold"]]
        inner_allowed = collections.Counter(ta.stem(r["argv"]) for r in inner_train if r["final"] in ta.ALLOWED)
        scores += [s if inner_allowed[ta.stem(r["argv"])] >= ta.MIN_TOKEN_ROWS else 1.0 for r, s in zip(held_risky, fold["scores"])]
    scores.sort()
    limit = scores[int(len(scores) * ta.RISKY_BUDGET)]
    write_model(out, final, limit, known)
    golden = final["golden"]
    for g in golden:
        g["known"] = ta.stem(g["argv"]) in known
    (out / "golden.json").write_text(json.dumps({"threshold": limit, "rows": golden}, ensure_ascii=False) + "\n")
    print(json.dumps({"threshold": limit, "risky_scored": len(scores), "known_programs": len(known), "golden": len(golden),
                      "names": len(final["names"]), "words": len(final["words"])}), flush=True)


if __name__ == "__main__":
    main()
