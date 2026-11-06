#!/usr/bin/env python3
"""Joins collection rounds into one directory train_actions.py can read.

  merge_rounds.py OUT_DIR MACHINE[,MACHINE...] DIR [DIR...]

Each DIR holds lab_NAME.jsonl and taught_NAME.jsonl. Rounds number their rows from zero, so every id but the first
round's gets a prefix. A command and stdin already seen on that machine keeps the earlier row: a repeat would count
one observation twice, and a later round was not chosen to overturn an earlier one.
"""
import json
import pathlib
import sys


def read(path):
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def merge(rounds):
    """rounds: (lab rows, taught rows) in order. Returns the kept lab and taught rows with ids unique across rounds."""
    seen, lab, taught, repeats = set(), [], [], 0
    for number, (lab_rows, taught_rows) in enumerate(rounds, 1):
        prefix = "" if number == 1 else f"r{number}-"
        kept = set()
        for row in lab_rows:
            key = (tuple(row["argv"]), row.get("stdin", ""))
            if key in seen:
                repeats += 1
                continue
            seen.add(key)
            kept.add(row["id"])
            lab.append({**row, "id": prefix + row["id"]})
        taught += [{**row, "id": prefix + row["id"]} for row in taught_rows if row["id"] in kept]
    return lab, taught, repeats


def main():
    out, machines, dirs = pathlib.Path(sys.argv[1]), sys.argv[2].split(","), sys.argv[3:]
    out.mkdir(parents=True, exist_ok=True)
    for machine in machines:
        rounds = [(read(pathlib.Path(d) / f"lab_{machine}.jsonl"), read(pathlib.Path(d) / f"taught_{machine}.jsonl"))
                  for d in dirs]
        lab, taught, repeats = merge(rounds)
        (out / f"lab_{machine}.jsonl").write_text("".join(json.dumps(r) + "\n" for r in lab))
        (out / f"taught_{machine}.jsonl").write_text("".join(json.dumps(r) + "\n" for r in taught))
        print(f"{machine}: {len(lab)} rows, {len(taught)} taught, {repeats} repeats dropped")


if __name__ == "__main__":
    main()
