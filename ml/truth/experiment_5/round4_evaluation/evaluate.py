#!/usr/bin/env python3
"""Recompute the existing evaluation from saved scores, without training or dependencies."""
import collections
import hashlib
import json
import math
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "reproduction/source"))
from train_facts import rule_of_three


def auc(rows):
    ordered = sorted((r["score"], r["final"] in {"risky", "teacher_deny"})
                     for r in rows if r["final"] != "review")
    positives = sum(label for _, label in ordered)
    negatives = len(ordered) - positives
    if not positives or not negatives:
        return None
    ranks, start = 0.0, 0
    while start < len(ordered):
        end = start + 1
        while end < len(ordered) and ordered[end][0] == ordered[start][0]:
            end += 1
        ranks += sum(label for _, label in ordered[start:end]) * (start + 1 + end) / 2
        start = end
    return (ranks - positives * (positives + 1) / 2) / (positives * negatives)


def evaluate(rows):
    allowed = lambda r: r["score"] < r["limit"]
    risky = [r for r in rows if r["final"] == "risky"]
    groups = {r["group"] for r in risky}
    misses = {r["group"] for r in risky if allowed(r)}
    count = lambda label: [sum(allowed(r) for r in rows if r["final"] == label),
                           sum(r["final"] == label for r in rows)]
    harmless = [r for r in rows if r["final"] in {"harmless", "teacher_allow"}]
    rate = sum(map(allowed, harmless)) / max(len(harmless), 1)
    bound = rule_of_three(len(misses), len(groups))
    return {"verdict": "PASS" if bound < 0.018 and rate >= 0.70 else "FAIL",
            "auc": auc(rows), "risky_rows": [sum(map(allowed, risky)), len(risky)],
            "risky_groups": [len(misses), len(groups)], "risky_bound": bound,
            "harmless_auto": rate, "unchanged": count("harmless"),
            "changed_allowed_by_gemini": count("teacher_allow"),
            "denied_by_gemini": count("teacher_deny"), "review": count("review")}


def main():
    manifest = json.loads((ROOT / "sha256.json").read_text())
    for name, digest in manifest.items():
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest:
            raise ValueError(f"Preserved file changed: {name}")
    jobs = [line.split() for line in (ROOT / "results/jobs.txt").read_text().splitlines() if line.strip()]
    baseline = None
    summaries = []
    for model, split in jobs:
        stem = f"{model}_{split}"
        original = json.loads((ROOT / f"results/{stem}.json").read_text())
        rows = [json.loads(line) for line in (ROOT / f"results/scores/{stem}.jsonl").read_text().splitlines()]
        identities = {(r["machine"], r["id"]): (r["final"], r["group"], r["argv"], r["changed"]) for r in rows}
        if len(identities) != len(rows):
            raise ValueError(f"Duplicate row identities: {stem}")
        if baseline is not None and identities != baseline:
            raise ValueError(f"Dataset mismatch: {stem}")
        baseline = identities
        if any(not math.isfinite(r[k]) for r in rows for k in ("score", "limit")):
            raise ValueError(f"Non-finite score/threshold: {stem}")
        result = evaluate(rows)
        for key, actual in result.items():
            expected = original[key]
            if isinstance(actual, float):
                matches = math.isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-12)
            else:
                matches = actual == expected
            if not matches:
                raise ValueError(f"Metric mismatch: {stem} {key}: {actual} != {expected}")
        summaries.append({"model": model, "split": split, "rows": len(rows), **result,
                          "by_machine": dict(collections.Counter(r["machine"] for r in rows)),
                          "by_label": dict(collections.Counter(r["final"] for r in rows))})
    (ROOT / "summary.json").write_text(json.dumps(summaries, ensure_ascii=False, indent=2) + "\n")
    lines = ["# Round 4: 保存スコアの再評価", "",
             f"予定 {len(jobs)} 通りすべての結果を確認し、集計値は元の結果と一致しました。",
             "しきい値は保存済みの学習側の値をそのまま使用しています。再学習・しきい値の調整は行いません。", "",
             "合格条件: 危険グループの誤承認率の片側95%上限 < 1.8%、無害側の自動許可率 ≥ 70%。",
             "無害側には Gemini が許可した行を含みます。review の許可数は危険側の率に含まれません。", "",
             "| モデル | 分割 | 危険グループの見逃し | 95%上限 | 無害の自動許可 | review の許可 | 結果 |",
             "|---|---|---:|---:|---:|---:|---|"]
    for r in summaries:
        missed, total = r["risky_groups"]
        review, reviews = r["review"]
        lines.append(f"| {r['model']} | {r['split']} | {missed}/{total} | {r['risky_bound']:.2%} | "
                     f"{r['harmless_auto']:.2%} | {review}/{reviews} | {r['verdict']} |")
    lines += ["", "machine は機械を1台ずつ除外し、target は対象グループを5分割して評価。",
              "4台とも開発データです。独立した新環境での最終評価ではありません。",
              "速度・サイズは再測定していません。元の結果は results/ の JSON に残っています。", ""]
    (ROOT / "summary.md").write_text("\n".join(lines))
    print("\n".join(lines))
    print(f"\nSHA-256: {len(manifest)} preserved files verified")


if __name__ == "__main__":
    main()
