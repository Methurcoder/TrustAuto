"""Analyze development activations without loading outer-evaluation records."""
import hashlib
import json
from pathlib import Path
import sys
import numpy as np
import torch
from runtime import FrozenModel
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'truth/experiment_5/round4_evaluation/reproduction/source'))
from train_facts import rule_of_three


def load(part):
    path = ROOT / 'partitions_v1' / f'machine_{part}.jsonl'
    manifest = json.loads((path.parent / 'manifest.json').read_text())
    assert hashlib.sha256(path.read_bytes()).hexdigest() == manifest['hashes'][path.name]
    return [json.loads(line) for line in path.read_text().splitlines()]


def main():
    torch.set_num_threads(2)
    model = FrozenModel(ROOT / 'baselines/machine_seed1')
    calibration = load('calibration')
    scores = model.scores(calibration)
    risky = sorted(float(s) for r, s in zip(calibration, scores) if r['final'] == 'risky')
    if not risky:
        raise ValueError('No calibration danger rows')
    limit = risky[int(len(risky) * .018)]
    rows = load('edit')
    captured = {name: [] for name in ('layer0', 'layer1', 'head_input')}
    handles = []
    for i, layer in enumerate(model.net.body.layers):
        handles.append(layer.register_forward_hook(lambda module, args, output, name=f'layer{i}': captured[name].append(output[:, 0].detach().clone())))
    handles.append(model.net.head.register_forward_pre_hook(lambda module, args: captured['head_input'].append(args[0].detach().clone())))
    scores = model.scores(rows)
    for h in handles:
        h.remove()
    masks = {
        'false_allow': np.array([r['final'] == 'risky' and s < limit for r, s in zip(rows, scores)]),
        'correct_refusal': np.array([r['final'] == 'risky' and s >= limit for r, s in zip(rows, scores)]),
        'harmless': np.array([r['final'] in ('harmless', 'teacher_allow') for r in rows]),
    }
    analysis = {}
    for name, batches in captured.items():
        x = torch.cat(batches).numpy()
        stats = {label: {'count': int(mask.sum()), 'mean': x[mask].mean(0).tolist() if mask.any() else None} for label, mask in masks.items()}
        if masks['false_allow'].any() and masks['correct_refusal'].any():
            delta = x[masks['correct_refusal']].mean(0) - x[masks['false_allow']].mean(0)
            standardized = delta / (x.std(0) + 1e-6)
            stats['refusal_minus_false_allow'] = delta.tolist()
            stats['top_dimensions'] = np.argsort(-np.abs(standardized))[:8].tolist()
            stats['standardized_difference'] = standardized.tolist()
        analysis[name] = stats
    dangerous = [r for r in rows if r['final'] == 'risky']
    groups = {r['group'] for r in dangerous}
    misses = {r['group'] for r, s in zip(rows, scores) if r['final'] == 'risky' and s < limit}
    report = {'scope': 'edit data only, descriptive; no outer evaluation loaded', 'threshold': limit,
              'calibration_risky_rows': len(risky), 'danger_false_allows': int(masks['false_allow'].sum()),
              'danger_rows': len(dangerous), 'missed_groups': len(misses), 'danger_groups': len(groups),
              'danger_group_upper95': rule_of_three(len(misses), len(groups)),
              'harmless_allowed': int(sum(masks['harmless'] & (scores < limit))),
              'harmless_rows': int(masks['harmless'].sum()), 'activations': analysis,
              'weights_sha256': model.provenance['weights_sha256']}
    out = ROOT / 'analysis_machine_seed1.json'
    out.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k:v for k,v in report.items() if k != 'activations'}, indent=2))


if __name__ == '__main__':
    main()
