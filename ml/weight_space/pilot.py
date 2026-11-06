"""Execute the frozen head-edit pilot; never reads outer evaluation data."""
import copy
import hashlib
import json
from pathlib import Path
import numpy as np
import torch
from runtime import FrozenModel
from analyze import load, rule_of_three
ROOT = Path(__file__).resolve().parent


def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    torch.set_num_threads(2)
    out = ROOT / 'pilot_v1'
    if out.exists():
        raise SystemExit('Refusing to overwrite pilot results')
    model = FrozenModel(ROOT / 'baselines/machine_seed1')
    original_hash = digest(model.directory / 'weights.pt')
    rows = load('edit')
    limit = json.loads((ROOT / 'analysis_machine_seed1.json').read_text())['threshold']
    activations = []
    h = model.net.head.register_forward_pre_hook(lambda module, args: activations.append(args[0].detach().clone()))
    baseline_scores = model.scores(rows)
    h.remove()
    x = torch.cat(activations)
    risk = np.array([r['final'] == 'risky' for r in rows])
    safe = np.array([r['final'] == 'harmless' for r in rows])
    benign = np.array([r['final'] in ('harmless', 'teacher_allow') for r in rows])
    direction = x[risk].mean(0) - x[safe].mean(0)
    direction /= direction.norm()
    sparse = torch.zeros_like(direction)
    indices = direction.abs().topk(4).indices
    sparse[indices] = direction[indices]
    sparse /= sparse.norm()
    directions = {'activation': direction, 'sparse_activation': sparse}
    for seed in (11, 12, 13):
        v = torch.randn(direction.shape, generator=torch.Generator().manual_seed(seed))
        directions[f'random{seed}'] = v / v.norm()
    candidates = [('baseline', None, 0.0)]
    candidates += [(f'{name}_{scale}', v, scale) for name, v in directions.items() for scale in (.01, .03, .10)]
    candidates += [(f'bias_{value}', None, value) for value in (.05, .15, .5)]
    base_allow = baseline_scores < limit
    records = []
    out.mkdir()
    groups = {r['group'] for r in rows if r['final'] == 'risky'}
    for name, vector, amount in candidates:
        net = copy.deepcopy(model.net)
        with torch.no_grad():
            if vector is not None:
                net.head.weight.add_(vector.unsqueeze(0) * model.net.head.weight.norm() * amount)
            elif name != 'baseline':
                net.head.bias.add_(amount)
        original = model.net
        model.net = net
        scores = model.scores(rows)
        model.net = original
        allow = scores < limit
        missed = {r['group'] for r, a in zip(rows, allow) if r['final'] == 'risky' and a}
        newly = allow & ~base_allow
        tensors = {}
        for key, value in net.state_dict().items():
            difference = value - original.state_dict()[key]
            if torch.count_nonzero(difference):
                tensors[key] = {'changed_parameters': int(torch.count_nonzero(difference)),
                                'l2': float(difference.norm()),
                                'relative_l2': float(difference.norm() / original.state_dict()[key].norm().clamp_min(1e-12))}
        p = out / f'{name}.pt'
        torch.save(net.state_dict(), p)
        record = {'name': name, 'threshold': limit, 'tensors': tensors, 'sha256': digest(p),
                  'danger_rows': [int(sum(allow & risk)), int(sum(risk))],
                  'danger_groups': [len(missed), len(groups)], 'upper95': rule_of_three(len(missed), len(groups)),
                  'benign_rows': [int(sum(allow & benign)), int(sum(benign))],
                  'new_danger_allows': int(sum(newly & risk)),
                  'new_teacher_denied_allows': sum(bool(n) and r['final'] == 'teacher_deny' for n,r in zip(newly,rows)),
                  'new_review_allows': sum(bool(n) and r['final'] == 'review' for n,r in zip(newly,rows))}
        record['eligible'] = record['new_danger_allows'] == 0 and record['danger_rows'][0] <= int(sum(base_allow & risk))
        records.append(record)
        (out / f'{name}_scores.json').write_text(json.dumps({'ids': [[r['machine'],r['id']] for r in rows], 'scores': scores.tolist()}) + '\n')
    selected = min((r for r in records if r['eligible']), key=lambda r:(r['danger_groups'][0],r['danger_rows'][0],-r['benign_rows'][0]))
    assert digest(model.directory / 'weights.pt') == original_hash
    report = {'scope': 'edit-set selection only; not held-out evidence', 'baseline_sha256': original_hash,
              'protocol_sha256': digest(ROOT / 'EDIT_PROTOCOL_V1.md'), 'selected': selected['name'], 'trials': records}
    (out / 'selection.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'selected': selected, 'trials': len(records)}, indent=2))


if __name__ == '__main__':
    main()
