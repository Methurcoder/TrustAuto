"""Execute frozen EDIT_PROTOCOL_V2 for one baseline; reads train/edit/calibration only."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import numpy as np
import torch
from runtime import FrozenModel
from analyze import rule_of_three
import edits
ROOT = Path(__file__).resolve().parent
MAGNITUDES = (.03, .10, .30)
SEEDS = (11, 12, 13)
DANGER = {'risky', 'teacher_deny'}
ALLOWED = {'harmless', 'teacher_allow'}


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def load(scenario, part):
    assert part != 'evaluation'
    path = ROOT / 'partitions_v1' / f'{scenario}_{part}.jsonl'
    manifest = json.loads((path.parent / 'manifest.json').read_text())
    assert sha(path) == manifest['hashes'][path.name]
    return [json.loads(line) for line in path.read_text().splitlines()]


def threshold(model, rows):
    risky = sorted(float(s) for r, s in zip(rows, model.scores(rows)) if r['final'] == 'risky')
    return risky[int(len(risky) * .018)]


def capture(model, rows):
    """Run with gradients enabled so the encoder avoids its fused fast path and submodule hooks fire."""
    store = {k: [] for k in ('out0', 'out1', 'ffn0', 'ffn1')}
    handles = []
    for i, layer in enumerate(model.net.body.layers):
        handles.append(layer.register_forward_hook(lambda m, a, o, i=i: store[f'out{i}'].append(o[:, 0].detach())))
        handles.append(layer.linear2.register_forward_pre_hook(lambda m, a, i=i: store[f'ffn{i}'].append(a[0][:, 0].detach())))
    with torch.enable_grad():
        for start in range(0, len(rows), 256):
            model.net(*model.inputs(rows[start:start + 256]))
    for h in handles:
        h.remove()
    result = {k: torch.cat(v) for k, v in store.items()}
    assert all(len(v) == len(rows) for v in result.values())
    return result


def finetune(model, train, seed, factor):
    net = copy.deepcopy(model.net)
    values, words = model.inputs(train)
    y = torch.tensor([float(r['final'] in DANGER) for r in train])
    weight = (1 - y.mean()) / y.mean().clamp_min(1e-6) * factor
    loss = torch.nn.BCEWithLogitsLoss(pos_weight=weight)
    optimiser = torch.optim.AdamW(net.parameters(), lr=1e-3, weight_decay=0.01)
    torch.manual_seed(seed)
    generator = torch.Generator().manual_seed(seed)
    net.train()
    for _ in range(2):
        for batch in torch.randperm(len(y), generator=generator).split(32):
            optimiser.zero_grad()
            loss(net(values[batch], words[batch]), y[batch]).backward()
            optimiser.step()
    net.eval()
    return net.state_dict()


def scaled(delta, weight, m):
    return delta * (m * weight.norm() / delta.norm())


def neuron_delta(weight, columns, m):
    delta = torch.zeros_like(weight)
    delta[:, columns] = weight[:, columns]
    return scaled(delta, weight, m)


def candidates(model, act, rows, train, seed):
    """Yield (name, family, state_dict) in the frozen protocol order."""
    base = model.net.state_dict()
    risk = torch.tensor([r['final'] == 'risky' for r in rows])
    safe = torch.tensor([r['final'] == 'harmless' for r in rows])
    steering = {L: act[f'out{L}'][risk].mean(0) - act[f'out{L}'][safe].mean(0) for L in (0, 1)}
    mu = {L: act[f'ffn{L}'][risk].mean(0) for L in (0, 1)}
    hidden = act['ffn1']
    pooled = ((hidden[risk].var(0) + hidden[safe].var(0)) / 2).sqrt() + 1e-6
    neuron_score = (hidden[risk].mean(0) - hidden[safe].mean(0)) / pooled
    top = neuron_score.topk(4).indices.tolist()
    info = {'steering_norm': {L: float(steering[L].norm()) for L in (0, 1)},
            'mu_norm': {L: float(mu[L].norm()) for L in (0, 1)}, 'top_neurons_L1': top,
            'top_neuron_scores': [float(neuron_score[i]) for i in top],
            'counts': {'risky': int(risk.sum()), 'harmless': int(safe.sum())}}

    def with_delta(key, delta):
        state = copy.deepcopy(base)
        state[key] = state[key] + delta
        return state

    yield 'baseline', 'baseline', copy.deepcopy(base), info
    for L in (0, 1):
        key = f'body.layers.{L}.linear2.weight'
        raw = edits.tftv(base[key], steering[L], mu[L])
        for m in MAGNITUDES:
            yield f'tftv_L{L}_{m}', 'tftv', with_delta(key, scaled(raw, base[key], m)), None
    key = 'body.layers.1.linear2.weight'
    raw = edits.mean_rank_one(base[key], steering[1], mu[1])
    for m in MAGNITUDES:
        yield f'meanr1_L1_{m}', 'meanr1', with_delta(key, scaled(raw, base[key], m)), None
    for L in (0, 1):
        k = f'body.layers.{L}.linear2.weight'
        for s in SEEDS:
            raw = edits.random_rank_one(base[k], s)
            for m in MAGNITUDES:
                yield f'randr1_L{L}_s{s}_{m}', f'randr1_L{L}', with_delta(k, scaled(raw, base[k], m)), None
    for m in MAGNITUDES:
        yield f'neuron_L1_{m}', 'neuron', with_delta(key, neuron_delta(base[key], top, m)), None
    for s in SEEDS:
        columns = torch.randperm(base[key].shape[1], generator=torch.Generator().manual_seed(s))[:4].tolist()
        for m in MAGNITUDES:
            yield f'randneuron_L1_s{s}_{m}', 'randneuron', with_delta(key, neuron_delta(base[key], columns, m)), None
    for b in (.05, .15, .5):
        yield f'bias_{b}', 'bias', with_delta('head.bias', torch.full_like(base['head.bias'], b)), None
    for label, factor in (('conservative', 3.0), ('plain', 1.0)):
        tuned = finetune(model, train, seed, factor)
        for alpha in (.25, .5, 1.0):
            state = {k: base[k] + alpha * (tuned[k] - base[k]) if base[k].is_floating_point() else base[k] for k in base}
            yield f'interp_{label}_{alpha}', f'interp_{label}', state, None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--scenario', required=True, choices=['machine', 'target', 'operation'])
    parser.add_argument('--seed', type=int, required=True)
    args = parser.parse_args()
    torch.set_num_threads(2)
    out = ROOT / 'pilot_v2' / f'{args.scenario}_seed{args.seed}'
    if out.exists():
        raise SystemExit('Refusing to overwrite v2 results')
    model = FrozenModel(ROOT / 'baselines' / f'{args.scenario}_seed{args.seed}')
    original_hash = sha(model.directory / 'weights.pt')
    rows, calibration = load(args.scenario, 'edit'), load(args.scenario, 'calibration')
    train = [r for r in load(args.scenario, 'train') if r['final'] in DANGER | ALLOWED]
    limit = threshold(model, calibration)
    act = capture(model, rows)
    risk = np.array([r['final'] == 'risky' for r in rows])
    benign = np.array([r['final'] in ALLOWED for r in rows])
    groups = {r['group'] for r in rows if r['final'] == 'risky'}
    original = model.net
    base_state = copy.deepcopy(original.state_dict())
    out.mkdir(parents=True)
    records, base_allow, analysis = [], None, None
    for name, family, state, info in candidates(model, act, rows, train, args.seed):
        analysis = analysis or info
        net = copy.deepcopy(original)
        net.load_state_dict(state)
        model.net = net
        scores = model.scores(rows)
        recalibrated = threshold(model, calibration)
        model.net = original
        allow = scores < limit
        if base_allow is None:
            base_allow = allow
        missed = {r['group'] for r, a in zip(rows, allow) if r['final'] == 'risky' and a}
        newly = allow & ~base_allow
        re_allow = scores < recalibrated
        tensors = {}
        for key, value in state.items():
            difference = value - base_state[key]
            if torch.count_nonzero(difference):
                tensors[key] = {'changed_parameters': int(torch.count_nonzero(difference)), 'l2': float(difference.norm()),
                                'relative_l2': float(difference.norm() / base_state[key].norm().clamp_min(1e-12))}
        path = out / f'{name}.pt'
        torch.save(state, path)
        record = {'name': name, 'family': family, 'tensors': tensors, 'sha256': sha(path),
                  'changed_parameters': sum(t['changed_parameters'] for t in tensors.values()),
                  'danger_rows': [int(sum(allow & risk)), int(sum(risk))],
                  'danger_groups': [len(missed), len(groups)], 'upper95': rule_of_three(len(missed), len(groups)),
                  'benign_rows': [int(sum(allow & benign)), int(sum(benign))],
                  'new_danger_allows': int(sum(newly & risk)),
                  'new_teacher_denied_allows': sum(bool(n) and r['final'] == 'teacher_deny' for n, r in zip(newly, rows)),
                  'new_review_allows': sum(bool(n) and r['final'] == 'review' for n, r in zip(newly, rows)),
                  'recalibrated': {'threshold': recalibrated, 'danger_rows': int(sum(re_allow & risk)),
                                   'benign_rows': int(sum(re_allow & benign))}}
        record['eligible'] = (record['new_danger_allows'] == 0 and record['new_teacher_denied_allows'] == 0
                              and record['danger_rows'][0] <= int(sum(base_allow & risk)))
        records.append(record)
        (out / f'{name}_scores.json').write_text(json.dumps({'ids': [[r['machine'], r['id']] for r in rows], 'scores': scores.tolist()}) + '\n')
    assert len(records) == 49
    # min() keeps the first of equal keys, so the baseline wins exact ties.
    selected = min((r for r in records if r['eligible']), key=lambda r: (r['danger_groups'][0], r['danger_rows'][0], -r['benign_rows'][0]))
    assert sha(model.directory / 'weights.pt') == original_hash
    report = {'scope': 'edit-set selection only; not held-out evidence', 'scenario': args.scenario, 'seed': args.seed,
              'threshold': limit, 'baseline_sha256': original_hash, 'protocol_sha256': sha(ROOT / 'EDIT_PROTOCOL_V2.md'),
              'analysis': analysis, 'selected': selected['name'], 'trials': records}
    (out / 'selection.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'scenario': args.scenario, 'seed': args.seed, 'selected': selected['name'],
                      'baseline': {k: records[0][k] for k in ('danger_rows', 'danger_groups', 'benign_rows')},
                      'chosen': {k: selected[k] for k in ('danger_rows', 'danger_groups', 'benign_rows', 'new_review_allows')}}))


if __name__ == '__main__':
    main()
