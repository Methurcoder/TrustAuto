"""Freeze development partitions before any weight-edit search. No training."""
import hashlib
import json
import pathlib
import sys
ROOT = pathlib.Path(__file__).resolve().parent
SOURCE = ROOT.parent / 'truth/experiment_5/round4_evaluation/reproduction'
sys.path.insert(0, str(SOURCE / 'source'))
import train_actions as ta


def bucket(value):
    return int(hashlib.sha256(('wsp-v1:' + value).encode()).hexdigest(), 16) % 5


def main():
    out = ROOT / 'partitions_v1'
    if out.exists():
        raise SystemExit('Partition directory exists; refusing to replace frozen partitions')
    names = ['deb137', 'ubu2610', 'ubu24', 'deb14']
    machines = {m: ta.Machine(SOURCE / 'data', m) for m in names}
    rows = ta.prepare([r for m in names for r in ta.load_labels(SOURCE / 'labels', m)], machines)
    out.mkdir()
    hashes = {}
    for scenario in ('machine', 'target', 'operation'):
        groups = {name: [] for name in ('train', 'edit', 'calibration', 'evaluation')}
        for r in rows:
            hold = (r['machine'] == 'deb14' if scenario == 'machine' else
                    ta.fold_of(r['group'] if scenario == 'target' else ta.stem(r['argv']), 5) == 0)
            part = 'evaluation' if hold else {0: 'edit', 1: 'calibration'}.get(bucket(r['group']), 'train')
            groups[part].append(r)
        for part, data in groups.items():
            p = out / f'{scenario}_{part}.jsonl'
            p.write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in data))
            hashes[p.name] = hashlib.sha256(p.read_bytes()).hexdigest()
        ids = [{(r['machine'], r['id']) for r in data} for data in groups.values()]
        assert sum(map(len, ids)) == len(set.union(*ids)) == len(rows)
        print(scenario, {k: len(v) for k, v in groups.items()}, flush=True)
    (out / 'manifest.json').write_text(json.dumps({'version': 1, 'hashes': hashes,
        'status': 'development-only; all four environments previously examined',
        'rule': 'outer held machine deb14, or existing target/operation fold 0; remaining target groups hashed to edit/calibration/train',
        'evaluation_rule': 'do not inspect evaluation labels or use them for edit selection; final independent evidence requires fresh data'}, indent=2) + '\n')


if __name__ == '__main__':
    main()
