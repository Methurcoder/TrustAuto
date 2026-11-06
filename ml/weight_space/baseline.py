"""Export one unchanged-architecture baseline, with its preprocessing and provenance."""
import argparse
import hashlib
import json
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent
SOURCE = ROOT.parent / 'truth/experiment_5/round4_evaluation/reproduction/source'
sys.path.insert(0, str(SOURCE))
import train_actions as ta
import torch


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--scenario', choices=['machine', 'target', 'operation'], default='machine')
    parser.add_argument('--seed', type=int, default=1)
    args = parser.parse_args()
    out = ROOT / 'baselines' / f'{args.scenario}_seed{args.seed}'
    if out.exists():
        raise SystemExit('Existing baseline directory: refusing to overwrite')
    data = ROOT / 'partitions_v1' / f'{args.scenario}_train.jsonl'
    manifest = json.loads((data.parent / 'manifest.json').read_text())
    assert sha(data) == manifest['hashes'][data.name]
    rows = [json.loads(line) for line in data.read_text().splitlines()]
    train = [r for r in rows if r['final'] in ta.DANGER | ta.ALLOWED]
    torch.set_num_threads(2)
    ta.SEED = args.seed
    out.mkdir(parents=True)
    started = time.monotonic()
    print(f'Training {len(train)} usable rows, seed {args.seed}, epochs {ta.EPOCHS}', flush=True)
    score, net = ta.fit_facts_transformer(train)
    # Original score closure owns inputs(); inputs owns fitted normalization and encoding.
    outer = dict(zip(score.__code__.co_freevars, [c.cell_contents for c in score.__closure__]))
    inputs = outer['inputs']
    values = dict(zip(inputs.__code__.co_freevars, [c.cell_contents for c in inputs.__closure__]))
    encoding = values['encoding']
    preprocessing = {'names': encoding.names, 'words': encoding.words,
                     'mean': values['mean'].tolist(), 'std': values['std'].tolist(), 'max_words': 16}
    torch.save(net.state_dict(), out / 'weights.pt')
    (out / 'preprocessing.json').write_text(json.dumps(preprocessing, indent=2) + '\n')
    sample = train[:32]
    predictions = score(sample).tolist()
    provenance = {'scenario': args.scenario, 'seed': args.seed, 'epochs': ta.EPOCHS,
                  'train_rows': len(train), 'partition_sha256': sha(data),
                  'source_sha256': {p.name: sha(p) for p in SOURCE.glob('*.py')},
                  'weights_sha256': sha(out / 'weights.pt'),
                  'preprocessing_sha256': sha(out / 'preprocessing.json'),
                  'seconds': time.monotonic() - started,
                  'sample_ids': [[r['machine'], r['id']] for r in sample], 'sample_scores': predictions,
                  'note': 'single-seed development baseline, not the historical four-seed cross-validation ensemble'}
    (out / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
    print(json.dumps({k: provenance[k] for k in ('train_rows', 'seconds', 'weights_sha256')}), flush=True)


if __name__ == '__main__':
    main()
