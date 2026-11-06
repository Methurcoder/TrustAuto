"""Load frozen experimental checkpoints without fitting or reading evaluation labels."""
import hashlib
import json
from pathlib import Path
import torch


class FactsNet(torch.nn.Module):
    def __init__(self, numbers, vocabulary):
        super().__init__()
        size = 32
        self.number_id = torch.nn.Parameter(torch.zeros(numbers, size))
        self.number_scale = torch.nn.Parameter(torch.zeros(numbers, size))
        self.word = torch.nn.Embedding(vocabulary + 1, size, padding_idx=0)
        self.cls = torch.nn.Parameter(torch.zeros(1, 1, size))
        layer = torch.nn.TransformerEncoderLayer(size, 4, size * 2, dropout=0.1, batch_first=True)
        self.body = torch.nn.TransformerEncoder(layer, 2, enable_nested_tensor=False)
        self.head = torch.nn.Linear(size, 1)

    def forward(self, values, words):
        tokens = self.number_id + values.unsqueeze(-1) * self.number_scale
        cls = self.cls.expand(len(values), -1, -1)
        mask = torch.cat([torch.zeros(len(values), values.shape[1] + 1, dtype=torch.bool), words == 0], 1)
        hidden = self.body(torch.cat([cls, tokens, self.word(words)], 1), src_key_padding_mask=mask)
        return self.head(hidden[:, 0]).squeeze(-1)


class FrozenModel:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.provenance = json.loads((self.directory / 'provenance.json').read_text())
        for name, field in [('weights.pt', 'weights_sha256'), ('preprocessing.json', 'preprocessing_sha256')]:
            digest = hashlib.sha256((self.directory / name).read_bytes()).hexdigest()
            if digest != self.provenance[field]:
                raise ValueError(f'Baseline integrity mismatch: {name}')
        self.encoding = json.loads((self.directory / 'preprocessing.json').read_text())
        self.word_ids = {w: i + 1 for i, w in enumerate(self.encoding['words'])}
        self.net = FactsNet(len(self.encoding['names']), len(self.word_ids))
        self.net.load_state_dict(torch.load(self.directory / 'weights.pt', weights_only=True, map_location='cpu'), strict=True)
        self.net.eval()

    def inputs(self, rows):
        # Normalize in float64 just as the original NumPy implementation, then cast.
        values = torch.tensor([[r['x'].get(k, 0.0) for k in self.encoding['names']] for r in rows], dtype=torch.float64)
        mean = torch.tensor(self.encoding['mean'], dtype=torch.float64)
        std = torch.tensor(self.encoding['std'], dtype=torch.float64)
        values = ((values - mean) / std).float()
        words = torch.zeros(len(rows), self.encoding['max_words'], dtype=torch.long)
        for i, r in enumerate(rows):
            ids = [self.word_ids[w] for w in r['words'] if w in self.word_ids][:self.encoding['max_words']]
            words[i, :len(ids)] = torch.tensor(ids, dtype=torch.long)
        return values, words

    def scores(self, rows):
        with torch.no_grad():
            return torch.cat([self.net(*self.inputs(rows[i:i+256])).sigmoid() for i in range(0, len(rows), 256)]).numpy()


def verify(directory):
    model = FrozenModel(directory)
    root = Path(__file__).resolve().parent
    path = root / 'partitions_v1' / (model.provenance['scenario'] + '_train.jsonl')
    if hashlib.sha256(path.read_bytes()).hexdigest() != model.provenance['partition_sha256']:
        raise ValueError('Training partition changed')
    lookup = {(r['machine'], r['id']): r for r in map(json.loads, path.read_text().splitlines())}
    sample = [lookup[tuple(key)] for key in model.provenance['sample_ids']]
    actual = torch.tensor(model.scores(sample))
    expected = torch.tensor(model.provenance['sample_scores'])
    torch.testing.assert_close(actual, expected, rtol=1e-6, atol=1e-7)
    result = {'sample_count': len(sample), 'max_absolute_error': float((actual - expected).abs().max()), 'status': 'PASS'}
    (Path(directory) / 'reload_verification.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    import sys
    torch.set_num_threads(2)
    verify(sys.argv[1])
