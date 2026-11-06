"""Pure weight-delta constructors; these functions do not modify a model."""
import torch


def tftv(weight, steering, mean_input):
    """Adapt equation 2 of arXiv:2609.09054v3 to a linear weight matrix.

    TrustAuto uses class-conditional CLS statistics rather than LLM completions;
    this is an adaptation, not a replication of that paper's behavioral results.
    Zero input projections contribute zero per the mathematical sign function.
    """
    if steering.norm() <= 1e-12:
        raise ValueError('Degenerate steering direction')
    _, singular, vh = torch.linalg.svd(weight.double(), full_matrices=False)
    right = (torch.sign(vh @ mean_input.double()) * singular) @ vh
    left = steering.double() / steering.double().norm()
    return torch.outer(left, right).to(weight.dtype)


def mean_rank_one(weight, steering, mean_input):
    if steering.norm() <= 1e-12 or mean_input.norm() <= 1e-12:
        raise ValueError('Degenerate rank-one direction')
    return torch.outer(steering / steering.norm(), mean_input / mean_input.norm()) * weight.norm()


def random_rank_one(weight, seed):
    rng = torch.Generator().manual_seed(seed)
    left = torch.randn(weight.shape[0], generator=rng, dtype=weight.dtype)
    right = torch.randn(weight.shape[1], generator=rng, dtype=weight.dtype)
    return mean_rank_one(weight, left, right)


def check():
    rng = torch.Generator().manual_seed(19)
    w = torch.randn(32, 64, generator=rng, dtype=torch.float64)
    s = torch.randn(32, generator=rng, dtype=torch.float64)
    mu = torch.randn(64, generator=rng, dtype=torch.float64)
    original = w.clone()
    delta = tftv(w, s, mu)
    torch.testing.assert_close(delta.norm(), w.norm())
    assert torch.linalg.matrix_rank(delta).item() == 1
    induced = delta @ mu
    coefficient = torch.dot(induced, s) / torch.dot(s, s)
    assert coefficient >= 0
    torch.testing.assert_close(induced, coefficient * s)
    torch.testing.assert_close(w, original, rtol=0, atol=0)
    zero = tftv(w, s, torch.zeros_like(mu))
    assert torch.count_nonzero(zero) == 0
    torch.testing.assert_close(random_rank_one(w, 11).norm(), w.norm())
    print('PASS: rank, norm, expected-input direction, zero-input edge case, no mutation, matched random norm')


if __name__ == '__main__':
    check()
