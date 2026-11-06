# Edit protocol v2: internal layers, rank-one, neurons, common-base interpolation

Frozen 2026-11-06 before any v2 weight edit. Written after the v1 pilot (pilot_v1/REPORT.md) and after deb14 was observed, so machine evaluation is no longer untouched. Target and operation evaluation partitions have not been read by weight-space code, but those environments were examined in earlier experiments; every v2 result is development evidence, not an independent final test.

The user asked (2026-11-06) to run the procedure to completion without pausing for confirmation. Every weight change is still recorded per tensor and reported; nothing is integrated into the product.

## Models
Nine baselines: scenarios machine / target / operation × seeds 1 / 2 / 3, each trained by baseline.py with the unchanged original fit_facts_transformer (30 epochs) on `<scenario>_train.jsonl`, reload-verified by runtime.py. Seeds 2/3 used a scratch venv (system torch 2.9.1 + scikit-learn 1.9.1); seed 1 used the earlier session's interpreter.

## Threshold
Per baseline: score the calibration partition, take the settled-risk scores sorted ascending, threshold = element at index int(n × 0.018) (same rule as v1). Fixed for every candidate of that baseline (primary). As a descriptive secondary metric only, each candidate is also recalibrated by the same rule on calibration data, to separate genuine ranking changes from uniform conservatism. Selection never uses the secondary metric.

## Statistics (edit partition only)
Hooks capture, at the CLS position: output of each encoder layer, and the input of each layer's `linear2` (64-d post-ReLU FFN hidden). Classes: settled `risky` vs settled `harmless`. Teacher, review and evaluation rows are excluded from estimating directions.
- steering_L = mean(layer L output | risky) − mean(layer L output | harmless) (32-d)
- mu_L = mean(linear2_L input | risky) (64-d)
- neuron score_L = standardized difference of linear2_L inputs (risky − harmless) / pooled std

## Candidates per baseline (49)
Relative magnitudes m ∈ {0.03, 0.10, 0.30} = ‖Δ‖ / ‖W‖ on the edited tensor.
1. `baseline` (unchanged; always selectable).
2. `tftv_L{0,1}_m`: Δ = edits.tftv(W2_L, steering_L, mu_L) scaled to m (arXiv:2609.09054v3 eq. 2 adaptation) on `body.layers.L.linear2.weight`. 6 candidates.
3. `meanr1_L1_m`: Δ = edits.mean_rank_one(W2_1, steering_1, mu_1) scaled to m. 3 candidates.
4. `randr1_L{0,1}_s{11,12,13}_m`: edits.random_rank_one with matched m. 18 candidates (norm-matched rank-one controls).
5. `neuron_L1_m`: the 4 layer-1 FFN neurons with the largest positive neuron score; Δ multiplies those columns of W2_1 by a common factor so ‖Δ‖ = m‖W2_1‖. 3 candidates.
6. `randneuron_L1_s{11,12,13}_m`: same with 4 neurons chosen by fixed seed. 9 candidates.
7. `bias_b` with b ∈ {0.05, 0.15, 0.5} added to head.bias (trivial conservatism control). 3 candidates.
8. Common-base interpolation: from the same baseline, train two copies for 2 extra epochs on the scenario train partition (same usable rows, frozen preprocessing, AdamW lr 1e-3, wd 0.01, batch 32, original pos_weight, generator seed = baseline seed):
   - `conservative`: loss pos_weight × 3
   - `plain`: original pos_weight (control for extra training alone)
   θ(α) = θ_base + α(θ_ft − θ_base), α ∈ {0.25, 0.5, 1.0}: `interp_conservative_α`, `interp_plain_α`. 6 candidates. Only common-base copies are interpolated; independently trained seeds are never interpolated.

## Selection (edit partition, fixed threshold)
Eligible: zero newly allowed settled-risk rows, zero newly allowed teacher-denied rows, and allowed risky rows ≤ baseline. Rank eligible by (missed danger groups, allowed danger rows, −benign allowed) ascending; ties keep the earlier candidate in the order above, so the baseline wins exact ties. Newly allowed review rows are reported, not used to select. One selection per baseline, written to selection.json with hashes before any evaluation file is opened.

## Evaluation
evaluate_v2.py opens `<scenario>_evaluation.jsonl` once per baseline, verifies hashes of selection, candidate and data, and scores only baseline and the selected candidate. Metrics as v1: danger rows/groups allowed with exact one-sided 95% upper bound, benign allowed, review allowed, new danger allows, fixed danger allows. Adoption gate (unchanged from the product criteria): new danger allows = 0, group upper95 < 1.8 %, benign allowed ≥ 70 %. With ≤ 80 danger groups per evaluation partition the 1.8 % group bound is unreachable even at zero misses (needs ≥ 165 groups); report this rather than relax the gate.

## Report
Every candidate on edit data, controls versus targeted edits, per-seed evaluation, and the conclusion in docs/ML_EXPERIMENT_6.md and weight_space/pilot_v2/REPORT.md. A targeted edit only counts as better than chance if it beats every matched random control and the bias control of the same scenario/seed on the primary objective.
