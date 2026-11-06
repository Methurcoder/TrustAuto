# Weight-space optimization — investigation started 2026-11-06

Goal remains active. No weights edited or training launched.

## Verified owning sources
- ml/truth/train_actions.py: facts Transformer uses width 32, 4 attention heads, 2 encoder layers, numerical feature tokens, up to 16 word tokens, CLS and binary linear head. Encoding vocabulary and numerical normalization are fitted within each training subset.
- Existing machine split excludes one machine; target split hashes target groups into five folds; operation split hashes command stems. Threshold uses inner three-fold predictions of settled risky rows at budget 0.018.
- No .pt/.pth/.safetensors/.ckpt artifacts found in project ml/ or the known Claude scratchpad (excluding site-packages). Existing results contain scores, not reusable model checkpoints. Reconstructing a baseline with frozen preprocessing and saved state is necessary before editing.
- Existing four-machine results have already been inspected and used for development. They cannot establish untouched final generalization.

## Primary research located
- https://rikiyat.github.io/blog/weight-space-programming/ — authors' preliminary demonstrations of direct reasoning-driven edits without gradient descent. Not evidence that TrustAuto edits will improve.
- https://arxiv.org/abs/2609.09054 — activation statistics mapped into rank-one weight edits. Full method/code still to inspect.
- https://arxiv.org/abs/2212.04089 — task vectors from common-base fine-tuned weights; requires learning to obtain vectors. Distinguish from training-free edits.

## Next work
1. Inspect original research experiment logs and rank-one method; formalize limited candidates and matched random controls.
2. Create a baseline checkpoint/export path in isolated experimental code, storing architecture, vocabulary, normalization, labels/split manifests, random seeds and state_dict. Preserve original training code.
3. Freeze nested training/edit-development/calibration/evaluation partitions before optimization. Outer labels cannot drive edits. Previously viewed datasets are development evidence; independent final evidence needs unused data/environment.
4. Notify user with exact proposed weight changes before performing edits (explicit user requirement). Baseline reconstruction also to be explained before training.
5. Compare targeted head/layer/neuron edits, norm-matched random edits, common-base interpolation and low-rank updates; record all trials, uncertainty, per-split paired regressions, row/group denominators, unsafe approvals, benign approvals and review approvals.
6. Save immutable originals and candidate copies; offline only. No production integration.

## Baseline reconstruction started
- Frozen partitions prepared successfully by prepare.py for machine/target/operation. Disjoint row identities checked. These remain development-only.
- baseline.py reuses the preserved original fit_facts_transformer unchanged; exports state_dict plus vocabulary/normalization and source/data hashes.
- User-facing notice provided before launching baseline training (30 epochs, seed 1, machine scenario, 2 CPU threads).
- Unified exec session 6961 was confirmed live, training 2,655 usable rows. Poll this session before considering a restart. Intended artifact: baselines/machine_seed1/provenance.json; existing directory alone does not prove completion.
- Direct weight edits not yet started. Need reload equivalence verification, activation analysis and frozen edit/control protocol next.

## Baseline and reload verified
- Session 6961 completed successfully (exit 0). Training took 61.49 seconds for 2,655 rows.
- Immutable-reference files saved under baselines/machine_seed1: weights.pt, preprocessing.json, provenance.json.
- runtime.py reconstructs the same architecture and preprocessing without fitting. Source-baseline predictions on 32 training records matched exactly (maximum absolute error 0); reload_verification.json records the check.
- Baseline SHA-256: e1bb1b20c3996e82039917403497ca428f6e6823d3046be00598e599a77c93c5.
- Next: freeze editing candidates and calibration/selection rules, analyze edit-split activations, then notify before direct edits. Evaluation labels remain unused by the new optimization.

## Development activation analysis completed
- analyze.py read only calibration and edit partitions; no evaluation file opened.
- Two encoder CLS activations and head inputs captured; descriptive means/directions stored in analysis_machine_seed1.json.
- Fixed threshold 0.002082918304949999. Edit split: 1/195 risky rows, 1/41 risky groups falsely allowed (upper95 11.0553%); 107/371 benign allowed. These are single-seed pilot numbers and not directly comparable with historical four-seed cross-validation results.
- EDIT_PROTOCOL_V1.md freezes pilot controls, magnitudes and selection before direct edits. Weight editing has not started; notify user before applying it. Further layer/low-rank/interpolation and generalization work remains.

## Head pilot completed
- Explicit user-facing notification given before weight changes. pilot.py created independent copies, preserved original SHA-256, and evaluated 19 conditions including unchanged baseline, dense/sparse activation direction, 3 random controls at matched norms and positive bias controls.
- Session 8683 finished exit 0. All trial weights, scores and changes stored under pilot_v1/.
- Frozen edit-data selection picked activation_0.1 (32 head parameters; relative L2 change 0.10). Risk unchanged: 1/195 rows, 1/41 groups, upper95 11.0553%; benign allowances increased from 107 to 117 of 371. Newly allowed REVIEW rows: 15. No new settled-danger or teacher-denied allowances on this edit set.
- This is not evidence of safer operation: primary danger objective did not improve; REVIEW regression must be reported. Candidate is experimental, not adopted. No evaluation labels read yet.
- Next: audit trial control results and checkpoint predictions, then evaluate the frozen selected candidate against baseline on the held machine without tuning. Continue remaining layer, low-rank, interpolation and generalization requirements.

## Fixed pilot held-machine evaluation completed
- evaluate_pilot.py evaluated only the preselected activation_0.1, with hashes verifying selection, checkpoint and dataset. Session 98757 exited 0.
- deb14: baseline and edit both falsely allow 1/263 risky rows, 1/78 danger groups, group upper95 5.938%. Benign 72/117 -> 77/117; review allowances 118 -> 130. No danger fixes. Not adopted.
- All random/bias controls on edit data likewise failed to fix the one danger miss; primary optimization objective remains unmet.
- Report saved at pilot_v1/REPORT.md. deb14 evaluation has now been observed and cannot be an untouched final test for subsequent adaptive work.
- Next: inspect full research methods; frozen layer/neuron and low-rank/interpolation pilot protocol; train target/operation baselines with checkpoint export, use only inner development labels for edits. Independent final environment evidence still absent.

## Generalization baselines and rank-one implementation
- Started target baseline (session 86721) and operation baseline (session 67828), seed 1, original architecture, 30 epochs, 2 threads each, after notifying user. Poll handles before restarting.
- Read TFTV primary full text https://arxiv.org/html/2609.09054v3 section 3.2 equations 2–3. It constructs a rank-one update using normalized steering and an SVD-weighted right vector signed by mean-input projections.
- edits.py implements pure deltas without mutating weights. Synthetic checks passed for rank one, matched norm, nonnegative expected-input steering, zero-input edge case, matched random rank-one norm and unchanged input weight.
- TrustAuto's class-conditional CLS statistics differ from the paper's contrastive prompt/completion statistics; report this as an adaptation, not a replication. No low-rank edits have yet been applied to model copies.

## Target/operation baselines reload verified (2026-11-06)
- Sessions 86721 and 67828 had completed; weights.pt, preprocessing.json and provenance.json exist for both.
- target_seed1: 2,504 train rows, 75.9 s; weights SHA-256 bced180a8e823148dc3f34dd8f76fdca1dea33d9de072f8aad9a2e8a71dc35f3. runtime.py reload on 32 training records PASS, max absolute error 5.96e-08 (float32 rounding, within rtol 1e-6 / atol 1e-7).
- operation_seed1: 2,112 train rows, 66.0 s; weights SHA-256 fb6a7c10c2e10b626dd0220d7b323aa760145761584653057c0055ed1772de6b. Reload PASS, max absolute error 0.
- reload_verification.json written in each directory. No evaluation partitions read; no weights edited.
- Next: freeze rank-one / low-rank / interpolation pilot protocol (EDIT_PROTOCOL_V2) using edit/calibration partitions only, run activation analysis for target/operation, then notify user with exact proposed weight changes before applying edits.

## Protocol v2 executed to completion (2026-11-06)
- User asked to run the procedure to the end without confirmation. EDIT_PROTOCOL_V2.md frozen (SHA-256 2d5707d3...) before edits.
- Seeds 2/3 baselines trained for all three scenarios (scratch venv: system torch 2.9.1 + scikit-learn 1.9.1; /usr/local/bin/python3 lacks sklearn). All 9 baselines reload-verified PASS.
- pilot_v2.py: 49 candidates × 9 baselines (TFTV L0/L1, mean rank-one L1, neuron amplification L1, norm-matched random rank-one/neuron controls, bias controls, common-base interpolation conservative/plain). Selection on edit data only.
- evaluate_v2.py: each selection evaluated once on its evaluation partition. No candidate adoptable; new danger allows 0 everywhere. Selected: baseline ×2, bias ×4, tftv ×1, meanr1 ×1, interp_plain ×1. Danger reductions came from uniform conservatism (benign often → 0); recalibrated thresholds remove nearly all gains. Targeted edits beat bias control on primary objective in 0/9.
- Report: docs/ML_EXPERIMENT_6.md, pilot_v2/REPORT.md. README links experiments 5 and 6.
- Weight-space line of work concluded as negative. Further progress needs ≥165 danger groups and an unseen environment, not more edits.
