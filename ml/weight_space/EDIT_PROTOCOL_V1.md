# Pilot edit protocol v1

Frozen after development activation analysis, before any direct weight edits.

Scope: machine scenario, single seed 1. This is a small pilot, not a substitute for the historical four-seed ensemble or the required three generalization axes.

Baseline threshold is 0.002082918304949999, calibrated once from 217 settled-risk calibration rows using the existing 1.8% order-statistic rule. It stays fixed for every pilot edit. This is a tuning rule, not a safety certificate.

Development observations: 1/195 dangerous rows incorrectly allowed, 1/41 dangerous groups (one-sided 95% upper bound 11.0553%); benign allowances 107/371 (28.84%). Only one false allowance makes the refusal-versus-miss direction unstable; it must not be portrayed as a reliable safety circuit.

First-stage candidates (no gradient training):
- Head direction: difference between settled-risk and settled-harmless CLS activation means, unit normalized. Edit only head.weight with relative L2 magnitudes 0.01, 0.03, 0.10. Exclude teacher-labeled data from estimating this direction.
- Sparse head direction: retain the four largest absolute components of that same direction, normalize and use the same magnitudes.
- Matched random head directions: three fixed random seeds 11/12/13 with exactly the same L2 magnitudes.
- Positive head-bias offsets 0.05/0.15/0.5 logits as a trivial conservatism control. Improvement must be compared against this control, rather than attributed to reasoning without evidence.

Record changed tensors, parameter counts, absolute/relative norms, baseline and candidate hashes and all outcomes. Save separate copies only. Model runs offline.

Selection on edit data only: require zero newly auto-approved settled-risk rows relative to baseline, no increase in risky rows or missed groups; also track teacher-denied and review newly allowed rows separately. Rank eligible candidates by fewer missed danger groups, fewer danger rows, then more benign allowances. Baseline remains a selectable option. Freeze selected candidate before opening outer evaluation labels. Report every candidate, including failures.

This first stage does not fulfill the full goal. Subsequent frozen protocols must cover internal layer/neuron edits, rank-one updates, interpolation from common-base minimally trained weights, matched controls, multiple seeds and machine/target/operation evaluations. Never interpolate independently trained networks as if their hidden coordinates were aligned. Existing environments are development evidence; genuinely untouched final evidence remains outstanding.
