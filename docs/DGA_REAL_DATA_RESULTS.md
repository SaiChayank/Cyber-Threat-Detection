# DGA on real data: independent evaluation and guard fix (30 October 2026)

Evidence: `docs/verification/dga-final-evaluation-20261030/`. Protocol, sources and decision rule were
committed **before** scoring (`data/dga_final_evaluation_20261030.json`, commit `6cba8b2`); the code is
`datasets/evaluate_dga_final.py` (candidate) and `datasets/evaluate_dga_guard.py` (active guard).

## 1. The frozen OOF candidate fails all four gates (stays disabled)

Sources: 81 DGA families from the 2025 drift set with every family seen in development excluded
(name-root rule plus aliases), up to 2,000 domains per family (123,372 domains after dropping overlaps);
93,499 benign domains sampled from 2.3 M; 1,308 unique first labels of real client DNS from the AIT testbed
(not used for training or design). The candidate was scored once at its frozen threshold 0.9.

| Gate | Required | Measured | Result |
| --- | --- | --- | --- |
| Recall (micro) | >= 80% | **59.5%** (32 of 81 families reach 80%; macro 57.9%) | fail |
| Precision at 1:1 prevalence | >= 95% | 94.1% | fail |
| Domain FPR | <= 2% | **3.7%** | fail |
| Benign-DNS FPR | <= 2% | **10.2%** (134 of 1,308) | fail |

Development validation had said 90% recall and 1.3% FPR: a large generalization gap. Per the pre-declared
rule there is no retune and no re-run. Families it misses almost entirely include chaes, coffeeloader,
fosniw, tinyfluff, vobfus, qsnatch (6 M domains), gazavat and recjs. The two earlier candidates were
trained on the same development material and are not promoted either.

Note: the CIC benign DNS captures cannot serve as an independent reference for any candidate (one trained
the models as hard negatives, the other informed their design), so an earlier 0.83% false-positive figure
measured on them was discarded as contaminated.

## 2. The active guard on the same samples, and a real-data fix

| Active guard | Recall (81 families) | Domain FPR | Real benign-DNS FPR |
| --- | --- | --- | --- |
| Before: first label (`active-guard-report-first-label.json`) | 8.55% | 0.20% | 6.1% of 1,501 names (92 flagged) |
| After: registrable label (`active-guard-report.json`) | **6.47%** | 0.20% | **0.0%** (0 of 1,494) |

The 92 real false positives were machine-generated **cloud hostnames** (AWS load balancers, Azure
`cloudapp`, Google `safeframe` hashes): randomness in a subdomain of a provider's own domain. A generated
domain's randomness is in the registrable label, so the guard now judges that label
(`detection/dga_rules.registrable_name`; two-label names are judged exactly as before). The cost is a
2-point loss of recall on names whose randomness is in a subdomain (dynamic-DNS style). A side effect that
real traffic called for: a long random subdomain of a stable domain is now reported as DNS tunnelling only,
no longer also as a DGA domain (the frozen demo drops from 15 to 13 alerts, same seven classes).

## 3. What this means

- **DGA recall on modern families is still low (about 6%)** and no available model passes the gates.
  The detector is a very low-false-positive guard (0.2% on benign domains, 0 on real client DNS), not a
  general DGA detector. This is now measured, not assumed.
- Improving recall would need a new model trained on real, family-diverse data with a fresh independent
  test; the 2025 families used here are now exposed.
