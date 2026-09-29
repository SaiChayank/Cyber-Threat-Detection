# DGA evaluation protocol — design freeze, 29 September 2026

The machine-readable design is
[`data/dga_evaluation_protocol.json`](../data/dga_evaluation_protocol.json).
This document freezes the split, sampling, metrics, and gates **before another
candidate is trained**. It does not claim a fresh evaluation result. No suitable
uninspected, algorithm-distinct positive and diverse legitimate set is currently
materialized in the repository. Until the separate reserved-source manifest is
complete and passes the checks below, **DGA promotion is blocked** and the
candidate remains disabled.

## Exposure inventory and split decision

| Source | Prior influence | New role |
| --- | --- | --- |
| Synthetic lab DGA strings and traffic | Rule/feature design, model and runtime regression tests | Development regression only |
| UMUDGA seven-list subset: banjori, corebot, dircrypt; matsnu; necurs, ramnit; legit | Legacy NB training; validation; previously examined evaluation; legitimate reference across buckets | Development history, never fresh evaluation |
| Expanded UMUDGA 50 DGA variants and 100,000-domain legitimate file | Candidate fitting, feature and threshold selection, three model comparisons, family-specific error diagnosis | Preserve the existing family-grouped training/validation/development comparison |
| CICBellEXFDNS2021 `benign_1.pcap` | 22,336 first-label hard negatives before exclusions/deduplication; also runtime checks | Training/reference history |
| CICBellEXFDNS2021 `benign_2.pcap` | Earlier DNS-reference evaluation and later error diagnosis | Development DNS check, never fresh evaluation |
| Other CIC DNS attack captures | Mixed traffic without reliable per-query DGA labels | Ineligible as DGA truth |

The prior comparison set has been inspected repeatedly, including the ccleaner,
symmi and kraken false negatives; it is **validation/tuning evidence for future
work**, despite its old `test` key in code/reports. The second benign DNS capture
has also been inspected and shares 1,278 labels with validation and 1,260 with
the comparison. Neither is an untouched holdout. No 51st UMUDGA family exists in
the downloaded expanded family list. Using unused rows from a *seen* algorithm
would not create a family-independent final set.

The current development partitions are retained exactly; this task does not
resplit data or change a trainer. Their unique scored-first-label counts are:

| Role | DGA variants | Positive labels | Benign labels | Use |
| --- | ---: | ---: | ---: | --- |
| Training | 35 | 69,993 | 67,715 | Fit candidate, including first DNS hard negatives |
| Validation/tuning | 8 | 80,000 | 15,236 | Select model/threshold and inspect errors |
| Inspected comparison | 7 | 60,577 | 14,910 | Development regression only |
| Inspected second DNS | — | — | 11,731 | Development benign reference only |

The training, validation and comparison variant names and all source/report
SHA256 values are pinned in the JSON manifest; its referenced publisher
manifests pin each raw file's URL, size, SHA256 and family. The training and
validation partitions have zero exact scored-label overlap and zero overlap
of the family groups currently derived by stripping variant suffixes. The same
is true for their comparisons with the inspected development set. The older NB
split used full FQDN hashes while scoring only first labels, so its scored labels
**do** overlap across partitions; it is excluded from future promotion evidence.

## Reserved evaluation set: predeclared construction

The reserved set must be acquired from **new documented sources** and recorded in
`data/dga_reserved_materialization.json` before any candidate score or error
example is computed. That future manifest must name publisher, source URL/DOI,
version, licence, acquisition date, raw byte count, raw SHA256, algorithm/stratum
provenance, first-label counts before and after exclusions, selection count, and
the SHA256 of its frozen selected-label file or canonical list. It must also
record the development source-manifest hashes pinned here. If a source's origin
or labels cannot be established, it cannot be called an independent evaluation.

Positive domain set: **three documented DGA algorithms absent from all 50
expanded UMUDGA variants**, including known aliases or derivative generators.
Take exactly 1,000 unique canonical first labels per algorithm after exclusions.
An algorithm and its variants cannot be split between development and reserved
evaluation. Do not substitute a different experiment of an already used UMUDGA
family as a new algorithm. Document the algorithm-group mapping in the future
materialization manifest before scoring. If three qualifying groups or 1,000
eligible labels per group are unavailable, the reserved set is invalid.

Benign domain set: **3,000 unique first labels**, exactly 600 from each of five
documented strata. These strata preserve the failure modes found in diagnosis:

1. Common popular domains from a dated, versioned popularity reference.
2. Legitimate machine-generated names whose service/generator role is documented
   by the source; unusual spelling alone is not proof of that role.
3. CDN/cloud-style names with documented benign service context.
4. Other short names, first-label length under 12.
5. Other long names, first-label length at least 12.

Apply the first three source categories in that order, then length to the
remaining documented benign labels. Each label belongs to one stratum. Do not
assign benign or service labels merely from a model score, entropy, or lexical
appearance. The separate benign-DNS set must come from a newly sourced,
documented benign capture/query log and contain **at least 2,500 distinct
eligible first labels**; include all eligible labels rather than selecting an
easy-looking subset. It is a distinct reference check, not a surrogate for
the five-stratum domain set.

Canonicalize with `ml.dga.domain_label`, reject unsupported names, and compare
the **actual scored first labels**, not just FQDNs. Remove label overlaps with
all prior development sources, across reserved positive/benign/DNS sets, and
between conflicting labels. Check algorithm aliases/derivatives separately.
Record every exclusion count. After eligibility checks, select the fixed domain
counts by ascending SHA256 of `PS26145-DGA-family-holdout-v1:<label>` for positive
algorithms and `PS26145-DGA-family-holdout-v1:<stratum>:<label>` for benign
strata. Break a hash tie lexicographically by label. These are deterministic
**within-algorithm/stratum samples**, not random row-level train/test splitting.
The DNS reference uses all eligible unique labels.

Before any tuning, an integrity/overlap checker may read raw sources and emit
only hashes, source metadata, total/stratum counts and collision counts. Do not
expose reserved example strings, outcome labels, score distributions, errors or
metrics to the model developer. Failed integrity, provenance, family-separation,
stratum or minimum-count checks invalidate the holdout; do not quietly shrink or
replace it. If the data cannot satisfy the preregistration, freeze a **new
versioned protocol before further tuning**, disclose the deviation, and do not
retroactively call the current cohort an untouched test.

## Fixed decision and promotion criteria

Train using development training labels only. Select one threshold using only
development validation and the existing fixed grid `0.5, 0.6, 0.7, 0.8, 0.85,
0.9, 0.95, 0.975, 0.99`. The inspected comparison and DNS sets may be reported
as diagnostics but cannot choose the final threshold or sample composition.
Record the candidate artifact SHA256, feature contract and threshold **before**
opening the reserved evaluation results. The reserved domain set is intentionally
balanced 3,000 positive / 3,000 benign; its precision is a reproducible
reference-set statistic, not production precision.

On one final scoring pass, require **all four** original gates:

| Gate | Definition | Requirement |
| --- | --- | ---: |
| Domain recall | TP / (TP + FN) | >=80% |
| Domain precision | TP / (TP + FP) | >=95% |
| Domain false-positive rate | FP / (FP + TN) | <=2% |
| Separate benign-DNS false-positive rate | DNS FP / DNS benign labels | <=2% |

Report per-algorithm recall, benign-stratum FP counts/FPR, full confusion counts,
and DNS-source counts alongside the aggregate gate results. Do not loosen a gate,
change the threshold, inspect a second subset, or retrain against the reserved
outcome. A failed candidate stays disabled. A candidate changed after this reveal
requires a newly reserved independent evaluation source for a final claim.

## Checks completed at design freeze

Read-only checks verified the SHA256 of the seven-list and expanded UMUDGA
manifests, every referenced raw UMUDGA file, the DNS catalog and both benign
PCAPs, all prior DGA reports, and the synthetic-lab manifest. Rebuilding the
existing partitions reproduced **69,993/67,715**, **80,000/15,236** and
**60,577/14,910** positive/benign counts and the 35/8/7 variant assignments.
Train/validation, train/comparison and validation/comparison each had **zero
scored-label and algorithm-group overlaps**. The previously used second DNS set
had 11,731 eligible labels, with the documented 1,278/1,260 overlaps.

**Reserved-source integrity and overlap checks cannot yet run:** no qualifying
new positive algorithms and no new five-stratum benign/DNS materialization are
present. Its source hashes, final counts and family names are intentionally
`null`/empty in the protocol manifest; inventing them would be a false freeze.
The next permitted task is to acquire and materialize that independent set,
verify its licence/provenance, SHA256, algorithm separation, stratum counts and
scored-label disjointness, then freeze the materialization manifest. **No model
training or promotion occurred in this task.**
