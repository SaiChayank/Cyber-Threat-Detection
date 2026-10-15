# DGA evaluation protocol — design freeze, 29 September 2026

The machine-readable design is
[`data/dga_evaluation_protocol.json`](../data/dga_evaluation_protocol.json).
This document freezes the split, sampling, metrics, and gates **before another
candidate is trained**. It does not claim a fresh evaluation result. No suitable
uninspected, algorithm-distinct positive and diverse legitimate set is currently
materialized in the repository. Until the separate reserved-source manifest is
complete and passes the checks below, **DGA promotion is blocked** and the
candidate remains disabled.

**Reconfirmed 2 October 2026:** the v1 protocol and its sidecar remain byte-identical
(`2bcf5534437fb55045d40be8f0558734184ea4d687abd97f9a5d10e8df79c763`).
[Exposure/integrity supplement](../data/dga_evaluation_design_review.json) records
the later rule validation, weighted-candidate training/validation and diagnostic
review, plus freshly rebuilt split/source hashes. It is protected by its
[SHA256 sidecar](../data/dga_evaluation_design_review.sha256). It supplements the
existing protocol; it does not resplit sources, change gates, train a candidate
or replace any previously frozen artifact/report.

The design is frozen. **A reserved dataset is not yet materialized or verified.**
Its actual source URLs, algorithm names, counts and hashes remain unavailable,
not fabricated. Final evaluation and promotion remain blocked.

## Exposure inventory and split decision

| Source | Prior influence | New role |
| --- | --- | --- |
| Synthetic lab DGA strings and traffic | Rule/feature design, model and runtime regression tests | Development regression only |
| UMUDGA seven-list subset: banjori, corebot, dircrypt; matsnu; necurs, ramnit; legit | Legacy NB training; validation; previously examined evaluation; legitimate reference across buckets | Development history, never fresh evaluation |
| Expanded UMUDGA 50 DGA variants and 100,000-domain legitimate file | Candidate fitting, feature and threshold selection, three model comparisons, family-specific error diagnosis | Preserve the existing family-grouped training/validation/development comparison |
| CICBellEXFDNS2021 `benign_1.pcap` | 22,336 first-label hard negatives before exclusions/deduplication; also runtime checks | Training/reference history |
| CICBellEXFDNS2021 `benign_2.pcap` | Earlier DNS-reference evaluation and later error diagnosis | Development DNS check, never fresh evaluation |
| Other CIC DNS attack captures | Mixed traffic without reliable per-query DGA labels | Ineligible as DGA truth |

Later exposure does not make a source independent again:

| Later work | Influence already incurred | Data role |
| --- | --- | --- |
| Feature/rule validation | Vowel/consonant feature reuse and rule trade-off assessment | Existing training/validation, never final evaluation |
| Weighted candidate | Training-only benign weighting, fitting and validation-only threshold selection at 0.85 | Same training/validation; all reserved metrics unmeasured |
| 2 October diagnostic review | Existing error interpretation and an unimplemented OOF-stacking recommendation | Saved inspected development reports/examples; no new cohort scored |

Model names, family labels and source identifiers are partition/provenance fields,
not predictive inputs. No model or feature change is authorized by this freeze.

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

For a reproducible literal sampling seed, the supplement records these exact
ASCII stratum IDs: `common_popular`, `machine_generated_legitimate`, `cdn_cloud`,
`short`, `long`, each with 600 domain labels. These instantiate the existing
`<stratum>` placeholder; the original category precedence and sample sizes remain
unchanged. The future materialization manifest must bind both the v1 protocol
hash and the supplement hash before any score is computed.

Overlap exclusions cover **full previously exposed raw sources**, including
unselected positive rows, rather than only the capped model-training rows. The
supplement records their canonical-label exclusion-union digest. Synthetic lab,
demo, unit/export-fixture exposures also remain development-only and must be
excluded/documented during materialization. Algorithm alias/derivative review is
required separately; name-prefix grouping alone is not proof of independence.

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

## Reconfirmation checks and immutable boundaries — 2 October 2026

Fresh read-only checks verified 58 raw domain files (seven smaller and 51 expanded)
and two previously inspected benign PCAPs. The current loader reproduced the
35/8/7 variant assignments and all counts in the table above. Pairwise scored-label
and declared-family-group overlaps are zero. Twenty conflicting labels remain
excluded; zero positive cross-split labels required exclusion. The inspected DNS
reference still has 11,731 eligible labels and 1,278/1,260 validation/comparison
overlaps. It remains **development evidence**, never a reserved DNS set.

Each source entry in the supplement records path, publisher/source, available
licence/DOI, bytes, SHA256, family or capture ID, canonical-label count and digest.
Each development partition records exact families/counts and a deterministic
selected-row digest. Actual reserved-source hashes/counts remain null because no
qualifying source manifest exists. No candidate score or threshold was computed.

**Not inspected during tuning:** the future three-unseen-algorithm positive set,
five-stratum legitimate-domain set and separate new benign-DNS set named by
`data/dga_reserved_materialization.json`. Until integrity-only eligibility checks
and frozen hashes exist, none may substitute for a passing final result. In an
eventual materialization check, emit only metadata/hashes/counts/collision counts;
do not reveal reserved example strings, scores, distributions or outcomes.

### Reproduce the integrity and development overlap checks

Run from the repository root with the already installed Python environment.
The imported module's training `main()` is not called. This checks only previously
exposed development sources; it neither reads nor creates a reserved set.

```powershell
@'
from pathlib import Path
import hashlib, json, socket
from datasets.train_dga_v2 import load_data
from ml.dga import DgaModel
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
p = Path('data/dga_evaluation_design_review.json')
assert sha(p) == p.with_suffix('.sha256').read_text().strip()
m = json.loads(p.read_text())
parent = m['original_protocol']
assert sha(Path(parent['path'])) == parent['sha256']
for item in m['raw_source_integrity']:
    assert sha(Path(item['path'])) == item['sha256']
def forbidden(*args, **kwargs):
    raise AssertionError('No scoring/network operations in a protocol check')
DgaModel.predict = DgaModel._uncached_score = socket.socket = forbidden
rows, provenance, captures = load_data()
digest = lambda v: hashlib.sha256(json.dumps(v, ensure_ascii=True,
    separators=(',', ':')).encode()).hexdigest()
labels = {k: {label for label, _, _ in v} for k, v in rows.items()}
groups = {k: {family.split('_')[0] for family in fs}
    for k, fs in provenance['family_splits'].items()}
for k, v in rows.items():
    expected = m['development_partitions'][k]
    assert provenance['split_counts'][k] == expected['counts']
    assert provenance['family_splits'][k] == expected['families']
    assert digest(sorted(v)) == expected['selected_rows_sha256']
for a, b in [('train','validation'), ('train','test'), ('validation','test')]:
    assert not labels[a] & labels[b]
    assert not groups[a] & groups[b]
second = captures['benign-benign_2'] - labels['train'] - captures['benign-benign_1']
assert len(second) == m['inspected_second_dns']['canonical_label_count']
assert {k: len(second & v) for k, v in labels.items()} == m['inspected_second_dns']['overlap_with_domain_partitions']
print('PASS: source hashes, frozen rows/families and development overlaps')
'@ | .venv/Scripts/python.exe -
```

The supplement uses compact sorted-key UTF-8 JSON **without a newline** so its
raw-byte hash survives Windows checkout without changing `.gitattributes` or
existing manifests. The v1 protocol, candidate plan, artifacts, prior numerical
reports, raw sources and analyst database retain their hashes. No code/tests were
added or changed; existing partition/manifest regressions are reused. Freeze these
definitions and limitations; do not refactor a completed detector in this task.

The documented integrity command passed. Reused tests passed with **17 passed**:
`python -m pytest tests/test_dga_diagnostic.py tests/test_dga_candidate.py -q`.
No regression tests were added because no executable behavior or bug was changed.
The full backend suite and frontend build were not rerun for this manifest/docs
task; this result makes no new claim about unrelated runtime behavior.

**Definition of Done:** evaluation-design freeze passes. Actual reserved dataset
materialization and its integrity/overlap checks are **blocked**, so this is not
a final-data freeze, model-quality pass or authorization to train/promote. The next
incomplete DGA evaluation task is eligible independent source materialization
followed by integrity-only verification and manifest freeze. No future task starts
automatically; the separate project completion-plan tasks remain unchanged.
