# DGA final-evaluation data readiness

14 October 2026. **Readiness review completed; final data gap remains BLOCKED.**
This task inspects the frozen protocol, development-source exposure, candidate
reports, loader and safeguards, and researches publisher documentation. It does
not train, tune, score reserved data, activate a candidate or alter any detector.

## Required deliverables still missing

The [frozen protocol](DGA_EVALUATION_PROTOCOL.md),
`data/dga_evaluation_protocol.json` and its exposure supplement govern this work.
`data/dga_reserved_materialization.json` remains absent; do not create an empty
file at that path that could be mistaken for an actual frozen evaluation set.

1. **Positive domains:** three documented algorithms absent from all 50 exposed
   UMUDGA variants, including aliases/derivatives. Exactly 1,000 distinct eligible
   first labels per algorithm after all exclusions: 3,000 positives total.
2. **Legitimate domains:** 3,000 distinct eligible first labels, exactly 600 each
   from `common_popular`, `machine_generated_legitimate`, `cdn_cloud`, `short`
   (under 12 characters) and `long` (at least 12). Apply source-category precedence
   before length. Source evidence, not lexical appearance or detector scores,
   establishes category and benign reference intent.
3. **Separate benign DNS:** a new documented benign query log/capture with at
   least 2,500 distinct eligible first labels after exclusions. Retain all
   eligible labels; do not cherry-pick a convenient subset.

Every input needs publisher, URL/DOI, version, licence, acquisition date, exact raw
bytes/SHA256, algorithm or benign provenance, counts before/after exclusions and
selected-label digest. No raw-source hashes or eligible counts exist yet for these
new roles. Domain sets and the DNS reference must be mutually disjoint after
canonicalization and disjoint from exposed development labels and fixture examples.

## Exposure and existing candidate

Retain existing 35/8/7 variant assignments. The old `test` partition is an inspected
development comparison, not a fresh test set. Both historical benign PCAPs have
already influenced development; their second-reference labels overlap validation
and comparison and cannot fill the new DNS slot. New rows/dates from seen UMUDGA
algorithms do not establish algorithm separation.

The public development exclusion union has 596,591 distinct first labels, including
unselected raw rows. Its frozen digest is
`a971fce2e75f0f25e7c51469d631dd343f56e5883547ff89ce3d98f5185643fe`.
Synthetic/demo/test/export examples require additional exclusions during actual
materialization; this public union is not the complete future exclusion registry.

The [OOF candidate](DGA_OOF_CANDIDATE.md) is already frozen at threshold 0.9.
Saved development validation: TP 72,052; TN 15,043; FP 193; FN 7,948; recall
90.065%; precision 99.733%; F1 94.653%; FPR 1.2667%. These are unchanged historical
measurements, not newly measured accuracy. The independent reserved domain and
separate benign-DNS results are null. The original, weighted and OOF candidates
remain disabled. Missing evaluation is not a measured numerical gate failure.

## Publisher leads and qualification gaps

Research was limited to documentation, search results and catalogues, not domain
files, Parquet rows, data viewers, capture downloads or model scores. This is a
bounded source review, not proof that no suitable data exists anywhere.

- **DGArchive:** the [official Fraunhofer FKIE service](https://dgarchive.caad.fkie.fraunhofer.de/)
  supplies DGA-domain provenance; its [terms](https://dgarchive.caad.fkie.fraunhofer.de/terms.html)
  must be respected. No authenticated access, terms acceptance, export or permission
  request occurred. Access conditions, eligible algorithm catalogue/aliases,
  source version and post-exclusion counts remain unverified for our holdout.
- **DRIFT longitudinal release:** the [author repository](https://github.com/snsec-net/2026-DSN-DRIFT)
  links a [dataset](https://huggingface.co/datasets/snsec-net/dga-detection-drift26dsn)
  derived from DGArchive and Alexa/Tranco. This is the most concrete published
  positive-data lead found, not a qualified assignment. The repository describes
  preprocessed effective-SLD inputs. Require original queried names or a documented
  mapping proving preservation of our scored first labels; eSLD is not silently
  interchangeable with `ml.dga.domain_label` on passive query names. Require exact
  family/alias metadata, licence scope and 1,000 eligible labels per chosen unseen
  algorithm. DGArchive/DRIFT exports are related sources, not independent duplicates.
  We do not adopt its transformer, publisher split or reported accuracy. The raw
  dataset-card document was inaccessible through the web tool; no access bypass.
- **Bader generator catalogue:** [author repository](https://github.com/baderj/domain_generation_algorithms)
  documents reversed algorithms. The catalogue includes `bumblebee`, `qsnatch` and
  `sharkbot`, names absent from the local 50-variant inventory. These are only
  shortlist leads: absence by name does not prove algorithm independence, correct
  implementation, eligible counts or label provenance. The [repository licence](https://github.com/baderj/domain_generation_algorithms/blob/master/LICENSE)
  contains GPL v2 terms; no source was vendored or executed. Generator-derived
  domains would need documented seeds/dates, provenance and scope, and could not
  be claimed as captured production attacks.
- **Popularity references:** the [Tranco authors' paper](https://tranco-list.eu/assets/tranco-ndss19.pdf)
  supports dated reproducible ranking references. A fixed list ID/version and
  source permissions would still be needed. Popularity is a reference label,
  not proof of uncompromised service intent. It cannot alone establish machine-
  generated legitimate or CDN/cloud provenance. The FAQ fetch failed; no list
  rows were downloaded or eligibility counts inferred from a ranking size.
- **DNS derivative lead:** the [Daumel author README](https://github.com/Daumel/dns-exfiltration-dataset)
  describes university traffic with authors' identified DGA domains removed,
  plus a separate top-sites/subdomain traffic source. Those filtering choices
  could bias a DGA false-positive test. Require original benign provenance,
  unfiltered scope, source independence, original query-name preservation,
  permission and the 2,500-label count. Its benign record count is not a distinct
  first-label count. No derivative or upstream captures were acquired; a tunnel
  label must not be reused as a DGA label. This is not yet an eligible DNS reference.

All leads remain unassigned. No exact release revision, three approved algorithms,
five qualified benign strata or qualified DNS export is frozen by this review.

## Incidental publisher-example exposure

The Bader README and DNS derivative README included example domain values in
documentation returned by browsing. Do not claim zero new domain-text exposure.
They were not scored or used for feature/threshold design. Their exposed examples
must be included in the exclusion registry before any related source could be
reserved. Until their exact example set is pinned and excluded, those sources
cannot be declared untouched. Do not relabel these documentation examples as
reserved data, train on them, or quietly omit this exposure history.

## Materialization boundary and smallest next action

**Next: perform metadata-only qualification of the DRIFT release.** Bind a release
revision and request/read schema, family catalogue, algorithm aliases, original
name versus eSLD mapping and data licence. Do not open Parquet/domain rows or its
dataset viewer. If family identity or original-name semantics are missing, record
that blocker rather than redefining our feature contract. No author message is
authorized by this source review alone.

This single action assesses the positive-data path. Separately qualified
legitimate service-category sources and a benign DNS query log will still be
required. One positive-source qualification cannot close the whole evaluation gap.

After all roles and provenance are bound, a separately authorized integrity-only
materializer may inspect source values locally without emitting examples, labels,
scores, distributions or outcomes to the model developer. It must:

- Verify raw hashes and canonicalize using the exact runtime `domain_label`.
- Reject unsupported names and remove development/fixture/documentation exposures,
  duplicate labels, cross-role collisions and conflicting truth; record counts.
- Check aliases/derivative provenance separately from string overlap.
- Apply the original SHA256 sampling prefixes and stratum IDs, keep every eligible
  separate-DNS label, and enforce all original count requirements.
- Freeze the real materialization manifest and selected-file hashes before the
  already-frozen candidate is scored once. A missing-count or provenance failure
  invalidates materialization; no shrinking, source replacement based on scores
  or retuning is permitted.

Promotion still requires all four gates: recall >=80%, precision >=95%, domain
FPR <=2%, separate benign-DNS FPR <=2%. The balanced reference-set precision is not
production precision. A failed final candidate remains disabled with failure
analysis only; no gate is weakened.

## Verification and task disposition

[Integrity checks](verification/dga-evaluation-gap-20261014/integrity-checks.json)
rerun only previously exposed development sources with network and classifier
scoring calls prohibited in the checking process. They verify frozen hashes,
partitions, label/group overlap, exclusion union and disabled artifact flags.
Actual reserved integrity/overlap checks are **NOT ASSESSABLE** while no
materialization exists; never report them as zero-overlap passes.

Results: all 60 existing source files match frozen hashes; all three development
partition pairs have zero exact scored-label and declared-group overlap; frozen
row digests/counts and the 596,591-label public exclusion union reproduce exactly.
The inspected second DNS reference retains 11,731 labels and its historical
1,278 validation / 1,260 comparison overlaps. All three candidate hashes match and
activation flags remain false. The first checking attempt used an incorrect
guessed weighted-artifact filename and stopped before writing a report; the
successful rerun uses the existing trainer's artifact constants. This was a
checking-command error, not a repository defect.

Existing targeted tests: **26 passed in 0.63s**, using
`python -B -m pytest tests/test_dga_diagnostic.py tests/test_dga_candidate.py -q -p no:cacheprovider`.
[Source-readiness evidence](verification/dga-evaluation-gap-20261014/source-readiness.json)
records the gaps, sources, unchanged gates, incidental exposure and absence of
role assignments. [Protected-file check](verification/dga-evaluation-gap-20261014/final-integrity.json)
compares the 177 scoped existing source/runtime/model/test/documentation files
against this task's initial snapshot. It is not a whole-repository/raw-archive
integrity claim. [Review freeze](verification/dga-evaluation-gap-20261014/freeze.json)
pins these findings and limitations, not a completed final dataset.

Only this report and its new review/check/integrity evidence are changed. No
diagnostic code or regression tests are added: no bug or executable behavior was
changed. Existing DGA diagnostic/candidate safeguards are reused; full backend and
frontend build are not rerun for this documentation/integrity-only task.

The review Definition of Done passes once its evidence checks are recorded.
The requested eligible-final-data outcome remains **BLOCKED**, with all three
required data components missing. Accuracy, models, thresholds and other detector
behavior are unchanged. Stop before acquisition, final scoring or promotion.
