# DGA candidate-positive integrity count

14 October 2026. The user authorized sequential prerequisites. This step freezes
the three canonical groups and checks eligible-label counts without evaluating a
model. **The provisional positive count requirement passes; complete final data
readiness remains BLOCKED.**

## Frozen boundary

[Plan](verification/dga-positive-intake-20261014/plan.json) was written before
opening intake domain rows. It pins the original protocol, raw DRIFT 2025 file
SHA256, the [alias review](DGA_ALIAS_REVIEW.md), canonical groups Bumblebee,
QSnatch and SharkBot, minimum 1,000 distinct labels per group and forbidden scoring,
tuning/training/example output. All related versions remain grouped. Input hashes,
classifier features, threshold and activation flags are unchanged.

The checker uses the exact runtime `ml.dga.domain_label`. It reads batches offline,
ignores unassigned families, discloses unsupported inputs/unexpected class labels,
deduplicates first labels across FQDNs/TLDs and removes prior exposures and
cross-group collisions. It prints only counts and readiness status, never domains,
lexical distributions or classifier outcomes. This is not the final scoring pass.

## Counts

- **Bumblebee:** 3,200 records; 3,200 supported unique first labels; 100 excluded by
  the development/documentation registry; **3,100 eligible** under current exclusions.
- **QSnatch:** 5,978,199 records; 3,227,497 supported unique labels; 8,807 excluded;
  **3,218,690 eligible** under current exclusions.
- **SharkBot:** 3,675 records; 1,155 supported unique labels; one excluded;
  **1,154 eligible** under current exclusions.

Zero cross-group label collisions, zero unsupported selected-group records and
zero unexpected selected-group class labels were observed. All three exceed the
unchanged 1,000-label prerequisite. No 1,000-label sample was selected or frozen,
and no TP/TN/FP/FN, recall, precision or FPR was computed.

[Counts and digests](verification/dga-positive-intake-20261014/counts.json) specify
the eligible-set digest encoding. These are integrity diagnostics, not project
accuracy or production threat generalization. The source is generator-derived,
not recovered malicious client traffic.

## Exposure scope and unresolved qualification

Verified the complete 596,591-label public development union against its frozen
digest. Added the alias-review documentation, current pinned Bader/Daumel READMEs,
DRIFT documentation and conservative regex exclusions from existing test literals,
fixtures, lab/demo JSONL and replay source. Publisher document exclusions total
682 canonical-label hashes before combining with development/fixture exclusions.

The exact older cached publisher rendition is not byte-certified, and source
literal extraction does not reconstruct every dynamically generated historical
fixture. These are explicit completeness limitations, not silently passed final
exposure checks. Eligible counts are provisional until the complete registry is
verified. Future benign-domain and DNS sets must also be checked for cross-role
overlap, which cannot yet be assessed. Alias review supports known canonical
family separation, not exhaustive generator-code equivalence.

## Diagnostic defect and tests

The new checker initially treated only `None` as an unsupported name. The existing
runtime canonicalizer returns an empty string instead. A new unit test caught the
incorrect guard before intake rows were processed. Fixed only this checker to
reject empty canonical results; the runtime canonicalizer and detector are unchanged.

Six new exact tests cover first-label/TLD deduplication, exposure exclusions,
cross-group collisions, unassigned families, invalid names/class labels and the
999/1,000 distinct-label boundary. Initial test run: one failed, 37 passed.
Corrected run: **38 passed in 0.57s**, combining the six new tests with acquisition
and existing DGA safeguards. No shared runtime behavior changed; full backend
suite/frontend build are not refreshed.

Changes: `datasets/check_dga_positive_intake.py`, `tests/test_dga_positive_intake.py`,
this document and its new plan/exclusion/count/integrity evidence. Existing
209 protected files remain unchanged. All public DGA candidates stay disabled.

## Disposition and next step

**Definition of Done:** integrity-only count task passed within the stated
exclusion scope; freeze code/tests/counts/input hashes and completeness limitations.
This does not approve a complete reserved materialization or permit final scoring.

Next sequential task is benign-domain/DNS provenance qualification. It must
establish all five 600-label legitimate strata and a separate >=2,500-label benign
DNS reference. The [benign-source decision](DGA_BENIGN_SOURCE_QUALIFICATION.md)
records the subsequent audit of the downloaded reference. Do not select a final
sample or promote a candidate while those requirements remain unresolved.
