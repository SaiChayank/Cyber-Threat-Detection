# Encrypted development-data feasibility — 12 October 2026

**Audit Definition of Done: PASSED. Streaming model training/promotion readiness:
BLOCKED.** Existing data supports limited, weakly labelled offline ClientHello
research, not independent validation of incremental malicious-session detection.
No detector, model, parser, threshold, frozen gate or dataset was modified.

## Inspected and data access boundary

Inspected dataset/licence/provenance manifests; downloaded TLS README/schema;
TLS adapter and previous group split/evaluation; encrypted protocols and sensitivity
findings; ClientHello parser, TLS sidecar, TrafficEvent normalization; existing PCAP
catalog and tests. No new sources were fetched and unauthorized IoT-23 was excluded.

All five downloaded TLS source files match their recorded SHA256 and size.
The release is Ondrej Rysavy's Annotated Encrypted Network Traffic Dataset v1.0.0, DOI
10.5281/zenodo.18336960, with CC BY 4.0 recorded in the existing download manifest.
This is frozen local provenance, not a fresh website/licence review.

Parquet footers/schema and annotation columns identify the historical partitions.
Feature values are read **only from members without any historical test-labelled
group**, and only for training/validation-labelled rows. Entire mixed/test members
are excluded from feature reads. SOHO is footer/schema only. Sample-overlap counts
use annotation IDs, hashed in memory; test handshake values are never examined.
No reserved evaluation dataset, labels-as-predictors, model inference or fitting.

The [protocol](verification/encrypted-data-feasibility-20261012/PROTOCOL.md) fixes
this scope. Reproduce with the already declared `datasets` extra installed:

```powershell
.venv/Scripts/python.exe -B -m datasets.audit_encrypted_data --output encrypted-data-audit.json
.venv/Scripts/python.exe -B -m pytest tests/test_encrypted_data_audit.py tests/test_encrypted_visibility.py tests/test_dataset_validation.py -q -p no:cacheprovider
```

The command never overwrites an existing report or invokes `train_tls.main()`.

## Source and capability inventory

**Annotated TLS winapps — CONDITIONAL for offline benign-reference research.**
5,892 Parquet members, 29,526 connections by footer. Existing training/validation
labels count 19,831/4,767; their 24,598 audited records all have nonempty client
cipher/extension arrays and JA3. Application annotations identify the originating
application, not independent verification of every connection's benign intent.
No raw PCAP or packet/handshake timestamps accompany this downloaded subset.

**Annotated TLS malware — CONDITIONAL for sample-associated research.**
916 members, 1,405,079 connections by footer (not the README's 828,171 summary).
There are 649,138 ambiguous/system/unlabelled rows. Original annotation partition
counts are 376,274 training, 237,120 validation and 142,547 historical test positives.
The positive label is MALWARE_RELATED: family present and system-service annotation
absent. Missing a known-service annotation does not prove a flow is malicious.

Strict whole-member exclusion leaves **18,065 training and 16,552 validation**
positive-related rows eligible for handshake coverage inspection. All 34,617 have
cipher arrays and JA3; 34,575 have nonempty extension arrays and 42 have explicit
empty extensions. This is a conservatively selected subset, not representative
coverage of all 755,941 family-labelled records. Do not infer quality or class
balance improvements from this selection.

**SOHO — UNLABELLED, unsuitable for supervised positives/negatives.**
104 members / 108,036 connections by footer. Its realistic provenance does not
make it automatically benign. No row values or supervised metrics were inspected.

**Existing DNS-reference PCAPs — insufficient encrypted-handshake controls.**
The two already used benign references produced 132,180 and 93,684 parsed IP
observations. Snaplen is 96 in both. The second has 5,902 port-443 hints, but both
yield **zero parser-returned ClientHellos**. Port 443 is not proof of TLS. Counts
are parser visibility, not flow-level FPR, physical capture throughput or evidence
that encrypted sessions never existed. Clipping and single-packet parser scope
limit visibility; no TCP reassembly/decryption was added.

**Other downloaded sources and fixtures — not qualifying encrypted truth.**
The 12 mixed DNS attack-category captures are catalogued, not replayed or labelled
malware. CIC completed-flow CSVs lack ClientHello cipher/extension sequences and
encrypted-malware-specific session truth. UMUDGA is domain-only. Existing lab/demo
metadata and 18 controlled scenarios remain regression fixtures with synthetic
intent, not an independent encrypted-capture evaluation set.

## Feature representation and causal compatibility

The public ClientHello arrays contain **four-digit hex strings**, including GREASE
IDs; runtime parser arrays contain integers. Counts are measurable, but any future
ID comparison needs a declared conversion/GREASE policy rather than interpreting
strings such as `1301` as decimal. The diagnostic accepts the observed hex format
and preserves null, empty and invalid distinctions. The first integer-only audit
wrongly marked these arrays invalid; that report is preserved, and the correction
has exact regressions. It was a diagnostic defect, not absent source metadata.

The parser supplies offered ClientHello version, cipher suites, extension count,
JA3 and visible SNI when a complete record fits one TCP packet. `from_packet()`
passes JA3/transport/bytes/timestamps but **drops cipher/extension sidecar fields**.
They are not current TrafficEvent or deployed GNB inputs. JA4/JA3S/QUIC fields
existing in a schema/public table do not establish raw runtime extraction.

ClientHello metadata is potentially causal at handshake observation, but the
completed-connection table has no handshake event time or packet sequence. `bs`,
`ps`, `td` and complete signed TLS-record lengths are unavailable as early packet
features. Positive TLS record lengths are not IP packet sizes. Missing handshake
metadata must not become an observed zero count (the old offline adapter's
`len(value or [])` is not a missingness policy for a future runtime feature).
No reconstructed timestamps, reverse observations or encrypted payloads are used.

## Separation and contamination findings

Existing exact family/application hash groups are disjoint between development
training and validation: winapps 36/17 groups, malware 70/18. That does **not**
establish sample or capture independence.

Annotation-only matching finds **544 malware sample IDs shared across training
and validation**, **382 across training/historical test**, and **432 across
validation/historical test**. Winapps sample overlap is zero for these pairs.
The historical family-label-string split can send observations from one underlying
sample into different partitions. Saved public-TLS metrics are preserved but
cannot be treated as independent sample-separated accuracy. No raw test feature
values were needed to demonstrate this leakage risk.

Sample-ID-derived dates overlap on all 68 observed winapps development days and
all 30 malware development days. Winapps prefixes span 2024-07-16 to 2024-10-08;
malware prefixes span 2025-09-01 to 2025-09-30. These are **annotation-prefix dates,
not validated packet timestamps**. Their difference and distinct collection
environments indicate potential cohort confounding. No chronological validation
or independent time holdout has been established.

All these collections already influenced earlier training/evaluation. Neither
historical test groups nor recycled development rows become a fresh reserved set.
Family/app grouping must also honor sample/capture identity before another offline
research split is accepted. Current final encrypted gates remain unchanged.

## Decision, tests and freeze

Feasible now: provenance/missingness work and a separately scoped **offline**
ClientHello-only research design after sample-aware grouping and label limitations
are addressed. Not feasible now: a credible full streaming candidate promotion,
independent malware-intent accuracy, QUIC fingerprint validation or early-alert
timing evaluation from these completed-session tables.

Added `datasets/audit_encrypted_data.py`,
`tests/test_encrypted_data_audit.py`, this document and dated evidence. Updated
dataset/model documentation and completion plan; runtime/model files unchanged.
Thirteen new diagnostic cases plus existing visibility/metric checks give
**18 passed**. Two optional Parquet guard tests skip only when the already declared
PyArrow dependency is absent; all passed in this audit environment. Full backend/
frontend build was not rerun because shared behavior did not change. No detection
quality/performance metric is refreshed, and no old report is relabelled current.

[Complete report](verification/encrypted-data-feasibility-20261012/report-complete.json)
records provenance, counts, coverage, exclusion, groups and sample/date overlap.
[Tests](verification/encrypted-data-feasibility-20261012/tests-final.log) cover
hex/int IDs, missing versus empty, label exclusion, invalid dates, mixed/test
member feature-read prohibition, sample overlaps and SOHO footer-only access.
Freeze this audit, tests, report and limitations; preserve data and failed artifacts.
Final integrity checks confirm **129 protected files unchanged**, including source
archives, frozen models, runtime code, prior diagnostics and analyst history.
The [freeze record](verification/encrypted-data-feasibility-20261012/freeze.json)
pins the new tool/tests/protocol/report and records the feasibility decision.

## Exactly next

**Prepare a sample-aware encrypted development split design only.** Keep every
sample/capture together, account for overlapping family-label groups, measure
whether both classes can remain represented in disjoint development partitions,
and explicitly retain weak-label/completed-session limitations. Record manifests
and acceptance criteria without feature/model changes, fitting or reserved-data
inspection. If adequate grouping is infeasible, report that blocker before sourcing
new data. Streaming promotion still separately requires permitted, labelled,
full-snaplen timestamped TLS captures; do not substitute metadata-table results.
