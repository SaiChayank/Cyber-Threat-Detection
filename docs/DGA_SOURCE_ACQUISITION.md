# DGA source verification and acquisition

14 October 2026. **Three research input files downloaded. Final evaluation
readiness remains BLOCKED.** Acquisition success does not authorize training,
final scoring, runtime promotion or claims of generalization accuracy.

## Inspected and preserved baseline

Inspected the frozen DGA protocol and supplement, readiness review, OOF report,
existing public-domain downloader, offline acquisition helpers and tests. The
[previous review](DGA_EVALUATION_DATA_GAP.md) remains unchanged and historical.
The frozen four gates, first-label canonicalizer, source-exposure exclusions,
threshold 0.9 and disabled artifacts remain unchanged. Other detectors, frontend,
alert history and existing raw datasets are not modified.

The task adds new quarantined inputs; it does not create
`data/dga_reserved_materialization.json`. A downloaded file is not automatically a
reserved set. Existing independent-final metrics remain null.

## DRIFT: metadata qualification and actual files

The [publisher dataset card](https://huggingface.co/datasets/snsec-net/dga-detection-drift26dsn/blob/3b31077020cd1c013d0a75cad51042a2327c4521/README.md)
documents **raw names including TLD plus family labels**, separate from eSLD model
inputs. This resolves the earlier documentation-level representation uncertainty;
the raw release can be checked with our existing canonicalizer without adopting
publisher preprocessing, split roles or its transformer.

Pinned revision: `3b31077020cd1c013d0a75cad51042a2327c4521`.
Authors: Chaeyoung Lee, Chaeri Jung, Seonghoon Jeong, Sookmyung Women's University.
Dataset DOI: `10.21227/za2s-9e09`. The card states CC BY-NC-SA 3.0 and research/personal
use; retain attribution and applicable noncommercial/share-alike terms. This
task does not establish commercial-use permission or redistribute raw data in Git.
DGA provenance is DGArchive algorithm outputs; benign provenance is Alexa/Tranco
ranking snapshots, not captured ordinary-client DNS activity. Release-wide paper
totals do not certify this selected year's counts or benign intent.

Selected the latest documented raw year, 2025, before content inspection. The
[acquisition plan](verification/dga-source-acquisition-20261014/acquisition-plan.json)
and checksum pin exact files, role boundary, byte sizes and publisher LFS SHA256.
No new package or service was installed. Files are in:

- `data/raw/dga-evaluation-intake/drift-2025/T25_dga.parquet`
  — **336,599,103 bytes**, SHA256
  `c6d410dbeb7e5d4e345523defb9752fbb62c1000182a20937c96192fc4080bbd`.
  Parquet footer: **26,882,985 rows**, 219 row groups.
- `data/raw/dga-evaluation-intake/drift-2025/T25_benign.parquet`
  — **19,772,657 bytes**, SHA256
  `37e0c10bd2ec750706dd153f4900c8f1fb7ed2d8fddf18393373ec278a9c4eea`.
  Parquet footer: **2,336,094 rows**, 20 row groups.

Both full-file SHA256/lengths match the pinned publisher LFS metadata. Both schemas
contain string `domain`, string `family` and integer `label`. Inspecting the family
identity column found **143 families in this file**; the card's 148 is release-wide,
not this year's observed count. Domain rows and class-label values were not read
or printed, and no classifier was invoked for acquisition/metadata verification.
Rows are not distinct eligible first-label counts and do not constitute metrics.

Metadata-only shortlist counts: `bumblebee` 3,200 records; `qsnatch` 5,978,199;
`sharkbot` 3,675. These names are absent from the exposed UMUDGA inventory by name.
**Alias/derivative independence is still unverified**, as are post-exclusion unique
label counts; none is bound as an approved final algorithm. Other families in the
full file are quarantined, especially previously exposed algorithms. Do not train
on this intake or use publisher splits as project roles.

Publisher documentation returned example domains. Their canonical first labels
are recorded in the plan as exposures; earlier Bader/Daumel documentation examples
also remain to be pinned and excluded. No related holdout is declared untouched
until that registry and all provenance checks are complete.

## Additional DNS-domain reference: downloaded, unqualified

[Mendeley Data version 5](https://data.mendeley.com/datasets/623sshkdrz/5), Claudio
Marques, DOI `10.17632/623sshkdrz.5`, states CC BY 4.0. It describes 90,000 balanced
malicious/nonmalicious domains derived from public DNS logs, with lexical and OSINT
enrichment fields. It does not establish the underlying log identities or benign
label method sufficiently for our independent DNS gate. Malicious domains are not
automatically DGA positives. Source-provided enrichment is not a runtime feature.

Downloaded directly from the publisher's linked file, with a frozen 16 MiB cap:

- `data/raw/dga-evaluation-intake/mendeley-dns-623sshkdrz-v5/BenignAndMaliciousDataset.csv`
  — **12,633,896 bytes**, local SHA256
  `b0e50977577597574c7aee1f1b119de7c6599d85f687d43cfa24f6edab816b8e`.

Only the header was inspected; no rows or classification outcomes were exposed.
Transport length was checked where declared; HTML/empty responses were rejected.
The metadata listing returned HTTP200 with an application error400, not usable file
metadata. A publisher checksum was unavailable: **local SHA256 is recorded, not
publisher-checksum verification**. Provenance, independent benign intent and 2,500
eligible distinct labels remain unresolved. The CSV is a sealed research lead,
not a qualified benign-DNS dataset or an enabled replay preset.

## Other required data and rejected substitutions

The bounded publisher search did not establish a downloadable source satisfying
all remaining roles. The Lashkari DNS-exfiltration page resolves to the already
exposed CIC-Bell-DNS-EXF-2021 collection; it is not a fresh source and was not
downloaded again. Related CIC feature tables do not prove benign service categories.
Mixed attack captures, reputation lists, packet count and a generic benign label
are not replacements for the frozen category/provenance requirements.

Still required before materialization:

- Three confirmed unseen algorithms with 1,000 eligible distinct first labels each,
  alias/derivative review and complete development/example exclusions.
- Five legitimate strata of exactly 600 labels each. Ranking-derived DRIFT benign
  data is a common-popular lead; do not manufacture machine-generated/CDN-cloud
  provenance from spelling or count all remaining ranking names as other short/long
  domains contrary to category precedence.
- A separately sourced, documented benign DNS capture/query log with at least
  2,500 eligible distinct labels. The new CSV does not yet satisfy this requirement.

Thus download success is not a claim that every required dataset has been obtained.
No source was substituted based on model performance, and no acceptance gate changed.

## Implementation and verification

`datasets/acquire_dga_evaluation.py` implements a narrowly pinned, offline acquisition
command. It checks the plan hash, publisher URL/revision allowlist, exact size cap
and SHA256, refuses complete/partial overwrites, and atomically publishes verified
bytes using an exclusive hard link. Failed partials remain excluded. It has no
runtime/model import, dataset-row read or monitored-source connection.

Run in a clean work copy with the selected files and report absent:

```powershell
.venv/Scripts/python.exe -B -m datasets.acquire_dga_evaluation
.venv/Scripts/python.exe -B -m pytest tests/test_dga_source_acquisition.py tests/test_dga_diagnostic.py tests/test_dga_candidate.py -q -p no:cacheprovider
```

The current workspace intentionally refuses repeated acquisition rather than
overwriting evidence. Do not delete existing inputs to rerun it. The additional
CSV's exact direct URL, plan, response metadata/header and local hash are retained
in the evidence directory; its acquisition was a bounded administrative download,
not a new integration path.

Six new acquisition tests cover byte preservation, overwrite refusal, incomplete,
oversized and wrong-checksum bodies, unapproved URLs and invalid size types.
Together with existing diagnostic/candidate safeguards: **32 passed in 0.53s**.
No runtime/shared contract changed; full backend/build results are not refreshed.
Initial/final scoped integrity evidence pins 180 existing files. New raw intake
hashes, schemas and decision limitations are recorded separately. Raw inputs are
excluded from Git by the existing `data/raw/` rule.

Evidence: [download report](verification/dga-source-acquisition-20261014/download-report.json),
[schema/family check](verification/dga-source-acquisition-20261014/schema-family-check.json),
[DNS reference report](verification/dga-source-acquisition-20261014/dns-reference-download-report.json),
[final integrity](verification/dga-source-acquisition-20261014/final-integrity.json),
and [freeze](verification/dga-source-acquisition-20261014/freeze.json).

Before/after: new downloaded raw inputs **0 -> 3**, **0 -> 369,005,656 bytes**.
Qualified complete final evaluation sets **0 -> 0**. Model scores/accuracy are
unchanged; all public DGA candidates remain disabled. No model was trained or promoted.

**Definition of Done:** selected downloads and byte-integrity verification passed
within the scopes above. The complete required-evaluation-data outcome remains
**BLOCKED**, not passed. Freeze acquisition provenance and known gaps.

**Exactly next:** verify the three named algorithms' aliases/derivatives and bind
eligible roles before an integrity-only canonical-label materialization. In parallel
planning, identify publisher-supported legitimate service controls and clarify the
new DNS reference's original sources/label truth; no contact or scoring starts
automatically. Missing roles/counts must not be invented to complete the manifest.
