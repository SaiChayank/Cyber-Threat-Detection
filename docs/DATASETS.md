# Downloaded public datasets and their use

**17 October 2026 acquisition update:** both open CC BY 4.0 Zenodo archives are
now saved in `data/raw/dns-public-intake/`: DNSTunnel2026 (497,565,428 bytes) and
UMA benign captures (6,853,462,196 bytes). Exact publisher MD5 and local SHA256
are verified in `data/dns_public_acquisition.json` and the
[acquisition report](DNS_PUBLIC_DATA_ACQUISITION.md). These are unextracted,
unqualified research inputs, not training/validation/reserved sets or runtime
replay presets. Existing DNS gate/contract and disabled candidate are unchanged.
The older totals and dated audits below are historical and exclude this intake.

Audited **2 October 2026**. The initial 28 September download recorded
**413,142,899 bytes (413.1 MB)** of source files and
the selected DDoS CSV are saved under `data/raw/`. Extracted DNS PCAPs occupy
additional space. These are actual downloaded files, not download links or mocks.
Large raw files are intentionally excluded from Git. The small manifests and
evaluation reports retain provenance, version, attribution and hashes.

Expanded UMUDGA was added on 29 September, in addition to that initial total.
No download or measurement was refreshed in this documentation task. Raw sources
are developer-local, excluded from Git and unnecessary for the bundled demo.
Public preset readiness means availability, not reliable positive detection or
per-query truth. [Report currency](STREAMING_VALIDATION.md) qualifies all metrics.

## Sources saved locally

**Independent-source review, 14 October 2026:**
[metadata-only findings](ENCRYPTED_VALIDATION_SOURCE_REVIEW.md) document eight
unqualified validation leads and exact missing evidence. No additional raw dataset
or annotation values were downloaded. The ARES catalogue/licence-document metadata
is saved, but no source is preassigned or integrated; training remains BLOCKED.

**Coverage/partition freeze, 14 October 2026:**
[source/family-aware plan](ENCRYPTED_COVERAGE_PARTITION_PLAN.md) binds the qualified
TQH cohort to training-development without fitting. All related TQH sources stay
outside primary validation/final reserve. Future independent TLS framework/source
roles and browser/update/API/ordinary application controls are explicitly missing;
no counts, identities or qualification are invented. The old sample-aware research
split and source hashes remain intact. Training remains BLOCKED; no new acquisition
or dataset values were examined during this design stage.

**Development-only raw TLS addition, 13 October 2026:**
[TQH-C2 v1.2.2](https://zenodo.org/records/22732327), CC BY 4.0, Deokjo Jeon and
DongGue Park. One original Ethernet PCAP member, 104,730,430 bytes, SHA256
`1846da399b88ebfa16ddbd89bfbc161bb29125cfa5bc87faa572659b1e96ecb1`, is saved at
`data/raw/tqh-c2-development/D_i300_j30-D_0648.pcap`, with selected UID/UTC labels.
Complete member CRC and corrected publisher label-archive SHA256 pass; the whole
PCAP archive hash is unverified because only one complete member was fetched.
Native ClientHellos qualify **115 controlled Merlin C2 + 467 benign TLS sessions**.
One framework/environment and one positive JA3 cannot support generalization;
publisher partial gate's H3 balance fails. **Training remains blocked**. See
[acquisition/qualification](TLS_CAPTURE_ACQUISITION.md) for exact hashes, timing,
roles and limitations. Also acquired three CIRA DoH archives (576,777,008 bytes),
but selected SLL captures, ambiguous baseline intent and unverified CSV timezone
fail qualification; incomplete benign PCAP downloads remain excluded. Neither
source is integrated into runtime or reserved evaluation.

**Development-only addition, 12 October 2026:** one public MS JOY derivative from
Carlos A. Novo and colleagues' [TLS research](https://github.com/CarlosANovo/extending12to13),
`data/raw/encrypted-ms-development/capture_getuid.joy.gz` (4,635,278 bytes, local
SHA256 `d18bad45afd5c62ee848a8db04e0216d22799a3824a58a6a9fd117f45a77ebc3`).
Official OSF API licence: CC BY 4.0. Schema inspection only: 17,421 flow records,
no explicit session labels, no raw-PCAP claim or runtime integration. Source
provenance is controlled Meterpreter/TLS; no blanket malicious-flow label is
assigned. See [split/source decision](ENCRYPTED_SPLIT_DESIGN.md) and its dated
source metadata/inspection evidence. No executable samples were acquired.

- **CIC-IDS2017:** complete `MachineLearningCSV.zip`, 235.1 MB, all eight capture
  CSVs. Publisher MD5 verified. Archive contains 2,830,743 labelled rows including
  benign, DoS/DDoS, port scans, botnet and other attacks. This particular CSV release
  omits IP tuples and event timestamps. It cannot be converted to a genuine packet
  stream without inventing observations. Manifest: `data/cicids2017_manifest.json`.
  Source: https://www.unb.ca/cic/datasets/ids-2017.html
- **CIC-DDoS2019:** first 100,000 complete rows of `03-11/UDPLag.csv` from the
  official archive, saved as `data/raw/cicddos2019/first-csv-100000-rows.csv`.
  47.6 MB of CSV, 6.2 MB compressed transfer. Labels in this prefix are 99,895 UDP
  and 105 BENIGN. This is a deliberate subset, not the full multi-gigabyte release.
  Full ZIP CRC is unavailable for a partial member; the local SHA256 is recorded.
  Manifest: `data/cicddos2019_manifest.json`.
  Source: https://www.unb.ca/cic/datasets/ddos-2019.html
- **CIC-Bell-DNS-EXF-2021:** complete benign PCAP archive plus the `Attacks.zip`
  archive from each light/heavy category, 55.9 MB downloaded. Extracted 14 PCAPs;
  the existing parser and streaming detector processed **609,583 IP packets**.
  Mixed attack captures are not treated as uniformly malicious. Source ZIP members
  were read to completion, verifying their CRC; local file SHA256 hashes are saved.
  Manifests: `data/cicdns2021_manifest.json`, `data/dns_capture_catalog.json`.
  Source: https://www.unb.ca/cic/datasets/dns-exf-2021.html
- **UMUDGA v1 original subset:** seven complete 1,000-domain lists: legitimate reference, banjori,
  corebot, dircrypt, matsnu, necurs and ramnit. Raw strings, not precomputed features.
  All seven files match publisher SHA256 values. MIT-licensed release by Mattia Zago,
  Manuel Gil Perez and Gregorio Martinez Perez, DOI 10.17632/y8ph45msv8.1.
  Manifest: `data/umudga_manifest.json`.
  Source: https://data.mendeley.com/datasets/y8ph45msv8/1
- **UMUDGA expanded subset (29 September):** 50 complete 10,000-domain variant
  lists plus a 100,000-domain legitimate reference, **11,451,100 additional bytes**.
  Publisher size/SHA256 verified for all 51 text files. Stored separately under
  `data/raw/umudga-expanded/`; manifest `data/umudga_expanded_manifest.json`.
  Same MIT-licensed release and authors. No executable generator code is included.
- **Annotated Encrypted Network Traffic Dataset v1.0.0:** all three public Parquet
  archives (`malware`, `winapps`, `soho`) and schema/README, 74.4 MB. Publisher MD5
  values verified. Author Ondrej Rysavy; CC BY 4.0 confirmed in the release API;
  DOI 10.5281/zenodo.18336960. The scanned files contain 29,526 Windows-application
  rows, 1,405,079 malware-collection rows, and 108,036 SOHO rows. The actual malware
  row count differs from the publisher README summary; reports use the observed
  count. Malware collection includes ambiguous/system traffic: only family-labelled
  rows without a system-service annotation enter the positive supervised class.
  SOHO is unlabelled, not automatically benign. Manifest: `data/public_manifest.json`.
  Source: https://zenodo.org/records/18336960

CIC registration was completed using the user-provided details. Contact information
is not saved in project configuration, source files or manifests. CIC datasets must
be cited according to their publisher guidance: https://www.unb.ca/cic/datasets/

## Integrated use

The dashboard scenario selector includes real DNS benign/light/heavy capture replay
and a UMUDGA DNS lab wrapper. Public presets replay up to 2,000 observations; the
DNS evaluation used complete captures. `GET /api/datasets` reports preset readiness.
PCAP observations retain original packet timestamps and tuples. The UMUDGA wrapper
uses public domain strings but **simulated** timestamps, addresses and packet sizes;
it is not evidence of real beaconing, throughput or source behavior.

Synthetic fixtures continue to cover controlled cases and regression tests. Public
sources provide external replay checks and separate research models. Unlike schemas
are not concatenated, and complete-flow totals are never backdated to the first packet.
There is no connection to monitored hosts, probing, mitigation or payload decryption.
Downloading research data is an offline administrative step outside the ingest path.

Optional research commands (downloaded inputs required; not setup/demo steps):

```powershell
.venv/Scripts/python.exe -m pip install '.[datasets]'
.venv/Scripts/python.exe -m datasets.evaluate_ddos
.venv/Scripts/python.exe -m datasets.prepare_dns
.venv/Scripts/python.exe -m datasets.validate_streaming
.venv/Scripts/python.exe -m replay.cli data/raw/cicdns2021/pcaps/light/light_audio.pcap
```

`datasets.download` and `datasets.download_domains` fetch the TLS release and DGA
subset. The CIC download modules read a JSON object from stdin containing
`first_name`, `last_name`, `email`, `institution`, `job_title`, `country`. Supply those
in memory or from a private input file; do not commit personal details. The DDoS
downloader deliberately closes the transfer after its documented prefix. Its source
ZIP is not saved or misrepresented as complete. DNS downloads include PCAPs of
transfers named `*_exe.pcap`; these are traffic captures, not executable downloads.

DGA training needs the `dga-training` extra; TLS/CIC research training also needs
research libraries and the raw sources. Training writes candidates/reports and
must be explicitly scoped. Capture/domain evaluation commands overwrite reports.
None was run for this audit; public training is not a frozen-demo prerequisite.

## Model results and limits

**Encrypted-data feasibility follow-up, 12 October 2026:** the
[development audit](ENCRYPTED_DATA_FEASIBILITY.md) verifies local TLS provenance and
finds countable ClientHello fields, but also 544 malware sample IDs shared across
historical training/validation (annotation-only routing; historical test features
unread). Family-group disjointness does not establish sample independence. Saved
TLS metrics remain historical and unpromoted. Metadata rows lack causal packet /
handshake timing, labels are sample-associated, and the clipped benign PCAPs expose
no parsed ClientHello. No source, model or old report was changed.

The original runtime pipeline was evaluated on all seven domain lists and 14 PCAPs,
exposing 91.2% false positives on the isolated legitimate-domain reference. The
29 September conservative-guard comparison reduced that sample's FPR to zero while reducing DGA
recall to 7.97%. See
[Streaming validation](STREAMING_VALIDATION.md) and `ml/streaming_validation.json`
for reproduction, packet-rate measurements, visibility gaps and next actions.

Separate public-data research candidates have been fitted and evaluated, with portable
JSON artifacts and SHA256 sidecars in `ml/`. They **do not replace the streaming
model**. The current dashboard still uses the synthetic-trained hybrid pipeline;
public replay is an external test of that pipeline.

- DGA character-bigram NB: train banjori/corebot/dircrypt, validate on matsnu, test
  necurs/ramnit. Legitimate domains split by stable domain hash; exact overlap with
  training positives excluded. At the fixed 0.99 threshold, matsnu recall is **0%**,
  test recall **27.8%**. The predeclared promotion gate failed. This exposes weak
  generalization to word-based DGA, rather than concealing it with a row shuffle.
  Report: `ml/public_dga_evaluation.json`.
- TLS Gaussian NB: forward byte/packet counts, duration, forward TLS record lengths,
  client cipher/extension counts. No reverse fields, IP addresses, annotations, or
  fabricated packet timings. Malware-family/application groups are disjoint across
  train/validation/test. Validation false-positive rate **20.1%**, test **2.39%**;
  this instability and complete-session feature availability preclude production
  promotion. Report: `ml/public_tls_evaluation.json`.
- CIC completed-flow Gaussian NB: Monday/Wednesday training, Tuesday benign-only
  validation, Friday DDoS test; sampled training and exact-vector deduplication.
  Friday recall **6.94%**, false-positive rate **13.62%**. External DDoS2019 UDP
  prefix recall **0%**, false-positive rate **10.59%** on only 85 unique benign
  vectors. These failures require a stronger baseline and broader experiments.
  Reports: `ml/public_cic_evaluation.json`, `ml/public_ddos_evaluation.json`.
- Original streaming baseline on real DNS PCAP: 1,671 alerts across the two benign
  reference captures, including 1,599 DGA alerts. These are false-positive candidates;
  deduplicated alert counts are not per-flow FPR. Mixed attack captures have no
  trustworthy per-flow labels in this download, so recall is not claimed. The current
  long-TXT tunnelling rule did not fire on these captures. Report:
  `ml/public_dns_evaluation.json`.

The 29 September runtime follow-up adds a conservative DGA corroboration guard and
fixes DNS/TCP framing and compressed-name parsing. The before/after report is in
[Streaming validation](STREAMING_VALIDATION.md), with machine-readable original
results in `ml/streaming_validation_baseline.json` and later historical results in
`ml/streaming_validation.json`. Reduced noise comes with substantially lower DGA
recall; no research candidate was promoted. These already inspected sources are
regression inputs, not independent holdouts.

Confidence remains an uncalibrated posterior or heuristic strength. None of these
results establishes deployment accuracy. Public-data next work should focus on
benign DNS diversity, realistic tunnelling formats, capture-aware supervised models,
and causal features shared between training and runtime, followed by calibration and
throughput checks. TLS record lengths must remain distinct from IP packet sizes.

The expanded DGA experiment fits a portable lexical classifier with family-grouped
splits and benign-capture hard negatives. Development comparison recall improves
to 76.77% with 1.68% FPR, but the 80% recall gate and separate DNS-reference FPR
gate fail, so it remains disabled. See [DGA development](DGA_DETECTION.md) and
`ml/dga_v2_evaluation.json`. Test-family results were inspected during development;
these comparisons are not an untouched final holdout. The original streaming guard
continues serving the dashboard.

The later weighted candidate is separate and disabled: public-domain validation
TP74,242/TN14,958/FP278/FN5,758, recall92.80%, precision99.63%, FPR1.82%. Reserved
domain and separate benign-DNS sets are unavailable, so final promotion is blocked.
See [weighted experiment](DGA_WEIGHTED_CANDIDATE.md). DGA family/file variants were
grouped and scored-label overlap checked, but already inspected cohorts cannot
be renamed final holdouts. Independent final gates remain unchanged.

Public DNS captures have96-byte snaplen and mostly clipped attack-associated
questions; complete QNAME/QTYPE and trustworthy session labels are missing.
LLMNR5355 is distinct from DNS53. The small controlled A/AAAA/TXT/NULL tunnel
candidate has no independent real-tool evaluation and remains disabled. Publisher
benign references inform qualitative alert checks, not per-session FPR estimates.

The [per-threat matrix](MODEL_AND_VALIDATION.md) distinguishes all active heuristics
from disabled candidates. Original dataset manifests, model artifacts and saved
evaluation JSON retain their hashes. The [audit](verification/documentation-audit.json)
records provenance; historical public reports are not final-runtime scores.

## Source still unavailable for integration

**IoT-23 individual mirrors were not downloaded.** Automatic approval review rejected
that action because the selected capture README explicitly requires Stratosphere Lab
authorization. A separately published CC BY licence was insufficient to resolve that
restriction in the review. No mirror workaround was attempted. Lab permission is
needed before revisiting those selected files. The remaining five sources above are
downloaded and usable independently.

## Encrypted source follow-up — 13 October 2026

[Source capability report](ENCRYPTED_SOURCE_FOLLOWUP.md) refines the existing
development-only MS JOY inspection. The public MS listing has 103 files across
21 metadata pages and no raw `.pcap`/`.pcapng`/`.cap` file. No additional dataset
was downloaded in this follow-up. Runtime-compatible raw chronology, ClientHello
position and per-session truth remain unverified. JOY payload-byte summaries
must not be substituted for IP-packet bytes. Original CIC DoH remains a narrower
encrypted-tunnel source with a publisher download-page error; the BCCC balanced
CSV derivative uses SMOTE and is not a genuine untouched raw evaluation cohort.
Existing source hash, development-only role and reserved-data protections remain.
# DGA acquisition update — 14 October 2026

[Acquisition report](DGA_SOURCE_ACQUISITION.md): downloaded the pinned DRIFT 2025
raw-domain DGA and benign Parquet files (both publisher SHA256 verified), plus
Mendeley DNS-domain reference v5 (local SHA256 recorded; publisher checksum
unavailable). Three files total 369,005,656 bytes under ignored
`data/raw/dga-evaluation-intake/`. They remain quarantined, not runtime presets or
approved final evaluation data. Algorithm aliases, legitimate service strata and
independent benign-DNS truth/counts remain unresolved; no training/scoring/promotion.

