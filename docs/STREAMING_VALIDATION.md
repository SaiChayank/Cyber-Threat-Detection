# External streaming validation

The expanded DGA candidate is documented in [DGA development](DGA_DETECTION.md).
It remains disabled after failing its gates. This streaming report checks the
active conservative guard and records the inactive candidate's hash/status; it
must not be confused with the candidate's development comparison metrics.

## Follow-up — 29 September 2026

Focused changes preserve the existing pipeline, model weights, API and frontend:

- Every DGA alert now requires the existing entropy/bigram rule, including a
  model-only prediction. Length >=20 is measured on the first label, consistently
  with the other lexical features. A readable suffix cannot satisfy this guard.
- The long TXT/NULL rule likewise measures first-label length >=50.
- DNS/TCP skips the two-byte message length and parses a complete first message
  within the packet. Partial TCP messages are left unparsed; no reassembly is added.
- DNS name compression is decoded with cycle, truncation, label, expanded-length
  and 128-step traversal checks. Invalid names no longer produce partial evidence.

The unchanged model SHA256 is
`4d8e08323374535789e21f9f7cd1ee3f1c84b663ce555e67bb4ced57c95e8010`.
The current report also records hashes of the pipeline, extractor and parser source.
No dependency, model promotion, source query or payload decryption was added.

### DGA comparison on the same inspected domain lists

| Measure | Original baseline | Conservative guard |
| --- | ---: | ---: |
| Legitimate domains evaluated | 1,000 | 1,000 |
| Legitimate false positives | 912 | 0 |
| Legitimate false-positive rate | 91.2% | 0% |
| DGA true positives | 5,996 | 478 |
| DGA false negatives | 0 | 5,518 |
| DGA recall | 100% | 7.97% |
| DGA precision in this sample | 86.80% | 100% |

**This fixes unsupported alert noise, not DGA coverage.** Most short and word-based
DGA families remain undetected. Zero false positives applies only to this limited
legitimate reference list; it does not establish deployment FPR. The same previously
inspected data is reused, so this is regression comparison, not an untouched holdout
or a promotion-quality evaluation. Addresses and timing remain explicitly simulated.

### Capture comparison and DNS visibility

All 14 captures still contribute 609,583 parsed IP packets. Across the two benign
references, DGA alerts fall from 1,599 to 25; total alerts fall from 1,671 to 97.
The remaining counts are 55 DDoS, 13 C2 and four reconnaissance alerts. These counts
remain deduplicated false-positive candidates, not per-flow FPR.

The final capture run takes 120.80 seconds, about 5,046 parsed IP packets/sec for
parsing, metadata adaptation, features and inference. It excludes hashing, replay
pacing, SQLite, HTTP and UI, and must not be compared directly with flow/event rates.

There are still **zero DNS-tunnelling alerts** in the downloaded captures. The
largest observed DNS/53 name is 36 characters; no long TXT/NULL first label reaches
the rule. Separate packet inspection of `heavy_text.pcap` found 97,017 UDP/5355
packets, including 68,703 parseable first questions: 66,685 PTR, 1,912 ANY and 106 A.
Common names are reverse lookups such as `252.0.0.224.in-addr.arpa`. This is consistent
with local name-resolution traffic, not evidence that the tunnel detector should
flag port 5355. LLMNR traffic remains distinct from DNS attack inputs.

Controlled UDP and complete-message TCP captures with a long TXT question do
produce a DNS-tunnelling alert through the parser, metadata adapter, API upload,
asynchronous replay and SQLite. This verifies that the implemented path works; it
does not establish recall on the public captures or justify lowering thresholds.

Verification: **59 tests pass**, including all seven threat scenarios, common-domain
regressions, malformed/compressed DNS and DNS/TCP capture upload. The unchanged
website's same-origin health, telemetry and benchmark routes respond successfully.
The refreshed 20,000-event core + SQLite benchmark sustains **2,827 metadata
events/sec** (target 2,000), with processing/persistence p95 **1.13 ms** (target
50 ms). It excludes capture, HTTP, SSE and browser rendering. Original dashboard
history is preserved; tests and benchmarking use separate databases.

Remaining priority: train and independently evaluate a stronger lexical DGA model,
obtain labelled tunnel traffic with visible DNS metadata, and validate other threat
classes before calibration or deployment claims. Authentication and broader capture
support remain separate deployment work.

## Original baseline — 28 September 2026

The current detector runs successfully, but its external detection quality does
not yet meet a defensible deployment standard. This validation establishes a
baseline before any model or threshold changes.

Run `.venv/Scripts/python.exe -m datasets.validate_streaming` from the repository
root for current results in `ml/streaming_validation.json`. The original run below
is retained in `ml/streaming_validation_baseline.json`. The command reads local
inputs, checks PCAP SHA256 values against the capture catalog, and records the
runtime model hash. It does not train a model, modify captures, write dashboard
alerts, contact monitored hosts, or decrypt encrypted payloads.

## Runtime DGA detector

Seven UMUDGA lists supplied 6,996 unique within-list domain decisions: 5,996 DGA
domains and 1,000 legitimate domains. Duplicate strings within lists are excluded;
legitimate strings overlapping attack lists would also be excluded. Positive
domains appearing in different families may contribute once per family.

- True positives: 5,996; false negatives: 0.
- False positives: 912; true negatives: 88.
- Recall: 100%; precision: 86.80%; legitimate-domain false-positive rate: 91.2%.
- False-positive examples include `google.com`, `youtube.com`, `facebook.com`,
  `baidu.com`, and `wikipedia.org`.

These results evaluate the deployed synthetic-trained hybrid detector, rather
than the separate public-domain research candidate. High recall is not useful
when almost all legitimate inputs also trigger an alert.

Domain names are real; addresses, packet sizes and times are simulated. Events
are separated by 61 simulated seconds to isolate lexical decisions from prior
peer history and 30-second alert suppression. Metrics measure whether a DGA
alert is emitted for a domain, not accuracy on genuine network flows. Other
emitted threat classes do not enter this DGA confusion matrix. Zero-denominator
metrics are stored as null, rather than reported as perfect accuracy.

## Full passive PCAP replay

All 14 prepared CIC-Bell-DNS-EXF captures were processed, totaling **609,583 parsed
IP packets**. Each capture starts with a fresh pipeline. Original packet times
and tuples are preserved; processing remains incremental.

The two benign-reference captures produced **1,671 alerts**, including 1,599 DGA
alerts, 13 C2 alerts, 55 DDoS alerts and four reconnaissance alerts. These are
false-positive candidates. Alert suppression and missing flow-level truth mean
these counts must not be converted into a per-flow false-positive rate.

No DNS-tunnelling alerts were emitted. The current adapter only attempts DNS
sidecars on port 53. Parsed DNS observations contained no first label of at least
50 characters with TXT type, so the current long-TXT rule had no matching input.
The largest parsed complete DNS name was 36 characters. UDP destination port
5355 dominated the attack-category captures, indicating a visibility question
that needs capture inspection; this alone does not establish where the attack
traffic resides. Simply lowering a TXT threshold would not resolve this gap.

Attack-category PCAPs contain mixed traffic and lack trustworthy per-flow attack
labels in the downloaded files. Their alert counts do not establish recall,
precision, or successful exfiltration detection. Similarly, encrypted-malware
alerts in these captures do not establish the presence of malware.

Measured parsing, event adaptation, feature extraction and inference took
108.76 seconds across all captures, approximately **5,605 parsed IP packets/sec**
in aggregate. Per-capture core-processing p95 ranged from 0.166 to 1.659 ms.
These are measurements of one local unpaced run, excluding integrity hashing,
SQLite persistence, HTTP, replay pacing and dashboard delivery. They are not
an end-to-end flow-throughput or alert-delivery benchmark.

## Separate completed-flow candidates

The CIC-DDoS2019 candidate evaluation was rerun against the existing 100,000-row
UDP prefix. After exact-vector deduplication, it missed all 43,145 evaluated
attack vectors and incorrectly flagged nine of 85 benign vectors: 0% recall and
10.59% false-positive rate. This is a completed-flow research baseline, not the
deployed streaming detector. See `ml/public_ddos_evaluation.json`.

Earlier CIC-IDS2017, TLS and DGA candidate reports remain separate and were not
retrained during this validation. Their definitions, splits and failed promotion
gates are described in [Dataset integration](DATASETS.md).

## Required follow-up

1. Fix DGA discrimination first: use diverse legitimate domains, inspect shared
   training/runtime lexical features, and compare rules with supervised baselines.
   Threshold changes alone must not conceal missed attacks or false positives.
2. Inspect capture protocol visibility and DNS record formats before expanding
   tunnelling features. Keep extraction passive and metadata-only.
3. Improve completed-flow DDoS baselines separately; do not invent packet arrival
   times from CSVs or backdate complete-session totals.
4. Collect trustworthy independent labels for C2, scanning, encrypted-session
   suspicion and exfiltration. Synthetic demonstrations remain regression checks.
5. Reevaluate, calibrate scores, and measure persistence/API alert latency after
   a candidate meets a predefined detection-quality gate.

All seven domain lists and 14 captures were inspected in the original run. Reusing them
after changes is a regression/comparison experiment, not an untouched holdout.
Credible generalization claims need new independent data or an explicitly
documented evaluation design. The original validation changed no deployed model
and promoted no public-data research candidate; the follow-up keeps model weights
unchanged but adds the conservative alert guard described above.

Verification: all 34 existing and validation-metric tests pass; the frontend
production build also passes. Functional checks do not establish detection accuracy.
