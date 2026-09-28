# External streaming validation — 28 September 2026

The current detector runs successfully, but its external detection quality does
not yet meet a defensible deployment standard. This validation establishes a
baseline before any model or threshold changes.

Run `.venv/Scripts/python.exe -m datasets.validate_streaming` from the repository
root. Results are saved to `ml/streaming_validation.json`. The command reads local
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

All seven domain lists and 14 captures have now been inspected. Reusing them
after changes is a regression/comparison experiment, not an untouched holdout.
Credible generalization claims need new independent data or an explicitly
documented evaluation design. The current validation changes no deployed model
and promotes no public-data research candidate.

Verification: all 34 existing and validation-metric tests pass; the frontend
production build also passes. Functional checks do not establish detection accuracy.
