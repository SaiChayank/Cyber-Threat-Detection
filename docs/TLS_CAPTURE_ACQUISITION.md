# Raw TLS capture acquisition and qualification

13 October 2026. **Acquisition Definition of Done: PASS, limited to one controlled
development cohort. Encrypted-model training: BLOCKED.** All failed candidates
remain disabled. No model fitting, prediction, detector change, activation,
reserved evaluation, replay or alert generation occurred.

## Inspected and frozen scope

Inspected the existing encrypted feasibility, source and split diagnoses, completion
plan, native PCAP reader/ClientHello parser, publisher source documentation, fixed
capture selections and matching annotations. The
[qualification protocol](verification/tls-capture-acquisition-20261013/PROTOCOL.md)
was written before reading new packet values. Each source's selection was recorded
before its content inspection. Acquisition uses ordinary publisher downloads,
outside the monitored traffic path. No executable samples, TLS keys, probes,
endpoint handshakes or decryption were introduced.

The source qualification gate requires original classic Ethernet PCAP supported by
the current reader, explicit session intent joined to tuple and capture time, and
a complete ClientHello with its original packet index/timestamp. These are data
provenance/visibility checks, not classifier acceptance criteria or measured
accuracy. No gate was relaxed after inspection.

## Qualified source: TQH-C2 v1.2.2

Primary sources: [publisher record](https://zenodo.org/records/22732327) and
[versioned README](https://zenodo.org/records/22732327/files/README_v122.md?download=1).
Attribution: Deokjo Jeon and DongGue Park, *TQH-C2*, v1.2.2, CC BY 4.0. The locally
saved README SHA256 is
`eed4c1f74bdb5f452389eee141e8a3bc0c530657ffc6f71034a07b6090966f07`.

The [selection](verification/tls-capture-acquisition-20261013/TQH_SELECTION.md)
chose Testbed D, Merlin HTTP/2 over TLS, then exactly one PCAP by smallest archive
compressed size with lexical tie-break. No prediction or traffic feature influenced
selection. Original member: `D_i300_j30/D_0648.pcap`. Matching cell:
`TQHC2-202607-D-i300-j30`; recorded interval 300 seconds, jitter 30%.

Local raw file: `data/raw/tqh-c2-development/D_i300_j30-D_0648.pcap`.
It is **104,730,430 bytes**, SHA256
`1846da399b88ebfa16ddbd89bfbc161bb29125cfa5bc87faa572659b1e96ecb1`.
The **complete member** was fetched through verified HTTP byte ranges; decompressed
size and ZIP-member CRC passed. The whole 1.8GB source PCAP archive was not fetched,
so its archive SHA256 is **not locally verified**. Original bytes were retained:
classic v2.4 PCAP, Ethernet linktype 1, snaplen 262,144, no format conversion.

The complete `TQH-C2_labels_D.zip`, **2,238,688 bytes**, has SHA256
`10d8e4ef6edd5416ae2d866d93e6165d174049c85a1ffa6861958784cabc2dc2`,
matching the corrected v1.2.2 publisher value. All archive member CRCs passed.
Only this cell's `conn.log`, `ssl.log`, `labeled.jsonl`, `manifest.json`, `gate.json`
and `labeled.jsonl.counts.json` were extracted/read for qualification. Their exact
hashes are in the [input manifest](verification/tls-capture-acquisition-20261013/tqh-input-manifest.json).
No other cell's packet/label values, QUIC logs, publisher code or features were used.

Observed results in the [frozen release report](verification/tls-capture-acquisition-20261013/tqh-qualification-release.json):

- **68,331 raw packets**, zero clipped packets; 66,544 native parsed IP packets
  and 1,787 non-IP/unparsed packets. All raw timestamps lie in the explicit UTC
  run, `2026-07-23T06:47:11.360455Z` to `2026-07-23T07:31:29.595469Z`.
- All **662 source labels** match a connection UID, endpoint tuple and source time
  values: 115 `malicious_c2`, 547 `benign`; zero label-integrity issues.
- **582 unique labelled TCP sessions** have complete native ClientHellos:
  **115 controlled C2 + 467 benign**. Each matches the same UID's source JA3.
  The remaining 80 labels are 57 UDP and 23 ICMP, not missing TLS handshakes.
- Exact raw ClientHello packet indices span 12–68,285. Each observation's integer
  nanosecond timestamp and index are preserved; the PCAP clock has microsecond
  resolution. Delay after source connection start: 0.209–330.006 ms, median
  6.623 ms. These are handshake positions, **not detection or API latency**.
- **267 adjacent timestamp reversals** and **zero exact frame-and-timestamp
  duplicates**. Raw order/indices were preserved. TCP retransmission/overlap is
  not separately characterized; zero exact duplicates does not prove none exist.
- All five frozen acquisition gates pass. An independent read-only review
  reproduced the report and verified input hashes.

The session truth is publisher-controlled lab intent: documented victims talking
to the specified C2 endpoint are labelled C2, and concurrent externally directed
traffic is labelled benign under the source's controlled setup. Labels are joined
to actual sessions; neither a whole archive nor all infected-host traffic is
blanket-labelled malicious. This establishes **controlled encrypted C2**, not
independently proven compromise or generic encrypted-malware truth.

Source label/connection numeric values are compared by exact binary64 equality,
without a numerical tolerance. Raw timestamp-to-connection interval association
uses a **±1 microsecond margin** for the two exports' representations; it is not
exact equality of raw and annotation timestamps. Ambiguous joins stay excluded.

## Acquisition limits that still block training

The publisher's cell gate reports `mode=partial`, status PASS, but **H3 balance
failed**: positive flow fraction 0.1737, outside that publisher's 0.4–0.6 target.
This failure is preserved, not reclassified. Publisher partial eligibility is
different from our frozen acquisition gate and from any model promotion gate.

All 115 C2 sessions share JA3 `3f9b835b5a7e7c2c3eb40390a93a3bf9`.
Benign sessions have two disjoint JA3s (410 and 57 sessions). Fingerprint,
internal/external endpoint role, port and environment can trivially separate this
lab. UID, labels, addresses, source/capture identity, filenames, service/history
annotations and scenario configuration are provenance, never predictive inputs.
A classifier on this single cell could learn the environment rather than intent.

Only one framework, run and source environment is inspected. Independent malware
families and verified browser/update/API hard controls are not yet established.
Publisher collection commit is `UNKNOWN(no-git)`. Raw SHA256/label checks prove
file integrity and annotation consistency, not independent forensic confirmation
of every publisher assertion. Unsupported IPv6/reassembled-only ClientHellos and
raw QUIC handshakes are outside this qualification; no new parser support was added.

All inspected captures/sessions are **development-only**. Consulted Testbed D
influenced source/visibility design and must not later be called untouched final
evaluation. No train/validation/evaluation split is authorized by this acquisition
result; existing frozen reserved sets remain unread. Model training remains blocked
pending suitable independent coverage and a frozen leakage-safe evaluation design.

## Excluded source: CIRA-CIC-DoHBrw2020

Primary source: [CIC dataset description](https://www.unb.ca/cic/datasets/dohbrw-2020.html).
Use/republication attribution recorded in
[source provenance](verification/tls-capture-acquisition-20261013/source-provenance.json):
MontazeriShatoori, Davidson, Kaur and Lashkari, *Detection of DoH Tunnels using
Time-series Classification of Encrypted Traffic*, IEEE CyberSciTech 2020,
DOI 10.1109/DASC-PICom-CBDCom-CyberSciTech49142.2020.00026, plus DoHMeter citation.

Three full archives, **576,777,008 bytes** combined, were obtained and verified:
`MaliciousDoH-dnscat2-Pcap-001-600.zip`, `MaliciousDoH-CSVs.zip` and
`BenignDoH-NonDoH-CSVs.zip`. Local SHA256 values and all-member CRC results are in
[acquisition summary](verification/tls-capture-acquisition-20261013/acquisition-summary.json).
Only the first three sorted PCAPs and matching CSVs were inspected. Original
colon-containing member names were made Windows-safe locally without changing
file bytes; [manifest](verification/tls-capture-acquisition-20261013/capture-manifest.json)
retains original names and all selected file hashes.

The three raw sessions expose complete ClientHellos at packet **4** in each,
about 15.3–15.4 ms after its first packet, but **do not qualify**:

- Original captures use Linux cooked linktype **113**, unsupported by the current
  Ethernet reader. Diagnostic SLL inspection never synthesizes Ethernet bytes or
  changes runtime support.
- The selected `default-baseline` filenames do not establish explicit malicious
  session intent. CSV `DoH=True` means endpoint-based DoH classification, not
  maliciousness. Fourteen CSV flow segments are not 14 independent TLS sessions.
- CSV times omit the UTC offset; a three-hour difference can be inferred from
  tuple/window alignment and publisher local-time export code, but the collector's
  timezone is not independently verified. No inferred timing is promoted to truth.

The Firefox/AdGuard benign PCAP download failed twice when the remote connection
closed. The original 358,612,992-byte partial and new 176,463,136-byte partial are
preserved/excluded. The publisher ignores byte-range requests, so no false resume
or complete-file claim is made. The zero-byte old annotation partial is also
preserved/excluded. Benign CSV contents were not evaluated. CIRA qualification
remains FAIL regardless of its archive category names.

## Minimal diagnostic code, corrections and tests

New offline helpers only:

- `datasets/acquire_tls_source.py`: bounded ZIP catalogue/member transfer, original
  bytes, size/CRC/hash checks and exclusive output; uses existing `httpx` dependency.
- `datasets/qualify_tls_capture.py`: original PCAP/CSV visibility and timing
  diagnosis; SLL support is diagnostic only and never passes the runtime gate.
- `datasets/qualify_tqh_tls.py`: source UID/tuple/UTC/native ClientHello verification
  and exact-duplicate reporting. Imports existing reader/parser; no classifier,
  TrafficEvent generation, capture transformation, database or replay.

Initial TQH diagnostic reports had false source mismatches caused by comparing
decimal spelling after JSON binary64 re-export, treating unavailable duration as
zero and comparing string versus integer pseudoports. These were diagnostic bugs:
exact binary64 equivalence, missing-duration preservation and numeric port
normalization correct them. Early reports (`tqh-qualification.json`,
`tqh-qualification-final.json`) remain preserved; the release report is current.
No label, threshold, gate, feature definition or candidate was modified.

Exact regression coverage in `tests/test_tls_capture_qualification.py`,
`tests/test_tls_source_acquisition.py` and `tests/test_tqh_tls_qualification.py`
includes timestamps/packet positions, truncation/clipping, complete record
boundaries, unsupported runtime linktype, DoH-only label exclusion, invalid CSV
duration, ignored/incomplete/stale HTTP ranges, CRC failure, original raw bytes,
UID duplicates/contradictions/ambiguity, JSON numeric round-trips, unavailable
duration and retained duplicate packet observations. **25 acquisition tests pass;
with 19 existing encrypted-data/split regressions, 44 tests pass in 3.46s.** The
[test log](verification/tls-capture-acquisition-20261013/tests.txt) and final integrity
evidence are recorded alongside the report. No shared runtime code changed, so no new frontend
build or production throughput/accuracy measurement is claimed here.

## Reproduction and freeze

From the repository root, with the documented Python environment and local raw
files, use new output paths (commands refuse existing outputs):

```powershell
.venv/Scripts/python.exe -B -m datasets.qualify_tqh_tls --manifest docs/verification/tls-capture-acquisition-20261013/tqh-input-manifest.json --output tqh-reproduced.json
.venv/Scripts/python.exe -B -m datasets.qualify_tls_capture --manifest docs/verification/tls-capture-acquisition-20261013/capture-manifest.json --output cira-reproduced.json
.venv/Scripts/python.exe -B -m pytest tests/test_tls_capture_qualification.py tests/test_tls_source_acquisition.py tests/test_tqh_tls_qualification.py tests/test_encrypted_data_audit.py tests/test_encrypted_split_design.py -q -p no:cacheprovider
```

Raw data is developer-local under `data/raw/`, ignored by Git. Small reports,
protocols, source attribution and hashes provide provenance. Publisher downloads
are reproducible via the pinned URLs; source availability is external, and CIC
still requires authorized registration. Private session cookies remain outside
publishable evidence. Existing alert history, detector/frontend code, model bytes,
prior data and reserved evidence are protected by the initial/final integrity check.
All **344 protected files** retain their initial SHA256 values, including the alert
database and model artifacts. The public TLS candidate remains disabled; no files
are staged. [Final integrity evidence](verification/tls-capture-acquisition-20261013/final-integrity.json)
and [freeze manifest](verification/tls-capture-acquisition-20261013/freeze.json)
pin this result. Existing unrelated pending work is preserved.

Before this task: zero raw cohorts qualified by this protocol. After: **one**
cohort, **582** labelled native TLS sessions; this is an acquisition change only,
not an accuracy improvement. Freeze these tools/tests, source selection, gates,
hashes, qualification report and limitations. The failed public TLS artifact's
`production_enabled=false` remains unchanged; the baseline encrypted detector is
still experimental. Final SIH release readiness is not changed by acquisition.

**Next incomplete task:** freeze a source/family-aware coverage and partition plan
that excludes this consulted cohort from untouched evaluation and specifies the
independent frameworks and benign application controls still needed. Do not train
or tune until that data prerequisite and evaluation design pass. This acquisition
task ends here.
