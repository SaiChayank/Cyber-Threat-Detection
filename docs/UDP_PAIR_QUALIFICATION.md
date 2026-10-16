# T21 — UDP development-pair source qualification

16 October 2026; inspected baseline `588d2cc`.
**Pair qualification: BLOCKED / NOT QUALIFIED. UDP quality remains UNRESOLVED.**
No detector experiment was implemented. Protocol preparation and bounded source
screening are complete; the requested qualified pair's Definition of Done is not.

## Inspected and frozen

Reviewed T20's collision/false-positive evidence, current UDP validation protocol,
completion plans, dataset documentation and existing CIC-DDoS2019 manifest.
Existing local CSV metadata cannot supply causal raw packets; mixed DNS captures
do not establish UDP-flood truth. No existing raw dataset values were reread.

[Qualification protocol](UDP_PAIR_QUALIFICATION_PROTOCOL.md) was frozen before
new capture values. Its hash/time are recorded in
[protocol freeze](verification/udp-pair-qualification-20261016/protocol-freeze.json).
The fixed screen requires producer-labelled, same-service runs and original-time
load/size overlap. It permanently assigns any eventual pair to development.
No pair, new evaluation partition or reserved receipt was materialized.

## Source findings

- [ORION 2026 publisher](https://www.uel.br/grupos/orion/datasets/orion-2026.html):
  CC BY 4.0, also confirmed by the archive licence. A bounded ZIP directory/README
  read identifies UDP attack intervals/endpoints and benign days, but no matched
  benign application/run on UDP/9090. Time-zone mapping is unspecified in the
  inspected metadata. `reordered` filenames require ordering/timestamp provenance;
  they do not prove timestamps were altered. Members are `.pcap.zst`; inner PCAP
  link type, completeness and original timing remain unverified. No decompressor
  dependency was added. Publisher citation: DOI `10.1109/ACCESS.2026.3738009`.
- [TRUST Lab](https://github.com/trustlabupct/trustlab_dataset/tree/c207488ba85804d74ff82413122e9762b7a4c529):
  README describes distributed completed-flow CSVs and research/educational use.
  It does not establish an accessible raw, independently labelled same-service
  high-volume UDP pair. No generators were executed or dataset rows read.
- [CIC-DDoS2019 publisher](https://www.unb.ca/cic/datasets/ddos-2019.html):
  raw captures and time/endpoint-based flow labels are described, with citation
  reuse terms. Listed benign workloads do not establish the required high-load
  same-UDP-service control. Existing local UDP-Lag data is only a CSV subset.
  This does not prove all CIC captures lack a suitable control.

These are bounded source-screening findings, not an exhaustive claim that no
suitable dataset exists. No restricted source or unapproved contact was used.
The linked IEEE full paper could not be retrieved using the available web tool;
its full methodology was not reviewed or treated as verified.

## Exact acquisition scope and integrity

[Source receipts](verification/udp-pair-qualification-20261016/source-receipts.json)
pin publisher pages/revision, ZIP size/ETag, directory members and response ranges.
[Archive metadata receipt](verification/udp-pair-qualification-20261016/archive-metadata-receipt.json)
pins the CRC32/SHA256-verified README/licence extracted by exact HTTP 206 ranges.
Requests were bounded to 1 MiB and checked against exact Content-Range; the ETag
was pinned when extracting documents. The 11,323,268,172-byte archive was not
downloaded in full. Its advertised SHA256 is recorded as **publisher supplied,
not locally verified**. Member listing does not verify inner packet format.

The ZIP tail range can include opaque compressed capture bytes preceding the
directory; none were decompressed or interpreted as traffic. Only README/licence
members were inflated and checked. No packet records or flow CSV rows were opened,
no load statistics measured, no model predictions produced. Local publisher
metadata snapshots are under ignored `data/raw/discovery/udp-pair-20261016/`;
tracked receipts preserve hashes, not an assertion those ignored files ship with
a clean checkout. A live publisher change requires a new metadata qualification.

## Root finding and smallest next action

The immediate blocker is **missing qualified benign run/service provenance**,
not a newly measured detection or accounting defect. Packet count, port and a
benign day label cannot prove an authorized application or matched rate/size.
We cannot substitute port rewriting, a generic UDP generator, a slowed attack,
completed-flow labels or opposite-label inference output for that evidence.

Next obtain ORION's producer runbook mapping one benign high-volume UDP application
and one UDP flood to the same actual service/port, exact capture members,
endpoint/direction, original timestamps/time zone, run boundaries and labels.
Also clarify what `reordered` denotes and the inner classic-Ethernet PCAP format.
If the producer cannot establish such a control, this lead remains unsuitable;
do not fabricate a pairing. No clarification message has been drafted or sent in
this task. External contact needs explicit recipient/message authorization.

Only after that provenance qualifies may the already frozen overlap screen run.
If overlap fails, retain the failure and stop. Even a qualifying pair supplies
development separability evidence, not accuracy, generalization or promotion.

## Validation, unchanged behavior and limitations

Changed only qualification protocol, manifest, this report, current plan pointers
and dated evidence. No runtime, diagnostic library, tests, model or gate changed;
no bug fix or new unit test was needed. Existing 23 UDP/observability regressions
passed in 1.54 seconds; results are recorded in the adjacent test log. Integrity
verification checks the protocol freeze, receipt consistency, source metadata
hashes when local snapshots exist, manifest blockers and protected tracked files
against `588d2cc`: 766 protected tracked files and six present metadata snapshots
verified. The initial byte-for-byte check encountered pre-existing Windows mixed
line endings; its failure log is retained. The final check uses Git's canonical
content comparison and separately records local-byte hashes. No application defect
was exposed. It does not import detectors or access the alert database.

No new TP/TN/FP/FN, accuracy, latency, runtime cost or throughput measurement.
T20's historical TP4/TN2/FP4/FN0, precision 50%, recall 100%, FPR 66.67% remain
historical failed-quality evidence. No before/after quality gain is claimed.
Full backend/frontend builds were not repeated for documentation-only work.
All ten original controls and failed candidates remain preserved; no reserved
scoring, training or activation. The legacy UDP heuristic remains active and
unvalidated. Release remains NOT READY. Stop at this provenance blocker.
