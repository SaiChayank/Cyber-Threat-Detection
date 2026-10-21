# Public DNS session-source follow-up — 21 October 2026

**One producer-checksummed real-tool capture acquired with a supported native
header; two named producer-labelled benign runs located. Formal evaluation remains
BLOCKED.** No candidate was scored, trained, retuned or activated. No runtime or
other detector changed. This is partial source qualification, not completed DNS
detection or a new accuracy result.

## Inspection and scope

Baseline `6aa53b4`. Reviewed the existing DNS source decisions, scorer/input
contract, upload header validator and tested ZIP-directory reader. Recorded a
[pre-value protocol](verification/dns-public-session-screen-20261021/PROTOCOL.md)
before screening four new collections. Reused normal public publisher HTTP/web
retrieval because Firecrawl's previously established connection requires an
unavailable `link_id`; no access challenge, account, private supplement or email.
Two guessed Mendeley version API routes returned 404; the publisher's public
dataset endpoint succeeded and explicitly identifies version 3. The university
web tool returned 403 while normal public HTTP retrieved its published record and
README without authentication. No endpoint failure is treated as missing data.

The [artifact selection](verification/dns-public-session-screen-20261021/HEADER_SELECTION.md)
was hashed before any selected capture/container bytes. Documentary examples,
upstream results and schemas are development exposures; supplementary first-label
exclusions are recorded without replacing the frozen global registry. No query
rows, packet records/timestamps, upstream scripts/models or classifier outcomes
were examined. Incoming captures have no training/validation/reserved assignment.

## Four sources and exact decisions

**Active Countermeasures — useful real-tool intake, not a session-qualified reserve.**
The [producer's dnscat2 lab account](https://www.activecountermeasures.com/malware-of-the-day-dnscat2-dns-tunneling/)
documents the generating tool, lab host/controlled namespace and original capture
exports, explicitly invites download/analysis and supplies SHA256s. Downloaded
only the one-hour artifact: **2,462,756 bytes**, SHA256
`b1056baaa15c441aa9fadd23885818db069f3cc5b560dc4f8a184d3494f3d3bd`, matching
the publisher. After identity verification, read exactly its 24-byte global
header: classic PCAP v2.4, Ethernet/linktype 1, snaplen 262,144, microsecond
timestamp encoding. Existing `validate_header` accepts it. No packet parsing or
prediction. Lab context is independent of our detector, but exact executed
session/time joins, original question visibility and independence from the related
24-hour export remain unestablished. Do not label every captured query malicious
or count exports as independent runs. Local analysis permission is not a grant
to redistribute the capture; bytes stay in ignored intake.

**Universidad de Burgos — named benign capture-level truth, native format pending.**
[DOI 10.71486/dgza-t550](https://doi.org/10.71486/dgza-t550) and the producer
[README](https://riubu.ubu.es/bitstream/10259/11037/4/readme.txt) establish CC BY
4.0, controlled benign IoT activity and two named benign runs. Reused the existing
bounded ZIP catalogue reader: **65,868 bytes** of metadata ranges, HTTP 206/exact
ranges and Last-Modified continuity. Its three actual members match the two benign
names and separate DoS member. No 1,269,092,760-byte bulk ZIP download, member
decompression or native capture-header read. First benign member is 8,852,172
uncompressed bytes (8,021,093 compressed); second is 1,188,515,374 uncompressed.
Full archive checksum is not locally verified; conditional metadata identity is
explicitly weaker than an independently published cryptographic checksum.

The README's approximate 1,087,920-packet claim for the first benign member cannot
fit that declared classic-PCAP length: even zero-length packets require 16-byte
record headers, allowing at most **553,259** records after the global header.
This is a documentary consistency bound, **not a measured packet count**, and
does not establish corrupt data or invalidate benign intent. Native header and
actual count/time semantics need checking. The README mentions microsecond
capture precision and millisecond timestamps; neither is silently selected as
the observed unit. Two benign capture runs do not establish >=50 eligible DNS
sessions, all five DNS categories, or per-query application attribution. Keep as
a useful partial benign-source lead, not a completed evaluation cohort.

**Ziza — public original-field CSV lead, incompatible with the current complete-question gate.**
[Mendeley version 3](https://data.mendeley.com/datasets/c4n7fckkz3/3), DOI
`10.17632/c4n7fckkz3.3`, declares CC BY 4.0 and executed iodine/DNSExfiltrator
observations mixed with ISP requests. The 1,628-byte producer schema matches its
published SHA256 `73d6ab1b930429bdd4dadf2204099578d26e103ef34cc804f80595ac4faf2902`.
It documents original anonymized client, timestamp, request text and attack flag
as well as causal ten-request aggregates; therefore it is not dismissed as only
an opaque feature table. However, it supplies no documented QTYPE column,
independent session/time manifest or required benign application categories.
Completeness of the original question sequence is unverified. The 8,252,974,842-byte
main CSV, modified CSV and word list remain unopened. An exfiltration-negative
ISP row is not automatically a verified benign DGA sample. No substitute defaults,
row-level splitting or population reclassification.

**netrack/learn — public sample lead, joined session provenance missing.**
[Producer repository](https://github.com/netrack/learn) is pinned to
`b19ea986df5517bd8ad89efd2e16bbf302e2ac03`; untruncated tree has 44 entries and
two retrieved documents match Git blob IDs. Root Apache-2.0 licence is present,
but the 24-byte README gives no executed run/time ledger, independent session
definition or benign application/category mapping. Nominal PCAP/CSV paths and
the repository description do not establish native headers or per-session truth.
No capture/CSV contents, predictive code or external generated documentation
were used to infer labels. Not qualified for a scored role at this stage.

## Implementation and verification

Added only bounded source-intake/documentary scripts, manifest/report/current-plan
pointers and six targeted acquisition regressions. Reused the existing header
validator and ZIP catalogue implementation; no new dependency/parser/framework.
Raw capture and documentary cache remain under ignored `data/raw/`; analyst
history, existing datasets, models, partitions and promotion gates are unchanged.

Tests cover identity verification before header inspection, exactly 24 header
bytes/no packet parsing, the 3 MiB download bound, unsupported link type,
truncation and refusal to overwrite existing intake. **83 targeted tests pass
in 3.00 seconds**, including the new six cases, existing bounded-range catalogue
tests and frozen DNS contract/scorer regressions. No shared application behavior
changed; full backend/frontend runs are not claimed as refreshed.

Nine documentary receipts, one publisher document SHA256, two pinned Git blobs,
the complete acquired capture checksum and **all 130 protected originals** verify.
See [checks](verification/dns-public-session-screen-20261021/checks.json) and the
machine-readable [source manifest](../data/dns_session_source_screen_20261021.json).
With retained local caches, reproduce non-network identity checks using:

```powershell
.venv/Scripts/python.exe -B docs/verification/dns-public-session-screen-20261021/check_evidence.py
.venv/Scripts/python.exe -B -m pytest -q -p no:cacheprovider tests/test_dns_source_intake.py tests/test_udp_archive_catalogue.py tests/test_dns_tunnel_evaluation_contract.py tests/test_dns_tunnel_scorer.py
```

**Before -> after in this package:** new producer-checksummed/native-supported
real-tool capture intake 0 -> 1; new named producer-supported benign runs 0 -> 2;
qualified reserved roles 0 -> 0. These are acquisition facts, not improved recall,
FPR, alert timing or independent-session totals. No formal evaluation was run.

## Definition of Done and exactly next

**Bounded source-screen/intake DoD: PASS. DNS validation DoD: BLOCKED. Release:
NOT READY.** Missing full session/category coverage and timing truth remain;
the candidate is disabled and every frozen numerical/coverage gate is unchanged.

Exactly next: preregister a bounded **Burgos benign native-header qualification**,
starting only with `benign_first_cap.pcap` and its 8,021,093 compressed bytes.
Verify archive identity/CRC and original member bytes, then the native global
header without query inspection. Do not acquire the >1 GB second member just to
obtain a header, slice sessions, treat missing categories as present, or run the
candidate. This is now an executable partial-source qualification step; it does
not promise that this collection can satisfy the complete frozen evaluation.
