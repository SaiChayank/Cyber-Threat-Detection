# Burgos benign-first capture verification — 21 October 2026

**File integrity, native-format compatibility and observed DNS visibility: PASS.**
**Full DNS-tunnelling evaluation: BLOCKED.** This verifies one producer-labelled
benign capture, not detector accuracy or the complete required session/category
coverage. No detector, threshold, feature, model, runtime flag or database changed.

## Inspected and method

Baseline `26256d7`. Reviewed the prior source-screen/run descriptions, source
catalogue, existing PCAP validator/parser, DNS visibility helpers and frozen
evaluation contract. Recorded the acquisition
[protocol](verification/burgos-benign-verification-20261021/PROTOCOL.md) and hashed
exact member/source selection before retrieving native capture bytes. Used only
the publisher's public Burgos DOI `10.71486/dgza-t550` ZIP and
`benign_first_cap.pcap`; no account, private annotation, producer message or
other source acquisition. No new dependency, archive/capture format or conversion.

Every request required HTTP 206, exact Content-Range/length, identity encoding and
unchanged Last-Modified with If-Unmodified-Since. Rechecked the pinned central
directory, used Python's existing ZIP-directory support to find the exact member,
checked its local-header identity, and downloaded only its bounded deflate stream.
Original bytes are trusted only after declared output size, deflate end state and
central-directory CRC match. The fixed output path does not derive from an
archive-supplied path. Existing and partial intakes are never overwritten.

After integrity and classic Ethernet compatibility passed, separately froze the
[visibility protocol](verification/burgos-benign-verification-20261021/VISIBILITY_PROTOCOL.md)
and exact script/parser/helper identities before reading packet records. Used
original order/time, existing transport/DNS helpers and the runtime question
parser. No query text/addresses printed, response RDATA decoded, TLS/QUIC payload
decrypted, reputation lookup, probe, feature/rule/model call or candidate score.
Supplemental first-label exposure hashes are kept for later exclusion; this is
inspected development-source qualification, not an untouched reserve assignment.

## Verified file and observations

- Original member: **8,852,172 bytes**, from **8,021,093 compressed bytes** in the
  public 1,269,092,760-byte ZIP. No second benign/DoS member or full ZIP acquired.
- Selected-member CRC32: **`5bd6ba90`**, matching the pinned central directory.
  Local original SHA256:
  **`f1b0e48cfdbdd38a7701c99b364ed0bd70521224402a9d96eeac7b0dd9845e57`**.
  A producer-published full-archive SHA256 remains unavailable; CRC/conditional
  source continuity are not represented as that stronger guarantee.
- Native header: **classic PCAP v2.4, Ethernet/linktype 1, snaplen 262,144**.
  Accepted by the existing header validator. Original timestamp encoding is
  **microseconds**, not milliseconds or a wall-clock replay timestamp.
- **11,005 complete packet records**, with **zero capture-truncated frames**.
  Original span **161.583704 seconds**, from
  `2025-02-20T12:07:57.295260+00:00` to `2025-02-20T12:10:38.878964+00:00`.
  Three backwards timestamp steps are preserved. Five repeated frame-byte
  strings are counted/preserved, not assumed to be duplicate analyst records.
- Observed ordinary DNS: **144 UDP/53 packets**, **72 client queries and 72
  responses**. All 72 complete first client questions reach runtime DNS sidecars,
  with **zero QNAME/QTYPE mismatches or missing sidecars** in this observed group.
  QTYPEs: **36 type 1, 36 type 65**. No observed AAAA/TXT/NULL client questions.
  One observed querying source; complete question lengths 10–31 characters.
- **1,371 UDP/5353 packets remain separate mDNS-service observations**, not
  DNS/53 evaluation questions or certified service-discovery controls. The
  parser has not been extended to consume them. There are 35 unsupported or
  non-transport frames, which are not claimed to have complete DNS visibility.
- Runtime parser error counters are zero **for the eligible client questions
  actually passed to it**, not a full semantic validation of every network frame.
  The three backwards capture-time steps do not establish that three DNS events
  would be dropped by the detector; no pipeline/watermark replay was run.

These are source visibility counts, not TP/TN/FP/FN, recall, FPR, throughput,
processing latency or API-to-SSE measurements. Original packet bytes are retained
under ignored `data/raw/burgos-benign-intake-20261021/`.

## Findings and limitations

The native capture is usable by the current input architecture. The publisher's
approximate first-capture counts/duration are inaccurate for these original bytes:
README describes approximately 1,087,920 packets and ten minutes; observed values
are 11,005 and about 162 seconds. The data pass selected-member integrity; this
documentation discrepancy is not called corruption or repaired by timestamp
adjustment. The source's declared collection month is compatible with the dates
observed here. Six fractional digits establish sub-millisecond timestamp encoding.

The producer's executed capture-level benign label is retained. It does **not**
establish 50 independent DNS sessions, per-query application attribution, all
five required benign categories or held-out role disjointness. Do not slice this
capture into sessions or use mDNS as ordinary DNS/53 controls. The required real
tunnel positives and complete separate benign coverage remain unqualified.
The previous dnscat2 intake remains header-only; its packet values were not opened
or scored in this task. No reserved cohort exists from these two files alone.

## Files, tests and preservation

Added dated acquisition/visibility scripts and pinned evidence, a qualification
manifest/report and two test modules. Updated only current plan/progress pointers;
previous frozen source-screen manifests and reports remain byte-identical.

**23 new acquisition/visibility test cases** cover bounded/identity-protected
range reads, CRC and inflated-output failure, wrong local names, original/partial
file preservation, unsupported link types, timestamp precision/order, malformed
records, DNS response/service separation and explicit runtime visibility misses.
**139 targeted tests pass**, one existing Starlette/httpx deprecation warning,
in **3.30 seconds**. Existing schema/parser, DNS contract/scorer and earlier source
regressions are included. No shared product behavior changed; a full backend or
frontend build is not falsely reported as rerun.

The verification checker confirms original intake bytes, source freezes,
all 130 protected originals and the prior producer-checksummed dnscat2 capture.
See [checks](verification/burgos-benign-verification-20261021/checks.json),
[test log](verification/burgos-benign-verification-20261021/tests.log) and
[qualification manifest](../data/dns_burgos_verification_20261021.json).
With original local intakes retained, reproduce integrity checks without network
access or re-parsing packets:

```powershell
.venv/Scripts/python.exe -B docs/verification/burgos-benign-verification-20261021/check_evidence.py
```

**Before -> after:** verified native benign capture **0 -> 1**; observed complete
client questions **unknown -> 72**. Formal accuracy metrics remain unmeasured;
qualified reserved roles remain **0 -> 0**. No model quality gain is claimed.

## Definition of Done and exactly next

**This capture verification DoD: PASS. Complete feature validation DoD: BLOCKED.**
Candidate remains disabled; frozen 20-positive/50-benign, category, quality and
incremental-timing gates remain unchanged. Final release remains NOT READY.

Exactly next: qualify a public executed-session manifest for the required real
dnscat2/iodine positives (tool, client, namespace and original time boundaries),
then complement it with independently documented benign category sessions. Keep
this inspected first capture as qualification evidence without assigning it to
reserve. Do not keep rechecking it, acquire the >1 GB second member without
specific coverage evidence, score a candidate, fabricate counts or lower gates.
