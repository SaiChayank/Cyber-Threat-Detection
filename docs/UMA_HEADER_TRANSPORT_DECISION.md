# UMA bounded capture-signature decision

18 October 2026 IST; source baseline `5f23a7d`. **Diagnostic DoD: PASS.**
**DNS evaluation-data qualification: BLOCKED; candidate remains disabled.**

Inspected the frozen downloaded-source qualification, producer-document follow-up,
original ZIP identity/catalogue, runtime classic-PCAP boundary and installed
`stream-inflate` 0.0.43 decoder. The [protocol](UMA_HEADER_TRANSPORT_PROTOCOL.md)
and [selection plan](verification/uma-header-transport-20261018/selection-plan.json)
were pinned before reading any new decompressed capture bytes.

The standard Python ZIP reader cannot decode method 9. A separate existing
Deflate64 decoder successfully returns exactly four bytes from each pinned entry.
**45/45 signatures are `0a0d0d0a` (PCAPNG)**. Total logical output is 180 bytes;
compressed input is 5,760 bytes (128 per member), below the 1 MiB/member bound.
No member was extracted, converted or parsed. No interface, packet block,
timestamp, DNS question, payload, feature or model value was inspected.

Root cause of the previous header-access failure was the selected archive reader's
unsupported compression. It was not proof of original archive corruption.
This follow-up resolves that transport uncertainty only. A four-byte signature
does not validate whole-file structure, member CRC, link type or usable DNS data.
Original archive SHA256 remains
`76f7f38dada4cbdb8110691ca981262f10eb55452bc1c2e3e1dc6297b191957d`.

Runtime supports classic Ethernet PCAP, not PCAPNG. Adding a parser/conversion is
outside this task and would not supply the independently verified DNS-session
labels and five benign application strata missing from this source. Training,
validation and reserve roles remain unassigned; all gates and contracts unchanged.
No quantitative detection metric was rerun or changed.

Only evidence-local transport scripts, eight exact tests, results, this supplement
and plan/data-status links were added. Production code/dependencies unchanged.
Tests cover the output/input bounds, short output, encrypted/wrong-method refusal,
catalogue/header mismatch and extraction avoidance: **8 passed, 0.10 seconds**.
Protected integrity is recorded alongside the reproducible runner and result.
The decoder is optional research tooling, not a new application requirement;
its unit module explicitly skips when absent in a clean base installation.

Freeze this decision, scripts, tests and limitations. Exact next independent task:
verify the current committed baseline from a new checkout using README instructions
and isolated services/database. Final T60 remains dependent on detector completion;
this rehearsal cannot establish final release readiness.
