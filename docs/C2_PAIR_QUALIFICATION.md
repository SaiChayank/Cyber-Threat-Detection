# T23 — C2/periodic-benign development-pair source screen

17 October 2026. Baseline `20f0c23`.
**Qualification DoD: BLOCKED — no qualified pair. Source screen completed.**
No detector, horizon, threshold, model, candidate activation or acceptance gate
changed. No training, inference, new accuracy result or reserved scoring.

## Frozen scope and inspected evidence

Used the [C2 observability diagnosis](C2_OBSERVABILITY_DECISION.md), frozen C2 gate,
current completion plan, saved TLS acquisition/source/partition reports and the
already exposed TQH publisher README/manifest metadata. Froze the
[qualification protocol](C2_PAIR_QUALIFICATION_PROTOCOL.md) before new values.
Its SHA256 is recorded in [the manifest](../data/c2_pair_qualification.json).

The bounded screen covers four publisher leads: TQH, AIT collections, TUC/DeepRed
and ARES. AIT-LDS is contextual documentation for the AIT lead, not a fifth pair
or a cross-source benign assignment. Published dataset descriptions and pinned
README/record metadata are the evidence; search snippets are discovery only.
No source was selected based on Univect alerts or published accuracy scores.

Firecrawl returned a missing `link_id` routing error; no search job/result was
created. Plugin discovery confirmed installation but exposed no connected handle.
Used built-in web search/read plus bounded public HTTP metadata/document requests.
No account access, monitor, email check or external message was performed.

## Lead decisions

**TQH-C2 1.2.2 — closest existing lead, not a C2 pair.**
[Publisher record](https://zenodo.org/records/22732327) declares CC BY 4.0.
The re-fetched README matches the saved original exactly. Prior acquisition
established a complete Ethernet capture and UTC/session joins for 115 controlled
C2 and 467 benign TLS sessions. Those are historical TLS session counts, not
callback counts. Configured interval/jitter, topology intent and connection UIDs
do not establish executed callback positions or identify a matched periodic
benign application. Those missing records block this pair before packet values.
The existing raw capture hash/reference is retained; no raw bytes were reread.

**AIT collections — no matched pair established.**
[CAM-LDS](https://zenodo.org/records/18861762) documents C2 attack steps and
time-based execution logs, but explicitly no normal-user simulation. Idle system
activity is not a verified periodic application control. Related
[AIT-LDS 2.0](https://zenodo.org/records/5789064) has normal simulations and
attack logs; its reviewed description does not establish the required callback-
labelled, matched-periodicity pair. No archives or label rows were read; neither
cross-collection pairing nor capture format/contact joins were assumed.

**TUC-RedTeam30 / DeepRed — raw lead with incomplete contact/control provenance.**
[Dataset record](https://zenodo.org/records/15668685) declares CC BY 4.0 and
advertises a representative selected-PCAP archive, not all raw scenarios.
[Publisher paper, Appendix A](https://www.usenix.org/system/files/woot25-hajizadeh.pdf)
describes randomized benign user activities. Reviewed documentation does not
establish a named matched periodic control or executed-contact-to-packet joins.
Flow/scenario labels cannot substitute for them. The raw archive is advertised
as 14,323,780,868 bytes; none was downloaded. Repository tag v1.0 is pinned to
`dc3478cf046738111129dca85319f4915c7c7da2`; only README text was read, no code run.

**ARES Cobalt Strike — existing blockers remain.**
[Author README](https://github.com/cp-tsp/ares2025-artifacts) provides file-prefix
intent labels. The existing source review catalogued benign PCAPNG/browser
controls; supported original Ethernet benign captures, periodic application
contact truth and capture-data permission remain unestablished. Current commit
still matches `7acfebc6f17fe774df91a1b550c4b23613b90fe9`. No capture values or
earlier email responses were checked; no additional message was sent.

These are evidence gaps within this bounded review, not proof that no suitable
dataset exists. Metadata consultation is recorded as C2 development influence;
these leads cannot later be presented as untouched C2 final evaluation. Existing
TLS/DGA/DNS or other detector partitions are unchanged. IoT-23/Stratosphere
authorization exclusions were respected; no mirrors or permission workaround.

## Retrieval correction and evidence integrity

The GitHub `/commits/main` API response unexpectedly included 10 file patches,
including CSV diffs, alongside commit metadata. Patch strings were not inspected,
parsed as CSV, evaluated or used for source selection. The original response is
preserved in ignored `data/raw/c2-source-metadata-quarantine/` and is ineligible
for training, validation or reserve. Only commit identity, tree, parent and
patch-bearing path metadata were inspected; the tracked summary omits all diffs.
This accidental transfer is disclosed in `metadata-receipts.json`; it is not a
planned annotation acquisition or a claim of purely metadata-only network bytes.
Subsequent repository requests fetched only exact pinned README paths.

Original publisher READMEs are cached locally outside Git; retrieval receipts pin
their URLs, byte counts and raw SHA256. The already committed licensed TQH README
is the portable reference. New tracked Zenodo records preserve publisher metadata
and file listings only. Public website/retrieval failures were not treated as
proof of global unavailability. No binaries, keys, archives or new packet records
were obtained. No analyst database was opened.

## Result, checks and next action

Qualified matched pairs **0 → 0**; selected pair, contact counts and measured
interval overlap remain **null/unestablished**. The nine-contact and interval-IQR
screen was frozen but not run because provenance fails first. No contact count,
overlap, new accuracy or runtime-cost number is invented. Historical controlled
C2 remains TP3/TN6/FP2/FN3, precision60%, recall50%, FPR25%; all gates unchanged.

Changed only this report/protocol, the qualification manifest, prepared request,
plan status and dated evidence. No runtime or diagnostic code changed, so no new
regression tests are needed. Existing 41 C2/baseline/UDP diagnostic regressions
are rerun; manifest/protocol/receipt and protected-file checks are recorded in
the evidence directory. Full backend/frontend build is not claimed for this
documentation/data-provenance step. The preceding full-suite evidence remains
historical, and no unrelated completed detector was refactored.

**Exactly next:** obtain the TQH producer's executed-contact mapping and named
periodic benign workload clarification for the existing D_i300_j30 capture.
[Exact request](C2_TQH_CONTACT_REQUEST.md) is prepared, not sent. Deokjo Jeon is
a new recipient requiring direct approval before sending; the public README
confirms the listed address, not delivery. Until those prerequisites qualify,
stop before packet-value inspection or any detector experiment. If no matched
benign workload exists, retain the blocker; do not relabel idle traffic or replace
the hard negative with irregular browsing.

Evidence: [manifest](../data/c2_pair_qualification.json) and
[receipts/checks](verification/c2-pair-qualification-20261017/).
Freeze this source screen and protocol. **T23 and release remain unresolved.**
