# UFU Do53 capture/run qualification — 21 October 2026

**Decision: NOT QUALIFIED for a reserved DGA or DNS-tunnelling evaluation role.**
Metadata/integrity check completed; detector completion remains BLOCKED. No
detector, threshold, feature, model or activation changed. No new quality metric
or accuracy improvement is claimed. Failed and unassessed candidates stay disabled.

## Inspected and method

Followed the current completion plan's next action at baseline `e53ede2` and
recorded a [pre-value protocol](verification/ufu-do53-qualification-20261021/PROTOCOL.md)
before new source documents. Reused the 20 October pinned Git tree, licence,
capture README, pipeline README and traffic methodology after verifying their
receipt hashes. Retrieved only three additional human documents (citation,
Do53 CSV description and input-artifact description), the public current-head
record and the release catalogue. Source revision remains
`1b3e59ffc3d14f41ccbf143be155cf791eb5e7ae`.

Firecrawl failed because this connection requires an unavailable `link_id`.
Used normal unauthenticated publisher GitHub HTTP metadata; no access challenge
was bypassed. No email, account form or supplemental annotation request was sent.
The reviewed documents contain upstream aggregate sample counts and feature
descriptions. These are documentary exposures only, not project accuracy,
eligible first-label counts or independent-session counts. No CSV rows, packet
values, archive contents, upstream model or generator were opened/executed.

## Proven evidence and unresolved requirements

- **Public permission: established for noncommercial research.** The existing
  licence and new citation identify CC BY-NC 4.0 for these data. Permission does
  not establish format, independent truth or suitability for a frozen role.
- **Capture containers: inventoried, inner members unverified.** The pinned Git
  tree contains exactly 34 sequential Do53 archive parts, totalling 880,360,679
  bytes. Those are compressed-volume counts, not 34 captures or sessions. No
  GitHub releases/assets are published in the checked catalogue.
- **Native format/link type: unverified.** The producer calls the captures PCAP
  in one document but elsewhere allows PCAP/PCAPNG and several link types.
  Parser support in the producer's own code is not a header receipt for the
  archived files. Classic Ethernet compatibility cannot be assumed.
- **Run/session mapping and original chronology: unverified.** The methodology
  supports controlled benign Do53 and dnscat2 scenarios. The capture README gives
  recommended filenames; the reviewed tree/document set supplies no actual inner
  member list joined to executed run IDs, source/namespace/time intervals or
  independent session boundaries. This is an eligibility gap, not a finding
  that the producer's labels are false or that annotations cannot exist elsewhere.
- **DNS-tunnelling coverage: not established.** Controlled dnscat2 is a supported
  source-level statement, but not evidence of >=20 independent eligible attack
  and >=50 benign sessions, record-type/rate coverage or all five required benign
  categories. Input files such as text/audio samples are not independent sessions.
- **DGA benign coverage: not established.** The source says benign queries resolve
  Tranco-selected names. That may be a useful controlled resolution source after
  format/run qualification; it does not establish five source-supported legitimate
  strata of >=600 eligible labels each or >=2,500 post-exclusion independent benign
  client-DNS labels. Counts, exposure exclusions and disjointness remain unmeasured.
- **Prepared CSV is not a causal substitute.** Its documented normalized lexical
  and whole-domain aggregates do not reconstruct original source-level query
  history, original timestamps or independent session annotations. Importing
  those rows would not evaluate the runtime's incremental feature definitions.
- **DoH remains outside lexical DNS visibility.** Encrypted HTTPS observations
  cannot supply clear-text QNAME/QTYPE without decryption, which is prohibited.

The [source inventory](verification/ufu-do53-qualification-20261021/source-inventory.json)
records Git blob IDs and public tree paths explicitly separately from the absent
inner-archive/session/header evidence. This is a bounded public-source decision,
not a claim that no suitable dataset exists anywhere.

## Changes and verification

Only this report, dated metadata scripts/receipts, supplementary documentation
exclusion hashes and current-plan/progress pointers change. Raw documentation is
cached under ignored `data/raw/ufu-do53-documents-20261021/`; no capture dataset is
added to Git. Existing frozen exclusion registries and data roles are unchanged.

With the original local documentary caches retained, reproduce the integrity
check without network requests or dataset values (the ignored caches are not
bundled into a clean checkout):

```powershell
.venv/Scripts/python.exe -B docs/verification/ufu-do53-qualification-20261021/check_metadata.py
```

Results: **13 reused plus five new document/metadata receipts match; three new
human-document Git blobs match the pinned tree; all 130 protected originals
match.** The retrieval script refuses to overwrite receipts. Archive volumes
and upstream CSVs are excluded from its fixed URL list and bounded responses.
See [checks](verification/ufu-do53-qualification-20261021/checks.json).

No application bug was fixed, so no new regression test is warranted. **88 existing
DNS/DGA protocol, scorer, candidate and acquisition tests pass** in 3.72 seconds,
recorded in the dated test log. No shared behavior changes; full backend/frontend checks are not relabelled
as rerun here. The preceding 616-backend-test/typecheck/build/Monitor results
retain their original scope and date.

**Before versus after:** newly qualified evaluation roles **0 -> 0**. Missing
requirements are now source-specific and reproducible. No detector-quality
before/after comparison, training, inference scoring or reserve inspection.

## Definition of Done and next action

**Metadata-screen DoD: PASS. Required detector validation DoD: BLOCKED. Final
release: NOT READY.** Do not bulk-download this archive, convert formats, train
or enable the DNS/DGA candidate to work around the missing evidence.

Exactly next: qualify a public source with an actual native capture/member
inventory and independently executed session/time manifest, then verify required
benign coverage before packet inspection. A newly published UFU run/header
manifest could reopen this lead; the checked documentation alone cannot. No
author follow-up is required or authorized by this public-only route. UDP/spoof,
C2 and encrypted-data prerequisites and recon/exfil observability blockers are
unchanged. No other detector experiment has been started as a substitute.
