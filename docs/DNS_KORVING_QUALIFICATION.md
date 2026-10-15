# Korving DNS source qualification — metadata follow-up

15 October 2026. **Qualification NOT MET. No capture acquisition or scoring.**

Inspected the existing DNS gap review/formal protocol and current candidate
configuration; prior backend/build/browser verification remains historical evidence.
Read 11 text documents from publisher revision
`bdc4486751f5e87fa6100b17dd57fc001743b43c`: three READMEs, four DNS-server
configuration files and the lexicographically first two `.metadata` files in each
of the two experiment groups. The selection plan was saved before fetching them.
All 11 byte sizes and Git blob SHA1 identities match the pinned publisher tree;
local SHA256s are recorded. No scripts, shell sessions or tool commands executed.

## Findings

All four DNS-server configurations and four sampled experiment metadata files
specify `tcpdump -i any`. This is a Linux cooked-linktype risk, not a verified
capture-header observation. Existing reader requires classic PCAP v2.4, Ethernet
link type 1; do not assume an extension proves compatibility or silently convert
captures/add cooked-link support. No explicit snap length in those commands
establishes preservation of every question: actual truncation needs checking.

Sampled metadata identifies DNS2TCP, DNSCAT and iodine components and execution
timestamps, but not timezone-qualified per-session query boundaries. Scenario
configuration documents intended activity, not proof every captured query belongs
to the tunnel. Terminal recordings may assist a later independent join; none were
read in this review. No independent positive/benign session totals are certified,
and none of the five required benign categories is newly established.

Repository MIT wording names DACA. Capture-data permission and redistribution
scope remain unconfirmed. No new role assignments or reserved-set declarations.
Metadata contains public example namespaces; they are exposed documentation and
must not later be represented as untouched evaluation observations.

## Contact and source access

Primary sources: [pinned repository](https://github.com/Korving-F/dns-tunnel-dataset/tree/bdc4486751f5e87fa6100b17dd57fc001743b43c),
[author profile](https://github.com/Korving-F),
[paper landing page](https://papers.academic-conferences.org/index.php/iccws/article/view/962).
The paper landing page confirms the DACA article and authors; its article licence
does not establish capture-data rights. PDF retrieval returned a verification
interstitial, despite HTTP 200, and was not treated as paper content or bypassed.
GitHub's public profile API has no public email; no email address was inferred.
The repository has Issues enabled. A public issue is a verified possible contact
route, not evidence the author will respond.

[Prepared request](DNS_KORVING_DATA_REQUEST.md) is draft-only. Sending/posting to
this new recipient requires explicit user authorization; earlier DGA/TLS contacts
do not authorize it. No external message was sent.

## Verification and outcome

Evidence: `verification/dns-korving-qualification-20261015/` contains the sampling
plan, publisher text snapshots, Git/SHA256 identities and integrity freeze.
All 185 checked backend/source/model/artifact files remain unchanged. No code or
tests changed, no new test run needed for this documentation-only step. Earlier
377-test backend pass, TypeScript/build pass and 32-check browser pass are retained
with their dates/scopes, not relabelled as fresh tests or detector-quality metrics.

Files added: this review, contact draft and new evidence directory. Completion-plan
supplement updated. No datasets, alert history, runtime flags, gates or frozen
evaluation report changes. An initial console print of a Unicode README failed
under cp1252 before saving evidence; metadata retrieval was repeated with safe
output and all saved document bytes verified against Git identities.

Definition of Done: metadata follow-up and actionable request complete; qualified
data availability NOT MET. Stop at the provenance/coverage/format blocker. Next:
with user authorization, post the prepared clarification; evaluate a response
before any bounded capture acquisition. The separate current-pipeline-contract
reconciliation from the gap report also remains required before reserved scoring.
