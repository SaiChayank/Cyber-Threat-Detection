# AIT client/question/session qualification — 21 October 2026

**Development source-qualification DoD PASS. Formal independent detector accuracy
remains BLOCKED.** Baseline `425af50`. No detector/rule/feature/model, frozen gate,
runtime flag, database/history, existing raw input or older frozen package changed.
No training, prediction, reserved scoring or promotion occurred.

## Completed steps and actual findings

**1. Original client context — partially established.** Reviewed the frozen
contract/scorer, [previous source report](DNS_SESSION_PROVENANCE_SEARCH_20261021.md),
original AIT host/group/clock metadata and actual receiver/application/service logs.
The original host map identifies `internal-share` as **10.143.0.103**, UTC.
That host contains the producer-named `put` service. Its original audit log records
successful SERVICE_START and SERVICE_STOP for that unit at the identical timestamp
**24 January 2022 13:50:39.298 UTC**. This establishes lifecycle context; it does
not provide a separately observed original client execution start.

The publisher's `dnsteal.domain.received` label is derived from the configured
domain and listener interval. Its own description explains the assumption and
suggests stronger checks for other scenarios. It is not a per-query receiver
acknowledgement or independently labelled session. No original label rows were
opened or used as quantitative truth.

**2. Client-to-original-question association — verified for transfer markers.**
After [freezing this whole run as development-only](verification/ait-session-join-20261021/STAGE_B.md),
verified and inspected only its original firewall DNSmasq log:

- Original bytes: **32,228,543**, selected ZIP-member CRC32 `c4cbb523`.
- SHA256: `3b26c8774eab02ea72c46e7c3eead9e7a3601c6f169ce83b3bd4cafd7674888b`.
- **275,900 source lines:** 81,277 parsed client-question records and 194,623 other
  records. Responses, forwarding and cache messages are not extra client queries.
- Observed question types: A 40,275; AAAA 38,967; TXT 582; SRV 196; PTR 1,055;
  MX 202. No NULL observed. The controlled DNSteal namespace has **17,693 A
  questions**, all logged from **10.143.0.103**.
- **20 exact transfer-end-marker associations:** literal filename/namespace,
  QTYPE A, expected original client and the same reported UTC integer-second
  bucket match independent receiver events. No nearest-time search, clock-offset
  fitting, payload decoding, detector predictions or forced matches.
- The remaining **11 of 31 receiver end markers precede the DNS observation
  interval**. They are out-of-window receiver evidence, not detector FNs.
- Input order/duplicates retained; no malformed query records, outside-interval
  questions or backwards query-time steps observed. This is offline log visibility,
  not proof of runtime alert timing, packet loss absence or capture completeness.

The source log timestamps have **one-second resolution**, reconstructed using
the original year/UTC metadata. Cross-host clock offset was not independently
measured. Exact bucket agreement is an association, not a subsecond latency claim.
Question names pass the diagnostic's textual structural checks; raw DNS wire
headers/question count/escaping completeness were not independently validated.

**3. Independent session boundaries — unresolved.** These observations belong
to one controlled source/run group. The receiver is already receiving data before
the declared DNS log interval starts, so the original operation is left-censored.
File completion is not a separate execution or independent experiment. There is
no justified conversion of 20 joined markers into 20 qualified sessions; the
original complete client execution bounds and session independence remain unknown.

**4. Benign controls — genuine application context, insufficient DNS attribution.**
Reviewed two original internal-employee state logs. Actor 0 has 999 records,
including 13 reported completed mail actions, but **all precede the DNS interval**.
No rotated state-log continuation is present in the reviewed archive directory.
The next actor's whole trace has 9,606 records, **7,493 in the observation interval**,
and reported mail/ownCloud/SSH/WordPress activity. Neither trace supplies explicit
DNS-question/transaction joins or independently annotated DNS sessions.

Repeated transition log messages are not additional completed actions or sessions.
The state logs also contain upstream simulation exceptions; not every intended
action succeeded. These are dataset context, not current backend faults. Observing
TXT/SRV/PTR requests or a mail/cloud application does not certify the five required
benign categories. Other DNS traffic is not automatically labelled benign.

**5. Traceable manifest/exposure — completed.** Added
`data/dns_ait_session_qualification_20261021.json` and 20 transfer-association
annotations with original source/receiver line references, times, filename hashes,
whole-run grouping and explicit unknowns. These are **not** a labelled final
session list. The entire russellmitchell experiment and related fragments,
copies/versions/derived exports are exposed development qualification. No future
overlap check may treat its inspected question values as unseen merely because
another dataset uses a different filename. Other AIT testbeds remain unopened and
unassigned; related-source independence still needs review.

**6. Freeze/evaluation — correctly blocked.** The DNS log also lacks the original
query's **destination address, TCP/UDP protocol and destination port**. All three
are required observed fields in the current frozen scorer; a host's default
address and presumed UDP/53 cannot supply them. A client-side capture/export or
equivalent independently supported original observations are needed. No runtime
DNSmasq adapter or capture-format support was added.

Only DNSteal is established; required dnscat2/iodine coverage is not filled. There
are still no >=20 independent positive/>=50 benign qualified sessions or all five
controls. Thus no reserved manifest or pass receipt was created, and no confusion
matrix, precision, recall, F1, FPR or detector accuracy is reported.

## Files, tests and reproduction

Added this report, the qualification manifest, dated selections/CRC/hash receipts,
diagnostic parser/join/context scripts, results, annotations and evidence checker;
updated current-plan/progress pointers. Original inputs remain ignored raw cache.
No publisher programs, transferred payload files or private communications opened.
Human unit/label metadata and existing printed command examples were read as data;
no commands from them executed. Credentials/message/payload contents are not
published in tracked evidence.

**27 new diagnostic cases; 63 targeted tests pass.** Tests cover question/response
separation, opaque DNS text, malformed/missing fields, exact source/type/time joins,
ambiguous receiver/question duplicates, original lateness, out-of-window markers,
invalid timestamps/filenames and avoiding transition-as-session counts. All older
intake/Burgos regressions pass. No shared application behavior changed, so the
full backend/frontend build was not rerun or relabelled current.

Offline evidence checks reproduce the join and application summaries and verify
14 new input receipts against cached bytes **and original ZIP members**. All
130 protected originals, both prior captures, the AIT archive, four prior frozen
packages and 23 contract source pins are unchanged.

With the original ignored inputs retained, from repository root:

```powershell
.venv/Scripts/python.exe docs/verification/ait-session-join-20261021/check_evidence.py
.venv/Scripts/python.exe -m pytest tests/test_ait_dns_session_join.py tests/test_dns_session_metadata_intake.py tests/test_dns_source_intake.py tests/test_burgos_benign_intake.py tests/test_burgos_dns_visibility.py -q
```

The verifier checks existing artifacts without scoring or rewriting original data.
This is reproduction of a research diagnostic with its raw inputs, not a new
clean-checkout/application/production-throughput claim.

## Before/after, remaining limitation and exactly next

Client/receiver associations **not established → 20 source/time/file marker joins**;
original question visibility **not examined → 81,277 parsed records**. These are
provenance/visibility counts, not detection metrics. Qualified reserved sessions
**0 → 0**; independent accuracy **NOT ESTABLISHED → NOT ESTABLISHED**.

Source-qualification DoD **PASS with explicit partial capability**. Full accuracy
task **BLOCKED**, candidate **DISABLED**, release **NOT READY**. The existing
recall/precision/FPR/timing gates and one reserved pass remain frozen.

**Exactly next:** qualify an additional readily available public dnscat2/iodine
collection with independently annotated client execution sessions and original
client-side packet/question fields. Keep this entire exposed AIT run out of the
reserved cohort. After valid subsets and independently attributed benign controls
meet every prerequisite, freeze roles/disjointness and perform the single final
evaluation. No model change or scoring is authorized by incomplete provenance.
