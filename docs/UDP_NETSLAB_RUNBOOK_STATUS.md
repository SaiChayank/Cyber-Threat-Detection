# NetsLab UDP runbook request — SENT

20 October 2026, Asia/Calcutta. Baseline `4b0d36f`.

The user approved the exact prepared request and selected **public datasets only**.
An isolated-lab collection is outside the selected route. The historical
[prepared request](UDP_NETSLAB_RUNBOOK_REQUEST.md) remains byte-for-byte unchanged;
its dated NOT SENT header describes preparation on 19 October, not current status.

## Dispatch evidence

- From: Sai Chayank, `saichayank07@gmail.com`.
- To: Chamara Sandeepa, `abeysinghe.sandeepa@ucdconnect.ie` only.
- No CC, BCC or attachments.
- Subject: NetsLab-5GORAN-IDD: original runbook for matching benign iPerf and UDP flood captures
- Focused Sent and draft searches found no match before composing. One Send click;
  Gmail confirmed **Message sent**. The opened Sent envelope confirms the addresses
  and subject. Gmail displays `20 Oct 2026, 01:29`; its timezone was not shown.
- [Verified Sent copy](https://mail.google.com/mail/u/0/#sent/KtbxLxgRNrnNsMKRThhhLjSwxJmPGmBLLq).
- Approved request SHA256:
  `41c248479b21a1cb0cbac995a258059f752c810e361d417ac4af795a98caec75`.
- Both composed and sent visible bodies match the approved body after NBSP-to-space,
  CRLF-to-LF and outer-whitespace normalization only. No semantic edits.
- [Machine-readable receipt](verification/udp-netslab-dispatch-20261020/receipt.json)
  and [focused screenshot](verification/udp-netslab-dispatch-20261020/sent-request.png).

## Finding and scope

Dispatch is verified; delivery, a producer response and T21 qualification are not.
The source remains a public-data lead lacking verified matching application/port,
independent run labels, original chronology and capture-integrity/format evidence.
T21 remains **BLOCKED / NOT QUALIFIED**, with no selected pair or experiment.

Inspected: approved request, duplicate searches, compose/Sent envelope and body,
current completion pointers and the existing 130-file protected hash inventory.
Changed: dispatch evidence, this status and current plan/progress pointers only.
No application/test implementation changed; no packet values inspected, capture
decompressed, model trained/scored/promoted, threshold changed or alert history modified.

Verification: run `python docs/verification/udp-netslab-dispatch-20261020/check_receipt.py`.
It checks request/body/screenshot hashes, dispatch scope, public-only policy and
all 130 protected originals. Application regressions/build were not rerun for
correspondence/documentation-only changes; earlier test results remain historical.
No detection/performance metrics changed or were remeasured.

**Dispatch Definition of Done: PASS** once the receipt check and Git whitespace
check pass. **T21 qualification Definition of Done: NOT MET / BLOCKED.** No release
readiness or dataset usability follows from an email being sent.

Exactly next: verify the producer's original service/run/label/timestamp and
capture-format/integrity records against the frozen T21 protocol before inspecting
packet values. Only then run the existing original-time load-overlap screen.
If no public source supplies those prerequisites, record the unresolved blocker;
do not substitute lab collection, inferred labels, speed changes or relaxed gates.
