# DNS detector accuracy check — 21 October 2026

**Controlled synthetic regression: PASS for the candidate. Independent/public
accuracy: NOT ESTABLISHED. Formal validation DoD: BLOCKED, no promotion.**
This does not complete the DNS-tunnelling feature's frozen acceptance gate.

## Inspected and executed

Baseline `47e82c3`. Inspected frozen DNS contract/scorer, existing development
generator/comparison, active baseline/candidate logic and the current public
source/Burgos verification records. Verified all 23 frozen source/artifact pins
before scoring. The [pre-run protocol](verification/dns-accuracy-check-20261021/PROTOCOL.md)
limits this task to the 20 already exposed synthetic scenarios and a reserved
readiness refusal; no new public capture, query row, session or reserved value
was scored. Original models, thresholds, partitions, gates and runtime stay frozen.

Ran the existing development CLI into a new output, retaining earlier reports.
For baseline comparison, reused `score_session`/`summarize` and the same event
generator with `Pipeline(dns_tunnel_candidate=False)`. Both arms force the general
model prediction to BENIGN as required by the frozen rule-only comparison. This
isolates the two DNS rules; it is **not full deployed hybrid accuracy**. No fitting,
feature change, parameter selection or automatic promotion.

## Current measured results and scope

The training/configuration split and validation split each contain five known
synthetic attack scenarios and five synthetic benign scenarios. Whole scenarios
remain separated, but both sets have already influenced development/inspection;
neither is an untouched independent test set. Do not pool them to claim field
accuracy or treat synthetic application labels as public benign ground truth.

**Candidate, validation only:** TP **5**, TN **5**, FP **0**, FN **0**; precision
**100%**, recall **100%**, F1 **100%**, benign-scenario FPR **0%**. All ten known
scenario decisions are correct in this small exposed synthetic split. Each of
the five attacks first alerts at **query 5 of 12**, with delays **7.2, 4.4, 4.8,
3.8 and 6.0 seconds**, respectively. They cover synthetic A/AAAA/TXT/NULL examples
and long/multiple-label shapes. Early fraction is 5/5 and all precede completion.
No late questions are dropped in these fixed scenarios.

**Candidate, training/configuration only:** TP **5**, TN **5**, FP **0**, FN **0**;
precision/recall/F1 **100%**, FPR **0%**. These values are not held-out evidence.

**Baseline long-TXT rule, validation only:** TP **0**, TN **4**, FP **1**, FN **5**;
precision/recall/F1 **0%**, benign-scenario FPR **20%**. The repeated legitimate
TXT-selector case alerts on its first query; all five encoded attack scenarios
are missed. The training/configuration split reproduces the same counts. F1 here
is the existing scorer's defined zero for zero precision plus recall; historical
documents with an undefined display are not silently rewritten. Early-TP fraction
is undefined because there are no TPs. These remain disclosed baseline weaknesses,
not proof of performance against production DNS.

**Before versus after this task:** counts match the previously exposed scenario
results. No detector change or new quality gain. The fresh run confirms current
frozen behavior and formal before-completion/timing semantics. Delays are capture/
simulated-event time, not wall-clock processing, persistence, SSE or browser latency.

Exact per-scenario evidence is retained in
[candidate results](verification/dns-accuracy-check-20261021/development.json) and
[baseline results](verification/dns-accuracy-check-20261021/baseline-rule.json).

## Why independent accuracy could not be run

The frozen contract still has `reserved_set_ready=false` and no reserved manifest.
Required evidence has not been supplied by the current intake:

- >=20 independent positive sessions with tool/client/namespace/original time
  labels. The acquired dnscat2 file has a supported header and producer lab
  context, but no qualified independent session/time manifest; exports are not
  counted as separate sessions or wholly malicious packet sets.
- >=50 independently labelled benign sessions across CDN/cloud, telemetry,
  service discovery, legitimate TXT and machine-generated hostnames. The inspected
  Burgos first capture proves 72 visible questions and one observed querying
  source, not 72 independent sessions or the five category labels.
- Complete qualified session exports, exposure/disjointness review, immutable
  whole-session roles and manifest. None is fabricated from filenames or by
  dividing the capture into windows.

Ran reserved mode as a readiness preflight. It returned
`Reserved evaluation blocked: qualified frozen data is unavailable` with a
nonzero shell exit (tool reported **1**). No reserved output, manifest access,
question scoring or consumed-pass receipt was created. This is an expected safety
refusal due to missing data, **not a failed or completed reserved accuracy run**.
The single reserved pass remains unused.

The candidate's development numerical checks are true, but those cannot override
missing formal coverage/independence. All frozen gates remain recall >=80%,
precision >=95%, session FPR <=2%, every TP before completion and >=90% of TPs
by query ten AND within ten seconds, with the unchanged 20/50 and category/tool
requirements. Independent TP/TN/FP/FN, precision/recall/F1/FPR and alert timing
remain **unavailable/NOT ESTABLISHED**, rather than zero or a passing value.

## Files, verification and freeze

Added this report, a dated baseline-comparison driver and immutable protocol,
results/command logs/pins/checks. Updated only current plan/progress pointers.
The CLI's Windows CRLF output is stored as LF with an explicit serialization
receipt: JSON values are identical and exact original bytes can be reconstructed
and SHA256-verified. No result was recomputed or changed to pass a gate.
No product/scorer/test code, raw data, model, alert history or existing report was
changed. No new regression tests were needed because no bug or behavior changed.

**115 existing targeted tests pass**, one existing Starlette/httpx deprecation
warning, in **3.89 seconds**. They cover candidate features, formal metrics/timing,
blocked-mode non-access, single-pass claims, source contract, visibility and
schema/parser behavior. Full backend/frontend builds were not rerun for this
offline measurement/documentation-only task. No broader fresh pass is claimed.

All **130 protected originals**, both newly acquired raw captures, their prior
frozen source/verification packages and the contract/source pins remain unchanged.
Evidence: [checks](verification/dns-accuracy-check-20261021/checks.json),
[test log](verification/dns-accuracy-check-20261021/tests.log),
[preflight](verification/dns-accuracy-check-20261021/reserved-preflight.json).
Freeze these scoped outcomes and limitations; do not keep rerunning the same
exposed examples as a substitute for independent evidence.

## Definition of Done and exactly next

**Controlled accuracy regression DoD: PASS. Complete independent accuracy
validation DoD: BLOCKED.** Candidate stays disabled; the legacy active rule stays
unchanged with its limitations disclosed. Release is NOT READY.

Exactly next: qualify a publicly released executed-session annotation bundle for
real dnscat2/iodine positives and independent benign application controls, then
freeze complete/disjoint roles and exports. Only after all prerequisites and
choices are verified may the unchanged candidate use the single reserved pass.
No threshold adjustment, new training, new architecture or synthetic result can
replace that missing evidence. Do not implement a new experiment in this task.
