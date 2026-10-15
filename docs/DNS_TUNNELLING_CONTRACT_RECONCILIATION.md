# DNS-tunnelling runtime contract reconciliation

15 October 2026. **Current configuration frozen; reserved evaluation BLOCKED.**
The September formal protocol and numerical gates remain unchanged. Its historical
runtime identity is superseded only by the new source-pinned configuration in
`data/dns_tunnel_evaluation_contract.json` with SHA256 sidecar. No existing final
evaluation result is carried forward: none exists. A newly qualified, independently
reserved session set is required before one formal pass.

## Inspected and reconstructed baseline

Read the formal protocol, candidate/development report and evaluator, pipeline,
feature extraction/history, rate windows, packet reader/adapter/parser, schemas,
models, and event-recovery tests. Found the exact protocol pipeline bytes in Git
commit `12c7933715662e8291154304c44607b429085d11`, matching SHA256
`c01de15ed0fff1c3576cd757e0665c78358bd3a0efd365c3ddb11e32c9efdb86`.
This is an exact historical identity, not a guessed reconstruction from prose.

The diagnostic restores tracked historical detection/features/schemas/model files
to a temporary directory and runs a fixed worker separately against historical
and current source trees. The same installed Python/dependencies are used for
both; this is not historical environment or performance reproduction. Inputs are
only the existing 20 previously exposed synthetic development scenarios. No raw
capture, new publisher label rows or reserved data read. No fitting or tuning.

Evidence and reproducible diagnostic are in
`verification/dns-contract-reconciliation-20261015/`. Existing reports are never
overwritten; the diagnostic now refuses existing output before doing work. Run
only in a new evidence directory/work copy after preserving the frozen record.

## Differences and implications

- Pipeline now stages causal state and publishes it only after successful
  inference/optional atomic persistence. A failed query is retryable without
  consuming history or duplicate suppression. Latency telemetry is measured
  outside the staged detector; it is not the capture-time detection delay.
- Shared SYN/UDP target accounting, forward-byte windows, observed-zero reverse
  handling and other-threat evidence/deduplication changed. Those changes are
  preserved; none was reverted or adjusted for DNS results.
- DNS candidate predicate, eight feature definitions, source history append/order,
  10-second window, 128 same-base cap, last-two-label base proxy and DNS dedup key
  are unchanged. DNS opt-in mode suppresses synthetic-model DNS predictions.
  DNS rule-only alerts retain MEDIUM severity, strength .8 and heuristic wording.
- Packet adapter adds SYN packet accounting; it does not change DNS name/type/time
  mapping. Parser still supports only complete currently representable questions,
  and cannot certify unseen capture format or QNAME preservation from filenames.

## Measured development compatibility

Compared 240 event traces across 20 scenarios, including all eight DNS features
and every DNS alert's stable fields/evidence. Excluded random UUID and creation
wall time, not captured event timestamps or flow identifiers. Results:

- **0/240 DNS feature-vector disagreements.**
- **0/240 stable DNS alert-list disagreements.**
- **0/20 first-alert query/capture-delay disagreements.**
- All ten synthetic attacks first alert on query 5/12 in both versions; the five
  validation attack delays are 7,200 / 4,400 / 4,800 / 3,800 / 6,000 ms. All ten
  known benign development scenarios produce no candidate DNS alerts in either.

These are compatibility diagnostics on already used inputs, not independent
accuracy, a promotion decision, mixed-network equivalence or CPU benchmarks.
Bounded-history eviction, very slow traffic and other unseen distributions can
still change outcomes. At intervals >2.5 seconds, five-query evidence cannot be
available by 10 seconds; the unchanged timing gate may therefore fail for such
sessions. Do not remove them or lower the gate to manufacture a pass.

## Frozen evaluation scope and remaining safeguards

New contract pins 23 production/data-definition files, historical protocol hash,
unchanged predicate, gates and source exclusions/prerequisites. Measured arm is
`Pipeline(dns_tunnel_candidate=True)` with synthetic model predict overridden to
BENIGN exactly as in prior controlled comparisons. Only DNS_TUNNELLING output is
scored. Default runtime remains candidate-disabled; this offline arm is not the
production mixed-threat/API/SSE service or automatic runtime promotion.

Inputs are independently annotated, complete client DNS questions; verify QR=0
from source sidecar, actual QNAME/QTYPE, source and capture time, preserve capture
order/observed duplicates and disclose unsupported/late observations. First
question only, matching parser capability. Do not fabricate rows for missing types
or silently discard difficult labelled sessions. Session isolation and query-only
arm do not prove behavior under arbitrary mixed-source/background history pressure.
No new protocol support, return traffic, probes, lookups or decryption.

Keep >=20 positive and >=50 benign independent sessions with all five controls;
recall >=80%, precision >=95%, benign-session FPR <=2%. True positives must occur
before the final query; >=90% of TPs must satisfy BOTH query<=10 and delay<=10s.
Undefined denominators cannot pass. The development evaluator's `summary()` counts
any alert and is **not a qualified formal scorer** for final-query-only FN/timing
semantics. Do not run that development script on reserved data. A conforming,
frozen scorer and session manifest remain prerequisites, not work done here.

Publisher permissions, full-question capture visibility, independent session truth,
whole-run/fragment disjointness and qualified benign coverage remain unresolved.
No reserved manifest has been materialized; the single pass has not been consumed.
Do not reinterpret the historical no-promotion decision as current acceptance.

## Tests, changes and freeze

Six added tests guard exact source/protocol integrity and gates/data block, disabled
default, suppression of an untrusted synthetic DNS posterior, preserved rule-only
evidence/timing, DNS query-five retry after persistence failure and refusal to
overwrite diagnostic evidence. Combined DNS/parser/event-recovery suite:
**70 passed in 12.30s**, one existing Starlette/httpx deprecation warning.
Earlier intermediate 68-test pass preceded the last two safeguards.

Files added: current contract + sidecar, six-test module, this report and new
diagnostic/evidence directory. Completion plan supplemented. No production code,
models, thresholds, datasets or analyst history changed; 69 protected source/model
files are byte-identical before/after comparison. Full backend/build/browser runs
from earlier tasks remain historical; not rerun because shared runtime is unchanged.

**Definition of Done:** reconciliation/configuration freeze PASSED within the
stated development scope. Historical protocol preserved. Freeze diagnostic, tests,
source contract, comparison results and limitations. DNS-quality acceptance remains
BLOCKED. Exact next action: assess Korving's response for compatible permitted
captures, independent labels and benign controls before any acquisition or scoring.
