# T20 — UDP-flood observability and next-experiment decision

16 October 2026. Baseline commit `8950e0b`.
**Decision DoD: PASS; UDP quality: UNRESOLVED / data-and-representation blocker.**
No runtime rule, feature, model, threshold, candidate activation or gate changed.
No training, new scenario generation, counterfactual scoring, reserved evaluation,
data acquisition, external lookup/message, database write or packet transmission.

## Inspected scope and reproducible method

Reviewed `UDP_FLOOD_VALIDATION.md`, `BASELINE_FAILURE_ANALYSIS.md`, original UDP
development/release-audit JSON and the 7 October attribution report, completion
plan, `validate_udp_flood.py`, `analyze_baseline_failures.py`, current Pipeline,
FeatureExtractor/RateWindow, model vector/loading, TrafficEvent, parser and packet
adapter. The completed encrypted fingerprint ablation is not repeated.

Extended the existing offline failure diagnostic with `--group UDP`; its default
all-group path remains available. The scoped run opens only the existing UDP
development report and generator, not other detectors' evaluation sets. It checks
generator identity, inventory, labels/format, event counts, first-FP event/evidence
and actual model/rule attribution. All ten already exposed scenarios remain.
Positive/negative verdicts below are historical, not a refreshed accuracy score.
The old UDP report predates recovery staging; only recorded FP outputs are newly
replayed against current source. Positive streams are used for representation
comparison, not a new inference-quality evaluation.

Opposite-label model-vector collisions are additionally compared in full serialized
TrafficEvent metadata and complete causal extractor dictionaries. These are
metadata comparisons, **not raw-packet byte equality**. The legacy report key
`identical_raw_event_pairs` means serialized TrafficEvent equality. Scenario names,
labels and capture identities are never inputs to the extractor/model.

Reproduce with an unused output path (existing outputs are preserved):

```powershell
.venv/Scripts/python.exe -B -m datasets.analyze_baseline_failures --group UDP --output udp-observability.json
.venv/Scripts/python.exe -B -m pytest -q -p no:cacheprovider tests/test_udp_observability.py tests/test_udp_flood.py tests/test_baseline_failure_analysis.py
```

Do not run `validate_udp_flood`'s main function here: it overwrites an old report.
The final run uses the final diagnostic source; an earlier attempt was stopped
while input guards were being completed and produced no report. It is not evidence.

## False positives and current attribution

All four recorded first DDOS false positives reproduce exactly:

- `benign_quic_bulk`: event 10,000; target rate 1,000 packets/s; mean 1,200 bytes;
  HYBRID, top GNB class DDOS, posterior 1.0.
- `benign_dns_queries`: event 10,000; target rate 1,000 packets/s; mean 80 bytes;
  HYBRID, top GNB class DDOS, posterior 1.0.
- `benign_video_bulk`: event 3; target rate 1,200 packets/s; mean 1,200 bytes;
  HYBRID, top GNB class DDOS, posterior 1.0.
- `benign_telemetry_many`: event 25; target rate 1,000 packets/s; mean 256 bytes;
  HYBRID, top GNB class DDOS, posterior 1.0.

Posteriors are saturated synthetic-trained estimates, not calibrated likelihoods
of attack intent. The UDP rule independently matches target rate >=1,000, so merely
retraining the model or changing its confidence cannot suppress these rule hits.
First-alert attribution does not describe later suppressed decisions.

Retained historical counts: TP 4, TN 2, FP 4, FN 0; precision 50%, recall 100%,
F1 66.67%, benign-scenario FPR 66.67%. No new quality gain or FP/FN change is claimed.
Four positives are too few to establish coverage; no public/production accuracy.

## Exact representation finding

`flood_single_large` and `benign_video_bulk` each contain four flow summaries,
4,000 packets and 4,800,000 bytes per event at identical one-second timestamps.
All serialized TrafficEvent values agree **except destination port: 9000 vs 5004**.
All 20 log-transformed GNB inputs and the **entire runtime feature sequence** agree.
The UDP rate-rule decision sequence also agrees, first matching at event 3.

Model-vector sequence SHA256:
`804003f989ca24f87c4c20979a3d2bf380a950933e501d123488254a00f89d32`.

This is a proven representation collision, not proof that complete observed
metadata is identical. Destination port is visible but is not a reliable standalone
intent label. Exempting 5004/443/53/8125 or treating 9000 as malicious would fit this
generator's service assignments. It would not establish behavior on floods using
those same services. Source addresses, scenario names or generated flow IDs must
not become substitute predictors.

There is a precise constraint on this exposed four-positive/six-benign matrix:
recall >=80% requires all four positives (3/4 is 75%). A deterministic decision
using the current identical feature sequences must also alert on the video control.
Even with every other benign case correct, FPR is at least 1/6 = 16.67% and precision
at most 4/5 = 80%. Thus no threshold/model choice using this representation can
satisfy all three quality criteria on this matrix. This is **not** a mathematical
claim about every future UDP dataset, all richer passive metadata, or the unexamined
reserved matrix. Do not remove the contradictory hard control to make a score pass.

## Feature and visibility diagnosis

- Target packet/byte totals are independent of the 512-event source history.
  At the raw 10,000th-event FPs, rate evidence is 1,000/s despite bounded source
  history. The existing one-second bucket/ten-second denominator semantics remain;
  this task does not retune warm-up or expiration behavior.
- Source diversity/entropy, target concentration and size behavior are already
  available to runtime evidence. Diversity does not prove forged sources; a
  concentrated legitimate workload is possible. The video collision includes
  these features too. A size/concentration threshold cannot separate that pair.
- Aggregate size CV is explicitly a `summary_mean_proxy`; within-summary packet
  variance cannot be recovered from bytes/packets. Raw fixture sizes have exact
  packet-level visibility. Missing observations must remain missing.
- Raw DNS fixture questions are actually parsed. DNSRecord has `is_response`,
  but TrafficEvent/from_packet do not carry this field. This is a potential
  representation gap, not evidence that a DNS question/response exemption is safe:
  both legitimate DNS and DNS floods can contain valid questions or responses.
  Do not implement that feature without qualified paired evidence.
- `benign_quic_bulk` is UDP/443 with zero-filled payload. The adapter marks it
  encrypted/QUIC from port context; no actual QUIC handshake proves its application
  identity. It is a **QUIC-like controlled bulk proxy**, not a qualified real QUIC
  benign capture. The other workload names also express generator provenance,
  not passively established authorization or packet-level malicious intent.
- Completed CIC UDP feature CSV rows lack the causal packet/timestamp/endpoint
  joins needed for this runtime experiment. Mixed/truncated DNS-category captures
  cannot supply uniformly malicious labels. No such raw values were newly read.
- Reflection, amplification factor, source forgery and authorization are not
  proved by one-way rates. Retain the current cautious evidence wording.

The immediate failure is **overlapping development data + insufficient separating
evidence**, with rate-only rule behavior and a synthetic model contributing to FPs.
It is not demonstrated to be a packet-accounting defect. New entropy, size or port
thresholds on the existing cases are not a justified next implementation.

## ONE smallest next experiment — not implemented

**Same-service, matched-load UDP development separability qualification.**

Before opening new values, freeze a metadata-only inventory/provenance manifest for
one independently labelled flood run and one independently labelled authorized
high-volume application run on the **same actual UDP service/port**, with overlapping
rate and packet-size ranges. Use existing, permitted, complete classic Ethernet
PCAP observations, original capture times, documented capture/run boundaries and
verified workload labels. Labels/authorization remain evaluation annotations only.
Do not synthesize permission/labels, rewrite ports, require reverse traffic,
execute attacks, or acquire a source without appropriate permissions.

Assign this pair to development only; it can never become an untouched final set.
Compare the existing causal metadata/features to determine whether an actually
observed distinction survives matching service and load. Record absent fields and
remaining collisions. Do not train, change rules, score a reserved set or declare
accuracy from two runs. Independent producer/run groups and fuller controls would
still be needed before any later training/validation/final partition.

Non-regression/stop criteria:

- Preserve all ten exposed controls, their labels and failed results; do not replace
  them with the easier new pair or fabricate absent fields in old summaries.
- A proposed future feature must be observed passively and causally in both training
  and runtime; no label/source/capture identity or port-only exception. Document its
  applicability/missingness before any implementation experiment is authorized.
- If permissions, labels, timestamps, format or a justified separating observation
  are absent, stop with the data/visibility blocker. Do not force alerts/suppression.
- Existing frozen recall >=80%, precision >=95%, FPR <=2%, timing, accounting and
  single/distributed/small/large coverage requirements remain unchanged. Any later
  candidate requires its own choice freeze and independent reserved evaluation.
- Any later shared runtime change must pass UDP/SYN accounting, missing-reverse
  semantics, full backend and frontend build checks. Those changes are not made here.

**T21 runtime improvement is blocked pending this qualification; no code experiment
is justified by the current ten cases alone.** If identical observations with
opposite intended labels persist, report the observability conflict explicitly;
it cannot be silently resolved by changing the official requirement or gate.

## Changes, tests and freeze

Changed only the existing offline diagnostic (UDP selection, label/format guard
and exact collision detail), seven targeted diagnostic tests, this decision and
current plan status plus dated evidence. **23 targeted tests passed**: seven new
observability cases plus 16 existing UDP/diagnostic regressions. Tests cover port-only
versus true feature differences, identical/empty/non-UDP/unaligned inputs, scoped
imports/report access and changed-label rejection. No detector bug was fixed.

Full backend/frontend build were not repeated: no shared runtime or frontend code
changed. The preceding clean-checkout evidence remains 443 passed/two optional
skips plus typecheck/build; it is not a new full-suite result for this task.
Preserved runtime/model and original report/protocol hashes are recorded separately.
The diagnostic does not open an analyst database. No measured runtime speed/accuracy
improvement is claimed.

Freeze the diagnostic behavior, tests, exact report, limitations and this decision.
The legacy UDP heuristic remains active but **unvalidated**; no new candidate is
trained or enabled, and failed experimental artifacts remain untouched. Release
remains NOT READY. Next incomplete task is the single T21 development-data
qualification experiment above, not detector tuning.

Evidence: [report](verification/udp-observability-20261016/report-final.json),
[tests](verification/udp-observability-20261016/tests-final.log) and the adjacent
protocol/integrity/freeze records.
