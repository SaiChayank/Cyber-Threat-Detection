# T22 — suspected spoofed-source observability diagnosis

17 October 2026. Baseline `06fb845`.
**Diagnostic DoD: PASS. Subtype quality: UNRESOLVED / visibility blocker.**
The failed diagnostic predicate remains disabled. Runtime still emits generic
`DDOS`, not a spoofed-source subtype. No runtime, model, threshold, horizon,
acceptance gate, dataset, alert history or other detector behavior changed.

## Inspected scope and method

Reviewed `SPOOFED_SOURCE_VALIDATION.md`, the original and release-audit JSON,
existing generator/tests, prior baseline-failure and semantic/parity decisions,
current extractor/RateWindow, Pipeline evidence/rules/guards/model combination,
TrafficEvent and the completion plan. Existing ten scenarios are exposed synthetic
flow-summary development evidence; no new captures, annotations or reserve.

Added `--group SPOOF` to the existing failure diagnostic. The historical default
five-group inventory remains unchanged. This scope imports/opens only the spoof
generator and its release-audit report, checks labels/inventory/source and stream
hashes, then replays only four recorded generic-DDOS FPs up to their first alert.
Actual first position and complete evidence must match; model predictions are
observed unchanged to establish attribution. No positive quality replay occurs.

The old spoof report has **no model checksum**. The scoped diagnostic explicitly
requires the existing baseline/semantic-audit artifact reference:
`4d8e08323374535789e21f9f7cd1ee3f1c84b663ce555e67bb4ced57c95e8010`.
That pins this replay, not independent proof of the original training execution.
Historical runtime sources predate recovery staging. We verify these four FP
outputs, not retroactively claim a full current-runtime evaluation of every row.

Separately reconstruct the existing target-window/singleton snapshots and unchanged
disabled predicate without Pipeline/model inference. Check every saved first/final
snapshot, keep historical counts, and hash complete diagnostic feature sequences.
Compare opposite-label model collisions in full serialized TrafficEvent metadata
and all runtime features as well. Legacy key `identical_raw_event_pairs` means
metadata equality, **not PCAP byte equality**. Names/provenance never enter inference.

```powershell
.venv/Scripts/python.exe -B -m datasets.analyze_baseline_failures --group SPOOF --output spoof-observability.json
.venv/Scripts/python.exe -B -m pytest -q -p no:cacheprovider tests/test_spoof_observability.py tests/test_spoofed_source_validation.py tests/test_baseline_failure_analysis.py tests/test_udp_observability.py tests/test_c2_observability.py tests/test_c2_beacon_validation.py
```

Use an unused output filename. Do not run the generator's main: it overwrites
the historical validation report. The dated protocol preceded reconstruction.
`report-final.json` is current; the earlier `report.json` is preserved and predates
the added full diagnostic-sequence hash. Neither is a fresh quality evaluation.

## False positives — exact current first-alert attribution

All four generic-DDOS FPs reproduce as **HYBRID**, top GNB class DDOS with
posterior 1.0, and an independently true target UDP rate rule:

- `genuine_distributed_32`: event 25 / 2.4 seconds; 1,000 packets/s, 1,200,000
  bytes/s, 25 sources, entropy 4.643856 bits, target concentration 1, size 1,200.
- `flash_crowd_64`: event 50 / 4.9 seconds; same packet/byte rate and size,
  50 sources, entropy 5.643856 bits, concentration 1.
- `genuine_repeat_32`: event 25 / 2.4 seconds; same first evidence as the
  distributed-32 case, before any source repeats.
- `authorised_telemetry_32`: event 25 / 2.4 seconds; 1,000 packets/s, 256,000
  bytes/s, 25 sources, entropy 4.643856 bits, concentration 1, size 256.

Sizes are bytes/packets **summary means**, not recovered per-packet variation.
The rate uses the existing fixed ten-second denominator and one-second buckets,
including partial warm-up. Delays are observed event time, not API/SSE latency.
Posteriors are synthetic-trained and uncalibrated, not probabilities of forgery.
Changing model confidence alone cannot suppress these independent rate-rule hits.

The fixed, **disabled** subtype predicate also indicated at the same four benign
event positions. Its requirements remain: >=1,000 target packets/s, >=16 sources,
entropy >=3.5 bits, observation singleton fraction >=0.75, concentration >=0.8
and complete source identities. The same causal snapshots reproduce exactly.

## False negatives and quality scope

There are **no historical FNs** among four exposed positive simulations. The saved
disabled-predicate indications occur at events 25/32, 50/64, 25/128 and 31/40,
all before the final event. This is not measured real forged-packet recall or
coverage of low-rate, protocol, source-population or environment variation.

Both saved mechanisms retain **TP4, TN2, FP4, FN0; precision50%, recall100%,
F1 66.67%, benign-scenario FPR66.67%**. No before/after metric improvement.
Frozen recall>=80%, precision>=95%, FPR<=2% and matched-benign/early-indication
requirements remain failed. No reserved set is constructed, inspected or scored.

## Separability, features and evidence quality

**Three complete collisions.** `forged_32_once`/`genuine_distributed_32`,
`forged_64_once`/`flash_crowd_64`, and
`forged_32_repeat`/`genuine_repeat_32` match in every supplied event field,
complete runtime features, all 20 model inputs and UDP rate-rule sequences.
The differing ownership/emitter stories are external generator annotations.
No deterministic function of those identical observations can classify both sides
correctly. This is intentional development ambiguity, not newly discovered
train/test contamination. Keep the hard controls and their original labels.

On this four-positive/six-benign matrix, recall>=80% requires **all four TPs**.
The three exact pairs then force at least three FPs: FPR>=50%, precision<=4/7
(57.14%), even if every other benign case were correct. This bound applies to
this exposed matrix and supplied representation, not every future dataset.

**Telemetry adds a narrower-feature collision.** It differs from the 32-source
positive only in bytes. Full runtime/model vectors differ, but every snapshot
in the disabled subtype's diagnostic feature sequence is identical. A mechanism
using only that sequence would additionally force the telemetry FP: at least
four FPs/FPR66.67% and precision<=50% if all four positives are retained. A size
exception would fit generator sizes; no independent evidence justifies it.

**Destination concentration is useful, but not proof of forgery.** The dispersed
benign control collides with `forged_32_once` in all GNB vectors, despite different
destination addresses and complete runtime features. It ends at concentration
1/32 and target rate40/s; the frozen target-rate guard rejects it, preserving
its historical TN. Low-rate diverse clients end at320/s and are also TN. Their
rejection does not distinguish a concentrated flash crowd from forged sources.

**Singletons must be causal observations.** At the repeat-case first indication,
25 distinct sources have one summary each, so the fraction is1; every summary
represents400 packets. At completion, the causal window fraction is0. Using
that later value to suppress an earlier indication would leak the future. These
source counts do not establish how many emitters owned the addresses or whether
one-packet sources existed on the wire. Within-summary packet times are absent.

**Entropy and bounds have defined scopes.** Target entropy is packet weighted;
the shared GNB's global entropy is event weighted. Equal per-summary packet
counts in these examples conceal that distinction. All populations are<=64,
below the256 target identity cap, so no overflow explains the failures. Rate
totals are independent of bounded per-source event history. High-cardinality
overflow, late events, packet granularity and new captures are not validated
by this diagnosis. Do not extrapolate exact identities beyond disclosed bounds.

**Runtime versus subtype.** The active generic UDP rule uses target rate, without
singleton/entropy/concentration as necessary spoof conditions. The disabled
predicate is offline-only; singleton fraction is not an active GNB input. Adding
these five indicators by themselves cannot repair the proven collisions. Model
synthetic diversity and historical semantic-drift limitations remain; current
trainer/extractor parity does not prove frozen-artifact compatibility. No model
ablation or causal claim about individual feature contributions was made.

The primary problem is **visibility/data non-separability**, reinforced by a
rate-only generic rule and saturated synthetic model. Source identity, ownership,
IP reputation, a scenario name or its label must not become shortcut predictors.
No forward observation here proves addresses forged. Runtime wording stays generic
and qualified; any future subtype must say **consistent with suspected
spoofed-source flood** or equivalent, never passive proof of forgery.

## ONE smallest next experiment — not implemented

**Qualify one already-collected, producer-labelled forged/genuine lab pair for a
passive separability check.** Before new values, freeze provenance for two permitted
original classic Ethernet PCAP runs on the same UDP service with overlapping load:
one lab emitter deliberately assigning source identities and one genuinely
distributed authorized workload. Require independent producer emitter/ownership
records, original timestamps/run boundaries, capture placement and file hashes.
Provenance supplies evaluation truth only, never an inference feature.

Then compare what existing forward passive observations actually preserve and
whether any genuinely observed distinction survives matched service/load. Record
unavailable fields and collisions; no training, feature implementation or scoring.
Do not execute attacks, probe sources, require return traffic, decrypt content,
use a mixed attack-category label as proof or manufacture packet times.

Stop if no permitted independently labelled pair exists or observations still
overlap. No further threshold/model trial on these ten cases is justified. A
later representation change needs its own authorization and exact training/runtime
definitions. Preserve all ten hard controls, frozen gates and disabled status.
This experiment is a data/visibility qualification, not a promotion path by itself.

## Tests, preservation and freeze

Added **19 diagnostic regression cases**. **66 targeted tests passed**, including
existing spoof validation, baseline attribution, UDP and C2 diagnostic/validation
checks. Cover full/partial feature collisions, causal prefixes, observation versus
packet counts, dispersed-target controls, invalid order/protocol, changed labels/
snapshots/counts/model, scoped imports/report reads and exactly125 model calls
(only the four recorded FP prefixes). The default diagnostic inventory is retained.
No runtime bug was fixed and no shared runtime/frontend file changed, so the full
backend/build were not rerun. Previous full-suite/build evidence stays historical.

Updated only the offline diagnostic, new tests, this decision, plan statuses and
dated evidence. Protected runtime/models/data manifests, original generator/reports
and analyst SQLite/history hashes remain unchanged. No new throughput, latency,
accuracy, calibration or generalization result is claimed. Freeze this diagnostic
behavior, tests, source-matching report and limitations. **T22 quality remains
BLOCKED; release remains NOT READY.**

Evidence: [protocol](verification/spoof-observability-20261017/protocol.md),
[final report](verification/spoof-observability-20261017/report-final.json),
[tests](verification/spoof-observability-20261017/tests.log), integrity/freeze records.
Exactly next: the single lab-pair provenance qualification above; no acquisition,
source contact or detector experiment has started.
