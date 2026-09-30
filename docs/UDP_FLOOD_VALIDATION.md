# UDP flood / amplification-style validation — frozen gate

## Preregistered controlled evaluation design (30 September 2026)

This gate was written before constructing or replaying the reserved UDP
evaluation scenarios. Existing rule code, rate-window tests, the SYN-only
validation report, `data/cicddos2019_manifest.json`, and DNS capture
visibility documentation were inspected first. No frozen model artifact is
changed. This is a passive UDP/17 task only; it neither verifies reflection
nor tests TCP SYN, C2, reconnaissance, DNS tunnelling or other detectors.

Classify independently labelled whole scenarios with a fresh `Pipeline()` in
timestamp order. A positive is a controlled high-rate UDP flood toward one
victim. A benign negative is an authorised high-volume UDP workload. TP means
the first `DDOS` alert occurs before the final event; final-event-only or no
alert is FN. Any `DDOS` alert on a benign scenario is FP; otherwise TN.
Record first-alert event and capture time, rates, mean/variation of observed
packet sizes, destination concentration, source count/entropy and evidence.
The same generator family may be used for development, but reserved seeds,
source populations, destinations and size/rate settings must be disjoint and
must not influence threshold choices after their results are viewed.

The reserved controlled matrix has **eight positives**: raw-packet single-
source and 32-source floods at small (~64-byte) and large (~1,200-byte) sizes,
plus four aggregated-flow floods with mixed packet sizes and single/distributed
sources. Each is above the pre-existing 1,000 packet/sec ten-second rate floor
for long enough to alert incrementally. The **twelve negatives** include
single- and multi-source high-volume QUIC-like bulk UDP, high-rate legitimate
DNS-like query/response traffic where complete metadata is visible, telemetry,
media/game-like UDP, and high aggregate UDP volume spread across destinations.
Some benign cases deliberately overlap flood rates and packet sizes to test
the ambiguity of passive metadata. DNS and QUIC labels are workload provenance,
not inferred protocol identity from port alone. At least four cases on each
side use parsed raw packets; the rest use explicitly labelled flow summaries.

Promotion of a UDP-specific rule requires **all** of:

- Scenario recall >=80%, precision >=95%, and benign-scenario FPR <=2%.
  With twelve negatives, this means **zero** FPs; report exact TP/TN/FP/FN,
  F1 and the small denominator rather than claiming population FPR.
- At least one detected single-source and one detected distributed-source
  flood, and at least one detected small-packet and one large-packet flood.
- Every TP alerts before scenario completion and by the event that first
  reaches 10,000 target UDP packets in the rolling ten-second rate window.
- Packet and byte rates equal causal bucket totals divided by ten, even past
  the 512-event source-history bound. Per-destination source entropy and
  packet-size evidence must match independently calculated references; source
  overflow and summary-based size variation must be disclosed.
- Evidence names the destination-scoped observed traffic and uses cautious
  wording: **“consistent with UDP reflection/amplification behavior”** only
  when the pattern warrants it. It must never state that reflection, spoofing,
  or an amplification factor was proven from one-way metadata.

The 99,895 labelled UDP rows in the local CIC-DDoS2019 CSV cannot validate
this causal runtime rule: they are completed flow features without original
packet timestamps and addresses. The two benign-reference CIC DNS PCAPs and
twelve mixed/truncated attack-category PCAPs also lack the joined per-session
truth needed for these scenario counts. They can support visibility or
qualitative checks, not a fabricated TP/FPR denominator. Controlled simulation
quality is not production/generalisation accuracy. A failed gate stays failed;
no threshold is lowered or evaluation set reused for tuning.

## Results and decision

**Unresolved; the reserved eight-positive/twelve-negative matrix was not
constructed, inspected, or replayed.** The development cases already fail
two frozen quality gates, so a reserved score would not justify promotion.
`ml/udp_flood_development_initial.json` preserves the pre-fix result and
`ml/udp_flood_development.json` records the same ten development scenarios
after the narrow attribution/evidence fix, including source-file SHA256s.

| Development-only result | TP | TN | FP | FN | Precision | Recall | F1 | Benign FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Previous global-rate / synthetic-model path | 4 | 0 | 6 | 0 | 40.0% | 100% | 57.1% | 100% |
| Destination-scoped UDP rate and model guard | 4 | 2 | 4 | 0 | 50.0% | 100% | 66.7% | 66.7% |

Previously the frozen synthetic classifier emitted `DDOS` on UDP flows as
early as 12.4 observed packets/sec and on a sparse target when unrelated
destinations raised the global rate. The existing rate rule also used that
global rate. The fix requires at least 1,000 **destination-scoped UDP
packets/sec** for either rule or model-backed UDP `DDOS` alerts. The rolling
window retains full packet/byte totals beyond the 512-event source-history
bound. Alert evidence now includes destination packet and byte rates, global
rate for context, source count and entropy, destination concentration, and
observed mean packet size/CV. For flow summaries, the latter CV is marked a
`summary_mean_proxy`: within-summary size variance is not visible.

All four controlled floods now alert before completion: raw single-source
small and 32-source large cases at packet **10,000 of 12,000**; aggregate
single-source large at event **3 of 4** (12,000 packets); aggregate 32-source
mixed sizes at event **25 of 32** (10,000 packets). The corresponding target
rates at first alert are 1,000, 1,000, 1,200 and 1,000 packets/sec. The
spread-across-20-targets workload and the low-rate DNS-like workload no
longer alert. Packet size is not a safe separator: the single-source
1,200-byte flood and authorised video-like bulk have identical passive
rate, size, entropy and concentration features. A 32-source large flood and
high-rate DNS-like queries have the same rate, source entropy and target
concentration; size differs but other authorised bulk traffic uses large
packets. The remaining FPs are high-volume QUIC-like bulk (packet 10,000),
DNS-like queries (packet 10,000), video-like bulk (event 3), and multi-source
telemetry (event 25). These are labelled controlled workloads, not public
capture ground truth. The classifier artifact was not modified, no port/size
exemption was fitted to this tiny development set, and no gate was weakened.

The output says “consistent with UDP reflection/amplification behavior” only
for a high-rate, diverse-source, larger-packet pattern, and explicitly says
passive metadata cannot verify reflection or amplification. It makes no
claim to prove forged addresses or a measured amplification factor. Even
this qualified pattern overlaps legitimate traffic; no UDP-specific rule is
accepted as validated. The existing heuristic remains active with this
narrower attribution, but its development false-positive rate makes it
unsuitable as an independently verified UDP flood detector. No production
FPR or generalisation estimate is available from these synthetic cases.

Shared feature-cost check: the 20,000-event **core processing + SQLite**
benchmark measured 3,888 metadata events/sec and 1.07 ms p95 processing plus
persistence, versus the preceding report's 4,822 events/sec and 0.87 ms p95
on the same declared workload. Both clear the existing 2,000 events/sec and
50 ms targets. This benchmark excludes capture, HTTP, SSE and browser stages
and is not an end-to-end throughput claim.

The smallest next experiment is to obtain **independently labelled,
time-stamped UDP flood and authorised high-volume UDP streams** with packet
and destination provenance, then test a separability hypothesis on a new
training/validation partition. Freeze any new acceptance design before
opening a reserved partition. Do not treat the mixed public captures or
completed flow CSV as causal ground truth.
