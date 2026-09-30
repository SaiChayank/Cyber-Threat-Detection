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

Pending the development comparison and one reserved replay.
