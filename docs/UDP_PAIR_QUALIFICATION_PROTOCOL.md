# T21 — same-service UDP development-pair qualification

Frozen 16 October 2026 against baseline `588d2cc`, before reading any new
capture values. This is source/data qualification, not a detector experiment or
an acceptance evaluation. Publisher descriptive metadata was inspected first.

## Required provenance before packet inspection

Select one flood run and one authorized application run, labelled by the producer's
run records independently of Univect predictions. Each must have an exact artifact
URL/version, reuse permission, SHA256, run boundaries, original timestamps,
endpoint/direction mapping and workload description. Mixed attack-day files must
have packet/session-to-run annotations; a day/category name alone is insufficient.
The actual UDP application/service and destination port must agree between runs;
a port number alone does not establish application identity or benign intent.

Use complete classic Ethernet PCAP v2.4 (link type 1), compatible with the current
parser. Verify captured/original lengths and disclose truncation, fragments,
unsupported traffic, duplicates and late events. No format conversion or new parser
support in this task. Do not infer missing application labels from packet shape.

## Fixed load-overlap screen, if provenance qualifies

Use producer-labelled intervals only, original capture order and timestamps. Keep
all intervals in the report, including failures; never select by alert output.
For the documented destination endpoint/service and observed forward direction,
count UDP packets and IP bytes in UTC-aligned one-second bins. Assess complete,
non-overlapping ten-second blocks entirely inside each labelled interval. Exclude
partial edge blocks only from the overlap screen and report their counts.

Both runs need at least three such blocks with >=1,000 packets/s (10,000 observed
UDP packets per ten seconds), retaining the existing UDP rate reference rather
than rescaling time. On those blocks require the observed packet-rate ranges to
overlap with positive width and the pooled IP-packet-length interquartile ranges
to overlap (endpoints inclusive). Report full ranges, quartiles, counts and joint
rate/size distributions; overlap does not prove distributional equivalence.
This screen is fixed for qualification only; it does not change any detector gate.
Do not rewrite ports/addresses, replay faster to manufacture load, duplicate packets,
or label a generic zero-filled UDP generator as an actual application.

If qualified, compare only existing causal metadata/features, with no model/rule
inference, to record surviving distinctions, missingness and collisions. All
observations in this pair are development-only permanently. Run identity, labels,
capture source and endpoint identity remain annotations, never predictors.

## Stop conditions and preservation

Missing permission, run labels, service identity, timestamps, supported complete
format or matched load means NOT QUALIFIED. Record unknowns rather than assuming
they pass. Metadata-only ZIP member listings and publisher documents may be read
to locate runbooks; packet/CSV values are not opened before provenance qualifies.
Bound metadata range downloads to 1 MiB per request and require HTTP 206 with the
requested Content-Range; do not silently fetch a multi-GB archive.

No training, threshold/rule/feature changes, detector scoring, reserved evaluation,
new attack execution, external message or candidate activation is authorized.
Retain all ten existing controlled cases, failed results, raw datasets, alert
history and frozen artifacts. Promotion gates stay recall >=80%, precision >=95%,
FPR <=2%, with existing timing/accounting/coverage requirements. A single pair
cannot establish accuracy or promotion eligibility.

Qualification DoD requires both independently labelled runs plus measured overlap
and a reproducible artifact/provenance record. Otherwise record a blocker and stop;
do not proceed to detector experiments or claim the UDP detector accepted.
