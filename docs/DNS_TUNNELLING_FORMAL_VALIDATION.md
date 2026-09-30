# DNS tunnelling formal validation — frozen protocol and decision

## Preregistered gate (30 September 2026)

The criteria below were fixed **before opening, replaying, or scoring any new
reserved evaluation observations**. The configuration under test is the
opt-in candidate in `detection/dns_tunnel_candidate.py`, with the production
`FeatureExtractor` and `Pipeline(dns_tunnel_candidate=True)`. Its source hashes
are SHA256 `c1713f2a8bbc59753bbad586054e5b103082f4d67bf5c9cfa617383965540a9a`
for the candidate rule, `8ded37ba73c2d605f22baf4571f80842791f7b2b1584ce0230ddc365466605eb`
for DNS features, and `c01de15ed0fff1c3576cd757e0665c78358bd3a0efd365c3ddb11e32c9efdb86`
for the pipeline. Any change to these invalidates this decision and requires a
new, separately reserved evaluation set. The already inspected synthetic
training/configuration and validation scenarios are **not** reserved data.

The unit of classification is a separately labelled DNS session/scenario,
identified by experiment log, process/tool, time interval, source and DNS
namespace. The label must be established independently of detector output.
Replay complete, passively observed queries in capture order, resetting
pipeline state between independent sessions. An attack is a TP only if its
first `DNS_TUNNELLING` alert occurs **before** its final labelled query; a
missing or final-query-only alert is an FN. A benign session with any such
alert is an FP; otherwise it is a TN. Keep every eligible session, including
hard misses and false alarms. Report the first-alert query index, total query
count and elapsed capture time from the first complete query for every attack.
The synthetic model's DNS prediction is suppressed exactly as in the
development comparison, so the measured arm is the candidate rule.

Promotion requires **all** of these fixed conditions on a previously untouched
evaluation set:

| Gate | Threshold / evidence requirement |
| --- | --- |
| Minimum labelled coverage | At least 20 independent positive sessions and 50 independent benign sessions, from captures preserving complete QNAME and QTYPE; documented source hashes and disjointness from development data. Include a real controlled tunnel tool (dnscat2 or iodine) and an independent mechanism if available. Report which A, AAAA, TXT and NULL query types are truly present, plus low (>2 s), medium (0.5–2 s) and high (<0.5 s) inter-query-rate groups. Missing types/rates are explicit coverage limits, never fabricated examples. |
| Recall | TP / (TP + FN) >= 80%. |
| Precision | TP / (TP + FP) >= 95%. |
| Benign-session FPR | FP / (FP + TN) <= 2%. Benign set must include CDN/cloud, telemetry, service discovery, legitimate TXT and machine-generated hostnames, as genuinely labelled traffic. |
| Incremental timing | Every TP alerts before scenario completion; at least 90% of TPs first alert by the 10th complete DNS query **and** within 10 seconds of the first complete query. Report misses and first-alert positions separately by tool, record type and rate. |

Report F1 as `2 * precision * recall / (precision + recall)` when defined.
Denominator-zero metrics are **undefined**, never assigned a passing value.
The 20/50 minimum is a practical floor, not a claim of production certainty.
If capture truncation, missing ground truth, too few sessions, missing benign
strata or missing required tool evidence prevents a gate from being assessed,
the outcome is **no promotion**. Mixed attack-category PCAPs cannot be labelled
wholly malicious. Publisher-designated benign reference captures without
per-session ground truth may inform a qualitative false-alert check, but not
the scored FPR denominator. No gate may be relaxed after results are seen.

## Source eligibility and result

| Available source | What is labelled/visible | Formal-scoring status |
| --- | --- | --- |
| `datasets/dns_tunnel_development.py`, 10 configuration and 10 validation scenarios | Deterministic project-generated metadata; all 20 scenarios have known synthetic labels, A/AAAA/TXT/NULL examples and varied rates. They already informed rule design and validation. | **Excluded from reserved evaluation**; development results only. |
| `data/lab/dns_tunnelling.jsonl` | Project-generated long-TXT regression scenario, already used by deployed-rule tests. | **Excluded**; neither independent nor a real tool capture. |
| `data/raw/cicdns2021/pcaps/benign/benign_1.pcap`, `benign_2.pcap` | Publisher-designated benign reference; no attached per-session annotation. Complete DNS/53 questions are visible in part of each capture. | Qualitative visibility/false-alert reference only; cannot certify 50 independent benign sessions or per-session FPR. |
| Twelve `heavy_*`/`light_*` PCAPs in `data/raw/cicdns2021/pcaps` | Mixed attack/benign capture labels; 96-byte snaplen clips almost all attack-associated DNS questions. No joined per-query/per-session truth. | **Excluded** from confusion counts and timing. See `DNS_TUNNELLING_VISIBILITY_AUDIT.md`. |
| dnscat2, iodine or other held-out controlled full-snaplen captures | None found in the local project at the eligibility inventory. | Unavailable. |

No eligible reserved set exists in the repository. Therefore **no reserved
evaluation was run**. The distinction between formal and previously inspected
development results is:

| Scope | TP | TN | FP | FN | Precision | Recall | F1 | FPR | First alert |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Reserved formal evaluation | unavailable | unavailable | unavailable | unavailable | undefined | undefined | undefined | undefined | unavailable |
| Already inspected synthetic validation, candidate | 5 | 5 | 0 | 0 | 100% | 100% | 100% | 0% | Query 5 of 12 in all five attacks |
| Already inspected synthetic validation, deployed rule | 0 | 4 | 1 | 5 | 0% | 0% | undefined | 20% | No attack alert |

The validation percentages have only five attack and five benign scenarios.
They are regression observations, **not** independent detection-quality
estimates. Those validation attacks include A, AAAA, TXT and NULL and intervals
of 0.95–1.8 seconds between queries; the benign validation cases include
CDN, telemetry, service discovery, legitimate TXT and machine-generated names
at 0.35–0.8 seconds. They do not cover a real tunnel implementation or the
predeclared low-rate group above 2 seconds. Missing formal measurements are
not zeros or passing values.

The decision is **do not promote** because quality and timing against an
independent labelled set remain unassessed. `Pipeline()` still uses the deployed rule;
the candidate remains opt-in and disabled for normal runtime. The unresolved
limitation is independent ground truth with complete DNS observations, not a
measured failure or success of the candidate on real tunnels. The existing
96-byte captures cannot establish A/AAAA/TXT/NULL coverage or incremental
alert timing for their hidden attack questions. LLMNR on port 5355 remains
outside ordinary DNS detection.

The smallest next experiment is a held-out, full-snaplen, passively recorded
controlled DNS capture with independently logged tunnel start/end and benign
sessions. Include dnscat2 or iodine, a second mechanism where available,
several query rates, the record types the tools actually emit, and the five
benign strata above. Freeze its session manifest and SHA256s before replaying
this unchanged candidate **once** against the gate above. Do not use the
existing mixed PCAP filenames as labels or tune on that held-out capture.
