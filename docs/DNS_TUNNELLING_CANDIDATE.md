# DNS tunnelling development candidate

## Frozen development design (before scoring)

This step compares one small rule candidate with the deployed long-TXT rule.
The candidate is **off by default** and cannot be promoted from these synthetic
results. The next formal-validation task must freeze independent acceptance
criteria and use genuinely labelled, complete DNS observations.

`datasets/dns_tunnel_development.py` defines ten configuration/training and ten
validation scenarios. Each side has five controlled encoded-query scenarios and
five benign counterexamples. The validation side changes seeds, suffixes,
record-type combinations and query intervals; entire scenarios are separated,
not individual query rows. The benign cases cover CDN/cloud asset names,
telemetry clients, service discovery SRV lookups, repeated legitimate DKIM TXT,
and machine-generated hostnames. These are deterministic **synthetic metadata**,
not production traffic or independent public ground truth.

For this development comparison, stability means: the candidate emits a DNS
tunnelling alert before the final query in each controlled attack scenario,
emits none in the five benign validation scenarios, and keeps the production
rule inactive when candidate mode is not requested. Report every scenario,
including failures. This is a regression criterion, **not** a promotion gate or
an accuracy estimate. The 14 downloaded 96-byte-snaplen DNS PCAPs are excluded
from quantitative scoring because most attack questions are incomplete and no
packet-level labels are joined; see [visibility audit](DNS_TUNNELLING_VISIBILITY_AUDIT.md).

## Candidate feature and rule contract

Only complete DNS questions on TCP/UDP destination port 53 enter this candidate.
`features/dns_tunnel.py` is called by the production `FeatureExtractor`, and
the development evaluator uses that same path. The source history is the
extractor's causal, bounded history: earlier/current questions in a 10-second
window, at most the newest 128 same-base queries. The base is a conservative
last-two-label proxy, **not** a public-suffix lookup. Responses, LLMNR/5355,
non-DNS events and clipped questions do not enter that history.

Current-query features are label count, maximum encoded-prefix label length,
total encoded-prefix length and Shannon entropy of the joined prefix labels.
Source/base history provides query count, distinct-name ratio and the number
of repeated encoded-looking questions. The candidate requires at least five
same-base queries, 80% distinct names, and four encoded-looking questions in
the 10-second window. It then accepts either a long encoded label (at least
40 characters, entropy at least 3.5) or a multi-label prefix (at least four
total labels, one encoded label at least 24 characters, combined encoded
prefix at least 48 characters, entropy at least 3.7). The type is intentionally
not a classifier shortcut: complete A, AAAA, TXT and NULL questions use the
same evidence. No source IP, domain literal, scenario ID, file name, external
DNS result or decoded content is predictive.

This configuration is deliberately narrow. High-rate legitimate random
subdomains can resemble an encoded tunnel, while slow or short encoded
channels may evade the candidate. The validation comparison will expose only
the controlled scenarios above; it cannot resolve these open-world limits.

## One validation comparison and decision

The frozen comparison was run once with
`python -m datasets.evaluate_dns_tunnel_candidate`. The machine-readable
per-scenario results and feature/rule source hashes are in
`ml/dns_tunnel_candidate_validation.json`. Both arms use the real pipeline's
`FeatureExtractor`; synthetic-model DNS predictions are removed from the
comparison. Scenario labels and source/domain literals are never predictors.

| Scenario split / rule | TP | TN | FP | FN |
| --- | ---: | ---: | ---: | ---: |
| Configuration/training, deployed long-first-label TXT rule | 0 | 4 | 1 | 5 |
| Configuration/training, candidate | 5 | 5 | 0 | 0 |
| Validation, deployed long-first-label TXT rule | 0 | 4 | 1 | 5 |
| Validation, candidate | 5 | 5 | 0 | 0 |

Every controlled validation attack (A, AAAA, TXT and NULL, including a
multi-label shape) first alerts on query **5 of 12**, before completion. The
five validation benign cases do not alert. The old rule misses the short-first,
long-second and multi-label cases and flags the repeated legitimate long-TXT
selector. The predeclared **development stability criterion passed**, so the
small candidate rule and feature configuration is stable for formal testing.
These are scenario-level synthetic counts, **not** estimates of field recall,
precision, FPR or generalization. No public mixed/unlabelled PCAP was scored
as malicious, and no frozen/reserved evaluation data was inspected.

On one local unpaced 5,000-event *complete-DNS* processing run, default mode
handled 8,254 events/sec (p95 0.159 ms) and opt-in candidate mode 7,926
events/sec (p95 0.164 ms). The same comparison on mixed metadata handled
63,258 and 62,310 events/sec, respectively. These are **core-only** figures;
they exclude capture, persistence, HTTP, SSE and browser rendering. The
20,000-event mixed synthetic **core + SQLite** check measured 3,070 events/sec
and p95 1.078 ms with 4,914 alerts, versus the previously saved 3,027
events/sec and p95 1.081 ms. These separate runs are not evidence of a speed
improvement, but show no observed throughput regression below the declared
2,000-event/sec core + SQLite target. Neither measurement is end-to-end.

The candidate is **not deployed**: `Pipeline()` still uses the existing rule,
while `Pipeline(dns_tunnel_candidate=True)` is for controlled development
replay only. The frozen formal gate and no-promotion decision are recorded in
`DNS_TUNNELLING_FORMAL_VALIDATION.md`. High-rate legitimate unique encoded subdomains may be
indistinguishable from tunnels using this metadata alone; slower, shorter,
or cross-suffix tunnels may be missed. Truncated 96-byte public captures
still lack complete QNAME/QTYPE and cannot validate this candidate.
