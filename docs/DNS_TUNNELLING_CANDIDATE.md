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

Results and any final configuration decision are appended after the one
validation comparison.
