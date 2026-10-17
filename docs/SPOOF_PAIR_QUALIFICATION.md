# T22 forged/genuine UDP pair qualification

17 October 2026; baseline `949e697`. **BLOCKED_NOT_QUALIFIED.** The bounded
five-source documentation screen is complete; the requested pair qualification
Definition of Done has **not** passed. No capture pair is selected, no new packet
or annotation values were examined, and load overlap remains unmeasured.

## Frozen scope and evidence

[Pre-value protocol](SPOOF_PAIR_QUALIFICATION_PROTOCOL.md), SHA256
`b2423abf0b23798eacbd5b0553a429e734a8a20ce6f5348cdf851e24e537d28c`,
requires producer-independent run/ownership truth, capture placement, the same
actual UDP service and destination port, original timestamps, permission and
compatible original captures before any value inspection. Its fixed ten-second
load screen was not reached. Rates, packet sizes and overlap are unknown, not zero.

[Manifest](../data/spoof_pair_qualification.json) records all five leads and
unknowns. [Evidence folder](verification/spoof-pair-qualification-20261017/)
contains HTTP/document hashes, public dataset metadata, a pinned Git catalogue,
the point-in-time ORION reply-check receipt and integrity results. HTML/README
caches under `data/raw/spoof-source-documents-20261017/` are publisher documents,
not downloaded traffic datasets. Published counts are not local measurements.

## Source findings

1. **BOUN DDoS v1**, [producer record](https://data.mendeley.com/datasets/mfnn9bh42m/1),
   DOI `10.17632/mfnn9bh42m.1`, Derya Erhan, CC BY 4.0. The producer explicitly
   describes hping3 attack packets with randomly generated spoofed source IPs,
   three attack computers and mirrored campus traffic alongside real users.
   This is the strongest source-forgery lead in this screen. The released data is
   described as converted CSV; an original supported PCAP release, precise
   emitter/run joins and a genuine distributed run of the same UDP service/port
   are not established. Concurrent campus users do not establish that matched
   control. No archive, capture or CSV rows were downloaded. The indexed paper
   abstract also describes payload removal and legitimate-address anonymization;
   full paper access was unsuccessful. This does not establish that originals
   never existed or require disclosure of user identities.
2. **SDN UDP Flood v1**, [producer record](https://data.mendeley.com/datasets/p3h8r89kc2/1),
   DOI `10.17632/p3h8r89kc2.1`, Sudesh Kumar / Sunanda Gupta, CC BY 4.0.
   Mininet UDP-server, hping3 attack and normal-traffic descriptions lead to
   CICFlowMeter CSV. Hping3 usage alone does not establish source-address forgery.
   Independent ownership labels, the matched distributed application run,
   original-time joins and a compatible original capture release are unestablished.
   No dataset values or archive members were inspected.
3. **BCCC UDP-QUIC IDS 2025**, [publisher page](https://www.yorku.ca/research/bccc/ucs-technical/cybersecurity-datasets-cds/udp-quic-network-threat-dataset-bccc-udp-quic-ids-2025/).
   Describes cloud attack traffic, benign traffic and flow reconstruction. Attack
   category names do not independently label forged packet sources. Capture
   placement/ownership, a matched benign service/port/run, original-time mapping
   after declared normalization, applicable raw-capture permission and compatible
   release are unestablished. The request form was not submitted.
4. **SHIELD-i46**, [producer repository](https://github.com/i46-projects/SHIELD-i46),
   pinned commit `d96eea3b833c2c6bc218daf31ddc18b6e93d28d7`. README and Git-tree
   metadata only: nominal DDoS/normal files do not establish forgery, matching UDP
   application, ownership or run timing. README numbering denotes capture order,
   with sessions/dates potentially differing. Five nominal PCAP entries are two
   bytes each in the catalogue, too small for a 24-byte classic global header;
   no file contents were opened. Larger files are unverified, not certified
   compatible. Git blob IDs are not raw-file SHA256. Research/credit guidance is
   present; exact capture licensing remains unestablished.
5. **ORION**, [publisher page](https://www.uel.br/grupos/orion/datasets/orion-2026.html).
   Reuses previously exposed README/licence evidence only. Documented UDP target
   `10.0.0.3:9090`, sources `10.0.0.[4-7]` and random source ports do not establish
   source-address forgery. Matched genuine workload, ownership, timezone/order
   provenance and inner capture format remain unknown. The large archive was
   not downloaded. A single focused check of the already approved runbook request
   found no matching incoming message at approximately **17 October 02:11 IST**;
   this is historical, not a fresh check at report completion, delivery proof or
   proof that no response could exist outside the query.

ScienceDirect and Scitepress returned HTTP 403; PMC presented a CAPTCHA. None
was bypassed. Firecrawl account routing was unavailable, so primary publisher
metadata was retrieved through available read-only tools. These access limits
and the bounded search mean this is not a claim that no qualifying dataset exists.

## Decision and verification

**Zero of five screened leads qualifies.** Artifact/run hashes, packet counts,
original-time load ranges and size overlap for a selected pair remain null.
No rewriting ports/timestamps/addresses, synthetic frame conversion or fabricated
benign labels was used to bridge missing provenance. Victim-side reflection
traffic cannot automatically label observed reflector addresses as forged.

Runtime code, artifacts, other partitions and alert SQLite/WAL/SHM are pinned by
106 before/after hashes. Receipt, protocol, catalogue and manifest checks are
recorded in `qualification-checks.json`; `freeze.json` binds the resulting files.
No tests were added or rerun: this change contains documentation/manifests only
and deliberately performs no inference. The preceding diagnostic's 66 passing
targeted tests are historical evidence, not a new run.

No fresh detector metrics were measured. Historical development counts remain
TP4/TN2/FP4/FN0. Recall >=80%, precision >=95%, FPR <=2%, early indications and
matched-benign discrimination remain unchanged. The failed subtype predicate
stays disabled; existing generic DDoS behavior is unchanged. Passive observations
may support suspected-spoof indicators, not prove source forgery.

## Exactly next

Obtain a BOUN producer provenance bundle identifying **original compatible
captures plus independently labelled forged and genuinely distributed benign
runs of the same UDP application/port**, emitter/ownership and capture-direction
mapping, permission and original timestamp/run boundaries. Verify that bundle
before packet values; only then bind artifact hashes and run the frozen overlap
screen. No recipient was guessed, no new message was sent, and no experiment,
training, promotion or reserved evaluation is authorized by this report.
