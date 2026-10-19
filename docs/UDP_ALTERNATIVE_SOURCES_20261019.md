# T21 alternative-source acquisition attempt

19 October 2026; baseline `4769d03`. **T21 remains NOT QUALIFIED.**
Source discovery and metadata inspection progressed; the required independent
service/run/timing evidence is still missing. No software fix can establish facts
that the reviewed source records do not supply. No acceptance gate was relaxed.

## Scope and findings

Reviewed the frozen T21 protocol, previous ORION source receipts and new primary
publisher documentation. Used Firecrawl for public searches/page/PDF retrieval,
plus bounded official Zenodo/GitHub JSON metadata and ZIP directory ranges. Source
URLs, returned-document hashes and range receipts are saved alongside this report.
Raw documentation snapshots are ignored under `data/raw/discovery/`; no dataset
packet/CSV values or model outputs were inspected. Published method descriptions
are not this project's evaluation measurements.

- **ORION:** the live publisher page still supplies dataset composition, licence
  and downloads, without establishing the requested paired same-service benign
  run. No additional mail check, resend or new contact occurred in this task.
- **NetsLab-5GORAN-IDD:** strongest new public lead. The Zenodo API verifies CC BY
  4.0 and raw archive metadata. Its descriptor documents benign iPerf activity and
  high-intensity floods. Bounded directory reads confirm
  `Benign/Network_data/iperf_benign.pcap`,
  `DDOS/Network_Layer/ddos_udp_hping3.pcap` and
  `DDOS/Network_Layer/ddos_udp_nping.pcap`. They are **possible members, not an
  accepted or selected pair**. The reviewed descriptor/record/repository does not
  establish matching application/UDP port, exact original run boundaries/time
  zone, per-member SHA256 or complete compatible capture format. The repository
  at `add5de9fe2a1491a8d0bf4ccf0239c553c286634` contains notebooks, databases and
  licence, with no separate run/configuration files in its untruncated tree.
  Notebooks/data/telemetry bodies were not read as substitutes for runbooks.
- **BCCC-UDP-QUIC-IDS-2025:** official page describes raw capture generation,
  benign profiles and UDP campaigns, but the reviewed page does not identify an
  eligible matched pair. Access points to a request form; no form was submitted,
  identity transmitted or permission inferred. The related 2024 cloud paper also
  does not establish the specific T21 pair.
- **TRUSTLab:** published single-class collection methodology is useful, but the
  reviewed sources do not supply an accessible matching raw-run pair/configuration.
  A broad class-level clean-label claim is not a substitute for the missing pair.
- **AdDDoSDN:** its producer describes 20–30 packets/sec for traditional phases
  and publicly listed CSV products. This does not meet the frozen >=1,000 packets/s
  raw-run qualification screen; no rate scaling or CSV-value inspection attempted.
- **NANCY O-RAN record 14811122:** producer README describes UDP scanning alongside
  other attacks; it does not establish the required UDP flood/benign pair. A scan
  was not relabelled as a flood.
- **SDN-DDOS Mendeley hkjbp67rsc/1:** documents generated attacks, without the
  required independently labelled high-volume same-service benign application.

## Bounded acquisition and diagnostic correction

The NetsLab web ZIP preview explicitly refuses these large files. The new small
controller therefore reads only end/directory metadata using exact HTTP 206 ranges,
Content-Range, with <=1 MiB per request. It uses conditional identity headers when
available and explicitly records when they are absent. It handles ZIP64
because Benign.zip exceeds 4 GiB; this is acquisition tooling, not runtime capture
format support. Each successful two-archive pass fetched **135,690 range-body
bytes**; the initial observation and final corrected pass total **271,380 bytes**.
The multi-GB captures were not downloaded/decompressed. A tail range can
contain opaque compressed capture bytes, which were not interpreted as traffic.
Publisher MD5 values remain publisher-supplied, not locally verified full hashes.
ZIP64 per-member size sentinel fields are marked unresolved, not full sizes.

An exploratory revision incorrectly made ETag mandatory, which is not a frozen
T21 requirement. Zenodo's range responses supplied neither ETag nor Last-Modified;
the API/download-route draft failures and exploratory unit failures are retained.
That extra requirement was removed. The corrected metadata-only controller records
`conditional_identity_verified=false`, `full_checksum_locally_verified=false` and
`qualification_evidence_complete=false`. It does not turn names into qualified
data or weaken the required full-artifact hash/provenance gates. The initial
unguarded observation remains separate from the corrected receipt. Tests cover
explicitly unverified source metadata, conditional guards when available, HTTP 200
refusal, wrong ranges, short/long bodies, changing ETags, malformed directories,
normal ZIP/ZIP64 names and no member decompression.

## Files and verification

Added the source/catalogue evidence and controller under
`verification/udp-alternative-sources-20261019/`, ten diagnostic tests in
`tests/test_udp_archive_catalogue.py`, this report and the precise
[NetsLab clarification draft](UDP_NETSLAB_RUNBOOK_REQUEST.md). Updated current
completion/progress pointers only. No runtime detector/parser, model, dependency,
original dataset/history, frozen protocol, qualification manifest or gate changed.

**22 targeted tests pass**: ten new acquisition regressions plus 12 existing UDP
flood/observability cases. No new detector accuracy, confusion counts, load overlap,
runtime cost, throughput or alert-latency measurement. Frontend/build/full runtime
suite was not rerun for this isolated research-tool addition. All 130 protected
original hashes remain unchanged. No generator, probe, capture replay, training,
reserved scoring or candidate activation was executed.

## Definition of Done and next action

Acquisition-tool checks pass; **T21 qualification DoD does not pass**. Neither a
filename, class description nor a new status flag proves service identity, intended
workload, original timing or matched load. Packet values stay uninspected until
those frozen provenance prerequisites pass.

The exact public-source next action is obtain the existing runbook clarification
for the three named NetsLab members; the reviewable request is prepared but **not
sent**. This is a new recipient beyond earlier mail approvals. No new message is
authorized by this report. A separate lab-capture collection task is another route
only if an isolated lab and explicit collection scope are available; the question
about that availability remains pending. Do not execute a new workload under the
current frozen qualification protocol or describe generated data as public truth.

Sources:

- [NetsLab deposit](https://zenodo.org/records/18923275),
  [producer descriptor](https://www.techrxiv.org/doi/pdf/10.36227/techrxiv.175606222.20740292/v1?onload=true),
  [repository](https://github.com/NetsLab-Demo/NetsLab-Demo-Netslab-5G-ORAN-IDD).
- [BCCC UDP/QUIC](https://www.yorku.ca/research/bccc/ucs-technical/cybersecurity-datasets-cds/udp-quic-network-threat-dataset-bccc-udp-quic-ids-2025/),
  [cloud methodology](https://www.mdpi.com/2078-2489/15/4/195).
- [TRUSTLab methodology](https://www.frontiersin.org/journals/computer-science/articles/10.3389/fcomp.2026.1803271/full),
  [AdDDoSDN producer](https://data.mendeley.com/datasets/9jp6r68y98),
  [NANCY README](https://zenodo.org/records/14811122/files/ReadMe.pdf),
  [SDN-DDOS producer](https://data.mendeley.com/datasets/hkjbp67rsc/1).
