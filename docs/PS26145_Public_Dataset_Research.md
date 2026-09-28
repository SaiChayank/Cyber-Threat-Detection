# PS26145 — Public dataset research

Checked 28 September 2026 using publisher / maintainer pages. This report is a
selection and integration plan for the existing project. No traffic archives were
downloaded, no registration forms were submitted, and the trained model was not changed.
This describes the initial research state. Subsequent downloads, registration,
integration and actual validation results are recorded in [DATASETS.md](DATASETS.md).
Public availability does not imply direct compatibility with our streaming schema.

## Recommended starting sources

### CIC-IDS2017 — broad intrusion baseline

PCAP and labelled flow CSV releases cover benign activity, DoS / DDoS, port scans and
botnet activity. Useful first baseline for DDoS, reconnaissance and realistic negative
traffic. Botnet labels alone do not establish periodic C2 beaconing. Re-extract our
features from selected PCAP intervals and join labels using tuples and timestamps.
The official download link currently presents a registration form and a server-error
message in the browser research response; successful archive retrieval is unverified.
Publisher guidance permits use with citation.

Source: https://www.unb.ca/cic/datasets/ids-2017.html
Download portal: https://cicresearch.ca/CICDataset/CIC-IDS-2017/
General reuse guidance: https://www.unb.ca/cic/datasets/

### CIC-DDoS2019 — specialized flood coverage

PCAP and labelled CSV include SYN / UDP floods and reflection-related attacks such as
DNS, NTP and LDAP. Stronger fit for the explicit flood subcategories than relying on
one general IDS dataset. Redistribution / reuse requires citation. The official portal
also returned a registration page with a server-error message; files were not fetched.

Source: https://www.unb.ca/cic/datasets/ddos-2019.html

### IoT-23 — C2, scanning and DDoS external validation

Twenty malware captures and three benign-device captures supply original PCAP and
labelled Zeek connection logs. Labels include C&C, heartbeat-related activity, DDoS
and horizontal scans. The full release is listed as 20 GB; the 8.7 GB light release
omits PCAP. Individual scenarios can be obtained separately. Start with selected
captures rather than the full archive. C&C does not automatically mean periodic
beaconing. Dataset licence terms should be checked in the selected release.

Source: https://www.stratosphereips.org/datasets-iot23

### CIC-Bell-DNS-EXF-2021 — DNS tunnelling / exfiltration

The publisher describes 270.8 MB of DNS captures and 30 extracted features, with
benign, light and heavy exfiltration scenarios. Good match for DNS query-length,
entropy and record-type behavior. Prefer PCAP over its precomputed features.
This specifically represents DNS exfiltration, not general outbound file transfer:
map relevant labels to DNS_TUNNELLING and retain mechanism provenance. The official
portal returned the same registration / server-error response as other CIC sources.

Source: https://www.unb.ca/cic/datasets/dns-exf-2021.html
Download portal: https://cicresearch.ca/CICDataset/CICBellEXFDNS2021/

### UMUDGA — DGA domain names

The University of Murcia dataset release describes over 30 million generated domain
names across 50 DGA variants, available as domain lists and extracted features. The
Mendeley dataset page lists an MIT licence. Prefer raw strings and recompute our
lexical features. Domain lists have no captured network timing: wrap them in clearly
labelled lab DNS experiments when testing the full stream. Split by DGA family and
generation parameters, not merely shuffled domain rows.

Source: https://data.mendeley.com/datasets/y8ph45msv8/1
Author paper: https://doi.org/10.1016/j.dib.2020.105400

### Annotated Encrypted Network Traffic Dataset (2026) — priority encrypted candidate

Zenodo release 18336960 lists 74.4 MB of public archives: malware-related TLS data,
Windows application traffic and SOHO traffic. The malware collection contains
828,171 TLS connections; these include benign/system connections as well as
malware-related connections. Raw PCAP is available only upon justified request.
The licence was not visible in the retrieved record and needs confirmation before
adoption. This is a promising candidate, not an already integrated dataset.

Schema documentation explicitly lists JA3, JA4, JA3S, JA4S, byte/packet counts,
connection start/duration and signed TLS-record-length sequences. All fields are
optional. It does not list per-packet timestamps. TLS record lengths are not IP packet
lengths: the current packet-size/timing feature path cannot ingest them unchanged.
A separate metadata adapter and model feature contract are needed. Sample IDs,
malware family and system-service annotations must remain labels / split metadata,
not detector inputs. Do not mark every connection in a malware execution as malicious.

Source: https://zenodo.org/records/18336960
Schema: https://zenodo.org/records/18336960/preview/Data.md?include_deleted=0
Labelling notes: https://zenodo.org/records/18336960/preview/Readme.md?include_deleted=0

## Useful secondary sources

### CTU-13

Thirteen botnet experiments provide botnet PCAP and labelled bidirectional Argus
flows. The complete mixed benign/background/botnet PCAP is not released for privacy
reasons. Background traffic is not verified benign. Useful additional C2 validation,
but not a complete benign-versus-attack raw-capture source. The maintainer overview
states CC-BY. Preserve attribution and verify the selected release contents.

Sources: https://www.stratosphereips.org/datasets-ctu13
https://www.stratosphereips.org/datasets-overview

### DGArchive

Fraunhofer FKIE's database contains malware DGA domain names. Access requires an
email request, brief vetting and credentials. It is not an anonymous bulk-download
source. UMUDGA is a practical initial alternative. No access request was sent.

Source: https://dgarchive.caad.fkie.fraunhofer.de/

### CESNET TLS / QUIC datasets

DataZoo supports encrypted application-classification datasets with packet-direction,
size and inter-packet-time sequences. Available auxiliary fields can include JA3 and
SNI. Useful application reference traffic / hard-negative candidates, especially for
QUIC, but application labels do not provide ground-truth malware labels or guarantee
that every record is benign. PPI sizes are transport payload lengths, while our parser
uses IP lengths; this semantic difference must be resolved in any adapter.

Sources: https://github.com/CESNET/cesnet-datazoo
https://cesnet.github.io/cesnet-datazoo/features/

### USTC-TFC2016

The maintainer distributes benign and malware PCAP collections. It can provide
additional malware / C2 captures, but we must verify TLS coverage, per-flow label
specificity and timestamps before choosing encrypted-session examples. Its malware
captures overlap CTU-derived material: deduplicate across sources before splitting.
The repository lists MPL-2.0; do not assume that independently resolves all upstream
capture redistribution terms.

Source: https://github.com/yungshenglu/USTC-TFC2016

## Integration decisions for this project

1. Keep synthetic fixtures for deterministic tests and coverage of controllable cases.
2. Start with a small CIC-IDS2017 PCAP subset, selected IoT-23 scenarios, a UMUDGA
   domain subset, and the DNS-exfiltration captures when portal access is resolved.
3. Inspect the 2026 encrypted dataset's actual schema, missingness, label quality and
   licence before developing its adapter. Its advertised fields materially improve
   the available-data options compared with our earlier design notes.
4. Feed PCAP through the existing parser and shared causal feature extractor. Retain
   labels in sidecars, joining by connection tuple and time interval. Do not substitute
   complete-session CSV totals for features used to make early streaming predictions.
5. Public bidirectional captures can traverse a one-way monitoring link. For the stricter
   zero-reverse-packet mode implemented here, derive a documented observation view
   and remove unavailable reverse fields before extracting features. Evaluate both
   scopes separately; never treat missing reverse traffic as measured zero bytes.
6. Do not concatenate unrelated CSV schemas. Missing DNS / TLS / sequence fields stay
   unavailable rather than becoming fabricated observations.
7. Preserve dataset / capture / experiment / time / attack-family provenance, record
   file hashes and licence attribution, and split by complete experiments and families.
   Duplicate or overlapping captures must never appear on both sides of a split.
8. Report synthetic-only, public-only and combined-training results separately. Hold
   out public captures for external evaluation; never use that holdout to tune thresholds.
9. Controlled generic outbound-transfer exfiltration and specific beaconing patterns
   still require lab scenarios. No source identified here fully covers every required
   threat, observation scope and modern TLS / QUIC condition with compatible labels.

Read-only packet analysis uses metadata only. Some source labels were established
using richer analyses; those labels can serve as offline ground truth but that does
not authorize using payload content, external lookups or sandbox annotations as
inference features. Download selected captures and label files, not malware binaries.
