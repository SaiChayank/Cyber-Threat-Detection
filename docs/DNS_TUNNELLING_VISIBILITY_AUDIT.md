# DNS tunnelling visibility audit — 30 September 2026

## Scope and method

This is a read-only inventory of all 14 locally extracted CIC-Bell-DNS-EXF-2021
classic Ethernet PCAPs. The files and SHA256s match `data/dns_capture_catalog.json`;
per-capture counts and hashes are in `ml/dns_visibility_audit.json`. Every PCAP has
**96-byte snap length**. The diagnostic script counts port headers even when a
captured UDP datagram is incomplete, then separately counts complete DNS-format
messages, visible question/answer types, names, labels and entropy. It does not
reassemble packets or TCP streams, infer missing name suffixes/types, decode
exfiltrated content, query any network service, or emit alerts.

Reproduce from the repository root in PowerShell:

```powershell
$capturePaths = @(Get-ChildItem data/raw/cicdns2021/pcaps -Recurse -File -Filter *.pcap | Sort-Object FullName | ForEach-Object FullName)
python -m datasets.audit_dns_visibility @capturePaths --output ml/dns_visibility_audit.json
python -m pytest -q tests/test_dns_visibility_audit.py
```

`UDP/53` and `UDP/5355` below are packets with readable IP/UDP port headers.
`Clipped` means the declared UDP length exceeds captured bytes. `Q/R` are complete
DNS/53 query/response messages; a clipped packet may expose only part of its
question. Counts are observations, **not malicious/benign classifications**.

| Capture | UDP/53 (clipped) | Complete DNS Q/R | UDP/5355 (clipped) | Complete DNS name max |
| --- | ---: | ---: | ---: | ---: |
| benign_1 | 100,740 (26,803) | 50,594 / 23,343 | 154,541 (99,469) | 36 |
| benign_2 | 66,850 (13,777) | 33,406 / 19,667 | 91,782 (59,087) | 36 |
| heavy_audio | 76,342 (76,243) | 98 / 1 | 96,838 (62,388) | 34 |
| heavy_compressed | 61,344 (61,244) | 100 / 0 | 96,818 (62,436) | 34 |
| heavy_exe | 81,309 (81,195) | 112 / 2 | 93,806 (60,488) | 36 |
| heavy_image | 84,162 (84,072) | 90 / 0 | 98,598 (63,581) | 34 |
| heavy_text | 54,280 (54,052) | 223 / 5 | 192,490 (124,085) | 36 |
| heavy_video | 89,778 (89,642) | 136 / 0 | 102,800 (66,242) | 34 |
| light_audio | 8,644 (8,615) | 28 / 1 | 47,826 (30,849) | 34 |
| light_compressed | 20,170 (20,150) | 19 / 1 | 27,658 (17,779) | 34 |
| light_exe | 13,144 (13,131) | 13 / 0 | 17,434 (11,219) | 34 |
| light_image | 978 (978) | 0 / 0 | 1,382 (887) | unavailable |
| light_text | 4,994 (4,986) | 8 / 0 | 9,382 (6,035) | 34 |
| light_video | 9,670 (9,662) | 8 / 0 | 11,878 (7,668) | 34 |
| **All 14** | **672,405 (544,550)** | **84,835 / 43,020** | **1,043,233 (672,213)** | **36** |

All 14 together contain 2,024,996 captured frames; 1,415,413 were cut shorter
than their original packet length. The existing strict parser accepted 609,583
complete IP/transport packets, matching the earlier replay count. No TCP/53 or
TCP/5355 packets were observed in this inventory.

## What is actually visible

- Of **84,835 complete DNS/53 queries**, 84,834 request **A** and one requests
  **TXT** (`light_exe`). No complete query requests AAAA or NULL. The readable
  answer sections contain 42,671 **A** records and no readable AAAA/TXT/NULL
  answers. This says nothing about the types hidden in clipped messages.
- Complete query names span 4–36 characters; their first labels reach at most
  32 characters in benign captures, 25 in heavy, and 12 in light. Benign complete
  name p95 is 21–23 characters; heavy/light complete-name p95 is 31–34 where
  queries exist. Complete names have 2–7 labels. First-label entropy p95 is
  3.252–3.379 bits/character in benign captures and generally 2.918–3.022 in
  attack-category captures. These attack values have **severe selection bias**:
  almost every attack-category UDP/53 datagram is clipped and excluded.
- The attack-category files expose **251,612 clipped UDP/53 query headers**.
  Exactly **251,535** show a short first label (1–5 characters) followed by a
  declared **63-character second label**. That second label is incomplete in
  the 96-byte capture. The visible prefix of the second label has median
  character entropy 4.343 bits in each heavy capture and 4.364–4.391 in the
  light captures. This is prefix entropy, not full-name entropy. For example,
  the visible wire structure begins with a short sequence/initialization label
  and then a 63-byte label; the suffix and QTYPE are beyond the cut. None of
  these clipped attack queries has a complete question. The current parser
  correctly declines to invent a DNS sidecar from them.
- Of **1,043,233 UDP/5355** port-visible packets, 371,020 complete messages
  have readable questions: 361,875 PTR, 7,993 ANY, 1,140 A, and 12 AAAA.
  Their destinations are the link-local multicast addresses `224.0.0.252` and
  `ff02::1:3`; repeated names include `252.0.0.224.in-addr.arpa` and other
  reverse lookups. The same pattern appears in both benign captures. This is
  **LLMNR**, which uses DNS-like wire framing but a distinct port and resolver
  scope, as specified in [RFC 4795](https://datatracker.ietf.org/doc/html/rfc4795).
  Parsing 5355 as ordinary DNS would contaminate tunnelling inputs.

## Label provenance and capability

| Source | Label confidence | Usable for this task |
| --- | --- | --- |
| `benign_1`, `benign_2` | Publisher-designated benign-reference captures; no packet-level annotation in the extracted files | Benign pattern and parser-visibility reference; avoid claiming a mathematically verified per-packet FPR. |
| Six `heavy_*` and six `light_*` PCAPs | Publisher documents DNSExfiltrator scenarios and broad attack times, but these downloaded archives contain PCAPs only and the captures include ordinary traffic | Attack-associated channel/format inspection; **not** blanket-positive truth or a precision/recall denominator. |
| `data/lab/dns_tunnelling.jsonl` | Project-controlled synthetic scenario | Regression of the implemented long-TXT path, not validation on public traffic. |

The [publisher's dataset description](https://www.unb.ca/cic/datasets/dns-exf-2021.html)
documents DNSExfiltrator with base64URL encoding, up to 63 characters per label,
and labels based on experiment times. The clipped 63-character second-label
pattern in UDP/53, concentrated between the capture's lab endpoints, is
consistent with that scenario. That is a **format and scenario inference**;
without a packet-level label join and complete names/types, individual packets
cannot be certified as tunnel queries or used for detection-quality metrics.

| Capability | Benign captures | Attack-category captures | Current runtime |
| --- | --- | --- | --- |
| DNS/53 port and directional rate | Visible, including clipped headers | Visible; attack-category clipped query headers dominate | Only complete UDP datagrams become DNS sidecars. |
| Complete QNAME, label lengths, lexical entropy | Usually visible on queries | Mostly unavailable; only first label and part of second visible | Available only for complete questions. |
| Query type A/AAAA/TXT/NULL | Visible for complete questions | Hidden in nearly all clipped attack queries | Required for the existing TXT/NULL flag. |
| DNS answer type/size | Some complete A answers; many clipped responses | Almost all responses clipped | Only complete messages yield response metadata; adapter does not feed DNS response size into the tunnelling rule. |
| Per-source history of truncated DNS | Port/header visibility only | Potentially measurable from captured headers, subject to integrity checks | Not represented as DNS query history. |
| UDP/5355 name resolution | LLMNR visible | LLMNR visible | Correctly excluded from DNS sidecars. |
| Packet-level tunnel truth | Benign reference only | No joined per-packet truth in downloaded PCAPs | Cannot calculate recall/precision here. |

## Finding and smallest justified change

The zero public-capture tunnel alerts are primarily a **capture/parser visibility
limit**: the 96-byte snap length clips 544,550 UDP/53 messages, including almost
all attack-category queries. It is also a **feature-assumption mismatch**:
the current rule requires a first label of at least 50 characters and TXT/NULL,
whereas the visible attack-associated pattern has a short first label and a
63-character *second* label; its QTYPE is unavailable. Port 5355 is LLMNR,
not a missing DNS parser port. The scenario traffic is not genuinely absent,
but the complete evidence needed by this rule is absent from these files.
Missing packet-level labels independently prevents quantitative validation.

The smallest next implementation change is to **surface a clipped-DNS/53
counter and explicit incomplete-question status at ingest**, without treating
partial names as complete DNS events or widening DNS parsing to 5355. For a
valid detector evaluation, obtain/produce a genuinely labelled passive capture
with a snap length that preserves full DNS datagrams, then verify name/type
visibility before testing a causal source-history rule. Do not lower current
thresholds or force alerts on these mixed captures. No detector was changed
in this audit.
