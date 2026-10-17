# Public DNS dataset acquisition — 17 October 2026

**Status: both original archives downloaded; publisher sizes and MD5 checksums
verified.** Acquisition DoD passes; final evaluation qualification remains blocked.
The two originals total **7,351,027,624 bytes**, with local SHA256:

- `DNSTunnel2026.zip`: `0c6eeadc3a55582b99f88cb31ec36b6b89d971a66804bccdce97a37dad401a0d`
- `capturasAgentes.zip`: `76f7f38dada4cbdb8110691ca981262f10eb55452bc1c2e3e1dc6297b191957d`

The authoritative local inventory is `data/dns_public_acquisition.json`; transfer
receipts and integrity checks are in `verification/dns-public-acquisition-20261017/`.
**76 acquisition/integrity checks pass; all 109 protected files remain byte-identical.**

User explicitly authorized downloading the two open Zenodo releases identified
in [the public-source screen](DNS_OPEN_SOURCE_ALTERNATIVES.md). This acquisition
does not supersede that screen's suitability findings or change the frozen DNS
evaluation contract. Both records declare open access and CC BY 4.0. Cite the
producer/record when using or redistributing the data; keep the original archives
unmodified. Dataset rights do not grant rights to private systems or live traffic.

## Exact original releases

- **DNSTunnel2026**, DOI [10.5281/zenodo.20137065](https://doi.org/10.5281/zenodo.20137065).
  Local destination: `data/raw/dns-public-intake/dnstunnel2026/DNSTunnel2026.zip`.
  Publisher size 497,565,428 bytes; MD5 `e2a4c675b480f9c10b8629494d9ae7dc`.
- **Benign Network Traffic PCAP Dataset for Reproducibility**, DOI
  [10.5281/zenodo.19206234](https://doi.org/10.5281/zenodo.19206234).
  Local destination: `data/raw/dns-public-intake/uma-benign/capturasAgentes.zip`.
  Publisher size 6,853,462,196 bytes; MD5 `9ab42d5978237a2b9e613d6b0d0f0440`.

Total verified original bytes: **7,351,027,624**. These are the two named releases,
not a download of all five reviewed sources. Producer creator/attribution fields
and exact file metadata are retained in their original record JSON and manifest
references. Current licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

## Acquisition boundary and reproduction

`verification/dns-public-acquisition-20261017/acquisition-plan.json` pins exact
official content URLs, original publisher size/checksum, metadata hashes and
unqualified research-intake roles before downloading. The original plan allows
opaque ZIP acquisition/checksumming only, not extraction or member inspection.
Nothing is assigned to training, validation or reserved evaluation. No automatic
PCAP upload/replay preset, model loading, inference or activation is added.

From repository root on Windows, with the documented Python environment and
built-in `curl.exe`:

```powershell
.venv/Scripts/python.exe docs/verification/dns-public-acquisition-20261017/download.py
```

The script rechecks official licence/open-access/file identity, downloads only
the exact releases, verifies complete size and publisher MD5, computes local
SHA256 and admits the verified archive without replacing existing original data.
It preserves failed `.part` downloads as incomplete and never extracts ZIPs.
An existing complete archive is verified again rather than blindly trusted.

For this acquisition, the slow initial sequential transfers were stopped with
their prefixes preserved. Standard HTTP Range support was confirmed; a separate
hash-pinned transport plan binds those exact prefixes and disjoint ranges.
`download_ranges.py` reassembles byte-identical originals only after each part's
identity/size and the full publisher checksum pass. Its checkpoint plan depends
on this task's original local partials; use `download.py` for a fresh checkout.
No timestamp/address rewriting, source format conversion, archive extraction or
data/session partitioning is performed by byte-range transport.

Large archives remain excluded from Git by existing rules. The small manifest,
source/transport plans, scripts and verification evidence are committed. A clean
checkout must run the acquisition command to obtain raw data; these research
archives are not required to start the bundled application/demo.

Duplicate prefix/range transport payloads are removed only after verifying the
complete originals; transport hashes/receipts are retained. Both download scripts
compile. No backend/frontend implementation changed, so no regression suite or
production build was rerun for this acquisition-only task. Protected runtime,
model, history and contract files are checked against the pre-acquisition snapshot.
No fresh detector accuracy, inference-latency or throughput metric is claimed.

## Suitability and next step

Acquisition is separate from qualification. Processed DNSTunnel2026 features do
not establish causal original client-question histories or dnscat2/iodine
coverage. UMA's recommended PCAPNG workflow and incomplete DNS session/category
mapping remain unresolved. Downloading does not establish >=20 positive/>=50
benign sessions, five required benign strata or independent ground truth.

No packet/query rows, archive members or model binary contents were inspected.
No raw QUIC support, decryption, new parser, training, reserved scoring, runtime
candidate activation or detector changes. No external messages sent.

The next task is source/annotation/format
qualification under a separate pre-value plan. Do not extract, parse, convert or
score these archives merely because they are now available locally. Existing
frozen contracts/gates and disabled candidate state remain unchanged.
