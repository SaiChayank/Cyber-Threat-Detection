# Sample-aware encrypted split and subsequent source check

Completed 12 October 2026 under the owner's authorization to execute remaining
steps sequentially. **Split-integrity DoD: PASSED. Adequate streaming training /
promotion data: BLOCKED.** Do not confuse successful isolation with useful model
support. No classifier, rule, threshold, parser or frozen artifact changed.

## Stage 1: frozen development design

Inspected the completed feasibility audit, raw-source manifests, existing label /
group functions, historical splits and tests. Recorded
[protocol](verification/encrypted-split-design-20261012/PROTOCOL.md) before assignment.
Read annotation columns only from the existing winapps/malware archives.

Observations sharing a sample ID, capture member or exact family/app group belong
to one indivisible connected component. Components touching a historical-test
group are quarantined; no feature values from those groups are inspected.
Remaining components are assigned once by fixed SHA256 modulo 10 (0–5 train,
6–9 validation), without shuffling rows, searching salts or revising assignments.

Measured development support:

- Training: **11,475 benign-reference / 14 malware-related rows**.
- Validation: **13,123 benign-reference / 32 malware-related rows**.
- The positive training support is **one independent component**. Validation is
  also **one positive component**, spanning two members of one family-label group.
- **755,895 of 755,941 positive-related rows** are quarantined through historical
  test connections; only 46 remain for development. No record is deleted.
- All sample/member/group overlaps across train, validation and quarantine are zero.

The predeclared technical gate (both classes represented, whole-component isolation,
no historical-test component in development) passes. It explicitly does not claim
statistical adequacy, independent malware generalization or a passing detector.
One-component positives, weak sample-level truth, completed-session availability
and cohort/environment confounding block a credible streaming candidate. Do not
fragment components or recycle historical test records to inflate support.

[Manifest](verification/encrypted-split-design-20261012/manifest.json) records full
component membership/counts/assignments; its `.sha256` pins raw LF bytes. Normalize
CRLF to LF when verifying this text manifest after checkout. The old split/model/
reports remain unchanged. Reproduce to a **new** output path:

```powershell
.venv/Scripts/python.exe -B -m datasets.design_encrypted_split --output encrypted-development-split.json
.venv/Scripts/python.exe -B -m pytest tests/test_encrypted_split_design.py tests/test_encrypted_data_audit.py -q -p no:cacheprovider
```

Six new regressions cover transitive grouping, quarantine, deterministic order,
missing sample IDs, unlabelled exclusion and identity preservation.
**19 targeted tests passed**. Shared behavior is unchanged; full backend/build
was not rerun for this metadata-only stage. No classification/performance result
is refreshed. Freeze this design and its feasibility limitations.

## Stage 2: subsequent source feasibility/acquisition

Continued with read-only primary-source research rather than training on the weak
cohort. Saved HTTP/official-API metadata under the dated evidence directory.

- [CICMalDroid2020](https://www.unb.ca/cic/datasets/maldroid-2020.html) supplies
  application-analysis captures/labels; application truth alone does not establish
  every TLS session's purpose. Not acquired or assigned final evaluation roles.
- [USTC-TFC2016 publisher repository](https://github.com/davidyslu/USTC-TFC2016)
  lists benign/malware-category PCAPs; raw TLS visibility and session-level truth
  are not established by directory names. Not acquired or evaluated.
- [CIRA-CIC-DoHBrw2020](https://www.unb.ca/cic/datasets/dohbrw-2020.html) offers
  captured, flow-labelled benign/malicious encrypted tunnelling. This is narrower
  than generic encrypted malware; no silent relabelling or reuse as plaintext DNS.
- The [authors' TLS research repository](https://github.com/CarlosANovo/extending12to13)
  links [MS](https://osf.io/b64e5/) and [Tranco](https://osf.io/zq9vs/) sources.
  Their public official API records declare CC BY 4.0. The MS data describes a
  Meterpreter payload communicating with a Metasploit server under TLS variants.
  Tranco raw-PCAP ZIP listings are approximately 3–5GB each, not downloaded here.

The web reader returned OSF 403s, but the official public API worked; that is not
reported as dataset unavailability. Used normal public API/download routes only.
The earlier restricted IoT-23 mirrors remain excluded; no permission workaround.

Before data inspection, recorded [development-only source plan](verification/encrypted-split-design-20261012/SOURCE_PLAN.md).
Downloaded **one** small MS derivative for schema/capability inspection:
`data/raw/encrypted-ms-development/capture_getuid.joy.gz`, **4,635,278 bytes**,
SHA256 `d18bad45afd5c62ee848a8db04e0216d22799a3824a58a6a9fd117f45a77ebc3`.
Source file ID `6691639fe9fa1301d756aa15`; CC BY 4.0 attribution is Carlos A. Novo
and colleagues' *Extending C2 Traffic Detection Methodologies: From TLS 1.2 to
TLS 1.3-enabled Malware* work. GZIP read completed with CRC verification. No
executables were downloaded/run and no monitored endpoint was contacted.

It contains one configuration row and **17,421 JOY flow records**, all with TLS
metadata and packet summaries. **Zero explicit session ground-truth fields** were
found. Source provenance describes a controlled Meterpreter capture; that is not
silently converted into an all-malicious per-flow annotation.

JOY exposes client ciphers/extensions and packet `b/dir/ipt`, but this downloaded
derivative is not raw PCAP and does not establish ClientHello observation position.
The semantics of `b` are not declared equivalent to runtime IP-packet bytes here;
`srlt` is not substituted for packet sizes. No new capture format, fabricated
TrafficEvents, handshake timestamps, classifier or runtime integration was added.
Future source use needs a verified label mapping and a causal feature contract.

## Current blocker and next action

The split and source-inspection stages have reviewable outputs, but their data
prerequisites for a streamed encrypted candidate do not pass. Therefore no training
or promotion follows automatically, even under continuous execution authorization.
The archived/public candidates remain disabled and the legacy baseline is unchanged.

Next necessary action: obtain/verify **per-session label mapping and raw timestamped
TLS development captures** from an eligible source, then freeze source roles before
any evaluation. Author-provided raw MS captures/label mapping or a correctly scoped
DoH development cohort are possible leads, not established qualifying data. Do not
contact authors, change detector scope or label mixed captures without authorization.
Other release-quality blockers (DGA final data, DNS tunnelling and baseline hard
negatives) remain; the complete project is not declared READY.
