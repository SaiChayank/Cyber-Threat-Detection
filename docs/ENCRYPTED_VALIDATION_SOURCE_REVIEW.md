# Independent TLS validation-source metadata review

14 October 2026. **Source preassignment Definition of Done: NOT MET.** Bounded
metadata research is completed, but none of the eight reviewed leads establishes
every mandatory condition in the [frozen plan](ENCRYPTED_COVERAGE_PARTITION_PLAN.md).
Validation and final reserve remain unassigned. Encrypted training stays BLOCKED;
failed candidates stay disabled. No gate, feature, detector or model changed.

## Scope and evidence

Inspected existing frozen acquisition/coverage/source documentation, then primary
publisher pages, papers and public file metadata. Firecrawl initially required a
connection handle; built-in web search supplied a temporary fallback. Normal
Firecrawl access worked after resolving the exposed connected account handle.
No authentication workaround or credentials are recorded. Search coverage is
bounded, not proof that no eligible dataset exists anywhere.

No raw PCAP/PCAPNG, annotation/feature CSV/Parquet, binaries, keys or reserved values
were obtained/read. Publisher scripts were not executed, monitored endpoints were
not contacted and authors were not messaged. Filename labels and published metrics
are not substituted for verified session intent or project accuracy.

[Protocol](verification/encrypted-validation-source-20261014/PROTOCOL.md),
[source observations](verification/encrypted-validation-source-20261014/source-page-observations.json)
and [decision/checklist](verification/encrypted-validation-source-20261014/decision.json)
record the exact boundary, candidates, evidence gaps and absent assignments.

## Strongest independent lead: ARES Cobalt Strike

[Author repository](https://github.com/cp-tsp/ares2025-artifacts) and
[primary paper](https://arxiv.org/html/2506.08922v1) describe Cobalt Strike HTTPS
captures from a Windows/Vagrant lab and Selenium browser controls. This is a
distinct documented framework/collection lead, not a qualified validation set.

Pinned [Git tree metadata](verification/encrypted-validation-source-20261014/ares-publisher-metadata.json)
at commit `7acfebc6f17fe774df91a1b550c4b23613b90fe9` lists 18 `.pcap` and 19
`.pcapng` capture paths. All **11 advertised benign capture paths** use `.pcapng`,
unsupported by the current reader. The Amazon benign paths share one Git object,
leaving **10 unique benign objects**, not 11 independent runs. These are catalogue
observations; no headers/raw packets were inspected or raw SHA256 verified.

README file-prefix labels do not establish exact session/tuple/UTC truth. Verified
updater, API/SDK and ordinary encrypted-application controls are not established.
Run dates/builds, matched environments and complete native ClientHello observations
also remain unverified. No PCAPNG conversion/parser expansion is introduced.

GitHub's repository licence field is null, but `src/LICENSE.txt` exists and contains
MIT software terms; [document provenance](verification/encrypted-validation-source-20261014/ares-license-document.json)
is saved. Paper CC BY-SA terms and a code-directory licence do not establish the
capture-data permission scope here. This does not assert permissions never exist.
The source remains a research lead with **no preassigned role**.

## Other reviewed leads

- **MTA-derived Cobalt Strike study:** [author repository](https://github.com/HuyLHP/encrypted-c2-detection)
  and [paper](https://arxiv.org/html/2609.27311v1) describe incomplete destination-
  indicator truth and treat nonmatching traffic as benign. No verified four-control
  inventory; inspected repository does not redistribute raw PCAP. Indicator absence
  cannot establish benign-only scenarios.
- **ECU-MALNETT:** [publisher record](https://ro.ecu.edu.au/datasets/151/) advertises
  PCAP/baseline data and CC BY-NC 4.0, but explicitly lacks process-to-flow truth.
  DNS/whitelist/beacon/HTTP/port heuristics infer labels, creating circular evaluation
  for similar detector signals. Required controls and TLS session/UTC truth remain
  unestablished.
- **MIT VNAT:** [publisher page](https://www.ll.mit.edu/r-d/datasets/vpnnonvpn-network-application-traffic-dataset-vnat)
  documents application-isolated libpcap captures, browsing/streaming/chat/file
  transfer. Its C2 category is legitimate SSH/RDP control, not malicious TLS C2.
  Genuine updater/API and full session/native-handshake qualification are missing.
- **TRUSTLab:** [author repository](https://github.com/trustlabupct/trustlab_dataset)
  and [paper](https://www.frontiersin.org/journals/computer-science/articles/10.3389/fcomp.2026.1803271/full)
  document controlled campaigns but release CICFlowMeter CSV, not established raw
  TLS/ClientHello timing. C2 is simulated protocol traffic. All four controls and
  a distinct TLS framework are unverified. The reviewer encountered browser
  verification on the official dataset DOI page; no global-absence claim or bypass.
- **MDA/TLS fingerprinting:** [author repository](https://github.com/matousp/tls-fingerprinting)
  and [paper](https://link.springer.com/article/10.1007/s12243-025-01114-z) describe
  PCAP/application and socket-to-process provenance. Independent malicious TLS,
  updater/API and UTC/build/native qualification are missing. Research-team overlap
  with the historical annotated TLS source requires collection/derivative checks.
- **ISOT HTTP Botnet:** [publisher page](https://onlineacademiccommunity.uvic.ca/isot/2022/11/27/botnet-and-ransomware-detection-datasets/)
  lists browsers/Windows Update, but the documented observations are DNS; they do
  not establish native TLS update-session controls.
- **SANS trusted-service study:** [publisher page](https://www.sans.edu/cyber-research/network-artifacts-of-trusted-service-abuse)
  metadata describes several framework/browser experiments. The retrieved HTTP200
  body reports a technical error500. Raw release/permission/session-time and four-
  control qualification remain unknown; metadata does not establish downloadable data.

Sources supplying only benign applications cannot be paired with TQH-only positives
as independent primary validation. All prior TQH/OSF/CIRA and permission exclusions
remain intact. No source is assigned to untouched final evaluation.

## Result, checks and next action

Root finding: **data evidence is incomplete**, not a measured detector defect.
Qualified development cohorts remain **1→1**, TLS sessions **582→582**, independent
validation cohorts **0→0**. No classification/performance results were refreshed.

Changed only this report, new protocol/source metadata/decision evidence and dated
dataset/model/completion summaries. No diagnostic code or regression test changed;
existing coverage-plan safeguards and checks are rerun. Full backend/frontend build
is not claimed for this documentation-only step. Original data, runtime, models,
prior freezes and analyst history remain protected.

**Smallest next action:** obtain a publisher/steward qualification bundle for the
ARES lead: applicable capture-data permission, session UID/tuple/UTC labels, native
classic-PCAP benign traces and verified updater/API/ordinary-application controls,
with build/run metadata. This is a missing-data prerequisite, not a trained-model
experiment. No contact, acquisition, format conversion or training follows from
this review. If the bundle cannot meet the frozen requirements, keep the source
unassigned and report the unresolved data gap rather than weakening the plan.
