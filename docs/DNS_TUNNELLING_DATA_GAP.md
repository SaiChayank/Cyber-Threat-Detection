# DNS tunnelling evaluation-data gap

15 October 2026. Source qualification only. **Independent final evaluation remains
BLOCKED; the candidate is not promoted.** No capture values or classifier outcomes
from a new source were examined. No tunnel software, generation commands or
publisher scripts were executed. No raw captures were downloaded in this task.

## Baseline inspected

Reviewed the formal protocol, visibility audit, development report/evaluator,
candidate, pipeline, classic PCAP reader and DNS regression tests. The 14 local
CIC captures match their catalogue SHA256s. Existing synthetic training/validation,
lab and demo inputs are exposed development material, not reserved observations.
The published visibility audit establishes 96-byte snaplen clipping and missing
joined session truth; its old packet counts were not recomputed or called current.
LLMNR/5355 is not an ordinary DNS source. Mixed capture filenames are not labels.

The unchanged formal gate requires >=20 independent positive and >=50 independent
benign sessions, full QNAME/QTYPE, a real dnscat2/iodine tool and an independent
mechanism where available. Report actual A/AAAA/TXT/NULL and low (>2s), medium
(0.5–2s), high (<0.5s) query intervals without fabrication. Benign sessions must
cover CDN/cloud, telemetry, service discovery, legitimate TXT and machine-generated
hostnames. Recall >=80%, precision >=95%, benign-session FPR <=2%; every TP before
completion, >=90% of TPs by query 10 AND within 10 seconds. Preserve undefined
metrics for unavailable denominators. Do not change these criteria to fit a source.

**Protocol integrity limitation:** candidate and DNS-feature source hashes still
match September's protocol. Current shared pipeline hash
`4e70bc3e50546e57fa5f0d9432f3a9be969b906897d837f6f3638311c9b54926`
differs from protocol hash
`c01de15ed0fff1c3576cd757e0665c78358bd3a0efd365c3ddb11e32c9efdb86`.
Existing development results are historical, not a current formal pass. Before any
reserved access, audit the pipeline changes and preregister the exact current
source/adapter/evaluation-arm contract against a newly reserved set. This task
does not certify compatibility or edit the historical protocol.

## Primary-source leads (metadata only)

- **Korving/TalTech**: [publisher repository](https://github.com/Korving-F/dns-tunnel-dataset)
  documents iodine, DNS2TCP and DNSCAT experiments with resolver configurations,
  query logs, terminal recordings and PCAPs. Pinned tree contains 136 `.gz`
  archives; archive count is not independent-session count. Some activities are
  manual. Its MIT statement names DACA software; capture-data licence applicability
  requires clarification. Best positive provenance lead, but full capture format,
  snaplen, session/time joins, related exports and all five benign controls remain
  unverified. No archive opened. No tool version inferred from the DNSCAT name.
- **GraphTunnel**: [publisher repository](https://github.com/ggyggy666/DNS-Tunnel-Datasets)
  describes simulated DNS traffic, multiple tunnel tools, popularity-derived
  normal queries and wildcard enumeration. Pinned tree has 131 PCAPs. Publisher
  explicitly splits large PCAPs: fragments must stay together and do not establish
  independent runs. Citation requested; data-use/redistribution scope, per-session
  truth and benign application categories not established. Popularity and wildcard
  enumeration alone do not certify telemetry, service discovery or legitimate TXT.
  A prospective secondary lead, not an assigned reserved source.
- **UFU/Rocha**: [Mendeley v2](https://data.mendeley.com/datasets/v2cy9y58t7/2)
  describes controlled dnscat2-related exfiltration records and CC BY 4.0.
  [publisher repository](https://github.com/ViniciusDMRocha/dataset-exfiltracao-DNS)
  instead references DOI v3 and raw PCAPNG via Drive, using NFStream aggregate
  flows and benign undersampling. Pinned Git tree has no raw capture files.
  Version alignment, session truth and application controls are unverified;
  PCAPNG is outside the current reader. Aggregate CSV cannot replace causal query
  order/timing. No Drive data or CSV rows inspected and no format expansion proposed.
- **dmachard**: [publisher repository](https://github.com/dmachard/datasets-malicious-dns)
  supplies five tool-associated PCAP filenames. Inspected README/tree does not
  establish joined session labels, independent run counts, benign controls or
  explicit dataset licence. Keep as an unqualified visibility lead; not quantitative
  ground truth and not a blanket-malicious corpus.
- **DNS-Threats**: [publisher listing](https://mcfp.felk.cvut.cz/publicDatasets/DNS-Threats-Dataset/)
  advertises domain-string train/test CSVs with laboratory tunnel names. This
  cannot establish timestamped source history or before-completion alerts. Do not
  access rows as a substitute for the missing session evaluation.

No source is assigned to training, validation or reserve by this review. No claim
of untouched domain text beyond raw data: search/documentation may contain example
names. Those public-document exposures must be recorded before any materialization;
no inspected documentation example can become a secretly untouched test case.

## Smallest next action and qualification contract

Obtain a metadata-only qualification bundle for the existing Korving collection:
capture-data permission, archive/member inventory and hashes, actual capture
format/link type/snaplen, tool/version/run identity, timestamp timezone/precision,
and independent process/experiment logs joining source, namespace and start/end
times to tunnel intent. Request available complete benign-only runs across the
five control categories; a missing category is a blocker, not a relabelling task.
Do not send a new publisher message without user authorization.

Before raw acquisition, pin an explicit bounded artifact list, intended roles,
whole-run/fragment grouping, known development exposures, immutable SHA256s and
no-scoring qualification rules. Unknown/mixed queries remain unknown; do not
manufacture 20/50 sessions by slicing files or performing random row splits.
Verify full DNS question visibility with the existing parser without detector
inference, then freeze an eligible session manifest before the one reserved pass.
No active verification, DNS lookups, generation on public endpoints or decryption.

## Verification and disposition

48 existing DNS-candidate/visibility/schema-parser tests passed in 2.21 seconds.
One existing Starlette/httpx deprecation warning; no dependency change. Initial
command named nonexistent `test_protocol_parsers.py` and ran no tests; corrected
to `test_schemas_and_parsers.py`. No bug fixed, no new tests, and no full backend
or frontend rebuild because runtime/shared behavior is unchanged.

Machine-readable pinned publisher file metadata, baseline hashes, existing raw
integrity and final checks are in `verification/dns-tunnel-data-gap-20261015/`.
Only this document, that evidence directory and a completion-plan supplement are
added. No model, detector, dataset, alert history or frozen report changes.

**Definition of Done:** gap identification/source shortlist complete; qualified
reserved data acquisition NOT MET. No new accuracy/timing metrics exist. Stop
dependent validation at the provenance/coverage and source-contract blockers.
Next is the Korving qualification bundle, not a rule change or model experiment.
