# DGA benign-source qualification decision

14 October 2026. **Downloaded DNS reference is not eligible as-is for the frozen
benign-DNS gate. Final DGA evaluation remains BLOCKED.** This is a source-
qualification failure, not a measured model failure. No numerical gate changed.

## Evidence inspected

Inspected the Mendeley v5 acquisition manifest and CSV header only, DRIFT's pinned
publisher metadata and the primary dataset paper,
[DNS dataset for malicious domains detection](https://pmc.ncbi.nlm.nih.gov/articles/PMC8437788/)
(DOI `10.1016/j.dib.2021.107342`, Marques/Malta/Magalhães, 2021).
No CSV rows, model predictions or reserved classifier outcomes were inspected.

The paper identifies the negative source as Rapid7 Labs Project Sonar lists and
the positive source as SANS Internet Storm Center suspicious-domain lists. Source
membership determined class. It reports encoding the Domain field to anonymize
the original names and rounding derived numerical features. The release page does
not document a raw-name recovery mapping or version-5 exception sufficient to
establish runtime-compatible observed first labels. These findings refine the
earlier unqualified-source status; the acquisition report remains historical.

## Root cause and rejected uses

- **Representation:** encoded/anonymized identifiers and precomputed rounded
  features cannot substitute for the runtime lexical representation without a
  documented, validated raw-name mapping. Do not infer original names from entropy
  or character ratios, or silently score an encoded identifier as a query name.
- **Truth/provenance:** being in a Sonar list does not establish ordinary benign
  client-query intent. The two source classes are not a verified benign-only DNS
  capture. General suspicious-domain labels are not DGA-algorithm labels.
- **Required controls:** no documented machine-generated legitimate/CDN-cloud
  strata or independent client-log provenance was established by this release.

Keep the CSV in its existing quarantine path; preserve its SHA256 and licence.
Do not turn it into a replay preset, score it, add its entropy/reputation/OSINT
columns as predictors or call it the separate benign-DNS final reference. Download
success and the nominal 45,000 negative records do not imply 2,500 eligible labels.
Raw-name compatibility, provenance and eligible counts remain unverified.

DRIFT's raw benign data is a common-popularity reference lead, not all five
legitimate categories and not a client query log. Assigning all its remaining
ranking names to short/long categories would violate the frozen category
precedence. No classifier results or spelling are used to assign categories.

## Task outcome and smallest next action

The qualification audit is complete; its required eligible-benign-data outcome
**fails to meet the Definition of Done**. The complete DGA final manifest is not
created and final scoring remains prohibited. Positive intake counts may be
preserved, but cannot satisfy missing benign requirements. No further model
experiment is justified by this source failure.

**Smallest next action:** obtain publisher-supported original, unencoded benign
client DNS query names with collection/label provenance, licence and service-
category context. A publisher clarification or a qualified new source is needed;
do not manufacture labels, lower sample counts, treat Sonar/popularity as verified
benign activity or automatically contact a new author without authorization.

Only this source-review document and decision evidence change. No code/tests or
runtime behavior is modified for this audit. Hash/disabled-state checks from the
preceding count task are retained, not relabelled as new classification metrics.
Stop sequential implementation at this documented data blocker until eligible
inputs or required source clarification becomes available.
