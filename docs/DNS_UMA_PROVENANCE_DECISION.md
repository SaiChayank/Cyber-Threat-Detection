# UMA public provenance follow-up

17 October 2026 UTC / 18 October IST; baseline `b9dd408`. Metadata-only follow-up.
**Executed DNS session/category provenance remains NOT ESTABLISHED.**

Reviewed the complete 47-entry public Git tree pinned to
`c756900b014fb9c5066b437372aba281e1bd320e`, the already exposed producer protocol
and appendix, and five further text documents selected before retrieval. All five
match publisher Git blob identities and sizes. No CSV, capture, packet header,
model, script or detector value was read or executed in this task.

The producer's external-reference manifest README explicitly says its manifests
are templates which users must adapt. Their stated columns describe capture path,
source/profile/host/local IP and nominal duration; they do not establish executed
per-DNS-session intent, namespace, original query timestamps or five DNS controls.
The pinned catalogue lists two template CSVs, descriptive example summaries and
capture-level metrics. None is read as a substitute for source session truth.

The external comparison uses one CIC-IDS2017 host and nonoverlapping 900-second
windows. It explicitly disclaims distributional equivalence. A window is not an
independently labelled DNS application session. Its workflow sorts packets and
exports windowed captures; those instructions were not executed and cannot replace
the frozen requirement to preserve original order/time. This is a scope mismatch,
not a claim that the publisher's descriptive comparison is invalid.

The reproducibility map references `docs/experimental_protocol.md`, `agents/`,
`planner/`, `exp1/` and `analysis/`; none appears in this pinned tree. The earlier
appendix's optional provenance/template descriptions therefore cannot be treated
as actual executed manifests delivered with this release. No inference is made
about unpublished material or future repository revisions.

**Decision:** no newly qualified source/time/namespace joins, independently
labelled DNS sessions, benign categories or supported original input. Both
downloaded sources retain null training/validation/reserved roles and the DNS
candidate remains disabled. No gate/readiness change, decoder install, conversion,
traffic generation, new contact or scoring. Dataset archives and alert history
remain intact; only primary text/document metadata is added.

Evidence: `verification/dns-uma-provenance-20261017/`; the selection plan predates
five document reads. Checks verify source identities, template-vs-executed-manifest
distinction and protected hashes. No application/helper code changed, so no new
tests, full suite or frontend build is reported. Findings are documentation/data
limitations, not a fixed backend bug or measured accuracy result.

**DoD:** bounded public provenance follow-up complete; DNS evaluation-data DoD
remains blocked. Further source/format work requires an actual original input/run
bundle; do not repeatedly inspect these same metadata hoping to infer labels.
Under the user's continuous-work authorization, the next independent task is
**T24 reconnaissance observability diagnosis**, using existing exposed development
cases only, with no model or detector change.
