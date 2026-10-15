# Formal DNS-tunnelling scoring tool — T01

15 October 2026. **Tooling DoD PASS; reserved evaluation/data readiness BLOCKED.**
No detector, feature, model, threshold, frozen contract or runtime flag changed.
No new raw data or reserved observations inspected. Failed candidates stay disabled.

## Inspected and finding

Reviewed the formal protocol, current source-pinned evaluation contract, historical
development evaluator, candidate/runtime implementation, DNS schema/adapter and
contract/recovery tests. The development evaluator treats any alert as detection;
it cannot implement the frozen final-query-only FN and joint early-alert gates.
It remains unchanged as a historical development comparison. The new offline
`datasets/score_dns_tunnel.py` reuses `Pipeline(dns_tunnel_candidate=True)` with the
same synthetic-model BENIGN override as the frozen evaluation arm.

Each independently labelled session gets a fresh pipeline. Complete question
events use the existing TrafficEvent schema, causal features and rule; no future
events, lookups, reputation, network calls, fitting or payload decryption. Queries
must supply observed type/name/time rather than relying on defaults, match the
annotated source/namespace and represent one question event, not aggregate flows.
Reserved sessions require labelled time bounds, enforced for every query. Preserve
capture order/duplicates; disclose dropped late questions and actual QTYPE/rate
counts, not invented coverage.

## Implemented scoring and guardrails

- TP only before the final labelled query; final-only positive is FN. Any benign
  target alert, including a final-query alert, is FP. Repeated alerts count once
  per session; retain first-alert evidence, query index and capture delay.
- Precision/recall/F1/FPR and early-TP fraction. Undefined denominators are null,
  cannot pass and are not converted to zero or 100%. Early requires query<=10
  AND delay<=10,000ms for >=90% of TPs; original numerical gates unchanged.
- Frozen contract identity, all 23 source pins and original protocol hash verified
  before evaluation. Source/contract mismatch refuses; no command-line bypass.
- Reserved manifest must pin this scorer's SHA256, role, explicit boolean labels,
  qualification report hashes, tool/benign category and annotated session identity,
  original session export/fragment grouping, source/namespace and interval.
  Require >=20 positive/>=50 benign sessions, the five controls and dnscat2/iodine.
  Duplicate sessions, independence IDs, original-session fragment groups and exact
  event artifacts refuse. Multiple genuinely independent sessions can share a run
  or capture: fragment_group identifies exports of ONE annotated session, not an
  entire physical capture. Independence requires reviewed evidence, not filename
  slicing or new IDs assigned by this tool.
- Reviewed permission/label/visibility/disjointness/role/client-question flags and
  referenced report identities are consistency checks, not automatic proof that a
  publisher has granted rights or labels are true. Source qualification is upstream.
- Local artifact paths stay within the repository after symlink resolution. No
  remote URL input, archive processing, capture-format addition or database writes.
- One fixed exclusive receipt precedes reserved question/hash reads and inference.
  Runtime/input failures keep it consumed and save an explicit incomplete
  NO_PROMOTION report. Changing output paths does not permit another pass. This is
  a local reproducibility guard, not tamper-proof infrastructure; never delete the
  receipt to reuse a consulted set. Existing reports are not overwritten.

The current frozen contract says readiness=false with no reserved manifest. Thus
reserved mode exits 2 before manifest/row access or receipt/output creation.
Unblocking it requires a separately approved source/session/scorer/contract freeze;
editing a flag and rehashing the file cannot bypass the built-in contract identity.
Nothing is automatically activated even after a future numerical PASS.

## Usage

From repository root, using the existing installed environment:

```powershell
.venv/Scripts/python.exe -B -m datasets.score_dns_tunnel --mode development --output "$env:TEMP/univect-dns-development.json"
```

Choose a new unused output filename on subsequent diagnostic runs. Development
mode only uses the existing 20 exposed scenarios and labels every result as such.
It cannot load arbitrary inputs or issue a promotion decision.

```powershell
.venv/Scripts/python.exe -B -m datasets.score_dns_tunnel --mode reserved --output "$env:TEMP/univect-dns-reserved.json"
```

Currently this must refuse; it is not a way to run final evaluation yet. Do not
alter the frozen readiness/identity or supply dummy qualification to make it run.

Future approved manifest schema: `role`, `contract_sha256`, `scorer_sha256`, the six
verified qualification flags in `PREREQUISITES`, `qualification_reports` mapping
local reviewed documents to SHA256, and `sessions`. Each session requires
`session_id`, `independence_id`, `run_id`, `fragment_group`, `label_reference`,
`start_ms`, `end_ms`, `source_ip`, `namespace`, `events_file`, `events_sha256`,
boolean `positive`, `tool` and `benign_category`. Event files are immutable JSONL
normalizations of qualified original queries, using existing metadata format;
their provenance/normalization must be reviewed and frozen BEFORE scoring. No
manifest or new event files are created here. The future manifest and sidecar path
must be bound in the separately approved contract; CLI does not select a reserve.

## Verification and exact scope

Added 61 parametrized/unit cases in `tests/test_dns_tunnel_scorer.py`: confusion
logic, numerical/timing boundaries, undefined values, repeated alerts, real known
runtime traces, late/invalid questions, missing/duplicate/insufficient metadata,
source hashes, interval bounds, path containment, non-overwrite, blocked-mode
non-access, exclusive receipt and hash/validation/runtime failure consumption.
Tests exercising a future-ready path use artificial qualification objects entirely
inside temporary directories, not actual reserved data or publisher permissions.

Combined scorer/DNS/parser/recovery check: **131 passed in 14.74s**, one existing
Starlette/httpx deprecation warning. Evidence: `verification/dns-formal-scorer-20261015/`.
Earlier intermediate test/development outputs are retained; final files are
`tests-final.log`, `test-result-final.json`, `development-final.json`, `cli-final.json`.

Known development comparison, before versus new scorer: each training and
validation split remains 5TP/5TN/0FP/0FN; all five validation attacks alert at
query 5/12, capture delays 3.8–7.2s. No final-only alert existed in those historical
traces; invented metric-boundary tests demonstrate that correction. These tiny
synthetic counts are NOT field accuracy or a new passing candidate evaluation.
Development decision is NOT_EVALUATED_DATA_BLOCKED. Actual reserved CLI refused
with no receipt or output, preserving the unused single-pass allowance.

Files added: scorer, tests, this doc and dated protocol/test/development/integrity
evidence; completion plan and remaining-work plan updated. No shared runtime or
frontend code changed, so full backend/build/browser checks are not relabelled as
newly rerun. Existing frozen inputs/artifacts/reports remain intact.

**Freeze:** scorer behavior/source identity, tests, result, scope and limitations.
Do not expand it into model training, a new ingestion system or a promotion task.
Next eligible independent package: **T02 — clean-checkout reproduction of the
committed baseline**. T30/source qualification and actual final scoring remain
blocked on genuine permitted data; do not wait-idle or substitute synthetic truth.
