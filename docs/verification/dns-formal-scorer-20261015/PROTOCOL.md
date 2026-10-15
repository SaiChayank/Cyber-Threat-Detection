# T01 — formal DNS scorer implementation boundary

15 October 2026. Recorded before implementation/test observations. Build only
offline evaluation tooling; preserve the current DNS contract, gates, detectors,
models, raw datasets and analyst history. Use known synthetic development inputs
and fabricated metric-boundary test observations only. No new source values.

Acceptance: correct session confusion counts (final-query-only positive is FN),
undefined denominators, F1 and FPR, first-alert capture delay/query index, AND timing
gate, independent-session/coverage metadata validation, exact contract/source pins,
output non-overwrite and fail-closed single-pass receipt before reserved rows.
Current frozen readiness is false; reserved mode must refuse before manifest/input
reads, classifier inference or receipt creation. Development output cannot promote.

Future reserved input must come from a separately reviewed/pinned session manifest;
this task neither supplies one nor authorizes changing readiness. A receipt remains
consumed on a scoring/runtime failure, preventing retries on a consulted reserve.
No public final evaluation or runtime activation is performed in this task.
