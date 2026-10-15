# Offline semantic preflight acceptance — 7 October 2026

This task accepts the **tool**, not the classifier or a model promotion.
It uses only the previous diagnostic's controlled fixtures and hand-specified
window/overflow/peer/missing-value counterexamples. No dataset split is inspected.

Required before freezing the tool:

1. Pin the frozen raw model SHA256, historical Git reference/source hashes, all
   20 feature names/order, transform, current source text hashes and definitions.
2. Verify current window, rate accounting, event weighting, reverse-data absence,
   observed-zero reverse, peer size/history and causal late-event behavior.
3. Expose known historical incompatibility separately from current conformance;
   it must return nonzero. Neither result implies prediction quality.
4. Negative tests must detect semantics changing while feature names remain
   unchanged, changed transform/order, integrity failures and unavailable history.
5. Numerical comparison must not equate null/false with zero or accept nonfinite
   values. Preserve existing reports rather than silently overwrite them.
6. Frozen artifacts, disabled candidates, detector/runtime source, diagnostic
   behavior, raw datasets and analyst history must remain unchanged.
7. Run the targeted preflight, diagnostic and existing rate regressions. Full
   backend/build is required only if shared runtime behavior changes; it does not.

An unexpected drift/error leaves compatibility **UNVERIFIED** (exit 2). Expected
legacy drift is **FAIL** (exit 1), even when current conformance is **PASS**.
Exit 0 requires both current conformance and historical compatibility to pass.
No self-updating manifest, training, prediction, activation or threshold tuning
is permitted. Stop after this offline check and its recorded decision.
