# README status notes (2 to 30 October 2026)

Archived verbatim from the README on 16 November 2026. Each note describes its own dated snapshot, not the current state.

**Status, 30 October 2026: a working passive prototype with every required feature built, tested
and pushed.** 832 backend tests and 3 frontend tests pass, TypeScript and the production build
pass, `npm audit` reports 0 vulnerabilities, and a live run of the production app replayed the
demo (256 events, 13 alerts, 7 classes, p95 0.84 ms) and a real 8.8 MB capture. Detector quality is
measured on **real traffic only for botnet C2 and DNS tunnelling**; the other detectors are validated
on controlled synthetic cases. Read [Current status](docs/CURRENT_STATUS.md) for the requirement-by-
requirement table, results and honest limits, and the [Model report](docs/MODEL_REPORT.md) for
models, features, training and validation. The earlier dated checkpoints are archived in
[docs/history](docs/history/README_STATUS_NOTES_20261029.md).

Working local NTRO / SIH prototype: read-only input → causal features → trained model
and rules → structured alerts → replay dashboard. The project owner's four supplied
screenshots govern the requirements, including encrypted-session malware detection.

Univect means a unidirectional vector: one-way traffic, deeper insight. Its shared
black/red/white interface includes an original U/vector symbol, responsive top
navigation, glass panels, a redesigned Monitor and a project footer. See
[the design system](docs/UNIVECT_DESIGN_SYSTEM.md) for branding and motion conventions.

**Clean-checkout follow-up, 15 October 2026:** local commit `a12eb48` passes isolated
installation, 443 backend tests (two optional PyArrow tests skipped), TypeScript,
production build/start, incremental Monitor replay and restart persistence.
The TypeScript lockfile mismatch is corrected. Two high-severity npm dependency
advisories remain; this is not a security clearance or detector-quality promotion.
These local commits have not been pushed. See the
[current reproduction report](docs/CLEAN_CHECKOUT_20261015.md). Older dated results
below describe their historical snapshots, not the current test count.

**Status audited 2 October 2026:** the deployed classifier is synthetic-trained.
Public/weighted DGA candidates and the DNS-tunnelling candidate remain disabled.
Controlled replay works; most threat-quality gates are unresolved or failed.
The corrected fresh checkout passes 225 backend tests, TypeScript, production
build/start, 20/20 Monitor checks and the documented demo. Three inactive public
model artifacts still lose byte-hash integrity under Windows checkout.
**Final release status: NOT READY** — detector-quality blockers remain. See the
[final release audit](docs/FINAL_RELEASE_AUDIT.md) for the requirement table and evidence.
Current local updates are not all published to the remote repository. See the
[completion plan](docs/COMPLETION_PLAN.md) and [report currency](docs/STREAMING_VALIDATION.md).

**Packaging follow-up, 3 October 2026:** all seven frozen models now preserve their
raw checksums in the corrected Windows-style checkout. Its isolated installation,
252 backend tests, TypeScript, production build and incremental demo passed.
This fix is still pending publication; detection-quality blockers are unchanged.
See [model packaging validation](docs/MODEL_PACKAGING_VALIDATION.md).

**Recovery follow-up, 3 October 2026:** failed inference/writes no longer commit
causal state or partial alert batches. Sixteen new regressions, the full 268-test
suite, TypeScript/build and unchanged demo traces pass. Scoped core/SSE performance
gates still pass; model quality is unchanged. See
[event recovery validation](docs/EVENT_RECOVERY_VALIDATION.md) for results and retry
limitations. These changes are pending publication.

