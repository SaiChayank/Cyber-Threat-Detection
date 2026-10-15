# Frozen model packaging validation — 3 October 2026

**Packaging implementation and fresh-checkout verification passed. Publication is
pending; the GitHub branch was not changed. Project release status remains NOT READY.**

## Finding and minimal fix

The previous attributes covered only three of seven model artifacts. Git's
`core.autocrlf=true` changed unprotected multiline JSON to CRLF, so raw SHA256
verification failed. The new checkout regression reproduced this for
`ml/public_cic.json` before the repair. The prior published-checkout audit also
found the active model unprotected because `.gitattributes` was unpublished.

`.gitattributes` now marks all seven frozen model JSON files, demo JSON/JSONL,
and checksummed DGA plans/protocol metadata as `-text`. Git therefore preserves
their exact bytes. Checksum sidecars remain LF text; loaders read their digest
values with whitespace stripped. No loader normalization, model reserialization,
checksum replacement, training or activation change was made.

The regression inventories every model checksum, exercises `core.autocrlf=true`,
`input` and `false`, compares frozen bytes/digests, checks explicit model attributes
and loads the primary model plus all three disabled lexical DGA candidates.
An unprotected control confirms that Windows-style conversion actually occurs.

## Reproducible verification

```powershell
.venv/Scripts/python.exe -B -m pytest tests/test_checkout_setup.py tests/test_demo_pack.py -q -p no:cacheprovider
```

A separate temporary repository copied the 354 non-ignored files of the corrected
pending working tree. Commit `43a67cfe830c068d866e6eb064be56857c5dd7fa` exists only in
that temporary source repository. It was cloned with `--no-local --no-hardlinks`
and `core.autocrlf=true`. The original repository branch and index were untouched.
This is verification of the pending snapshot, not of a newly published release.

The clone began without `.venv`, `node_modules`, `.env`, raw datasets or analyst
history. `npm install` used a fresh cache; `npm run dev` created its own Python
3.13.5 venv and installed `requirements.txt` using a fresh pip cache.
`include-system-site-packages=false`; `pip check` passed. Test ports were
API port18089/website port13089 with matching `API_PROXY_URL`; only the clone's disposable
database received replay alerts. Services were stopped before the default-proxy
production build. Production startup and browser rendering were not rerun.

| Check | Result |
| --- | --- |
| Before repair, expanded checkout regressions | 2 passed / 3 failed |
| After repair, checkout regressions | 5 passed; all three Git policies covered |
| Packaging plus frozen-demo tests | 20 passed |
| Explicit model packaging coverage | 3 → 7 artifacts |
| Fresh checkout artifact checksums | 7/7 unchanged and matching |
| Fresh isolated backend suite | 252 passed, 0 failed/skipped, one existing warning |
| Fresh TypeScript check | Passed, incremental caching disabled |
| Fresh production build | Passed, Next.js 16.3.6 |
| Fresh demo preflight | Nine fixtures verified; benign zero alerts |
| Fresh development startup | Landing, Monitor and proxied health HTTP 200 |
| ALL replay at 20x through Next.js | 256 events, 15 persisted/SSE-delivered matching alerts, seven classes |
| Incremental alert observation | Replay still running at event 38 |
| Candidate activation | Public DGA and DNS-tunnel candidate disabled |

All seven original model payloads and checksum sidecars, frozen demo inputs, DGA
metadata, inspected runtime files, analyst database and original Git index retained
their pre-verification hashes. See the [machine-readable report](verification/model-packaging-20261003/report.json)
and accompanying test/build/replay records. Existing benchmark and evaluation
reports were not overwritten or rerun; synthetic replay is functional evidence,
not generalization accuracy or capture-to-browser throughput.

## Freeze and next step

Freeze this packaging policy and its regressions with the unchanged artifacts.
The packaging task's local Definition of Done passed. The correction and required
pending demo/model files must still be committed and published before a GitHub
clone can receive the fix. Historical release reports retain their original scope.

**Next implementation task:** persistence/inference retry recovery only, with
regressions for failed writes and state consistency. It has not been started.
