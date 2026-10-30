# Univect — Passive Threat Intelligence · PS26145

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

## Run locally

Requires Python 3.11+ on PATH, Node.js 22.14+, npm and a modern browser.
Git is required to clone the repository. Initial package installation needs
Internet access. The website uses Next.js 16,
React 19, TypeScript, Tailwind CSS 4, Radix UI, Motion, Lucide, Recharts and Three.js.
Start from a fresh directory in PowerShell:

```powershell
git clone https://github.com/SaiChayank/Cyber-Threat-Detection.git
cd Cyber-Threat-Detection
npm install
npm run dev
```

Open http://localhost:3000 for the platform, http://localhost:3000/monitor for the
dashboard, or http://localhost:3000/docs for interactive API documentation.
The launcher creates `.venv` and installs `requirements.txt` on first use if needed,
then starts FastAPI on loopback port 8000 and Next.js on loopback port 3000.
If a compatible API is already running, it reuses that service. Stop with Ctrl+C.
If port 3000 is occupied, the launcher selects a free port up to 3010 and prints
the website URL. An explicitly configured `WEB_PORT` is respected.
PowerShell installations that block `npm.ps1` can use `npm.cmd` for the same commands.
The frozen fitted model is included; do not retrain it during setup or a demo.
No Redis server, paid service, network attack generator or model download is required.
Use one API worker so streaming state and replay controls stay consistent.

If another application occupies API port 8000, copy `.env.example` to `.env` and
set both `API_PORT` and the port in `API_PROXY_URL` to the same free port before
starting. `WEB_PORT` can select a free website port. Do not stop unrelated services;
the automatic website-port fallback does not change the API port.

Select **All threat scenarios** and **20× speed**, then start replay. The bundled
256-event demo completes in approximately 44 seconds plus delivery overhead and
produces 13 alerts across seven classes; its benign segment emits no alerts.
The initial UI speed is 100×. Select 20× explicitly for the demonstration timing
above; acceleration changes presentation pace, not detector features. Alerts appear while
processing continues. Click an alert for its connection details and numeric evidence.
Replay each class individually or upload an Ethernet `.pcap` or `.pcapng` file (up to 16 MiB).
Filters and JSON export operate on the latest 200 displayed alerts. SQLite retains the
full alert history; `/api/alerts` supports sequence-based pagination and class filtering.

After the first `npm run dev` has installed Python dependencies, stop it with
Ctrl+C before testing the production workflow:

```powershell
npm run build
npm start
```

The production launcher starts both the API and dashboard. No existing `.venv`,
`.env`, raw datasets or analyst database is needed. The API creates a new local
SQLite database automatically; existing history is never cleared by startup.
For the frozen eight-scenario demonstration and offline replay fallbacks, follow
[Final demo guide](docs/FINAL_DEMO.md). Run
`.venv/Scripts/python.exe -m replay.demo_pack` first to verify artifact hashes,
expected evidence and incremental alert positions without changing analyst history.

`npm run typecheck` checks frontend types. Copy `.env.example` to `.env` to customize
ports, API proxy and alert database; defaults work without an environment file.
The browser uses same-origin `/api` requests, including SSE and PCAP uploads.
Root build and runtime commands both load `.env`; rebuild after changing the proxy URL.
For manual Python setup: `python -m venv .venv`, then
`.venv/Scripts/python.exe -m pip install -r requirements.txt` (Windows) or
`.venv/bin/python -m pip install -r requirements.txt` (macOS/Linux).
See [Website guide](docs/FRONTEND.md) for architecture, environment variables and verification.

## Required detection coverage

- DDoS: SYN / high-rate flood summaries, traffic volume and source entropy; slow-HTTP
  exhaustion from many long-lived, low-rate connections
  ([slow-HTTP detection](docs/SLOW_HTTP_DETECTION.md)).
- Botnet C2: inter-arrival regularity and repeated peer communication.
- DGA: domain entropy, digits and bigram statistics.
- DNS tunnelling: long first-label TXT / NULL evidence and synthetic-model hits;
  the broader causal-history candidate is disabled.
- Encrypted-session malware suspicion: client JA3/JA4 and server JA3S fingerprints,
  an operator indicator list, fingerprint rarity and per-session packet-size /
  timing regularity; no application payload decryption. See
  [encrypted-session detection](docs/ENCRYPTED_SESSION_DETECTION.md).
- Reconnaissance: destination host and port fan-out.
- Exfiltration: outbound volume and observed directional byte ratios when available.

DGA and tunnelling are two modules within one official threat category.
Every alert includes timestamp, flow identifier, threat class, confidence, evidence
and severity. Severity is separate from the model score. Rule-only scores are heuristic
strengths; model scores are synthetic-trained posteriors, not calibrated deployment
probabilities. The evidence and dashboard disclose this distinction.

DGA alerts require corroborating first-label lexical evidence even when the model
is confident. This reduces false alarms but misses short and word-based families.
The [before/after validation](docs/STREAMING_VALIDATION.md) reports both noise and
recall; detection quality remains a prototype limitation.

A broader lexical DGA classifier has optional integration behind quality gates.
It recorded 76.77% recall / 1.68% FPR in inspected development comparisons, but
remains disabled because recall and separate benign-DNS FPR 2.34% miss their gates.
The later weighted candidate recorded validation recall 92.80%, precision 99.63%,
FPR 1.82%; it is also disabled because independent reserved domain and separate
benign-DNS evaluations are unavailable. These are not deployed-model accuracy.
The existing guard stays active. See [DGA development](docs/DGA_DETECTION.md) for
the expanded dataset, reproducible training and limitations.

## Reproduce validation

```powershell
.venv/Scripts/python.exe -m pytest -q
node --test tests/frontend/monitor-alert-recovery.test.cjs
.venv/Scripts/python.exe -m replay.demo_pack
.venv/Scripts/python.exe -m benchmarks.run --events 20000
.venv/Scripts/python.exe -m benchmarks.delivery --events 100
.venv/Scripts/python.exe -m replay.cli data/demo/all.jsonl --speed 20
```

Run these after launcher installation, or after the documented manual Python
setup above. They require no downloaded datasets or optional training libraries.
Use `.venv/bin/python` on macOS/Linux. Benchmarks use disposable databases and
write their reports inside this checkout. The offline CLI prints alerts without
writing analyst history. Stop servers before benchmarking to reduce interference.

Training/export commands are optional development tools, not setup or demo steps.
Do not run `python -m ml.train` as a smoke check: it replaces the frozen model.
Public-data evaluations need separately downloaded sources, and candidate training
needs optional training libraries; neither is required for the bundled demo.

`ml/train.py` trains Gaussian naive Bayes on independent synthetic experiments using
exactly the runtime feature extractor. It writes the hash-verified JSON model and
`ml/evaluation.json` with per-class metrics and confusion matrices. Whole experiments
are split into training seeds 1–30, validation 31–40 and test 41–50. The same generator
family supplies each split; this is lab validation, not real-malware validation.

The target is **2,000 simulated flow-metadata events/sec** with core processing and
SQLite persistence **p95 below 50 ms**. Actual measured results and test workload are
stored in `benchmarks/latest.json`; the benchmark excludes HTTP, browser delivery and
raw capture overhead. Packet records and flow summaries are different units.

Earlier saved source-matching run, 1 October 2026:20,000 metadata events,1,170 committed
alerts,5,649.91 events/sec, processing+SQLite p95 0.8416 ms. Separately,
`benchmarks/delivery_latest.json` records100/100 API/persisted/SSE alerts with
loopback p95 240.27 ms against the<1,000 ms gate, excluding capture, Next.js proxy
and browser rendering. [Performance evidence](docs/PERFORMANCE_VALIDATION.md)
records hardware, p50/p95/p99, workload and provenance. Neither is a
raw-capture-to-browser throughput claim. The later clean-checkout release audit
measured 6,248.12 events/sec, core p95 0.8070 ms and API-to-SSE p95 247.48 ms
(100/100 alerts). Its separate reports preserve the earlier JSON measurements.

## Passive architecture and visibility

The detector never probes hosts, completes a handshake, issues mitigation, or decrypts
application payload. Input files are read-only. The offline CLI can operate with no
network IO. The dashboard API is a separate loopback analyst service, not a return
path to monitored hosts. Software tests do not certify physical data-diode isolation.

Missing reverse traffic produces an unavailable ratio, rather than a fabricated
measurement. Volume-only exfiltration suspicion states this limitation. Exported
records may include reverse-byte counts only when explicitly passively observed.

The initial encrypted-session model uses controlled synthetic patterns and a lab
fingerprint, not a production malware feed. Complete single-record TLS ClientHello
JA3/JA4 and ServerHello JA3S are parsed from PCAP. QUIC packet dynamics and supplied metadata are accepted,
but raw QUIC handshake fingerprint extraction is not implemented. TCP reassembly,
IPv6 extension decoding and production authentication are outside this local
prototype. DoH / DoT hide DNS names. Read the full limits before assessing accuracy.

DNS extraction supports UDP/53 and a complete first length-prefixed DNS/TCP message
in one packet, with bounded compression-pointer decoding. Segmented TCP questions
are not reconstructed. Local LLMNR/5355 traffic is not silently classified as DNS
tunnelling; the available captures still need independently labelled attack flows.

## Project files

- `schemas/`: validated metadata and standardized alert contracts.
- `ingest/`: PCAP reader, protocol parsers, metadata adapter and dead-letter handling.
- `features/`: bounded causal feature state shared with training.
- `ml/`: fitted portable model, reproducible training and evaluation.
- `detection/`: model inference, rule baseline, evidence and alert deduplication.
- `persistence/`: SQLite alert storage.
- `backend/`: FastAPI, event ingestion, replay, SSE and saved benchmark output.
- `frontend/`: Next.js / React website and analyst dashboard; modular features,
  shared UI, typed services, Zod schemas, hooks and procedural 3D illustrations.
- `scripts/`: local service launcher and Python environment setup.
- `replay/`: offline scenario simulation, JSONL export and passive CLI replay.
- `benchmarks/` and `tests/`: measured performance and behavior verification.

Current implementation and requirement traceability: [Expected solution](docs/EXPECTED_SOLUTION.md).
Remaining work, acceptance checks and current progress: [Completion plan](docs/COMPLETION_PLAN.md).
Stream-accounting fix and delivery verification: [Streaming reliability](docs/STREAM_RELIABILITY.md).
Model, features and evaluation: [Model documentation](docs/MODEL_AND_VALIDATION.md).
Offline feature definitions/integrity and known historical drift:
[Semantic contract preflight](docs/FEATURE_SEMANTIC_CONTRACT.md) (expected exit 1;
not a runtime activation change or an accuracy gate).
Downloaded public sources, replay presets and measured limitations: [Dataset integration](docs/DATASETS.md).
Scoring detectors on your own labelled lab captures: [Lab evaluation harness](docs/LAB_EVALUATION.md).
Sweeping thresholds on train/validation captures, then the one-shot test run: [Tuning workflow](docs/TUNING_WORKFLOW.md).
One-document summary of models, features, training and validation: [Model report](docs/MODEL_REPORT.md).
Recording those lab captures (setup, scenarios, labelling, splits): [Lab capture protocol](docs/LAB_CAPTURE_PROTOCOL.md).
Importing NetFlow/IPFIX/sFlow exports: [Flow export import](docs/FLOW_EXPORT_IMPORT.md).
Current runtime results and prioritized detection gaps: [Streaming validation](docs/STREAMING_VALIDATION.md).
Older design documents describe proposals; they do not override the supplied screenshots
or establish implemented features and measured results.
