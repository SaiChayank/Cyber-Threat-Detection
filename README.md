# Univect — Passive Threat Intelligence · PS26145

Working local NTRO / SIH prototype: read-only input → causal features → trained model
and rules → structured alerts → replay dashboard. The project owner's four supplied
screenshots govern the requirements, including encrypted-session malware detection.

Univect means a unidirectional vector: one-way traffic, deeper insight. Its shared
black/red/white interface includes an original U/vector symbol, responsive top
navigation, glass panels, a redesigned Monitor and a project footer. See
[the design system](docs/UNIVECT_DESIGN_SYSTEM.md) for branding and motion conventions.

## Run locally

Requires Python 3.11+ on PATH and Node.js 22.14+. The website uses Next.js 16,
React 19, TypeScript, Tailwind CSS 4, Radix UI, Motion, Lucide, Recharts and Three.js.
From the repository root in PowerShell:

```powershell
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
The fitted model is included, so training is optional.
No Redis server, paid service, network attack generator or model download is required.
Use one API worker so streaming state and replay controls stay consistent.

Select **All threat scenarios**, choose a speed, and start replay. Alerts appear while
processing continues. Click an alert for its connection details and numeric evidence.
Replay each class individually or upload a classic Ethernet `.pcap` file (up to 16 MiB).
Filters and JSON export operate on the latest 200 displayed alerts. SQLite retains the
full alert history; `/api/alerts` supports sequence-based pagination and class filtering.

To run the optimized website, use `npm run build` followed by `npm start`.
`npm run typecheck` checks frontend types. Copy `.env.example` to `.env` to customize
ports, API proxy and alert database; defaults work without an environment file.
The browser uses same-origin `/api` requests, including SSE and PCAP uploads.
Root build and runtime commands both load `.env`; rebuild after changing the proxy URL.
For manual Python setup: `python -m venv .venv`, then
`.venv/Scripts/python.exe -m pip install -r requirements.txt` (Windows) or
`.venv/bin/python -m pip install -r requirements.txt` (macOS/Linux).
See [Website guide](docs/FRONTEND.md) for architecture, environment variables and verification.

## Required detection coverage

- DDoS: SYN / high-rate flood summaries, traffic volume and source entropy.
- Botnet C2: inter-arrival regularity and repeated peer communication.
- DGA: domain entropy, digits and bigram statistics.
- DNS tunnelling: long query names and TXT / NULL anomalies.
- Encrypted-session malware suspicion: TLS fingerprints and encrypted packet-size /
  timing patterns; no application payload decryption.
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

## Reproduce validation

```powershell
.venv/Scripts/python.exe -m pytest -q
.venv/Scripts/python.exe -m datasets.validate_streaming
.venv/Scripts/python.exe -m ml.train
.venv/Scripts/python.exe -m benchmarks.run --events 20000
.venv/Scripts/python.exe -m replay.export
.venv/Scripts/python.exe -m replay.cli data/lab/dga_domains.jsonl
```

`ml/train.py` trains Gaussian naive Bayes on independent synthetic experiments using
exactly the runtime feature extractor. It writes the hash-verified JSON model and
`ml/evaluation.json` with per-class metrics and confusion matrices. Whole experiments
are split into training seeds 1–30, validation 31–40 and test 41–50. The same generator
family supplies each split; this is lab validation, not real-malware validation.

The target is **2,000 simulated flow-metadata events/sec** with core processing and
SQLite persistence **p95 below 50 ms**. Actual measured results and test workload are
stored in `benchmarks/latest.json`; the benchmark excludes HTTP, browser delivery and
raw capture overhead. Packet records and flow summaries are different units.

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
JA3 is parsed from PCAP. QUIC packet dynamics and supplied metadata are accepted,
but raw QUIC handshake fingerprint extraction is not implemented. TCP reassembly,
PCAPNG, IPv6 extension decoding and production authentication are outside this local
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
Model, features and evaluation: [Model documentation](docs/MODEL_AND_VALIDATION.md).
Downloaded public sources, replay presets and measured limitations: [Dataset integration](docs/DATASETS.md).
Current runtime results and prioritized detection gaps: [Streaming validation](docs/STREAMING_VALIDATION.md).
Older design documents describe proposals; they do not override the supplied screenshots
or establish implemented features and measured results.
