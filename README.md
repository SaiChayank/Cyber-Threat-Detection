# PS26145 — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

Working local NTRO / SIH prototype: read-only input → causal features → trained model
and rules → structured alerts → replay dashboard. The project owner's four supplied
screenshots govern the requirements, including encrypted-session malware detection.

## Run locally

Requires Python 3.11+ and Node.js 22.12+ (the current frontend uses Vite 8).
From the repository root in PowerShell:

```powershell
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt
npm.cmd install --prefix frontend
npm.cmd run build --prefix frontend
.venv/Scripts/python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000 for the dashboard or http://127.0.0.1:8000/docs for
interactive API documentation. The fitted model is included, so training is optional.
No Redis server, paid service, network attack generator or model download is required.
Use one API worker so streaming state and replay controls stay consistent.

Select **All threat scenarios**, choose a speed, and start replay. Alerts appear while
processing continues. Click an alert for its connection details and numeric evidence.
Replay each class individually or upload a classic Ethernet `.pcap` file (up to 16 MiB).
Filters and JSON export operate on the latest 200 displayed alerts. SQLite retains the
full alert history; `/api/alerts` supports sequence-based pagination and class filtering.

For frontend development, run `npm.cmd run dev --prefix frontend` alongside the API.
The development dashboard at port 5173 connects to the local API on port 8000.

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

## Project files

- `schemas/`: validated metadata and standardized alert contracts.
- `ingest/`: PCAP reader, protocol parsers, metadata adapter and dead-letter handling.
- `features/`: bounded causal feature state shared with training.
- `ml/`: fitted portable model, reproducible training and evaluation.
- `detection/`: model inference, rule baseline, evidence and alert deduplication.
- `persistence/`: SQLite alert storage.
- `backend/`: FastAPI, event ingestion, replay, SSE and dashboard serving.
- `frontend/`: TypeScript / Vite analyst dashboard.
- `replay/`: offline scenario simulation, JSONL export and passive CLI replay.
- `benchmarks/` and `tests/`: measured performance and behavior verification.

Current implementation and requirement traceability: [Expected solution](docs/EXPECTED_SOLUTION.md).
Model, features and evaluation: [Model documentation](docs/MODEL_AND_VALIDATION.md).
Downloaded public sources, replay presets and measured limitations: [Dataset integration](docs/DATASETS.md).
Current runtime results and prioritized detection gaps: [Streaming validation](docs/STREAMING_VALIDATION.md).
Older design documents describe proposals; they do not override the supplied screenshots
or establish implemented features and measured results.
