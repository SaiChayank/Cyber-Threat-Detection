# Frozen final demonstration pack

Prepared 1 October 2026. This pack verifies **functional, incremental synthetic
replay**, not independent detection quality or production accuracy. It uses the
unchanged default `Pipeline()` and frozen synthetic model. Public/weighted DGA
candidates and the DNS-tunnelling candidate remain disabled. No probes, source
lookups, return path, inline mitigation or payload decryption are involved.

Documentation audit2 October: the original streaming narrative used as benign
reference documentation is preserved in `docs/history/STREAMING_VALIDATION_20260929.md`.
The manifest's documentation pointer follows that byte-identical archived record;
fixture/model hashes and expected alert traces are unchanged. Checksum-sidecar
provenance also normalizes line endings following the clean-checkout packaging fix.
These are provenance corrections, not new detector results or a completed clean run.

## Preflight and safe startup

From the repository root, with the existing Python environment:

```powershell
.\.venv\Scripts\python.exe -m replay.demo_pack
.\.venv\Scripts\python.exe -m pytest tests/test_demo_pack.py -q
```

Preflight is read-only. It verifies the manifest sidecar, runtime/model/report
hashes, fixture hashes, generator equivalence, complete ordered alert evidence,
counts and first-alert positions. It fails on drift rather than rewriting
expectations. All nine fixtures are supplied under `data/demo`; no dataset download or
retraining is needed. Code/report/checksum-sidecar hashes normalize CRLF to LF; fixture and model
hashes cover exact bytes. `.gitattributes` pins their line endings for Windows
checkouts without changing model artifacts.

For an empty Monitor demonstration, stop the existing development server first.
Run in a new PowerShell terminal with a fresh database path:

```powershell
$env:ALERT_DB = Join-Path ([IO.Path]::GetTempPath()) ("univect-demo-" + [guid]::NewGuid().ToString("N") + ".sqlite3")
npm.cmd run dev
```

Open the printed website URL and `/monitor`. Confirm the new history is empty.
The launcher can reuse an already-running compatible API, which retains its own
database; restarting the server is necessary for isolation. Existing `.env` can
customize ports; the variable above applies to the newly launched backend. Stop
with Ctrl+C. The disposable database is not automatically deleted. Existing
analyst history, raw datasets and `data/lab` files are preserved.

## Standalone scenarios and combined order

| Standalone preset | First event / 32 | Observed delay | First alert at 20x | Total alerts |
| --- | ---: | ---: | ---: | ---: |
| `BENIGN` | none | 0.000 s | 0.000 s | 0 |
| `DDOS` | 3 | 1.743 s | 0.087 s | 2 |
| `BOTNET_C2` | 8 | 17.476 s | 0.874 s | 2 |
| `DGA_DOMAINS` | 1 | 0.000 s | 0.000 s | 2 |
| `DNS_TUNNELLING` | 1 | 0.000 s | 0.000 s | 4 |
| `ENCRYPTED_MALWARE` | 2 | 0.924 s | 0.046 s | 2 |
| `RECONNAISSANCE` | 17 | 18.511 s | 0.926 s | 1 |
| `DATA_EXFILTRATION` | 1 | 0.000 s | 0.000 s | 2 |

| Scenario | Evidence | Known limitation |
| --- | --- | --- |
| `BENIGN` | Normal low-volume lab metadata; expect no alerts. | A tiny synthetic control, not a production false-positive estimate. [Report](STREAMING_VALIDATION.md). |
| `DDOS` | TCP packet/byte rate, declared SYN fraction, source diversity and ten-second window evidence. | Aggregated SYN summaries with explicit simulated counts; not raw capture throughput, UDP amplification or proof of forged sources. [Report](SYN_FLOOD_VALIDATION.md). |
| `BOTNET_C2` | At least eight same-peer observations; regular interarrival mean/CV and one destination. | Periodic health checks can be indistinguishable; slow/rotating beacons remain unresolved. Timing pattern already informed training. [Report](C2_BEACON_VALIDATION.md). |
| `DGA_DOMAINS` | Observed random first label, entropy, length and bigram surprise. | Current conservative lexical guard only; public/weighted candidates remain disabled. Short/word-based DGA generalization remains unresolved. [Report](DGA_WEIGHTED_CANDIDATE.md). |
| `DNS_TUNNELLING` | Long high-entropy TXT query label and txt_record=1; DGA overlap is expected. | Controlled long-TXT metadata only, not a real dnscat2/iodine capture. Formal candidate is disabled; other record types/rates not validated by this pack. [Report](DNS_TUNNELLING_FORMAL_VALIDATION.md). |
| `ENCRYPTED_MALWARE` | Encrypted flag, lab fingerprint risk, observed size CV and timing CV; metadata-only suspicion. | Supplied synthetic TLS/QUIC metadata, not decrypted malware. Lab JA3 is not reputation evidence; no raw QUIC fingerprint extraction; detector remains experimental. [Report](ENCRYPTED_SESSION_VALIDATION.md). |
| `RECONNAISSANCE` | Ten-second destination/port fan-out and observed SYN fraction. | Authorized scans/service discovery can trigger; slower scans beyond the window may be missed. Passive metadata cannot infer authorization. [Report](RECON_VALIDATION.md). |
| `DATA_EXFILTRATION` | Observed source-forward bytes and explicitly supplied reverse availability/ratio; possible-exfiltration wording. | Reverse bytes are explicitly simulated as observed here. Missing reverse stays unavailable in runtime. Backups/uploads can match; stolen content/intent is not proven. [Report](EXFIL_VALIDATION.md). |

| Combined order | Segment | First global event (segment event) | First alert at 20x |
| ---: | --- | --- | ---: |
| 1 | `BENIGN` | none | no alerts |
| 2 | `DDOS` | 37 (5) | 6.31 s |
| 3 | `BOTNET_C2` | 72 (8) | 12.98 s |
| 4 | `DGA_DOMAINS` | 97 (1) | 18.08 s |
| 5 | `DNS_TUNNELLING` | 129 (1) | 24.08 s |
| 6 | `ENCRYPTED_MALWARE` | 162 (2) | 30.12 s |
| 7 | `RECONNAISSANCE` | 206 (14) | 36.79 s |
| 8 | `DATA_EXFILTRATION` | 225 (1) | 42.01 s |

| Preset | Frozen artifact | Exact-byte SHA256 |
| --- | --- | --- |
| `BENIGN` | [benign.jsonl](../data/demo/benign.jsonl) | `b04d997f45fea4daca3cc82fc019d34e35198742c74d649f333ef36d2f99cd9a` |
| `DDOS` | [ddos.jsonl](../data/demo/ddos.jsonl) | `16e4c8ef2d5c5b5aa709c60cdaa2bfde030fd460ebd15e9db889c5d1a461109d` |
| `BOTNET_C2` | [botnet_c2.jsonl](../data/demo/botnet_c2.jsonl) | `bb16c8f8e0ed94e00b02dca13510f89c501be964f033a537304b313919a53dc1` |
| `DGA_DOMAINS` | [dga_domains.jsonl](../data/demo/dga_domains.jsonl) | `36009ec4123b69a9dd1de84be66f8365429f6e51293f5599fc71b39c0edc4407` |
| `DNS_TUNNELLING` | [dns_tunnelling.jsonl](../data/demo/dns_tunnelling.jsonl) | `57af1a6c53a44ddf9dfb7a56bcc1277eb139e03b2f47e6dc755e3ac94ca7034f` |
| `ENCRYPTED_MALWARE` | [encrypted_malware.jsonl](../data/demo/encrypted_malware.jsonl) | `a044d690d65334972fe40d3a79abf8dd93e3db1d7355f920eed3b5af37f86175` |
| `RECONNAISSANCE` | [reconnaissance.jsonl](../data/demo/reconnaissance.jsonl) | `0d5e053da87068f767ea46a1bb26b91979709754c4bcf7df8c618abee01c31ff` |
| `DATA_EXFILTRATION` | [data_exfiltration.jsonl](../data/demo/data_exfiltration.jsonl) | `6c43c51516b95c2a49a0be07ec75acbb61458cf6478f85a0598871938b4bd9c1` |
| `ALL` | [all.jsonl](../data/demo/all.jsonl) | `fb21cc5a7942dedb9f319dad0ef21fdb7bae4e8f0ea9f2be8605530b04e18444` |

Manifest SHA256: `e6eec414a1d32aa7ef3dd98024c02192f45f68d71bdd3285d6ec8139b7819442`. [Manifest](../data/demo/manifest.json) records complete source/model/report provenance, first-alert payloads and ordered alert trace hashes; [sidecar](../data/demo/manifest.sha256) pins it.

Each individual Monitor/API preset uses `scenario(label, seed=100, count=32)`
with a fresh pipeline. Choose **20Ãƒâ€”** and let each finish before starting another.
Each saved JSONL is its offline fallback. Timing is from the first observed event,
excluding scheduler/API/SSE/browser delay. Acceleration changes presentation pace,
not detector semantics.

Benign must produce zero new alerts. TXT tunnelling produces two tunnelling and
two DGA alerts; overlap is expected, not four independent attacks. Other standalone
positives each emit two primary alerts except reconnaissance, which emits one.
Repeated alerts beyond the 30-second event-time dedup interval are expected.

For one presentation, select **All threat scenarios** (`ALL`) at **20Ãƒâ€”**. It uses
`mixed_demo(seed=100)`: eight 32-event segments, seeds 100Ã¢â‚¬â€œ107, starts separated
by 120 seconds. This differs from concatenating standalone seed-100 files.
`data/demo/all.jsonl` is the exact frozen combined fallback. One shared pipeline
receives 256 events and emits 13 alerts (15 before the 30 October registrable-label DGA guard, which stopped
labelling tunnel subdomains as DGA); approximate duration is **43.72 seconds**
plus delivery overhead.

Present in this order: benign Ã¢â€ â€™ DDoS Ã¢â€ â€™ C2 Ã¢â€ â€™ DGA Ã¢â€ â€™ DNS tunnelling Ã¢â€ â€™ encrypted-session
indicators Ã¢â€ â€™ reconnaissance Ã¢â€ â€™ possible exfiltration. Wait for **Complete**, confirm
seven threat classes, open one record per class, inspect evidence, filter and
export JSON. ALL contains two DGA records, two each for
DDoS/C2/tunnelling/encrypted/exfiltration, and one reconnaissance record.

Full first-alert payloads, observed DNS names, numeric evidence, detection source,
severity and stable flow identifiers are in the manifest. Confidence is heuristic
strength or a synthetic-trained posterior, not calibrated malicious intent.
Deterministic positive replays do not close unresolved quality gates.

## Replay fallbacks

Every entry is **replay-only**: loopback analyst API/Monitor or offline CLI.
No live hostile traffic is generated. These are already inspected development/
training-family examples, not reserved evaluation data. Unreliable mixed public
PCAPs were excluded. Legacy `data/lab/ddos.jsonl` lacks explicit SYN summary counts
and is not the current DDoS fallback; it is preserved.

If the browser is unavailable but the backend works, call the existing API:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/replay/start -ContentType "application/json" -Body '{"scenario":"ALL","speed":20}'
Invoke-RestMethod http://127.0.0.1:8000/api/telemetry
Invoke-RestMethod http://127.0.0.1:8000/api/alerts
```

Use the configured API port. Replace `ALL` with any standalone preset. Stop an
active replay before starting another. Start resets feature/dedup state while
preserving alert history.

If the API or browser is unavailable, run the existing detection pipeline offline:

```powershell
.\.venv\Scripts\python.exe -m replay.cli data/demo/all.jsonl --speed 20
.\.venv\Scripts\python.exe -m replay.cli data/demo/ddos.jsonl --speed 20
```

Replace the path with any listed artifact. `--speed 0` is unpaced. Each invocation
starts fresh causal state and streams actual JSON alerts to stdout; it does not
persist them or populate Monitor. JSONL files are CLI fallbacks, **not PCAP
uploads**. Do not rename them to `.pcap`.

## Reproducibility and verification

UUIDs, creation wall clocks and database sequences vary on each run to keep
persisted records unique. Preflight checks the full ordered alert projection
excluding those fields, rounding floating metrics to nine decimals. Flow IDs,
event timestamps, classes, narratives, severity, source, confidence, counts and
evidence remain checked. Runtime output itself is unchanged. Presentation timing
is not a latency benchmark.

To reproduce inputs into a separate directory, iterate each exact `source` call
in the manifest and write `TrafficEvent.model_dump_json()` followed by LF in UTF-8.
The verifier independently regenerates those event objects and checks equality,
as well as the frozen file bytes. Do not bless new expectations automatically
when preflight fails; inspect the drift first.

Python 3.13.5: **15 targeted tests passed**. These cover repeated offline preflight
with network access forbidden, tamper/drift rejection, stable identity projection,
and all nine API presets twice using temporary databases. Replays completed
without errors; restart reproduced payloads without deleting prior records.
Frontend and detector behavior were unchanged in this task.

The actual offline `replay.cli` ALL entry point was also smoke-tested unpaced:
15 alerts, all seven expected classes, successful exit and no stderr output.
The original analyst database SHA256 remains unchanged.

Full backend suite: **223 passed**, one existing Starlette/httpx deprecation warning. TypeScript/build were not rerun: no frontend or shared runtime behavior changed; the prior UI pass records their successful run.

**Definition of Done:** eight standalone scenarios plus ALL, pinned artifacts,
benign zero-alert control, seven early threat alerts, evidence/timing/limitations,
replay fallbacks and deterministic verification. Demo-pack preparation is complete;
independent quality gaps, fresh-install/package checks and publication are separate.
The next proposed task is a clean-checkout installation and complete demo smoke
test, after explicit authorization.
