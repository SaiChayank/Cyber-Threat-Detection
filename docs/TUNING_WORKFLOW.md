# Tuning workflow (P0-5), once your lab captures exist

Everything below is ready; only your labelled captures are missing. Record and label
them per [Lab capture protocol](LAB_CAPTURE_PROTOCOL.md), assigning whole runs to
`train`, `validation` or `test` **before** looking at any result.

## 1. Baseline

```powershell
.venv/Scripts/python.exe -m datasets.evaluate_lab runs/*train*.json runs/*validation*.json --out baseline.json
```

Read episode recall, alert precision and benign false alerts per 1,000 events per
threat (see [Lab evaluation](LAB_EVALUATION.md)). Note every miss and false alert by
run and scenario.

## 2. Sweep thresholds (train and validation only)

Write a grid of the thresholds you want to explore (whitelisted, at most 200
combinations):

```json
{
  "tls_indicators.MIN_CLIENT_POPULATION": [3, 5, 8],
  "tls_indicators.MAX_SIZE_CV": [0.15, 0.25, 0.4],
  "slow_http.MIN_SLOW_CONNECTIONS": [30, 50, 100],
  "slow_read.MIN_SLOW_READ_CONNECTIONS": [30, 50, 100]
}
```

```powershell
.venv/Scripts/python.exe -m datasets.tune_lab grid.json runs/*train*.json runs/*validation*.json --max-false-alerts 1.0 --out sweep.json
```

`datasets/tune_lab.py` ranks settings by mean episode recall subject to a cap on
benign false alerts per 1,000 benign events, then fewer false alerts, then
precision. It **refuses any capture labelled `test`** and never edits the runtime.
Tunable knobs: `tls_indicators` (`MIN_SESSION_PACKETS`, `MAX_SIZE_CV`, `MAX_IAT_CV`,
`MAX_MEAN_BYTES`, `MAX_FINGERPRINT_CLIENTS`, `MIN_CLIENT_POPULATION`), `slow_http`
(`MIN_SLOW_CONNECTIONS`, `MIN_AGE_S`, `MAX_CLIENT_RATE_BPS`) and `slow_read`
(`MIN_SLOW_READ_CONNECTIONS`, `SMALL_WINDOW`, `MIN_AGE_S`). Other rule thresholds
(reconnaissance fan-out 20, C2 history 8 and IAT CV, exfiltration 20 MB, flood rates
of 1,000/s) are literals in `detection/pipeline.py`; changing one is a code change that
needs its own regression and a re-freeze.

## 3. Apply, confirm, then test once

1. Edit the chosen constants deliberately in the module, add a regression, run the
   demo check and `scripts/refreeze_runtime_pins.py`, then the full test suite.
2. Re-run `evaluate_lab` on the **validation** split to confirm the gain holds on
   runs the sweep did not train on (if you swept both, hold one validation run back).
3. Run `evaluate_lab` on the **test** split once. Do not change a threshold afterwards.
4. Keep the report; enable a disabled candidate (DGA, DNS-tunnel) only if it passes its
   predeclared gate on data it never saw, and record failures as failures.

Hard-to-separate cases (backups vs exfiltration, authorised scans vs reconnaissance)
may remain false alerts: passive metadata cannot always tell intent. Report them
rather than tuning them away.
