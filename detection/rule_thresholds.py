"""Named thresholds of the active rule layer, so they can be tuned on labelled lab captures.

Values are the long-standing defaults; the pipeline reads them at call time, so
datasets/tune_lab.py can sweep them without editing code. Changing a default is a
reviewed change: re-run the demo check, scripts/refreeze_runtime_pins.py and the tests.
"""
C2_MIN_HISTORY = 8          # Same-peer events needed before a beaconing alert
C2_MIN_IAT_MEAN_S = 1       # Mean seconds between same-peer events
C2_MAX_IAT_CV = .3          # Inter-arrival coefficient of variation below this is "regular" (tuned on CTU-13 Neris, was .05)
RECON_MIN_FANOUT = 20       # Distinct destinations or ports in 10 s for a rule hit
RECON_ALERT_FLOOR = 10      # Below this fan-out no reconnaissance alert is ever emitted
EXFIL_BYTES_60S = 20_000_000  # Source-forward bytes in 60 s
