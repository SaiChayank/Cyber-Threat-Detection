# Frozen GNB feature-parity diagnosis

Completed **7 October 2026**. Measurements and targeted tests were run on
**3 October 2026**, preserved under `verification/feature-parity-20261003/`.
This is a diagnostic only: no fitting, tuning, promotion, reserved-data inspection
or detector changes. Passing this diagnosis does not establish detection accuracy.

## Inspected and reproducible scope

Inspected `ml/train.py`, `ml/model.py`, `ml/artifact.json`, the extractor/rate
windows, runtime Pipeline, metadata input, synthetic scenario generator, existing
model/evaluation documentation, and the pinned original extractor/scenario source
at commit `8c1b7cc70d3318a28f107fa2ca9f292e95e9a583`.

The historical and active model bytes match SHA256
`4d8e08323374535789e21f9f7cd1ee3f1c84b663ce555e67bb4ced57c95e8010`.
This establishes a historical source reference for the same artifact, not proof
of the exact original training execution. The artifact records seeds but lacks
an extraction-semantics version or training-source hash.

Reproduce without invoking the training entry point:

```powershell
.venv/Scripts/python.exe -B -m datasets.audit_feature_parity --output parity-report.json
.venv/Scripts/python.exe -B -m pytest tests/test_feature_parity_diagnostic.py tests/test_dga_rules.py tests/test_event_recovery.py -q -p no:cacheprovider
```

The standalone script needs the pinned commit in local Git history and does not
fetch it. Unit tests use checksummed copies of those two historical source files,
so source archives/shallow validation snapshots can run them. The diagnostic reads
only previously used training seeds 1–30: 7,680 events, 960 per class. It uses the
actual current training generator and captures the actual runtime model inputs.
Validation seeds 31–40, test seeds 41–50 and reserved domain/DNS data are excluded.
All vectors retain the same 20 names/order and `log1p(max(0, value))` transform.

## Results and feature-level finding

**Current training-to-runtime vector mismatches: 0/7,680.** However, current
extraction semantics differ from the historical reference used with the frozen
artifact. **Frozen-model predicted-label disagreements: 0/7,680** on these
already-used training inputs. This measures sensitivity, not holdout accuracy,
calibration, alert quality or generalization.

| ML inputs | Historical vs current finding | Remaining representation limitation |
| --- | --- | --- |
| `packet_rate`, `byte_rate` | Both change on 2,214 rows; max absolute deltas 1,086.5 packets/s and 556,155.8 bytes/s | Complete one-second buckets replace capped/exact lookback; boundary overhang remains. |
| `source_entropy` | Changes on 256 rows; max delta 0.362570 | Event-weighted globally; packet vs flow-summary granularity changes meaning; saturated source tracking is partial. |
| `syn_fraction` | No meaningful difference in sampled rows | Legacy ML input counts SYN-bearing events; separate target-rule evidence uses explicit packet counts. |
| `iat_mean`, `iat_cv`, `history_count` | No meaningful difference | Per source/destination/service history, bounded to 512 source events and 60 seconds; summaries and mixed traffic can truncate peer evidence. |
| `destination_count`, `port_count` | No meaningful difference | Recent source-event fan-out; authorized scanning shares the same observable behavior. |
| `domain_entropy`, `domain_length`, `domain_digit_ratio`, `bigram_surprise` | No meaningful difference | Name-only lexical representation does not prove malicious domain generation. |
| `txt_record` | No meaningful difference | Legacy name-present TXT/NULL indicator; broader tunnel features are separate and candidate remains disabled. |
| `encrypted` | No meaningful difference | Supplied metadata/parser availability and synthetic generator distributions differ. |
| `size_cv` | No meaningful difference | Both historical and current paths use per-event bytes/packets, not total bytes; not a corrected serving-skew defect. |
| `egress_bytes` | No meaningful difference | Legacy ML sum remains capped by 512 source events; uncapped source-forward byte evidence is a separate rule feature. |
| `byte_ratio`, `reverse_available` | No meaningful difference on training rows; explicit observed-zero reverse probe changes numeric ratio 100 to 0 | Unavailable reverse traffic remains unavailable; zero reverse makes ratio undefined. Numeric ML fallback does not itself identify this edge case. |
| `fingerprint_risk` | No meaningful difference | Exact synthetic lab fingerprint is an obvious shortcut, not independent encrypted-threat evidence. |

Controlled probes confirm:

- A bucket boundary changes 0.1 to 10.1 packets/s because the retained bucket
  contains earlier packets. No future observations are used.
- With 4,097 one-packet events, historical global rate is capped at 409.6 packets/s;
  current accounting reports 409.7. Current source-forward bytes are 245,820,
  while the frozen ML `egress_bytes` input remains 30,720 (512 × 60).
- Missing reverse traffic has numeric ML ratio zero **in both versions**, and no
  observed ratio. It was not historically fabricated as an observed ratio of 100.
  Explicitly observed zero reverse is the distinct changed case; positive reverse
  bytes of 25 with outbound 100 still produce ratio 4.
- The same nine-plus-one packets represented as two flow summaries give global
  source entropy 1, versus 0.468996 as ten packet events. Rates match; entropy is
  input-granularity shift, not different current training/runtime code.

## Shortcuts and limitations

The artifact's mean transformed `reverse_available` is log(2) for exfiltration
and zero for the seven other synthetic classes. Mean `fingerprint_risk` is
0.680873 for encrypted malware and zero for other classes. These are generator
shortcuts. Class balance is equal here; lack of independent family/environment
diversity is the problem rather than row imbalance. Seed-separated experiments
reuse the same scenario styles, and this diagnosis does not make them unseen
families or establish uncontaminated public-data evaluation.

Training resets context per scenario; production can mix sources/categories and
use packet granularity. Raw QUIC fingerprint extraction is absent; supplied QUIC
metadata is a different visibility scope. Long/high-cardinality histories and
the bounded legacy ML byte sum need explicit interpretation. Model posterior
normalization is not probability calibration. The separate DGA/tunnel candidates
and their frozen gates were not altered or evaluated.

## Changes, verification and freeze

Added diagnostic script, three unit tests and a historical-source fixture only.
The targeted feature/DGA/recovery run passed **37 tests**, with one existing
Starlette deprecation warning; an earlier diagnostic/Pipeline run passed 30.
Saved numerical/source-hash evidence is in
[report.json](verification/feature-parity-20261003/report.json) and
[tests.log](verification/feature-parity-20261003/tests.log).
No shared runtime behavior changed, so the full backend/build were not rerun for
this diagnostic; the preceding recovery recheck passed 268 tests and TypeScript/
production build. No new runtime performance or classification metric is claimed.

**Definition of Done: PASSED for diagnosis only.** Freeze this diagnostic,
tests, pinned sources, measured scope and limitations. Runtime artifacts,
thresholds and failed-candidate activation remain unchanged.

## One smallest next correction

Add an **offline feature-semantic contract preflight** for the frozen classifier:
record its historical reference and current supported extraction definitions,
then regression-check rate/window, source weighting and missing-value semantics
even when all 20 names/order still match. Report incompatibilities explicitly;
do not silently bless a new definition, modify the artifact, restore incorrect
accounting, or refit. The absence of a semantic contract is demonstrated; this
training-only sensitivity result does not justify changing a detector threshold
or promoting a model. That separate task requires authorization; it has not begun.
