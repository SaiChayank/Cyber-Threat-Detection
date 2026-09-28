# Model, features and training / validation

The initial prototype uses a Gaussian naive Bayes model with eight labels: benign
and the seven detection modules. This portable baseline is implemented using Python
standard-library math and JSON; it requires no downloaded executable model artifact.
It is intentionally simpler than several algorithms proposed in historical designs.

`python -m ml.train` creates the fitted means, variances and priors in
`ml/artifact.json`, writes its SHA-256 companion and generates `ml/evaluation.json`.
All 20 feature names are stored with the artifact and checked at inference startup.
Each nonnegative input is transformed with log(1+x). Conditional variance has a
0.03 floor to avoid division by zero. Log likelihoods are normalized into posterior
scores. The independence assumption and correlated inputs can produce overconfident
posteriors. Scores are **not** advertised as real-world calibrated probabilities.

The detection pipeline evaluates model output at a 0.8 posterior threshold, alongside
seven rule detectors. A model and rule match is labelled HYBRID; a rule-only alert
uses 0.8 as heuristic strength. Evidence explicitly records the score kind. Operational
severity is assigned separately by threat category. Repeated source/destination/class
alerts are suppressed for 30 event-time seconds. C2 needs eight peer observations;
reconnaissance requires at least ten observed ports or hosts even for a model hit.

Training consists of 30 independently seeded experiments per class, 32 incremental
observations per experiment: 7,680 rows. Validation uses seeds 31–40 (2,560 rows),
and the untouched test set uses seeds 41–50 (2,560 rows). Whole experiments remain
within a split. Every experiment gets fresh feature state and goes through the same
`FeatureExtractor.update` method as runtime. No labels, scenario names, seeds or
source addresses are supplied as direct model inputs. A fixed synthetic fingerprint
indicator is part of the controlled encrypted-session fixture, so its presence is
a shortcut signal that should not be confused with independent malware validation.

The evaluation JSON reports per-class precision, recall, F1, confusion matrices and
macro F1 for validation and test. It evaluates the model classifier, not the complete
hybrid alert stream. The test suite separately checks the streaming detector behavior.
High synthetic F1 reflects separable lab scenarios, not validated production accuracy.

The scenarios include randomized browsing/DNS metadata, flood summaries, periodic
C2 connections, generated domains, long TXT tunnelling queries, low-variance encrypted
packet summaries with optional lab fingerprints, host/port sweeps and asymmetric
transfers. They are created offline, without transmitting attack packets.

For stronger models, capture diverse benign and attack sessions in an isolated lab,
retain trustworthy experiment labels, split by time and attack family, include hard
negatives (periodic benign agents, backups, CDNs, high-rate legitimate traffic), and
compare the hybrid pipeline to rules alone. Fit calibration only on a separate
validation set and remeasure throughput after any model change. No such real-capture
training claim is made for the deployed streaming model. Separate public-data
research candidates and actual external-capture results are now documented in
[Dataset integration](DATASETS.md). These candidates have not been promoted; the
synthetic streaming metrics above must not be reported as public-data accuracy.

The latest external runtime check is documented in
[Streaming validation](STREAMING_VALIDATION.md). It evaluates the actual hybrid
alert decisions, rather than only the model classifier, and exposes substantial
legitimate-domain false positives. No model or threshold was changed during that run.
