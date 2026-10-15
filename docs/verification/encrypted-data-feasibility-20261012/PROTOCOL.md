# Encrypted development-data feasibility audit — 12 October 2026

Inventory/visibility only. No training, inference, threshold adjustment, candidate
promotion, detector/parser change, new download, external lookup or decryption.
Use downloaded provenance/licence manifests and already used development sources.

For the annotated TLS ZIPs, verify source SHA256 and read Parquet footer/schema
metadata. Route members with annotation columns only using the existing family/app
hash partition rule. Never read feature columns from any member containing an
historical test-labelled group (including mixed members). SOHO gets footer-only
inventory because it lacks supervised truth. These previously inspected historical
test groups are not a new reserved set; no reserved dataset is opened.

Measure training/validation-only label eligibility, client cipher/extension/JA3
presence, explicit empty versus null arrays, and group/time separation potential.
Annotations label sample provenance, not verified maliciousness of each flow.
Record missingness explicitly; no missing handshake becomes an observed zero.
Session totals/duration/record sequences must not become first-packet features.

Replay only the two already used benign DNS-reference PCAPs through the existing
parser for TLS-sidecar visibility. Count parsed observations, port-443 hints and
returned ClientHello metadata; do not run detection or infer malware truth.
Mixed attack-category captures are catalogued only. No unauthorized IoT-23 mirror.

Definition of Done: reproducible provenance/counts, source/label/visibility matrix,
precise runtime compatibility and split limitations, targeted tests and preserved
runtime/models/raw data/history. A successful audit may still find model training
or final promotion infeasible. Stop with one smallest next action; no next phase.
