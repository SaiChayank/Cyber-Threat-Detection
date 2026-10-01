# Encrypted-session indicator validation finding

The predeclared protocol is in [ENCRYPTED_SESSION_VALIDATION.md](ENCRYPTED_SESSION_VALIDATION.md).
The reproducible controlled replay is `python -m datasets.validate_encrypted`; its
scenario-level evidence and source hashes are in
`ml/encrypted_session_validation.json`. This is **malicious encrypted-session
indicator** testing, not decrypted-malware detection or an independent malware
accuracy estimate.

| Controlled scenarios | TP | TN | FP | FN | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 8 malicious-like, 10 benign | 3 | 6 | 4 | 5 | 42.86% | 37.50% | 40.00% | 40.00% |

The frozen gates (recall >=80%, precision >=95%, benign FPR <=2%, and an alert
before the final event) **failed**. The first two positive lab-JA3 cases alerted
on event 1, where `size_cv=0` and `iat_cv=0`: only the fixed fingerprint rule
supported the alert. The variable-size/variable-timing QUIC-like positive alerted
on event 15 through the synthetic model. Novel-fingerprint TLS, TLS without a
visible ClientHello, stable QUIC-like traffic and sparse TLS were missed. In the
benign controls, browser TLS and ordinary encrypted-app traffic triggered the
synthetic model at event 15; the same size/timing pattern also produced the QUIC
positive. Browser and update traffic using the demo JA3 triggered the rule at
event 1, demonstrating that this fingerprint is not specific to malicious intent.
The API client, other low-variance client, software update without the demo JA3,
ordinary/stable QUIC and unparsed port-443 controls did not alert.

## Metadata and shortcut audit

- The raw TCP parser extracts a complete, single-packet ClientHello's offered
  version, ciphers, extension count/IDs, visible SNI and JA3 without decryption.
  The runtime event passes only the JA3 hash. Cipher/extension metadata are not
  runtime detector features. The parser does not reassemble split ClientHello.
- `size_cv` uses mean IP bytes per event packet in peer history, not TLS record
  lengths. `iat_cv` uses observed event timestamps for the same destination IP and
  port within the bounded source window. They are causally available but can be
  indistinguishable between malicious-like and normal encrypted applications.
- UDP destination port 443 is tagged `QUIC` by convention; raw QUIC Initial
  handshake/JA4 extraction is not implemented. A supplied QUIC event can carry
  packet size/timing metadata, but the current detector has no QUIC-specific
  handshake feature. Port 443 can set `encrypted` without a parsed handshake.
- The runtime rule checks one hard-coded demo JA3 in the peer history. It can
  alert on a single observation with no corroborating size or timing pattern.
  The synthetic training scenario reuses this fingerprint across seeds and even
  supplies it to some QUIC events. Family and time generalization cannot be
  inferred from the old random-seed synthetic split.
- The separate public completed-TLS candidate is disabled. Its already inspected
  family/app-group split gave validation recall 68.05%, FPR 20.10%, and test
  recall 77.47%, FPR 2.39% (`ml/public_tls_evaluation.json`). The benign class
  comes from a Windows-application collection and the malware-related class from
  sandbox captures, so capture environment may proxy the label. Capture identity
  and chronological separation are not proven. Its completed TLS-record and
  duration features are not first-packet runtime-compatible.
- Runtime model inputs exclude case/family labels, source IP, destination IP,
  capture name and file name directly. Source-specific causal histories and rate
  features can still reflect environmental differences. The controlled scenarios
  use the same address pool across labels and distinct groups/start times, but
  generated labels are not independently verified malware ground truth.

**Decision:** encrypted-session malicious indicators remain experimental. No
threshold, model artifact, runtime detector, or unrelated feature was changed.
The controlled replay is too small and synthetic to establish a population FPR,
and there is no fresh, trustworthy, runtime-compatible reserved capture in the
repository. The smallest next experiment is a passive, labelled TLS/QUIC metadata
collection with multiple malware families and browser/update/API/application
controls in each capture environment. Freeze family, capture and time partitions,
then evaluate a candidate using exactly the causal runtime fields. Keep the
single demo JA3 only as a labelled lab signature, not general malware evidence.
