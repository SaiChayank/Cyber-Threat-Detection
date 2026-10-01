# Encrypted-session indicator validation protocol

## Frozen decision rule (recorded before the controlled replay)

The only positive claim under test is **malicious encrypted-session indicators**.
The unit of evaluation is a complete, independently reset, causally replayed
scenario. A positive is detected only if an `ENCRYPTED_MALWARE` alert appears
before its final event. A benign scenario is a false positive if it produces any
such alert. Required point-estimate gates are recall >= 80%, precision >= 95%,
and benign-scenario FPR <= 2%. An alert must retain its flow ID, timestamp,
confidence, severity and observable supporting evidence. These are necessary,
not sufficient, conditions for deployment: the controlled cases cannot establish
a population FPR of 2% or true malware generalization. A credible promotion also
requires independent, trustworthy, group-separated, runtime-compatible capture
labels with browser, update, API and other benign encrypted traffic. No gate will
be changed in response to observed results.

`python -m datasets.validate_encrypted` replays the fixed controlled cases with a
fresh runtime `Pipeline` for each scenario and writes
`ml/encrypted_session_validation.json`. Positives model several distinct
malicious-like metadata patterns, including a JA3-unseen pattern and QUIC-like
packet metadata. Negatives include browser TLS, update traffic, API clients,
ordinary encrypted applications, shared-JA3 benign traffic and a port-443 packet
without an observed handshake. The labels describe *controlled scenario intent*;
they do not prove infection or make the generated traffic a real-world holdout.
Scenario families and start times are distinct; no random row split is used.

## Data separation and availability

The synthetic `replay/scenarios.py` family, including its single fixed demo JA3,
already influenced model training, rule design and previous test results. The
`ml/runtime_evaluation.json` validation/test seeds are previously inspected lab
regression data, not fresh evaluation. The public completed-TLS `winapps` and
`malware` collections already trained and evaluated the *separate disabled*
`ml/public_tls.json` candidate. Its family/app-hash partitions have been inspected
in `ml/public_tls_evaluation.json`; they cannot be reused as a fresh reserved set.
Moreover, completed TLS-record sequence/count/duration fields cannot be mapped to
first-packet runtime IP sizes or causal interarrival times without fabrication.
No new reserved, labelled, runtime-compatible encrypted-session capture is available
in this repository. This task therefore cannot claim an independent final recall,
precision or FPR. No public candidate or frozen synthetic artifact is promoted.

## Observable contract to audit

Raw PCAP parsing supports a complete TLS ClientHello contained in one TCP packet:
offered version, ciphers, extension IDs/count, SNI where visible, and JA3.
The normalized `TrafficEvent` carries only the JA3 hash, packet/flow bytes and
counts, timestamp, transport and an encryption flag. The current detector uses
the fixed demo-JA3 match in peer history plus IP packet/flow size CV and event
interarrival CV. These are not TLS record-size sequences. Port 443 alone may set
`encrypted`; this is an inference, not proof of TLS. The raw parser does not
extract a QUIC Initial/JA4/JA3S fingerprint, reassemble fragmented ClientHello,
or decrypt application payload. Explicitly supplied `QUIC` metadata can enter the
event contract, but the detector has no QUIC-specific fingerprint model.

The report must name false positives/negatives and attribution to rule versus
synthetic model. It must audit dependence on the one demo JA3, malware family,
source environment and capture identity. Family or environment labels, addresses,
case names and start times must never be predictive model inputs. If the gate fails
or the independent evaluation evidence remains insufficient, this detector remains
experimental; no threshold or model-artifact change follows from this replay.
