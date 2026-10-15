# Raw TLS development capture acquisition — 13 October 2026

Freeze this data-qualification protocol before inspecting new capture contents.
This task acquires and validates data only. No classifier training/inference,
runtime feature/parser changes, model promotion, threshold changes or final
evaluation. Existing failed candidates remain disabled.

Eligibility: publisher/author provenance with permitted research use; genuine
classic Ethernet PCAP (the supported format), raw packet timestamps and lengths;
documented session ground truth joined to TCP endpoint tuple and capture time.
Labels apply only to explicitly attributable sessions, with unknown/background
traffic excluded. Endpoint IPs may establish lab provenance, never predictive
features. Controlled encrypted tunnelling is labelled as such, not generic malware.

Initial acquisition is development-only. Every inspected capture/session is marked
as already used for source/visibility design; none may become untouched final
evaluation. Record source URLs, licence/citation, byte counts, SHA256, exact label
basis and unsupported/ambiguous sessions. Do not inspect reserved data values.

Qualification gate: valid supported capture; at least one explicitly labelled TLS
session; packet-level observation timestamp and position of a complete ClientHello
parsed by the current implementation; observed tuple/time matches label provenance.
Record clipping, missing handshakes, parser-invisible/reassembled-only handshakes,
duplicates, out-of-order data and session-boundary ambiguity rather than inventing
observations. A positive source and benign source are preferred; failure of either
is reported honestly. This small acquisition gate is not statistical adequacy or
a model promotion gate. Existing precision/recall/FPR gates are unchanged.

Downloads contain captures/annotations only, no executable malware or TLS keys.
No monitored endpoints, probes, authentication workaround, payload decryption or
author messaging. Publisher registration already authorized in this conversation
may use the supplied details, but personal details must not enter source/docs/logs.
Protect existing raw inputs, analyst history, frozen artifacts and prior evidence.
Any diagnostic helper stays outside runtime, uses existing parser and minimal
standard-library/development dependencies, with exact regression tests.
