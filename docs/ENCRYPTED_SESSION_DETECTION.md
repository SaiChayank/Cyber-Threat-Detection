# Encrypted-session detection (P0-4)

29 October 2026. Metadata only: no payload is decrypted, no endpoint is
contacted. Replaces the single lab-fingerprint shortcut as the main
encrypted-malware path; the frozen 20-feature model and demo traces are unchanged.

## What is extracted

| Signal | Source | Where |
| --- | --- | --- |
| JA3 (client) | ClientHello, as before | `ingest/protocol_parsers.py` → `TrafficEvent.tls_fingerprint` |
| **JA4 (client)** | ClientHello: highest offered version (supported_versions), SNI flag, cipher/extension counts, first ALPN, sorted ciphers, sorted extensions + signature algorithms; GREASE ignored | `schemas/tls_metadata.py::generate_ja4` → `TrafficEvent.tls_ja4` |
| **JA3S (server)** | ServerHello: version, selected cipher, extension order | `_try_parse_tls_server_hello` → `TrafficEvent.tls_server_fingerprint` |
| **Session size/timing** | Per client/server/service session (60 s idle restart): packets, duration, mean size, size CV, small-packet share, inter-arrival mean/CV | `features/tls_session.py` |
| **Fingerprint rarity** | Distinct clients that offered the same client fingerprint (JA4, else JA3), and total TLS clients seen | `features/tls_session.py` |

JA4 follows the FoxIO JA4 specification (BSD 3-Clause) and reproduces its
published example `t13d1516h2_8daaf6152771_e5627efa2ab1` in
`tests/test_tls_fingerprints.py`. All state is bounded (4,096 sessions,
fingerprints and clients; 64-entry sequences) and staged with the existing
failure-safe event recovery.

## Detection paths (`detection/tls_indicators.py`)

An encrypted event raises `ENCRYPTED_MALWARE` when any of these holds:

1. **Legacy lab fingerprint** (unchanged): the frozen `fingerprint_risk` feature.
2. **Indicator list:** the session's JA3, JA3S or JA4 is listed in
   `detection/tls_indicators.json`. The list is operator-maintained; add
   fingerprints from threat intelligence or your labelled lab captures, each
   with a provenance note. Evidence: `tls_basis=indicator_<kind>` and the note.
3. **Behaviour:** a rare client fingerprint (offered by ≤1 client once ≥5 TLS
   clients have been seen) in a session of ≥8 packets with size CV ≤0.25,
   inter-arrival CV ≤0.25 and mean size ≤600 bytes, i.e. small machine-regular
   traffic. Evidence: `tls_basis=rare_fingerprint_regular_session`.

Thresholds are development defaults; tune them in P0-5 on labelled lab
captures with the [lab evaluation harness](LAB_EVALUATION.md). Severity stays
HIGH and the confidence is a heuristic strength, not a probability.

## Limits

- ClientHello/ServerHello must be complete in one TCP segment; no TCP
  reassembly. TLS 1.3 encrypts later handshake messages, so JA3S reflects the
  ServerHello only.
- Raw QUIC JA4 is deliberately NOT implemented: the Initial ClientHello is
  protected, and reading it would mean deriving keys and decrypting QUIC content,
  which the project's no-decryption constraint forbids. See the QUIC header
  fingerprint below.
- Rarity needs a client population; small or single-host captures cannot
  trigger the behaviour path. Rare legitimate software and regular keep-alive
  clients can still match; they appear as false alerts in lab evaluation.
- JA4+ variants other than JA4 (for example JA4S, JA4X) are not implemented.

## Frozen pins re-frozen

Runtime source hashes are pinned by the demo manifest, the feature semantic
contract and the DNS tunnelling evaluation contract. After confirming all nine
demo traces are byte-identical, `python scripts/refreeze_runtime_pins.py`
re-pinned them and added the new runtime modules to the DNS contract. Events
without JA3S/JA4 serialize exactly as before, so recorded stream hashes still
match. The 14 Oct encrypted training plan is superseded by the lab route; its
test now accepts only the re-pinned feature contract as a stale reference.
Run the script (after the demo check) whenever runtime code changes again.

## QUIC header fingerprint (no decryption)

For UDP/443 datagrams whose first byte marks a QUIC Initial long header
(`0xC0` pattern, non-zero version), `ProtocolParser._quic_initial_fingerprint`
reads only unencrypted fields and builds
`q<version hex>.d<dest conn-ID length>.s<source conn-ID length>.t<token present>.l<datagram bytes>`,
for example `q00000001.d8.s0.t0.l1252`. Stacks differ in connection-ID lengths,
token use and first-flight padding, so it is a weak client-stack fingerprint,
not JA4. It travels as optional `TrafficEvent.quic_fingerprint` (omitted when
absent), joins the session and rarity features (`tls_quic`, shared with the
JA3/JA4 rarity counts), and can be listed under `"quic"` in
`detection/tls_indicators.json`. Limits: different QUIC stacks can share a
value; version negotiation and short-header packets give none; the protected
payload (and so TLS parameters) is never read. Tests: `tests/test_quic_header.py`.
