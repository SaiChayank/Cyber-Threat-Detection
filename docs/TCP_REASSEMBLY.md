# Bounded TCP reassembly for TLS and DNS/TCP

29 October 2026. Large TLS ClientHellos (for example with post-quantum key shares)
and long DNS/TCP messages can span several TCP segments. `ProtocolParser` now
rebuilds exactly one such message per stream before parsing. It reads only the
TLS record header (`0x16 0x03`, length) or the DNS/TCP two-byte length prefix;
nothing is decrypted and no byte stream is kept beyond one message.

Rules:
- A message that begins in a segment and does not fit it is buffered; later
  in-order segments (by sequence number, wrap-around safe) are appended until the
  declared length is reached, then it is parsed as if it had arrived whole. The
  fingerprint or DNS name is attached to the packet that completes the message.
- Retransmitted bytes are ignored. A gap or reordering abandons the buffer and
  nothing is guessed. FIN or RST, or 10 s idle, drops the buffer.
- Bounds: at most 256 buffered streams, 16 KiB plus 5 bytes each (about 4 MB).
  Records declaring more are not buffered. Oldest streams are evicted first.
- Everything that fits one segment behaves exactly as before; the nine demo
  traces are unchanged.

Limits: one message per stream (a ClientHello split across two TLS records is
not joined); no out-of-order reassembly; streams are per parser instance (one
capture). Tests: `tests/test_tcp_reassembly.py`.
