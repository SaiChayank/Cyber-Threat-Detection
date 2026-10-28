# Spoofed-source flood indicator

29 October 2026. Passive metadata cannot prove that flood sources are forged:
the project's own validation (`ml/spoofed_source_validation.json`) showed forged
and genuine distributed floods are identical in the available fields, so no
separate "spoofed" class is raised and none was validated.

What is added is evidence on existing flood alerts. When a SYN or UDP flood
(`DDOS`) alert fires, the tracked sources of the target's rate window (at most
256 identities) are checked. If at least four are tracked and any are
loopback, multicast, unspecified, link-local or reserved (240/4) addresses, the
alert gains `source_reserved_count`, `source_reserved_fraction` and
`source_reserved_basis`, and its narrative says reserved or martian sources are
a passive indicator of forged sources that cannot prove forgery. Private
(RFC 1918), documentation and shared (100.64/10) ranges are not counted.

Limits: the check never changes whether an alert fires; sources beyond the
256-identity window are not inspected; absence of reserved sources proves
nothing; forged addresses drawn from ordinary public or private space are
invisible to it. Code: `detection/spoof_indicators.py`; tests:
`tests/test_spoof_indicators.py`. The nine demo traces are unchanged.
