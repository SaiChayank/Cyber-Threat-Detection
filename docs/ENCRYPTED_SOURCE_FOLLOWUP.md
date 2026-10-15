# Encrypted source feasibility follow-up

13 October 2026. **Diagnostic DoD: PASS. Streaming candidate data readiness:
BLOCKED.** No training, labels, inference, thresholds, detector activation or
reserved evaluation changed. Previous frozen evidence remains intact.

Inspected the existing split/source plan, publisher preprocessing at revision
`5562b6a31e5b078f51c2564d8229514697248c3c`, JOY source at revision
`21770513e27ad10cde7c1ab7c1e6f024c8668119`, public MS file metadata and the already
designated development-only `capture_getuid.joy.gz`. Publisher code was read,
never executed; notebook outputs and reserved features were excluded.

| Required capability | Finding | Decision |
| --- | --- | --- |
| Raw MS capture | 21 public metadata pages list 103 files; zero `.pcap`, `.pcapng` or `.cap` files | Not available in the inspected public listing. This does not say authors never captured PCAP. |
| Per-session truth | Inspected MS notebook consumes completed CSVs, assigns directory-derived TLS/certificate variants and retains command names; no verified session label/capture join | Remains unverified. Do not label all 17,421 sessions malicious. |
| Runtime-compatible bytes | JOY TCP summary `b` and accumulated bytes use transport payload size; runtime raw-packet events use IP bytes | Direct substitution is incorrect. No fabricated headers or new input adapter. |
| Full causal packet accounting | Derivative configuration omits zero-payload and retransmitted packets and limits summaries to 50 per direction; all 17,421 flow totals exceed their stored sequence lengths | Not a complete packet stream. Omission versus limit truncation is not separately quantified. |
| Timing | JOY `ipt` describes millisecond inter-entry deltas, not epoch timestamps | Some recorded timing exists; it does not establish a complete raw packet chronology. |
| ClientHello availability | Client ciphers/extensions exist; 17,421 rows lack an explicit ClientHello timestamp or packet index. Record-type sequences include handshake records | Handshake record presence alone does not prove the metadata-to-packet join or runtime parser visibility. Do not backdate completed metadata. |
| Original CIC DoH | Publisher describes raw PCAP and flow labels for controlled encrypted tunnelling; download form still displays a server error | Potential narrower source; not acquired. No silent generic-malware or plaintext-DNS relabelling. |
| BCCC DoH derivative | Publisher describes three SMOTE-balanced CSV files | Does not solve raw-capture/causality requirements; synthetic oversampling is not untouched evaluation truth. |

The downloaded JOY configuration reports version **4.5.0**, bidirectional export,
TLS enabled and no raw initial payload export. Stored summaries total **135,704**;
all 17,421 records lack explicit ClientHello observation position. Source-code
semantics are tied to the pinned public revision, not proof of the exact exporter
binary used by the author. Existing source hash remains
`d18bad45afd5c62ee848a8db04e0216d22799a3824a58a6a9fd117f45a77ebc3`.

Evidence and source revisions/hashes: [findings](verification/encrypted-source-followup-20261013/findings.json),
[protocol](verification/encrypted-source-followup-20261013/PROTOCOL.md),
[public listing](verification/encrypted-source-followup-20261013/ms-file-inventory.json)
and [sequence capability](verification/encrypted-source-followup-20261013/development-sequence-capability.json).
External source copies were temporary inspection material; provenance and
paraphrased findings are retained instead of redistributing publisher code.

Primary sources: [publisher repository](https://github.com/CarlosANovo/extending12to13),
[MS public API](https://api.osf.io/v2/nodes/b64e5/),
[JOY TCP accounting](https://github.com/cisco/joy/blob/21770513e27ad10cde7c1ab7c1e6f024c8668119/src/pkt_proc.c#L481),
[JOY summary export](https://github.com/cisco/joy/blob/21770513e27ad10cde7c1ab7c1e6f024c8668119/src/p2f.c#L1414),
[original CIC DoH](https://www.unb.ca/cic/datasets/dohbrw-2020.html),
[BCCC derivative](https://www.yorku.ca/research/bccc/ucs-technical/cybersecurity-datasets-cds/dns-over-https-bccc-cira-cic-dohbrw-2020/).

No diagnostic production code required changes, so no new unit tests were added.
The concurrent UI integration pass runs all **333 backend tests**, including the
existing encrypted-data/split regressions. This is no new accuracy, throughput or
promotion result. There are no before/after classification metrics to report.

Freeze this diagnosis. The smallest next experiment is to acquire **one eligible
development-only raw TLS cohort with documented session labels**, verify its
label join and causal ClientHello visibility, and record roles before fitting.
Dependent encrypted model training remains stopped. All failed public candidates
remain disabled; final SIH release remains **NOT READY**.
