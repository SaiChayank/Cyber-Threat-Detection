# Second source selection — before reading packet/label values

Source documentation identifies TQH-C2 v1.2.2, Zenodo record 22732327, as a
controlled C2 testbed with concurrent labelled benign traffic. Documentation
describes session UID joins to conn.log, UTC run manifests and intentional TLS
re-handshakes. These are publisher claims to verify, not qualification results.
Licence is declared CC BY 4.0 in the source README.

Select Testbed D (Merlin HTTP/2-over-TLS), whose declared archive is smaller than
Testbed A. Fixed public URLs:

- https://zenodo.org/records/22732327/files/README_v122.md?download=1
- https://zenodo.org/records/22732327/files/TQH-C2_pcap_D_merlin_h2.zip?download=1
- https://zenodo.org/records/22732327/files/TQH-C2_labels_D.zip?download=1

Role: **development-only**. This source/testbed influences source design and must
not later be called untouched final evaluation. No fitting, inference, detector
change, activation or model-quality claim is authorized. All failed models stay
disabled. No binaries, TLS keys or executable publisher code are obtained.

Before reading any capture or annotation values, choose exactly one `.pcap`
member by smallest ZIP compressed size, with lexical member-name tie-break. Keep
the matching label/log/manifest cell only for value inspection. Selection uses
archive metadata, never traffic features, prediction results or success/failure.
Bound selected compressed transfer to 256 MiB and raw member to 1 GiB. Any
interrupted bytes or incomplete ZIP member remain excluded.

Preserve the original frozen qualification gates: raw classic Ethernet PCAP
accepted by the current reader; complete observed ClientHello with exact raw
packet timestamp/index; explicit session intent labels joined by UID, TCP tuple
and independently specified UTC time window. Verify label method and source
hashes; ambiguous/unlabelled flows stay unknown. A C2 lab label supports controlled
encrypted C2 only, not generic malware truth. Exact capture/member hashes and CRC
must be recorded. Partial archive retrieval cannot verify the whole-archive hash.

No format conversion, new runtime parser support, active traffic generation,
source probes or decryption. If publisher access or any gate fails, record the
failure and stop dependent modelling. Do not relax gates after inspecting data.
