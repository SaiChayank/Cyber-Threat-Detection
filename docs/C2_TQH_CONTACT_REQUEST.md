# Prepared TQH-C2 contact/provenance clarification

17 October 2026. **PREPARED ONLY — NOT SENT; recipient-specific approval needed.**
Proposed sender: Sai Chayank, `saichayank07@gmail.com`.
Proposed recipient: Deokjo Jeon, `dejeon@stud.assist.ac.kr`, corresponding author
listed in the [publisher README](https://zenodo.org/records/22732327/files/README_v122.md?download=1).
The README was rechecked byte-identical on 17 October; this establishes its public
contact listing, not mailbox deliverability or a response. Earlier email approvals
for other dataset authors do not authorize sending this new request.

Subject: TQH-C2 v1.2.2 — beacon contact timing and periodic benign control clarification

Dear Deokjo Jeon,

My name is Sai Chayank. Our team is building Univect for PS26145, a passive network
monitoring prototype. We analyze copied traffic metadata without active probes,
inline blocking, return-path requirements or TLS/QUIC payload decryption.

Thank you for releasing TQH-C2 v1.2.2 under CC BY 4.0. We have one original
Testbed D capture, D_i300_j30/D_0648.pcap, and its corresponding UID-based labels
and UTC manifests. It remains development-only; we have not trained a model on it.

We need to distinguish individual C2 callbacks from packets, TLS handshakes and
Zeek connections, and compare them against genuinely periodic benign clients.
Could you please clarify whether the following records are available?

1. Actual callback/task-exchange timestamps for this capture, with agent/run IDs,
   original clock/timezone and a mapping to TCP tuples, Zeek UIDs or packet ranges.
   If a connection corresponds to one callback, what producer evidence verifies
   that relationship? We do not want to substitute the configured 300-second
   interval/jitter for actual executed contacts.
2. The names and schedules of benign applications in the same run, especially
   periodic health checks, telemetry or scheduled polling, with execution/contact
   records identifying their traffic independently of endpoint or timing heuristics.
   Is there a benign application on a comparable service with overlapping contact
   intervals? If none was collected, confirmation would also be useful.
3. Any timestamp changes, capture rotation, clock offsets, dropped/truncated
   observations or connection splitting affecting contact-to-packet joins, and
   permission to use/cite any additional annotations you can share.

We would use such records only for a small development-data qualification, keep
labels and addresses out of predictive inputs, and report missing evidence rather
than infer malicious intent from periodicity. No executable malware, credentials,
TLS keys or decrypted content are requested.

Thank you for your time.

Sai Chayank
Univect / PS26145 student project
