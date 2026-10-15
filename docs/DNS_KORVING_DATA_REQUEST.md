# Korving DNS dataset clarification — draft only

Prepared 15 October 2026. **Not posted or sent.**

Proposed audience: maintainers of `Korving-F/dns-tunnel-dataset`, via a public
[GitHub issue](https://github.com/Korving-F/dns-tunnel-dataset/issues).
The issue and the posting GitHub identity will be public. No verified author email
was established. User authorization is required before posting this exact request.

Title: Capture format, session provenance and data-use clarification for passive DNS evaluation

Hello Frank Korving and dataset maintainers,

We are building Univect for PS26145, a passive monitoring prototype using copied
metadata without probes, blocking, a return path or payload decryption. Your
scenario-backed DNS tunnelling dataset is a promising independent evaluation lead.
Before acquiring captures, could you clarify the existing collection's metadata?

1. Does the dataset's permission cover local research/validation and a hackathon
   demonstration? What attribution and raw/derived-data redistribution rules apply?
   The README's MIT statement names DACA, so we do not assume its capture scope.
2. Which existing captures are classic Ethernet PCAP (link type 1)? Configurations
   use `tcpdump -i any`, while our current reader does not support Linux cooked
   linktypes or PCAPNG. Please identify compatible originals, if any; we are not
   requesting conversion or a new collection. Are complete QNAME/QTYPE preserved?
3. Is there an archive/member inventory with sizes, hashes, tool/version, run ID,
   capture timestamps/timezone and truncation notes? Which files are fragments,
   copies or different exports of the same run?
4. Can experiment/process logs independently join each session's source, namespace
   and start/end times to tunnel activity, distinguishing background/unknown DNS?
   Execution timestamps alone cannot label every query. Which record types and
   query-rate settings are documented for existing sessions?
5. Are at least 20 independent tunnel and 50 independent benign sessions available?
   Benign controls need documented CDN/cloud, telemetry, service discovery,
   legitimate TXT and machine-generated hostnames. Missing controls or unavailable
   labels are useful to confirm; we will not reinterpret them or lower criteria.

A metadata-only answer or pointer to existing documentation is sufficient. Please
do not post private client identifiers, credentials, packet contents or decoded
data. We are not requesting new attack execution.

Thank you,
Sai Chayank
Univect / PS26145 project team
