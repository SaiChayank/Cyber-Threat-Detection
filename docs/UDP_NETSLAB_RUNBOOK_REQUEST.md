# NetsLab UDP paired-run clarification — prepared, NOT SENT

19 October 2026. Preparation only; this does not authorize sending or posting.
Recipient: Chamara Sandeepa, `abeysinghe.sandeepa@ucdconnect.ie`, published as the
corresponding author in the producer's [paper](https://www.techrxiv.org/doi/pdf/10.36227/techrxiv.175606222.20740292/v1?onload=true).
Sender if separately authorized: Sai Chayank, `saichayank07@gmail.com`.
No attachments, CC or BCC. No mail draft has been created.

Subject: NetsLab-5GORAN-IDD: original runbook for matching benign iPerf and UDP flood captures

## Exact prepared body

Dear Chamara Sandeepa and NetsLab team,

My name is Sai Chayank. Our student team is developing Univect for PS26145, a
passive, read-only network-threat detection prototype. Thank you for publishing
NetsLab-5GORAN-IDD and the raw captures under CC BY 4.0 on Zenodo record 18923275.

We reviewed the descriptor, public repository file tree and bounded ZIP directory
metadata only; we have not inspected packet records or trained on these captures.
The deposit contains the following possible development-pair members:

- Benign.zip: Benign/Network_data/iperf_benign.pcap
- DDOS.zip: DDOS/Network_Layer/ddos_udp_hping3.pcap
- DDOS.zip: DDOS/Network_Layer/ddos_udp_nping.pcap

Could you share existing run/configuration records clarifying:

1. What actual application, server process and UDP destination port were used in
   the iPerf capture? Did either listed UDP flood target that same running service
   and port? If not, is there another existing matched benign/flood pair?
2. Which executed run IDs, endpoints, directions and original capture start/end
   times identify the benign and flood workloads? Are the files single-workload
   captures, or are packet/session-to-run annotations required? Please include
   the time zone/clock reference and any offset, merging, reordering or rewriting.
3. Are the captures complete classic Ethernet PCAP v2.4 with link type 1? Please
   note truncation, capture loss, encapsulation or fragmentation limitations and
   any available per-member SHA256 checksums.
4. Do original configuration/log summaries indicate naturally overlapping load
   and packet sizes? Our already fixed qualification screen requires at least
   three complete ten-second blocks at >=1,000 observed UDP packets/second per
   run, overlapping rate ranges and overlapping IP-packet-length IQRs. We will not
   alter replay speed, ports, packet populations or labels to manufacture a match.

We request existing provenance, not new traffic generation or labels inferred
from detector output. An explicit confirmation that no matching control exists
would also help us avoid an unsupported pairing. Any qualifying pair would stay
development-only; it would not by itself establish detection accuracy or promotion.

We will cite the dataset and descriptor, DOI 10.1109/IEEEDATA.2025.3614167. Thank
you for your guidance.

Best regards,
Sai Chayank
Univect / PS26145 student project team
