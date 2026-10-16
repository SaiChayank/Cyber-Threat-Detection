# ORION UDP runbook clarification — prepared, not sent

16 October 2026. This exact message is ready for user review. Sending is pending
explicit authorization for this recipient. No Gmail draft or external message has
been created. No attachments, CC or BCC recipients.

Recipient: `proenca@uel.br` — Prof. Mario Lemes Proença Jr., ORION coordinator.
Verified on the producer's [contact page](https://www.uel.br/grupos/orion/contact.html)
and [people page](https://www.uel.br/grupos/orion/people.html).
Intended sender: Sai Chayank, using his existing Gmail account.

Subject: ORION 2026: runbook clarification for same-service UDP flood/benign comparison

## Exact email body

Dear Professor Proença and ORION team,

My name is Sai Chayank. Our student team is developing Univect for PS26145, a
passive, read-only network-threat detection prototype. Thank you for publishing
ORION 2026 and its CC BY 4.0 dataset.

We have reviewed the dataset page and archive README/licence, without inspecting
ORION packet records or training on the data. Before selecting a development
pair, could you share an existing runbook, configuration or annotation document
addressing the following?

1. Does ORION contain an authorized, high-volume legitimate UDP application run
   targeting the same actual service and destination port as a UDP flood? The
   README identifies the 6 November 2025 UDP flood, 07:00:00–07:29:59, targeting
   10.0.0.3:9090. What application/service ran there, and is there a corresponding
   benign run? If no such control exists, an explicit confirmation would help us
   avoid assigning unsupported labels.
2. For any qualifying pair, which exact capture members, run IDs, endpoints,
   directions and start/end times identify each workload? How were flood/benign
   labels established from the execution records, and are there sidecars joining
   mixed-capture packets or sessions to those run labels?
3. What time zone/clock reference applies to the README intervals and PCAP
   timestamps? What does `reordered` mean: were packet order or timestamps changed,
   merged, shifted or regenerated, and are original capture times available?
4. Are the inner captures classic PCAP v2.4 with Ethernet link type 1 and complete
   packets? Please identify snaplen/truncation or capture-loss limitations and any
   available per-member checksums.

We need naturally overlapping original-time packet rates and packet sizes, rather
than replay-speed rescaling. Our fixed qualification screen requires at least
three complete ten-second blocks at >=1,000 UDP packets/s in each run, overlapping
packet-rate ranges, and overlapping packet-length interquartile ranges. Existing
run configurations or summaries may establish whether this is plausible; we do
not request a newly generated workload or labels inferred from detector output.

We will cite DOI 10.1109/ACCESS.2026.3738009, keep any selected pair development-only,
and make no reflection/source-forgery or detection-accuracy claim from two runs.
If another team member maintains the runbook, please forward this request or point
us to the appropriate public documentation.

Thank you for your guidance.

Best regards,
Sai Chayank
Univect / PS26145 student project team
