# DGA benign-source clarification request

Prepared 14 October 2026. **Sent with user approval on 15 October 2026.**

Proposed recipient: Cláudio Marques, `claudioms@ipvc.pt`, the corresponding-author
address published in [the dataset paper](https://pmc.ncbi.nlm.nih.gov/articles/PMC8437788/).
The public listing was checked on 14 October 2026. The user explicitly approved
this recipient and prepared request before sending from `saichayank07@gmail.com`.
Gmail displayed **Message sent**; the sent copy was verified at 02:15 IST on
15 October 2026. Delivery, a publisher reply and permission to release additional
data remain unconfirmed. This contact does not resolve the data qualification gate.

Sent copy: https://mail.google.com/mail/u/0/#sent/KtbxLwhGKPLJnlHBRwpvHbtznKNxFmpqtg

Evidence: [sent-request.png](verification/dga-publisher-contact-20261015/sent-request.png).
Only this contact record and screenshot change; no detector, dataset, model,
threshold or frozen evaluation report changes. No tests were required for this
documentation-only contact update. Next: review a publisher response for raw-name
compatibility, benign-client provenance, service context and permissions before
any new data qualification or final scoring.

Subject: DNS dataset v5 — original-name compatibility and benign-source clarification

Hello Cláudio Marques,

We are building Univect for PS26145, a passive network-monitoring prototype that
uses copied metadata without probes, blocking or payload decryption. We downloaded
version 5 of your DNS-domain dataset (DOI 10.17632/623sshkdrz.5) and are checking
whether it can support an independent DGA false-positive evaluation.

Your paper describes encoding the Domain field to anonymize names, deriving the
negative class from Rapid7 Project Sonar lists, and deriving the positive class
from SANS suspicious-domain lists. Our detector uses the actual first label of an
observed DNS query, so we cannot substitute anonymized IDs or precomputed rounded
features. Could you clarify:

1. Does version 5 contain original domain names, or is its Domain field encoded?
   Is there a documented permitted mapping or separate raw-name release?
2. Which dated/versioned Sonar exports supplied the negative class, and what
   evidence establishes non-malicious intent beyond membership in those exports?
3. Are any original, permitted benign client DNS query logs/captures available,
   with collection and label provenance? We need at least 2,500 distinct eligible
   first labels after excluding previously used domains, not just 2,500 rows.
4. Do any available observations identify legitimate machine-generated names,
   CDN/cloud service names and other ordinary-client names through documented
   service/client context rather than spelling or classifier results?
5. What licence, attribution and redistribution restrictions apply to any original
   names or additional logs? Could you provide an artifact/version inventory and
   SHA256 values if available?

A metadata-only answer is sufficient initially. Please do not send credentials,
client identifiers or private internal domain names. If your release does not
provide these observations, confirmation of that limitation or a pointer to an
appropriate public collection would be helpful. We will not reinterpret its
labels or lower our evaluation criteria to fit the data.

Thank you,
Sai Chayank
Univect / PS26145 project team
Teammates: Sai Surya, Surya Teja, Shalini, Vindhya, Pravallika
