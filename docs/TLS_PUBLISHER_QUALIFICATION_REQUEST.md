# TLS publisher qualification request

Prepared 14 October 2026 for PS26145 / Univect. **First request bounced;
alternate request sent with user approval, delivery/reply unconfirmed.**
Proposed recipient: Clément Parssegny, ARES paper coauthor,
`clement.parssegny@telecom-sudparis.eu`, published on the
[Télécom SudParis SCN team directory](https://scn.telecom-sudparis.eu/membres.html)
and checked on 14 October 2026. Public listing verifies the contact source, not
mailbox deliverability or authority to grant data permissions. The user approved
sending from their Gmail account; the recipient server rejected the address.
This document changes no detector,
feature, model, gate or partition.

## Basis and scope

Use the [frozen coverage plan](ENCRYPTED_COVERAGE_PARTITION_PLAN.md) and its
[machine-readable manifest](verification/encrypted-coverage-plan-20261014/plan.json),
LF-normalized SHA256
`1f8192e3ffd2f22c2a9e786846222457d8b81114d7622ae5ecdb70e4cbee8e4f`.
The [source review](ENCRYPTED_VALIDATION_SOURCE_REVIEW.md) records the unresolved
evidence. ARES is an unqualified validation lead, not an assigned cohort or final
reserve. The reviewed artifact reference is commit
`7acfebc6f17fe774df91a1b550c4b23613b90fe9` of
[the author repository](https://github.com/cp-tsp/ares2025-artifacts).
These are previously recorded observations, not a fresh publisher availability check.

## Publisher message draft

Subject: ARES Cobalt Strike dataset — session labels and capture qualification for Univect

Hello Clément Parssegny and ARES artifact authors,

We are building Univect for PS26145, a passive network-monitoring prototype. It
observes copied traffic and produces structured alerts from metadata. It does not
probe endpoints, require a return path, block traffic or decrypt TLS/QUIC payloads.

Your Cobalt Strike HTTPS collection is a promising independent validation source
for our encrypted-session indicators. Before using it, we need to establish data
permissions, reliable session intent and compatibility with our current reader.
Could you confirm whether the following information and existing artifacts are
available?

1. **Capture-data permission:** the applicable licence or written permission for
   local research, model validation and a hackathon demonstration; required
   attribution; and whether raw captures or derived metadata may be redistributed
   with a source repository. We will not assume the paper or software licence
   automatically covers capture data. If redistribution is prohibited, please
   specify permitted access and use without redistribution.
2. **Session ground truth:** a mapping from capture/run and session UID (if used)
   to source/destination IP and port, transport protocol, start/end UTC times and
   explicit malicious, benign or unknown intent. Please describe how intent was
   established independently of destination reputation, fingerprint matching or
   traffic heuristics, and identify unlabelled/background sessions.
3. **Capture visibility:** available original classic Ethernet PCAP captures
   (link type 1), including benign traces, capture start/end UTC, clock precision
   and timezone, snap length, loss/truncation notes and whether capture began
   before the TLS ClientHello. Our current reader does not support PCAPNG or TCP
   handshake reassembly. Please identify whether complete ClientHello messages
   are visible in a single packet/record, and disclose exceptions rather than
   filtering them out. We are not requesting conversion or alteration of the
   published captures.
4. **Benign controls:** verified TLS browser browsing, genuine software-update
   clients, ordinary API/SDK clients (including scheduled polling/telemetry), and
   ordinary encrypted applications such as sync or messaging. Please identify
   the concrete application/build, TLS stack, activity and session mapping for
   each available category. A web download or CDN destination alone does not
   establish an updater or other application control.
5. **Run and environment provenance:** at least two existing separate capture
   runs on different documented UTC dates/deployments, their framework/version,
   environment and collection identifiers, and how malicious and benign traffic
   were observed under comparable conditions. We also need separately captured,
   complete benign-only control scenarios; removing malicious sessions from a
   mixed capture would not supply those controls. Please identify copies,
   rotations, fragments and related exports so they are not counted as separate
   runs.
6. **Artifact inventory:** filenames, byte sizes and raw-file SHA256 values,
   together with the label/manifest version and its hashes. Please identify any
   shared provenance with other released datasets or derivative collections.

An initial metadata-only response is sufficient. Please do not send packet
contents, session label rows, TLS keys, credentials or executable malware at this
stage. We can first determine whether the existing collection fits our frozen
validation design, then agree on an appropriate permitted acquisition path.
Unknown or unavailable fields are useful to record; we are not requesting new
malware execution or changing our acceptance criteria to fit the source.

Thank you,
Sai Chayank
Univect / PS26145 project team
Teammates: Sai Surya, Surya Teja, Shalini, Vindhya, Pravallika

## Reviewer checklist for the response

Record each item as **VERIFIED**, **UNKNOWN**, **UNAVAILABLE** or **CONFLICT**.
For VERIFIED, cite the publisher/steward statement or manifest, date/version and
evidence location. An empty answer is UNKNOWN, never an implicit pass.

- [ ] Capture-data licence explicitly covers the intended use and records any
  redistribution restrictions. Code-directory MIT and paper terms alone are
  insufficient. Confirm the responder can speak for the dataset.
- [ ] Source, collection environment and canonical Cobalt Strike framework
  provenance are documented and distinct from the TQH/Merlin training source.
  Check related releases/re-exports; distinct filenames or IPs are not independence.
- [ ] Labels support session UID/tuple/UTC joins and explicit intent provenance.
  Unknown traffic stays unknown; file prefixes or absence from an indicator list
  cannot label all sessions.
- [ ] Raw format, link type, capture timing and complete native ClientHello
  visibility are attested. PCAPNG, SLL, clipped/mid-session captures and unsupported
  fragmentation remain capability gaps; do not add format support in this task.
- [ ] Browser, updater, API/SDK and ordinary encrypted-application controls are
  documented, including concrete application/build/TLS-stack/deployment identities.
  Categories need comparable capture conditions and explicit session intent.
- [ ] At least two separate dated/deployed runs are evidenced. Git-object copies,
  capture rotations, reconnects and slices are not independent runs.
- [ ] Complete separately captured benign-only scenarios are identified, with
  known boundaries; mixed captures retain their benign background.
- [ ] Artifact inventory supplies raw SHA256 and sizes plus label/manifest hashes.
  Publisher hashes are attestations until verified against acquired bytes; Git
  object IDs are not raw SHA256 verification.
- [ ] Whole provenance-connected groups remain in one role: collection/re-exports,
  framework, campaign/sample, agent deployment, runs/rotations, duplicate artifacts,
  namespaced session identity and concrete benign application/build/deployment.
  Do not inspect values before the exact eligible source identities are bound.

ARES remains **UNASSIGNED** until every mandatory metadata condition is verified.
If eligible, record the exact proposed validation source/family/environment and
artifact identities in a separate versioned acquisition manifest referencing the
frozen plan. Do not rewrite the frozen plan or existing research decision.
Acquire and qualify raw values only in a subsequent authorized step. Metadata
attestation is not proof that the native parser successfully processes the files.

## Conditions this bundle cannot satisfy by itself

Even a qualified ARES validation cohort does not make training ready. The existing
plan also requires an independent third source/framework for sealed reserved
evaluation, two runs and all four control categories in every role, training
fingerprint diversity (at least two positive configurations and a genuine shared
positive/benign fingerprint counterexample in development), and a frozen causal
candidate feature contract. Current training coverage remains incomplete.

Preserve the unchanged scenario-level promotion criteria: recall >= 80%,
precision >= 95%, benign-scenario FPR <= 2%, and a matching malicious-session alert
before the positive scenario's final event. Session metrics are secondary;
parser-blind valid positives must not disappear from evaluation denominators.
No criteria are negotiated away in response to missing data.

Do not request reserved packet, fingerprint or label-value contents for tuning.
Future reserve access before training is limited to permitted identity, licence,
hash and coverage attestation metadata. Source/family separation is assessed
before training; no random row splitting, manufactured controls or late role
reassignment is allowed.

## Handoff and Definition of Done

The preparation task was completed when the draft and checklist covered the
recorded ARES gaps and preserved the frozen requirements. Subsequent user approval
authorized sending the message; that contact attempt is recorded below.
No acquisition, training or activation was performed.
No credentials, affiliations or unverified contact details are included.

Next action: identify a working alternative author/steward contact and obtain
approval for that recipient before resending. Assess any reply against this
checklist before preassignment or acquisition.
If no qualifying bundle is available, record the blocker and keep training blocked
and failed candidates disabled; evaluate another source under the same protocol.

## Contact attempt outcome

14 October 2026, Gmail thread displayed 17:58. The signed-in account matched the
user-approved sender. The approved subject and message (plain-text formatting,
with the team signature) were sent to `clement.parssegny@telecom-sudparis.eu`.
Gmail confirmed "Message sent", then its Mail Delivery Subsystem returned
"Address not found". The recipient server response was:

> 550 5.1.1: Recipient address rejected: User unknown in local recipient table

The request is **not delivered**; no publisher reply or permission was obtained.
The public contact listing was insufficient to establish mailbox availability.
No alternate recipient was contacted and no automatic retry was made. The source
remains unassigned, training blocked and failed candidates disabled. The sent
request and failure notice remain in Gmail; unrelated mailbox contents are not
copied into project evidence.

## Alternate contact — approved and sent

Proposed next recipient: **Olivier Levillain**, `olivier.levillain@telecom-sudparis.eu`.
The [official SCN author profile](https://scn.telecom-sudparis.eu/olivierL.html)
publishes this address; the [ARES paper](https://arxiv.org/html/2506.08922v1)
lists him as a coauthor. Both were checked on 14 October 2026. Mailbox deliverability
and authority to grant capture permissions remain unverified. Do not infer a
working mailbox from a public listing or send a test message.

For the alternate message, retain the approved subject, six qualification requests
and team signature above. Replace the greeting with:

> Hello Olivier Levillain and ARES artifact authors,

Insert this routing sentence immediately after the greeting:

> I am contacting you as a coauthor because our request to the published address
> for Clément Parssegny was returned as undeliverable. If another author or dataset
> steward handles these questions, could you please direct us to the appropriate
> contact?

The user approved this specific alternate recipient and the prepared routing
sentence. Sent from the previously approved account on 14 October 2026; Gmail
displayed 18:05 and "Message sent". The Sent-folder copy was opened and verified.
No immediate bounce was visible during verification; this is not recipient
delivery confirmation, a reply or data permission. No automatic monitoring is
configured. The user also authorized assessment of the previously described
alternatives if this contact fails; that does not authorize training, gate changes
or generation of active lab traffic.

## Alternative ways to close the evidence gap

- **Another source:** qualify an independent author-held or public TLS collection
  against the same requirements before assigning roles or inspecting raw values.
  None of the eight reviewed leads is a ready substitute; preserve their recorded
  limitations. Do not silently combine TQH positives with unrelated-source negatives.
- **Benign application source:** the [MIT VNAT publisher record](https://www.ll.mit.edu/r-d/datasets/vpnnonvpn-network-application-traffic-dataset-vnat)
  describes application-labelled packet captures. It is a benign-control research
  lead, not verified malicious TLS truth or a complete four-control validation
  cohort. Permissions, native visibility, session timing and role provenance still
  require qualification.
- **Controlled collection:** a university/lab partner could supply independent,
  documented TLS test scenarios and benign application controls. This requires a
  separately authorized collection task and source/family-aware design review.
  Capturing only our own synthetic sessions does not establish independent public
  generalization or replace the frozen three-role prerequisites. No traffic
  generation or framework execution is authorized by this contact-preparation task.
- **Interim demo:** retain the existing clearly experimental encrypted-session
  indicators and deterministic regressions while the evidence gap remains open.
  This is a demonstration fallback, not permission to claim validated encrypted
  threat coverage or mark the project fully complete.

PCAPNG conversion alone would not resolve session truth, application controls,
permissions or independence; no parser expansion is proposed here. Nfdump exports
alone likewise do not establish raw ClientHello visibility or independent labels.
Training remains blocked under every alternative until the frozen prerequisites
are actually satisfied.
