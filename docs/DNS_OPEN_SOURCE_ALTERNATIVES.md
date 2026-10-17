# Publicly licensed DNS alternatives: bounded source screen

17 October 2026, baseline `21f571a`. User selected alternative public datasets
instead of depending on pending producer replies. Scope starts with DNS
tunnelling; other detector data/model tracks are unchanged.

**Open-access alternatives found; qualified final evaluation set NOT established.**
This is a five-source documentation/metadata screen, not an exhaustive search or
a conclusion that no qualifying dataset exists. No traffic archive, query rows,
model binary or upstream executable was downloaded. Publisher documents and
record/catalogue JSON were downloaded and hashed locally.
Original publisher text bytes are retained under the ignored
`data/raw/dns-open-source-documents-20261017/` cache and in byte-preserving base64
JSON copies in the evidence package. This preserves upstream formatting/encoding
without introducing its trailing whitespace into repository text diffs.

## Contract retained

[Screen protocol](DNS_OPEN_SOURCE_SCREEN_PROTOCOL.md) was pinned after initial
search/documentation excerpts and before data values. The existing
`data/dns_tunnel_evaluation_contract.json` stays unchanged: >=20 independent
positive and >=50 benign sessions; dnscat2 or iodine; five benign categories;
recall >=80%, precision >=95%, FPR <=2%; every TP before completion, >=90% of TPs
by query 10 AND within 10 seconds. Classic Ethernet PCAP v2.4/linktype1 or
equivalent original source/time/QNAME/QTYPE client-question logs are required.
No format conversion, new parser, inferred labels, redefined sessions, threshold
change, reserve assignment or scoring was performed.

## Primary-source results

- **DNSTunnel2026**, [Zenodo 20137065](https://zenodo.org/records/20137065).
  Publisher API explicitly declares open access and CC BY 4.0. Listed release is
  `DNSTunnel2026.zip`, 497,565,428 bytes, publisher MD5
  `e2a4c675b480f9c10b8629494d9ae7dc` (not locally verified archive SHA256).
  Documentation describes processed company/domain windows and a model, not a
  verified released sequence of original client questions. SmoothFlow positives
  do not establish dnscat2/iodine coverage. Label support includes behavioral and
  reputation indicators, which cannot be presumed independent session truth.
  Five-minute/24-hour features cannot reconstruct the frozen causal input.
  Clear licence solves a rights dependency for the listed release, not these
  evaluation gaps. No archive/model/CSV acquired.
- **UMA benign network captures**, [Zenodo 19206234](https://zenodo.org/records/19206234).
  Publisher API explicitly declares open access and CC BY 4.0. Listed archive
  `capturasAgentes.zip` is 6,853,462,196 bytes, publisher MD5
  `9ab42d5978237a2b9e613d6b0d0f0440` (not a locally verified SHA256).
  [Producer repository](https://github.com/Sergiolopezflores/BehaviorallyGroundedAgent-BasedBenignTrafficGenerationwithLLMVariability)
  at `c756900b014fb9c5066b437372aba281e1bd320e` documents 45 expected
  profile/duration replications, recommends PCAPNG and makes some logs/provenance
  optional. Browser/gamer/admin roles do not establish the five required DNS
  categories, original per-source question joins or >=50 independent DNS sessions.
  Forty-five expected captures are not a measured session count. Some appendix
  parameters remain `fill`; instructions do not prove executed run manifests.
  No bulk archive was acquired or converted.
- **Elastic iodine example**, [producer example](https://github.com/elastic/examples/tree/master/Security%20Analytics/dns_tunnel_detection).
  Repository Apache-2.0 licence and sample instructions are saved at a pinned
  commit. Catalogue lists one 77,524-byte iodine PCAP. The
  [producer blog](https://www.elastic.co/blog/detecting_dns_tunnels_with_packetbeat_and_watcher)
  describes replaying an iodine tunnel. This is a useful small example lead, not
  >=20 independently joined positive sessions and five-category benign controls.
  Exact original per-session attribution/boundaries, capture rights/provenance
  beyond the repository licence and original compatible header remain unverified.
  Upstream time-shifting, active query and stack-install instructions were read
  as documentation only; none was executed. No sample PCAP acquired.
- **shanu0x17 DNS lab**, [producer repository](https://github.com/shanu0x17/dns-tunnel-detection-lab)
  at `056f27abaa2540877f42d52cf0f58097ce9c348e`. MIT repository licence;
  README describes a small custom chunk/session protocol and limited local data.
  Catalogue contains two capture files. No dnscat2/iodine use, sufficient independent
  session/run truth, capture-specific permission statement or five-category benign
  coverage is established. This is not a replacement final dataset. No captures
  or upstream generation/detection scripts executed.
- **CNR/mopamopa**, [producer repository](https://github.com/mopamopa/DNS-tunneling)
  at `f39471e68adef1f58f1efa2899d940ab38900489`. README describes DNS2TCP
  statistics and links original text dumps separately. Root catalogue has no
  licence; `LICENSE` returned 404. A third-party index's CC BY-NC claim is not
  substituted for applicable producer data rights. QNAME/QTYPE/source/time session
  equivalence, required tool and controls remain unverified. No text data, generated
  mix, CSV/statistics rows or SharePoint content acquired.

## Evidence and checks

`data/dns_open_source_screen.json` records source identity, declared rights,
document receipts, unknown raw checksums/counts and disposition. Evidence is in
`verification/dns-open-source-screen-20261017/`. Git refs/tree/catalogue responses
contain no file patches. Metadata/licence/README examples are exposed documents,
not untouched reserved data; all roles remain unassigned. No data-derived accuracy,
timing or quality metric exists from this screen.

Firecrawl routing failed with a missing account `link_id`; built-in web search
and public publisher HTTP metadata were used. Web retrieval of Zenodo API URLs
was unavailable through that tool; ordinary unauthenticated API HTTP requests
succeeded without an access challenge. CNR licence absence is recorded, not
bypassed. An initial console Unicode error occurred after some documents were
saved; UTF-8 output and incremental receipt persistence corrected it. Recovered
receipts explicitly use local-save times, not invented retrieval timestamps.

No code/tests changed or were rerun. Before/after protected hashes, HTTP byte
hashes, Git-blob identities for selected documents, catalogue relationships,
unchanged evaluation gates and no-scoring checks are recorded in `checks.json`.
`freeze.json` binds this package; earlier regression/build evidence remains dated
historical evidence. Failed DNS candidate remains disabled; runtime/history and
other detector models/partitions are unchanged.

## Disposition and next step

Source-screen DoD passes when recorded integrity checks pass. **Final data
qualification DoD remains blocked**; zero eligible complete evaluation collections,
zero assigned reserved sessions and no current promotion decision. No email or
GitHub message sent, no monitoring started and no raw bulk download claimed.

The next prerequisite is an openly licensed **original dnscat2/iodine query/capture
release with executed session/run annotations**, complemented by independently
documented benign DNS categories. Public availability alone cannot fill those
fields. Stop this bounded screen here; a further source-qualification task must
bind exact artifacts and roles before any packet/question values, without changing
the frozen scorer or gate. Do not replace this missing evidence with either new
synthetic data or a tabular-model rewrite.
