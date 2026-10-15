# DGA canonical-family and alias review

14 October 2026. **Review completed with limitations; no final dataset approved.**
The user authorized sequential DGA prerequisites. This step reviews documented
identity and related variants for the three metadata-selected DRIFT groups. No
domain rows, candidate scores, training, threshold changes or promotion occur.

## Findings

- **Bumblebee:** the [Fraunhofer Malpedia entry](https://malpedia.caad.fkie.fraunhofer.de/details/win.bumblebee)
  records COLDTRAIN, SHELLSTING and Shindig. None matches an exposed UMUDGA group
  name. [Primary reverse-engineering notes](https://bin.re/blog/the-dga-of-bumblebee/)
  describe arithmetic generation with static/date configurations. All configurations
  stay in one canonical family. The notes contain an apparent BazarLoader heading
  and inconsistent time/TLD details, so they are not treated as per-row generator
  certification. Shared threat actors or malware delivery chains do not establish
  identical DGAs; the report does not declare BazaLoader an alias of Bumblebee.
- **QSnatch:** the [joint NCSC/CISA notice](https://www.ncsc.gov.uk/news/legacy-risk-malware-targeting-qnap-nas-devices)
  documents the alias Derek. [The reversing author](https://bin.re/blog/the-dga-of-qsnatch/)
  describes related A/B versions with shared SHA1/Base64 construction and overlapping
  domains. Treat both as one group, never as two independently held-out algorithms.
  No known alias/group-name collision with the exposed UMUDGA inventory was found.
- **SharkBot:** [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/details/apk.sharkbot)
  identifies the Android malware; [primary reversing notes](https://bin.re/blog/the-dgas-of-sharkbot/)
  describe four related versions using week/year and Base64/MD5 constructions.
  Keep all versions together. Multiple TLDs can share one first label, so 3,675
  publisher rows cannot be equated with 3,675 independent eligible labels. Generic
  antivirus BankBot labels are not specific algorithm-alias evidence.

The [machine-readable review](verification/dga-alias-review-20261014/alias-review.json)
records all 50 exposed variants, their existing named groups, canonical aliases,
scope and limitations. Known-name/alias separation is supported by the inspected
evidence; this is not an exhaustive code-equivalence audit of every generator or
proof of all possible undisclosed aliases. Common hash/PRNG primitives alone are
not evidence of algorithm derivation. DRIFT lacks per-row version/seed identifiers;
keep whole families together and disclose that provenance limit.

## Documentation exposure and preservation

Six publisher documents were inspected. Their DNS-like example/link strings are
pinned as **195 conservative canonical first-label exclusions** in
[documentation exposures](verification/dga-alias-review-20261014/documentation-exposures.json).
These strings are newly exposed development documentation, never untouched
evaluation examples or tuning inputs. False-positive strings in this conservative
registry only exclude data; they do not acquire ground-truth labels. Earlier
Bader/Daumel/DRIFT documentation exposures still need inclusion before counts can
qualify a final cohort. No malware/sample links or code in the documents were run.

Only this report and new review evidence changed. No code or existing tests were
changed and no model/detector behavior was refactored. Existing integrity checks
must preserve the 199 scoped existing files and disabled model flags. Quantitative
accuracy and eligible-label counts remain unchanged/unmeasured in this step.

**Definition of Done:** the alias-review record is complete within its stated
evidence scope; complete final evaluation remains BLOCKED. Freeze this review,
its provenance and limitations. Next is an integrity-only eligible-label count
using prebound canonical groups and complete exclusions. It must emit no domain
examples, scores, distributions, errors or accuracy metrics. The five benign strata
and separate DNS-reference requirements still apply; this step does not waive them.
