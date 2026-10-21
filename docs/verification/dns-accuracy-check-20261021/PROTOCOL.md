# DNS accuracy request: frozen controlled check and reserved-readiness preflight

21 October 2026, baseline `47e82c3`. User explicitly requests detector accuracy
validation. Inspect the frozen DNS evaluation contract/scorer and latest source
verification first. Independent reserved data remain unavailable: minimum 20
positive/50 benign independently annotated sessions, all five benign categories,
real dnscat2/iodine coverage, original source/namespace/time joins, disjoint roles
and immutable event/session manifest are not established. Existing numerical,
coverage and before-completion/timing gates remain byte-identical.

Do not score newly acquired public captures, relabel every packet, invent session
boundaries, change readiness, materialize a reserve, retrain, tune, activate or
modify any detector. New public inputs remain in their current unassigned roles.

Allowed reproducible work under the existing documented development path:
1. Verify contract/source/artifact and current source-evidence identities.
2. Run existing `datasets.score_dns_tunnel --mode development` once with a new
   unused output path. Only its 20 already exposed synthetic scenarios enter.
3. Compare the existing long-TXT baseline on the same scenarios, using that
   scorer's exact session classification/timing semantics and the same BENIGN
   model override. Report it as rule-only, not full deployed hybrid accuracy.
4. Run reserved-mode readiness once. It must refuse before manifest/event access,
   receipt claim or scoring. Confirm no reserved output/receipt was created;
   this is not a consumed evaluation pass or a model-quality failure.
5. Run existing targeted contract/scorer/candidate/parser regressions. Preserve
   all prior reports and data; verify 130 protected originals plus the two newer
   acquired captures before/after. No product code change or extra dependency.

Report per-split TP/TN/FP/FN, precision, recall, F1/FPR, first-query/capture-delay
and late-question counts. Preserve undefined metrics; do not combine training
and validation into independent accuracy. Tiny synthetic success cannot pass
the formal promotion/data gate. No metric is tuned or used for model selection.
Record missing prerequisites precisely, with formal metrics NOT ESTABLISHED.
Stop after this diagnostic result; candidate remains disabled and release NOT
READY. Next eligible work is genuine public session/category qualification.
