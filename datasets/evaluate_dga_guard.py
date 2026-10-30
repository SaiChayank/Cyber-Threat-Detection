"""Score the ACTIVE conservative DGA guard on the same samples as the pre-declared candidate evaluation.

The guard has no trainable parameters, so scoring it on those samples (same config, same seed) selects and
tunes nothing; it only states the current runtime's real-data recall and false-positive rate honestly.
Run: python -m datasets.evaluate_dga_guard --out report.json
"""
import argparse
import json
import random
import sys
from pathlib import Path

from datasets import evaluate_dga_final as ev
from detection.dga_rules import conservative_rule, registrable_name
from features.extractor import dga_lexical_features
from ml.dga import domain_label


def ait_benign_names(overlap):
    """Unique real benign client DNS names (full names, not labels: the guard judges the registrable label)."""
    names = set()
    path = ev.ROOT / 'data/raw/ait-session-join-20261021/dnsmasq-original.log'
    for line in path.read_text(encoding='utf-8', errors='replace').splitlines():
        match = ev.QUERY.search(line)
        if match and not match.group(1).lower().endswith('kennedy-mendoza.info'):
            name = match.group(1).lower()
            if domain_label(name) and domain_label(name) not in overlap:
                names.add(name)
    return sorted(names)


def flagged(domain):
    """Runtime behaviour: lexical guard on the registrable label; internationalized labels never alert."""
    label = domain_label(domain)
    if not label or label.startswith('xn--'):
        return False
    return bool(conservative_rule(dga_lexical_features(registrable_name(domain))))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    config = json.loads(ev.CONFIG.read_text(encoding='utf-8'))
    rng = random.Random(config['sampling']['seed'])
    overlap = ev.development_labels()
    sources = config['sources']
    seen, kept = ev.reservoirs_by_family(ev.ROOT / sources['dga_positives'].split(' ')[0], config, rng)
    families = {f: d for f, d in kept.items() if seen[f] >= config['sampling']['min_family_domains_in_source']}
    per_family, tp, total = {}, 0, 0
    for family, domains in sorted(families.items()):
        usable = [d for d in domains if not (domain_label(d) and domain_label(d) in overlap)]
        hit = sum(flagged(d) for d in usable)
        per_family[family] = dict(evaluated=len(usable), detected=hit, recall=round(hit / len(usable), 4) if usable else None)
        tp, total = tp + hit, total + len(usable)
    _, benign = ev.reservoir(ev.ROOT / sources['benign_domains'].split(' ')[0], config['sampling']['benign_domain_sample'], rng)
    scored = [d for d in benign if domain_label(d) and domain_label(d) not in overlap]
    fp = sum(flagged(d) for d in scored)
    dns = ait_benign_names(overlap)
    dns_fp = sum(flagged(name) for name in dns)
    recall = tp / total if total else 0.0
    fpr = fp / len(scored)
    report = dict(format='ps26145-dga-guard-report/1', note='Same samples/seed as the candidate evaluation; the guard has no tunable parameters.',
                  recall=round(recall, 4), domain_fpr=round(fpr, 5), precision_at_1_to_1=round(recall / (recall + fpr), 4) if recall + fpr else 0.0,
                  benign_dns_fpr=round(dns_fp / len(dns), 5), positives_evaluated=total, true_positives=tp,
                  benign_scored=len(scored), benign_false_positives=fp, benign_dns_names=len(dns), benign_dns_false_positives=dns_fp,
                  macro_family_recall=round(sum(f['recall'] for f in per_family.values() if f['recall'] is not None)
                                            / max(1, sum(f['recall'] is not None for f in per_family.values())), 4),
                  families_at_80_percent=sum(1 for f in per_family.values() if f['recall'] and f['recall'] >= 0.8),
                  families=len(per_family), per_family=per_family)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: v for k, v in report.items() if k != 'per_family'}, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
