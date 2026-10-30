"""Single pre-declared evaluation of the frozen OOF DGA candidate. Read-only on all inputs.

Run once: python -m datasets.evaluate_dga_final --out report.json
The procedure, sources, exclusions, sampling and the all-four-gates decision rule are fixed in
data/dga_final_evaluation_20261030.json (committed before this ran). Nothing here tunes anything.
"""
import argparse
import hashlib
import json
import random
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import pyarrow.parquet as pq

from ingest.pcap_reader import PcapReader
from ml.dga import DgaModel, domain_label

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / 'data' / 'dga_final_evaluation_20261030.json'
QUERY = re.compile(r'query\[[A-Z]+\] (\S+) from (\S+)')


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def normalized(name):
    return re.sub(r'[^a-z0-9]', '', name.lower())


def excluded_family(name, config):
    roots = config['family_exclusion']['development_roots']
    aliases = config['family_exclusion']['aliases_excluded']
    flat = normalized(name)
    return any(flat.startswith(root) for root in roots) or flat in aliases


def development_labels():
    labels = set()
    for folder in ('umudga', 'umudga-expanded'):
        for path in (ROOT / 'data/raw' / folder).glob('*.txt'):
            for line in path.read_text(encoding='utf-8', errors='replace').splitlines():
                label = domain_label(line.split(',')[0])
                if label:
                    labels.add(label)
    for name in ('benign/benign_1.pcap', 'benign/benign_2.pcap'):
        for batch in PcapReader().read_packets(ROOT / 'data/raw/cicdns2021/pcaps' / name):
            for flow, dns, tls in batch:
                if dns is not None and flow.dst_port == 53:
                    label = domain_label(dns.query_name)
                    if label:
                        labels.add(label)
    return labels


def reservoirs_by_family(path, config, rng):
    cap = config['sampling']['per_family_cap']
    seen, kept = Counter(), defaultdict(list)
    for batch in pq.ParquetFile(path).iter_batches(batch_size=500_000, columns=['family', 'domain']):
        for family, domain in zip(batch.column(0).to_pylist(), batch.column(1).to_pylist()):
            if excluded_family(family, config):
                continue
            seen[family] += 1
            bucket = kept[family]
            if len(bucket) < cap:
                bucket.append(domain)
            else:
                slot = rng.randrange(seen[family])
                if slot < cap:
                    bucket[slot] = domain
    return seen, kept


def reservoir(path, size, rng, column='domain'):
    seen, kept = 0, []
    for batch in pq.ParquetFile(path).iter_batches(batch_size=500_000, columns=[column]):
        for value in batch.column(0).to_pylist():
            seen += 1
            if len(kept) < size:
                kept.append(value)
            else:
                slot = rng.randrange(seen)
                if slot < size:
                    kept[slot] = value
    return seen, kept


def ait_benign_labels():
    labels = set()
    path = ROOT / 'data/raw/ait-session-join-20261021/dnsmasq-original.log'
    for line in path.read_text(encoding='utf-8', errors='replace').splitlines():
        match = QUERY.search(line)
        if match and not match.group(1).lower().endswith('kennedy-mendoza.info'):
            label = domain_label(match.group(1))
            if label:
                labels.add(label)
    return labels


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    config = json.loads(CONFIG.read_text(encoding='utf-8'))
    candidate = config['candidate']
    if sha256(ROOT / candidate['artifact']) != candidate['artifact_sha256']:
        raise SystemExit('Candidate artifact differs from the frozen hash; refusing to evaluate')
    model = DgaModel(ROOT / candidate['artifact'])
    threshold = model.data['decision_threshold']
    if threshold != candidate['decision_threshold']:
        raise SystemExit('Candidate threshold differs from the frozen value')
    rng = random.Random(config['sampling']['seed'])
    overlap = development_labels()

    def predicted(label):
        return model._uncached_score(label) >= threshold

    sources = config['sources']
    seen, kept = reservoirs_by_family(ROOT / sources['dga_positives'].split(' ')[0], config, rng)
    families = {f: d for f, d in kept.items() if seen[f] >= config['sampling']['min_family_domains_in_source']}
    per_family, tp = {}, 0
    total = unscorable = dropped_overlap = 0
    for family, domains in sorted(families.items()):
        hit = count = miss_unscorable = 0
        for domain in domains:
            label = domain_label(domain)
            if label and label in overlap:
                dropped_overlap += 1
                continue
            count += 1
            if not label:
                miss_unscorable += 1
            elif predicted(label):
                hit += 1
        per_family[family] = dict(domains_in_source=seen[family], evaluated=count, detected=hit,
                                  unscorable=miss_unscorable, recall=round(hit / count, 4) if count else None)
        tp += hit
        total += count
        unscorable += miss_unscorable
    recall = tp / total if total else 0.0

    benign_seen, benign = reservoir(ROOT / sources['benign_domains'].split(' ')[0], config['sampling']['benign_domain_sample'], rng)
    scored = fp = benign_overlap = benign_unscorable = 0
    for domain in benign:
        label = domain_label(domain)
        if not label:
            benign_unscorable += 1
            continue
        if label in overlap:
            benign_overlap += 1
            continue
        scored += 1
        fp += predicted(label)
    domain_fpr = fp / scored if scored else 1.0

    dns_labels = sorted(ait_benign_labels() - overlap)
    dns_fp = sum(predicted(label) for label in dns_labels)
    dns_fpr = dns_fp / len(dns_labels) if dns_labels else 1.0

    precision = recall / (recall + domain_fpr) if recall + domain_fpr else 0.0
    gates = config['gates']
    result = {
        'recall': dict(value=round(recall, 4), gate=gates['recall_min'], passed=recall >= gates['recall_min']),
        'precision_at_1_to_1': dict(value=round(precision, 4), gate=gates['precision_min'], passed=precision >= gates['precision_min']),
        'domain_fpr': dict(value=round(domain_fpr, 4), gate=gates['domain_fpr_max'], passed=domain_fpr <= gates['domain_fpr_max']),
        'benign_dns_fpr': dict(value=round(dns_fpr, 4), gate=gates['benign_dns_fpr_max'],
                               passed=dns_fpr <= gates['benign_dns_fpr_max'] and len(dns_labels) >= gates['min_benign_dns_labels']),
    }
    counts_ok = len(families) >= gates['min_eligible_families'] and len(dns_labels) >= gates['min_benign_dns_labels']
    verdict = 'PASS: all four gates and minimum counts' if counts_ok and all(v['passed'] for v in result.values()) else 'FAIL'
    report = dict(format='ps26145-dga-final-report/1', config_sha256=sha256(CONFIG),
                  candidate_sha256=candidate['artifact_sha256'], threshold=threshold, verdict=verdict, gates=result,
                  counts=dict(eligible_families=len(families), positives_evaluated=total, true_positives=tp,
                              positives_unscorable_counted_as_misses=unscorable, positives_dropped_overlap=dropped_overlap,
                              benign_scored=scored, benign_false_positives=fp, benign_unscorable=benign_unscorable,
                              benign_dropped_overlap=benign_overlap, benign_source_rows=benign_seen,
                              benign_dns_labels=len(dns_labels), benign_dns_false_positives=dns_fp),
                  per_family=per_family,
                  macro_family_recall=round(sum(f['recall'] for f in per_family.values() if f['recall'] is not None)
                                            / max(1, sum(f['recall'] is not None for f in per_family.values())), 4),
                  worst_families=sorted(((f, v['recall']) for f, v in per_family.items() if v['recall'] is not None),
                                        key=lambda item: item[1])[:10])
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: report[k] for k in ('verdict', 'gates', 'counts', 'macro_family_recall', 'worst_families')}, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
