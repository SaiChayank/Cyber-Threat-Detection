"""Compare DNS tunnel rules on frozen, controlled development scenarios only."""
from collections import Counter
import hashlib
import json
from pathlib import Path

from datasets.dns_tunnel_development import SCENARIOS, events
from detection.pipeline import Pipeline


ROOT = Path(__file__).resolve().parents[1]


def evaluate(candidate):
    rows = []
    for spec in SCENARIOS:
        scenario_id, split, positive, pattern, qtype, seed, base, interval_ms = spec
        pipeline = Pipeline(dns_tunnel_candidate=candidate)
        pipeline.model.predict = lambda _: ('BENIGN', 1.0)
        first_alert = None
        sequence = list(events(spec))
        for index, event in enumerate(sequence, start=1):
            if any(alert.threat_class == 'DNS_TUNNELLING' for alert in pipeline.process(event)):
                first_alert = index if first_alert is None else first_alert
        rows.append({'scenario': scenario_id, 'split': split, 'positive': positive,
                     'pattern': pattern, 'qtype': qtype, 'interval_ms': interval_ms,
                     'queries': len(sequence), 'first_alert_query': first_alert,
                     'detected_before_end': first_alert is not None and first_alert < len(sequence)})
    return rows


def summary(rows, split):
    counts = Counter()
    for row in rows:
        if row['split'] != split:
            continue
        counts[('TP' if row['positive'] else 'FP') if row['first_alert_query']
               else ('FN' if row['positive'] else 'TN')] += 1
    return {name: counts[name] for name in ('TP', 'TN', 'FP', 'FN')}


def main():
    baseline = evaluate(False)
    candidate = evaluate(True)
    report = {
        'scope': 'Controlled synthetic training/configuration and validation scenarios only; no public mixed PCAP truth',
        'candidate_runtime_default_enabled': False,
        'source_sha256': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                          for name in ('datasets/dns_tunnel_development.py',
                                       'features/dns_tunnel.py', 'detection/dns_tunnel_candidate.py')},
        'baseline': {'training': summary(baseline, 'training'),
                     'validation': summary(baseline, 'validation'), 'scenarios': baseline},
        'candidate': {'training': summary(candidate, 'training'),
                      'validation': summary(candidate, 'validation'), 'scenarios': candidate},
    }
    path = ROOT / 'ml/dns_tunnel_candidate_validation.json'
    path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'baseline': {k: report['baseline'][k] for k in ('training', 'validation')},
                      'candidate': {k: report['candidate'][k] for k in ('training', 'validation')}}, indent=2))


if __name__ == '__main__':
    main()
