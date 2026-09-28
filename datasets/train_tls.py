"""Completed-connection Gaussian NB experiment; never early-packet inference."""
import hashlib
import json
import math
from collections import Counter
from datasets.download import ROOT
from datasets.tls import FEATURES, label, rows, vector


def group(row, collection):
    # Malware family/app names used only to isolate groups, not as predictors.
    return collection + ':' + str(row.get('meta.malware.family') if collection == 'malware' else row.get('meta.application.name'))


def bucket(value):
    return int(hashlib.sha256(value.encode()).hexdigest()[:8], 16) % 10


def predict(model, x):
    scores = {k: math.log(s['prior']) - .5 * sum(math.log(2 * math.pi * v) + (a-m)**2 / v for a, m, v in zip(x, s['mean'], s['variance'])) for k, s in model['classes'].items()}
    delta = scores['BENIGN_REFERENCE'] - scores['MALWARE_RELATED']
    return 1 / (1 + math.exp(max(-700, min(700, delta))))


def main():
    n = len(FEATURES)
    stats = {k: dict(count=0, mean=[0.] * n, m2=[0.] * n) for k in ('BENIGN_REFERENCE', 'MALWARE_RELATED')}
    inventory = Counter()
    groups = {'train': set(), 'validation': set(), 'test': set()}
    heldout = []
    for collection in ('winapps', 'malware', 'soho'):
        for row in rows(collection):
            truth = label(row, collection)
            inventory[f'{collection}:{truth}'] += 1
            if truth == 'UNLABELLED':
                continue
            try:
                x = vector(row)
            except ValueError:
                inventory['invalid_measurements'] += 1
                continue
            gid = group(row, collection)
            b = bucket(gid)
            partition = 'train' if b < 6 else 'validation' if b < 8 else 'test'
            groups[partition].add(gid)
            if partition != 'train':
                heldout.append((partition, truth, x))
                continue
            s = stats[truth]
            s['count'] += 1
            for i, value in enumerate(x):
                delta = value - s['mean'][i]
                s['mean'][i] += delta / s['count']
                s['m2'][i] += delta * (value - s['mean'][i])
        print(f'Inspected {collection}', flush=True)
    if any(s['count'] < 2 for s in stats.values()):
        raise ValueError('Insufficient training classes')
    total = sum(s['count'] for s in stats.values())
    model = dict(kind='Gaussian NB', scope='completed TLS connection; forward-only view', features=FEATURES, classes={k: dict(prior=s['count']/total, mean=s['mean'], variance=[max(.03, m/s['count']) for m in s['m2']]) for k, s in stats.items()}, threshold=.99)
    reports = {}
    for partition in ('validation', 'test'):
        c = Counter()
        for part, truth, x in heldout:
            if part != partition:
                continue
            actual = truth == 'MALWARE_RELATED'
            positive = predict(model, x) >= model['threshold']
            c['tp' if actual and positive else 'fn' if actual else 'fp' if positive else 'tn'] += 1
        reports[partition] = dict(**{k: c[k] for k in ('tp', 'fn', 'fp', 'tn')}, precision=c['tp']/max(1,c['tp']+c['fp']), recall=c['tp']/max(1,c['tp']+c['fn']), false_positive_rate=c['fp']/max(1,c['fp']+c['tn']))
    # Different observation contract: the candidate is deliberately offline only.
    model['production_enabled'] = False
    raw = json.dumps(model, indent=2).encode()
    path = ROOT / 'ml/public_tls.json'
    path.write_bytes(raw)
    path.with_suffix('.sha256').write_text(hashlib.sha256(raw).hexdigest())
    report = dict(inventory=dict(inventory), training_counts={k:s['count'] for k,s in stats.items()}, split='SHA256 family/app group modulo 10: 0-5 train, 6-7 validation, 8-9 test', groups={k:len(v) for k,v in groups.items()}, **reports, production_enabled=False, scope=model['scope'], caveats=['Completed-session features cannot be used at the first packet', 'Malware-related label is inherited from sandbox annotations, not independently verified per-flow compromise', 'SOHO and ambiguous malware sandbox records excluded from supervised labels', 'Forward TLS record sizes are not IP packet sizes', 'Source environment differences may inflate classification performance', 'Uncalibrated posterior; no QUIC validation'])
    (ROOT / 'ml/public_tls_evaluation.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2), flush=True)


if __name__ == '__main__':
    main()
