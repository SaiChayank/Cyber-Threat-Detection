"""Separate completed-flow DDoS/DoS baseline with capture/day holdouts."""
import hashlib
import json
import math
from collections import Counter
from datasets.cic import FEATURES, rows, vector
from datasets.download import ROOT


def main():
    stats = {k:dict(count=0, mean=[0.]*len(FEATURES), m2=[0.]*len(FEATURES)) for k in ('BENIGN', 'DDOS')}
    inventory, invalid = Counter(), Counter()
    heldout = []
    train_signatures = set()
    for capture, row in rows():
        truth = row['Label'].strip()
        inventory[truth] += 1
        if not (capture.startswith(('Monday', 'Wednesday', 'Tuesday')) or 'DDos' in capture):
            continue
        if truth != 'BENIGN' and not truth.startswith('DoS') and truth != 'DDoS':
            continue
        target = 'BENIGN' if truth == 'BENIGN' else 'DDOS'
        try:
            x = vector(row)
        except (KeyError, ValueError):
            invalid[capture] += 1
            continue
        signature = hashlib.sha256(json.dumps(x).encode()).hexdigest()
        if capture.startswith(('Monday', 'Wednesday')):
            # Deterministic bounded-rate sampling, preserving complete capture holdouts.
            if int(signature[:8],16) % 20 or signature in train_signatures:
                continue
            train_signatures.add(signature)
            s = stats[target]
            s['count'] += 1
            for i,value in enumerate(x):
                delta = value - s['mean'][i]
                s['mean'][i] += delta / s['count']
                s['m2'][i] += delta*(value-s['mean'][i])
        else:
            heldout.append(('validation' if capture.startswith('Tuesday') else 'test', target, x, signature))
    if any(s['count'] < 2 for s in stats.values()):
        raise ValueError('Insufficient training classes')
    total = sum(s['count'] for s in stats.values())
    model = dict(kind='Gaussian NB', features=FEATURES, scope='completed flow, forward-only features', production_enabled=False, threshold=.99, classes={k:dict(prior=s['count']/total,mean=s['mean'],variance=[max(.03,v/s['count']) for v in s['m2']]) for k,s in stats.items()})
    reports = {}
    for partition in ('validation','test'):
        c, seen = Counter(), set()
        for part, truth, x, signature in heldout:
            if part != partition:
                continue
            if signature in train_signatures or signature in seen:
                c['duplicate_vectors_excluded'] += 1
                continue
            seen.add(signature)
            scores = {k:math.log(s['prior']) - .5*sum(math.log(2*math.pi*v)+(a-m)**2/v for a,m,v in zip(x,s['mean'],s['variance'])) for k,s in model['classes'].items()}
            score = 1/(1+math.exp(max(-700,min(700,scores['BENIGN']-scores['DDOS']))))
            actual, predicted = truth == 'DDOS', score >= .99
            c['tp' if actual and predicted else 'fn' if actual else 'fp' if predicted else 'tn'] += 1
        reports[partition] = dict(c, recall=c['tp']/max(1,c['tp']+c['fn']) if c['tp']+c['fn'] else None, false_positive_rate=c['fp']/max(1,c['fp']+c['tn']))
    raw = json.dumps(model,indent=2).encode()
    path = ROOT / 'ml/public_cic.json'
    path.write_bytes(raw)
    path.with_suffix('.sha256').write_text(hashlib.sha256(raw).hexdigest())
    report = dict(inventory=dict(inventory), invalid=dict(invalid), training_counts={k:s['count'] for k,s in stats.items()}, training_captures=['Monday','Wednesday'], validation_captures=['Tuesday'], test_captures=['Friday DDoS'], **reports, production_enabled=False, caveats=['Original archive has no addresses or event timestamps; cannot replay as real packet traffic', 'DoS variants train; unseen Friday DDoS capture tests transfer', 'Tuesday labelled attacks outside target class excluded: benign-only validation has no recall', 'Forward IAT units and duration retained as provided by CICFlowMeter', 'Predeclared 0.99 threshold; no holdout tuning', 'Exact feature vectors deduplicated against training and within each evaluation partition; full capture duplicates cannot be ruled out without raw tuples', 'Other official labels inventoried, not silently collapsed to benign'])
    (ROOT / 'ml/public_cic_evaluation.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(report,indent=2),flush=True)


if __name__ == '__main__':
    main()
