"""Public-domain character bigram NB candidate, family-disjoint evaluation."""
import hashlib
import json
import math
from collections import Counter
from datasets.domains import domains
from datasets.download import ROOT


def tokens(domain):
    value = '^' + domain.lower().rstrip('.').split('.')[0] + '$'
    return Counter(value[i:i+2] for i in range(len(value) - 1))


def split(domain):
    # Stable exact-domain grouping, avoiding duplicate leakage.
    return int(hashlib.sha256(domain.encode()).hexdigest()[:8], 16) % 10


def score(model, domain):
    x = tokens(domain)
    logs = [sum(n * model['log_prob'][c].get(t, model['unknown'][c]) for t, n in x.items()) for c in ('BENIGN', 'DGA_DOMAINS')]
    return 1 / (1 + math.exp(max(-700, min(700, logs[0] - logs[1]))))


def main():
    root = ROOT / 'data/raw/umudga'
    families = {name: sorted(set(domains(root / (name + '.txt')))) for name in ['legit', 'banjori', 'corebot', 'dircrypt', 'matsnu', 'necurs', 'ramnit']}
    train_positive = set().union(*(families[k] for k in ('banjori', 'corebot', 'dircrypt')))
    counts = {'BENIGN': Counter(), 'DGA_DOMAINS': Counter()}
    training = [('BENIGN', d) for d in families['legit'] if split(d) < 6] + [('DGA_DOMAINS', d) for d in train_positive]
    for label, domain in training:
        counts[label].update(tokens(domain))
    vocab = set().union(*counts.values())
    model = dict(kind='character-bigram multinomial NB', training_source='UMUDGA 1', features='first DNS label character bigrams; no timing, addresses, labels or family identifiers', log_prob={}, unknown={}, decision_threshold=.99)
    for label, count in counts.items():
        total = sum(count.values()) + len(vocab) + 1
        model['log_prob'][label] = {t: math.log((count[t] + 1) / total) for t in vocab}
        model['unknown'][label] = math.log(1 / total)
    def evaluate(positive_families, benign_buckets):
        positives = set().union(*(families[k] for k in positive_families)) - train_positive
        negatives = [d for d in families['legit'] if split(d) in benign_buckets and d not in train_positive]
        rows = [(True, d) for d in positives] + [(False, d) for d in negatives]
        confusion = Counter()
        for actual, domain in rows:
            predicted = score(model, domain) >= model['decision_threshold']
            confusion['tp' if actual and predicted else 'fn' if actual else 'fp' if predicted else 'tn'] += 1
        c = {k: confusion[k] for k in ('tp', 'fn', 'fp', 'tn')}
        return dict(families=positive_families, records=len(rows), **c,
                    recall=c['tp'] / max(1, c['tp'] + c['fn']),
                    precision=c['tp'] / max(1, c['tp'] + c['fp']),
                    false_positive_rate=c['fp'] / max(1, c['fp'] + c['tn']))
    validation = evaluate(['matsnu'], {6, 7})
    # Predeclared gate, never chosen using test results.
    model['production_enabled'] = validation['recall'] >= .8 and validation['false_positive_rate'] <= .05 and validation['precision'] >= .95
    test = evaluate(['necurs', 'ramnit'], {8, 9})
    raw = json.dumps(model, indent=2).encode()
    path = ROOT / 'ml/public_dga.json'
    path.write_bytes(raw)
    path.with_suffix('.sha256').write_text(hashlib.sha256(raw).hexdigest())
    report = dict(training_records=len(training), training_families=['banjori', 'corebot', 'dircrypt'], validation=validation, test=test, production_enabled=model['production_enabled'], threshold=.99, caveats=['Small seven-list subset; limited legitimate coverage', 'One experiment per DGA family', 'Character NB posterior is uncalibrated', 'Family-disjoint results are separate from synthetic streaming accuracy'])
    (ROOT / 'ml/public_dga_evaluation.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
