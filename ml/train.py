"""Run python -m ml.train. Split by whole independently seeded experiments."""
import argparse
import hashlib
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from features.extractor import FeatureExtractor, FEATURES
from ml.model import ARTIFACT, Model, vector
from replay.scenarios import CLASSES, scenario


def examples(seeds):
    for seed in seeds:
        for label in CLASSES:
            extractor = FeatureExtractor()
            for event in scenario(label, seed):
                yield label, extractor.update(event)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evaluate-only', action='store_true',
                        help='Evaluate the frozen artifact with current features; never refit or replace it')
    args = parser.parse_args()
    if not args.evaluate_only:
        fit()
    model = Model()
    reports = evaluate(model)
    root = Path(__file__).resolve().parent.parent
    reports['metadata'] = dict(generated_at_utc=datetime.now(timezone.utc).isoformat(),
                               model_sha256=hashlib.sha256(ARTIFACT.read_bytes()).hexdigest(),
                               model_refitted=not args.evaluate_only,
                               runtime_source_sha256={name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                                                      for name in ('features/extractor.py', 'features/rate_window.py', 'ml/model.py')},
                               scope='Frozen-model classifier on synthetic lab experiments, not hybrid alert accuracy or deployment validation',
                               caveats=['Historical generator families and seeds, already inspected; regression inputs, not a fresh holdout',
                                        'Synthetic fingerprint is a shortcut signal; scores remain uncalibrated'])
    name = 'runtime_evaluation.json' if args.evaluate_only else 'evaluation.json'
    ARTIFACT.with_name(name).write_text(json.dumps(reports, indent=2))
    print(json.dumps({k: reports[k]['macro_f1'] for k in ('validation', 'test')}))


def fit():
    groups = defaultdict(list)
    for label, features in examples(range(1, 31)):
        groups[label].append(vector(features))
    stats = {}
    total = sum(map(len, groups.values()))
    for label, rows in groups.items():
        columns = list(zip(*rows))
        means = [sum(c)/len(c) for c in columns]
        variances = [max(.03, sum((v-m)**2 for v in c)/len(c)) for c, m in zip(columns, means)]
        stats[label] = dict(mean=means, variance=variances, prior=len(rows)/total)
    data = dict(algorithm='Gaussian naive Bayes', features=FEATURES, classes=stats,
                provenance='offline synthetic metadata; not captured malware',
                training_seeds=[1, 30], validation_seeds=[31, 40], test_seeds=[41, 50])
    raw = json.dumps(data, indent=2).encode()
    ARTIFACT.write_bytes(raw)
    ARTIFACT.with_suffix('.sha256').write_text(hashlib.sha256(raw).hexdigest()+'\n')


def evaluate(model):
    reports = {}
    for split, seeds in [('validation', range(31, 41)), ('test', range(41, 51))]:
        confusion = {k: {p: 0 for p in CLASSES} for k in CLASSES}
        for truth, features in examples(seeds):
            predicted, _ = model.predict(features)
            confusion[truth][predicted] += 1
        metrics = {}
        for label in CLASSES:
            tp = confusion[label][label]
            fp = sum(confusion[k][label] for k in CLASSES if k != label)
            fn = sum(confusion[label][k] for k in CLASSES if k != label)
            metrics[label] = dict(precision=tp/max(1, tp+fp), recall=tp/max(1, tp+fn),
                                  f1=2*tp/max(1, 2*tp+fp+fn))
        reports[split] = dict(per_class=metrics, confusion=confusion,
                             macro_f1=sum(m['f1'] for m in metrics.values())/len(CLASSES))
    return reports


if __name__ == '__main__':
    main()
