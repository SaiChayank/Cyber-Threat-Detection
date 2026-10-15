"""Training/validation-only DGA rule comparison; no fit, export, or promotion.

The fitted candidate is evaluated offline through its disabled private scorer.
No previously inspected comparison or reserved evaluation outcome is scored.
"""
import argparse
import hashlib
import json
import platform
import statistics
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from datasets.download import ROOT
from datasets.train_dga_v2 import GATE, evaluate, load_data, passes
from detection.dga_rules import conservative_rule, validation_rule
from features.extractor import COMMON_BIGRAMS, dga_lexical_features, entropy
from ml.dga import ARTIFACT, DgaModel, NUMERIC_FEATURES


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def old_lexical_features(label):
    """Exact four-feature computation used by the old runtime rule path."""
    pairs = [label[i:i + 2] for i in range(max(0, len(label) - 1))]
    return (entropy(label), len(label), sum(c.isdigit() for c in label) / max(1, len(label)),
            sum(pair not in COMMON_BIGRAMS for pair in pairs) / max(1, len(pairs)))


def benchmark(labels, operation, repeats=5):
    for label in labels:  # Warm both code and input paths before timing.
        operation(label)
    elapsed = []
    for _ in range(repeats):
        started = time.perf_counter_ns()
        for label in labels:
            operation(label)
        elapsed.append((time.perf_counter_ns() - started) / len(labels))
    median_ns = statistics.median(elapsed)
    return dict(samples=len(labels), repeats=repeats, median_ns_per_label=median_ns,
                labels_per_second=1e9 / median_ns)


def compare_rules(rows):
    features = [dga_lexical_features(label) for label, _, _ in rows]
    return {
        'old_rule': evaluate(rows, [float(conservative_rule(f)) for f in features], .5),
        'validation_rule': evaluate(rows, [float(validation_rule(f)) for f in features], .5),
    }


def rule_length_breakdown(rows):
    counts = Counter()
    for label, actual, _ in rows:
        f = dga_lexical_features(label)
        for name, rule in (('old_rule', conservative_rule), ('validation_rule', validation_rule)):
            if rule(f):
                counts[f'{name}:positive' if actual else f'{name}:benign',
                       'short_under_16' if len(label) < 16 else 'long_16_plus'] += 1
    return {f'{name}:{length}': value for (name, length), value in sorted(counts.items())}


def main(output=None):
    path = Path(output) if output is not None else ROOT / 'ml/dga_rule_validation.json'
    if path.exists():
        raise FileExistsError('Preserve existing DGA evidence; choose a new --output path')
    protocol = ROOT / 'data/dga_evaluation_protocol.json'
    if sha(protocol) != (ROOT / 'data/dga_evaluation_protocol.sha256').read_text().strip():
        raise ValueError('Frozen DGA evaluation protocol changed')
    review_path = ROOT / 'data/dga_evaluation_design_review.json'
    if sha(review_path) != review_path.with_suffix('.sha256').read_text().strip():
        raise ValueError('Frozen DGA exposure review changed')
    review = json.loads(review_path.read_text())
    model_hash = sha(ARTIFACT)
    model = DgaModel()
    if model.enabled:
        raise ValueError('This comparison requires the unchanged disabled candidate')
    rows, provenance, _ = load_data()
    for split in ('train', 'validation'):
        digest = hashlib.sha256(json.dumps(sorted(rows[split]), ensure_ascii=True,
            separators=(',', ':')).encode()).hexdigest()
        if digest != review['development_partitions'][split]['selected_rows_sha256']:
            raise ValueError('Frozen DGA development partition changed')
    train = compare_rules(rows['train'])
    validation = compare_rules(rows['validation'])
    # The public candidate is disabled; this is only an offline development score.
    train_scores = [model._uncached_score(label) for label, _, _ in rows['train']]
    train['current_candidate_features'] = evaluate(rows['train'], train_scores, model.threshold)
    scores = [model._uncached_score(label) for label, _, _ in rows['validation']]
    validation['current_candidate_features'] = evaluate(rows['validation'], scores, model.threshold)
    if any(value['tp'] + value['fn'] != provenance['split_counts']['validation']['DGA']
           for value in validation.values()):
        raise ValueError('Validation positive denominator changed')
    if sha(ARTIFACT) != model_hash:
        raise ValueError('Frozen candidate changed during comparison')
    saved = json.loads((ROOT / 'ml/dga_v2_evaluation.json').read_text())
    for key in ('tp', 'fn', 'fp', 'tn'):
        if validation['current_candidate_features'][key] != saved['validation'][key]:
            raise ValueError('Current candidate no longer matches frozen validation counts')

    benign = [label for label, y, _ in rows['validation'] if not y][:2500]
    positive = [label for label, y, _ in rows['validation'] if y][:2500]
    sample = [label for pair in zip(benign, positive) for label in pair]
    for label in sample:
        f = dga_lexical_features(label)
        if old_lexical_features(label) != (f['domain_entropy'], f['domain_label_length'],
                                           f['domain_digit_ratio'], f['bigram_surprise']):
            raise ValueError('The old DGA feature values changed')
    timings = dict(old_lexical_four_fields=benchmark(sample, old_lexical_features),
                   shared_lexical_six_fields=benchmark(sample, dga_lexical_features),
                   old_rule_with_features=benchmark(sample, lambda s: conservative_rule(dga_lexical_features(s))),
                   validation_rule_with_features=benchmark(sample, lambda s: validation_rule(dga_lexical_features(s))),
                   candidate_uncached_inference=benchmark(sample, model._uncached_score))
    report = dict(scope='Existing training and validation partitions only; no final evaluation',
                  measured_at_utc=datetime.now(timezone.utc).isoformat(),
                  protocol_sha256=sha(protocol), candidate_sha256=model_hash,
                  exposure_review_sha256=sha(review_path),
                  comparison_source_sha256=sha(Path(__file__)),
                  source_manifest_sha256=provenance['manifest_sha256'],
                  fixed_gates=GATE, candidate_threshold=model.threshold,
                  candidate_enabled=model.enabled, candidate_numeric_features=NUMERIC_FEATURES,
                  candidate_ngram_features='first-label character bigrams and trigrams',
                  development_train=train, development_validation=validation,
                  validation_rule_length_breakdown=rule_length_breakdown(rows['validation']),
                  validation_gate={name: passes(result) for name, result in validation.items()},
                  validation_selection='Current candidate features pass the validation-only gate and have the highest recall; experimental rule is the stronger rule-only fallback but misses the recall gate; neither is activated or promoted',
                  runtime_cost=dict(scope='DGA lexical features/rules and uncached candidate inference on 5000 preselected validation labels; not packet parsing/API/SSE/browser or full pipeline',
                                    python=platform.python_version(), processor=platform.processor(), **timings),
                  caveats=['The comparison-family and DNS-reference gate failures are unchanged and were not rescored',
                           'Separate benign-DNS FPR and reserved final metrics are not measured; this is not the four-gate promotion decision',
                           'The current candidate remains disabled despite its validation metrics',
                           'Candidate training scores are in-sample diagnostics, never generalization evidence',
                           'The new rule is validation-only; the existing conservative rule remains active',
                           'Microbenchmark is environment-specific and excludes capture and end-to-end stages'])
    # Exclusive creation also protects frozen evidence if another process writes
    # the selected destination while this comparison is running.
    with path.open('x', encoding='utf-8') as target:
        target.write(json.dumps(report, indent=2))
    print(json.dumps({name: {key: result[key] for key in ('tp', 'fn', 'fp', 'tn', 'recall', 'precision', 'false_positive_rate')}
                      for name, result in validation.items()}, indent=2), flush=True)
    print('Saved ' + str(path), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='New report path; existing reports are never overwritten')
    main(parser.parse_args().output)
