"""Read-only diagnosis of the existing disabled DGA candidate, never fitting it.

Run python -m datasets.diagnose_dga. Only already-inspected local reference sets
are read. Writes one diagnostic report; models, thresholds and inputs are untouched.
"""
import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from statistics import mean, median

from datasets.domains import domains
from datasets.download import ROOT
from datasets.train_dga_v2 import GATE, load_data, evaluate, family_split
from datasets.train_dga import split as legacy_split
from features.extractor import COMMON_BIGRAMS
from ingest.pcap_reader import PcapReader
from ml.dga import DgaModel, NUMERIC_FEATURES, domain_label, lexical_features

FEATURE_BINS = {
    'length': [8, 12, 16, 20, 32],
    'entropy': [2, 3, 3.5, 4],
    'digit_ratio': [.000000001, .25, .5, 1],
    'bigram_surprise': [.5, .8],
    'vowel_ratio': [.2, .4, .6],
}


def shape(label):
    """Exclusive syntactic groups, not malware/source-role labels."""
    if label.isdigit():
        return 'digits_only'
    if '-' in label:
        return 'hyphenated'
    if len(label) >= 8 and any(c.isdigit() for c in label) and all(c in '0123456789abcdef' for c in label):
        return 'hexadecimal_shaped'
    if any(c.isdigit() for c in label):
        return 'mixed_alphanumeric'
    return 'letters_only_short' if len(label) < 12 else 'letters_only_long'


def features(label):
    bigrams = [label[i:i + 2] for i in range(len(label) - 1)]
    return lexical_features(label) | dict(length=len(label),
        bigram_surprise=sum(t not in COMMON_BIGRAMS for t in bigrams) / max(1, len(bigrams)))


def guard_failures(f):
    return [key for key, passed in [('length', f['length'] >= 20),
                                   ('entropy', f['entropy'] >= 3.5),
                                   ('bigram_surprise', f['bigram_surprise'] >= .8)] if not passed]


def interval(value, boundaries):
    for i, upper in enumerate(boundaries):
        if value < upper:
            return f'[{boundaries[i - 1] if i else 0}, {upper})'
    return f'[{boundaries[-1]}, +inf)'


def profile(records):
    if not records:
        return dict(count=0, means={}, score_median=None, length_median=None)
    return dict(count=len(records), means={k: mean(row['features'][k] for row in records)
                                           for k in records[0]['features']},
                score_median=median(row['score'] for row in records),
                length_median=median(row['features']['length'] for row in records))


def summarize(rows, scores, threshold):
    if len(rows) != len(scores):
        raise ValueError('Every diagnostic row must have a score')
    groups, patterns, bins, guard = defaultdict(list), defaultdict(Counter), defaultdict(lambda: defaultdict(Counter)), Counter()
    for (label, actual, family), score in zip(rows, scores):
        predicted = score >= threshold
        outcome = 'tp' if actual and predicted else 'fn' if actual else 'fp' if predicted else 'tn'
        f = features(label)
        row = dict(label=label, score=score, features=f, family=family)
        groups[outcome].append(row)
        patterns[shape(label)][outcome] += 1
        for name, boundaries in FEATURE_BINS.items():
            bins[name][interval(f[name], boundaries)][outcome] += 1
        if actual:
            guard['+'.join(guard_failures(f)) or 'passes'] += 1
    errors = {}
    for outcome in ('fp', 'fn'):
        # Example selection is deterministic and shows both extremes, not only
        # convenient errors. It never selects or changes a decision threshold.
        ordered = sorted(groups[outcome], key=lambda row: (row['score'], row['label']))
        errors[outcome] = ordered[:5] + ordered[-5:] if len(ordered) > 10 else ordered
    fn_by_family = {}
    for family in sorted({family for _, actual, family in rows if actual}):
        missed = [row for row in groups['fn'] if row['family'] == family]
        detected = [row for row in groups['tp'] if row['family'] == family]
        fn_by_family[family] = dict(missed=profile(missed), detected=profile(detected),
                                    examples=sorted(missed, key=lambda row: (row['score'], row['label']))[:3])
    return dict(metrics=evaluate(rows, scores, threshold), patterns={k: dict(v) for k, v in sorted(patterns.items())},
                feature_bins={name: {bin_name: dict(c) for bin_name, c in sorted(values.items())}
                              for name, values in bins.items()},
                outcome_profiles={key: profile(groups[key]) for key in ('tp', 'fn', 'fp', 'tn')},
                guard_failures_on_positives=dict(guard), false_negatives=fn_by_family,
                error_examples=errors)


def overlap(left, right):
    common = sorted(set(left) & set(right))
    return dict(count=len(common), examples=common[:10])


def partitions(rows, captures):
    labels = {split: {label for label, _, _ in values} for split, values in rows.items()}
    groups = {split: {family.split('_')[0] for _, y, family in values if y} for split, values in rows.items()}
    dns = captures['benign-benign_2'] - labels['train'] - captures['benign-benign_1']
    return dict(exact_label_overlap={f'{a}_{b}': overlap(labels[a], labels[b])
                                     for a, b in [('train', 'validation'), ('train', 'test'), ('validation', 'test')]},
                family_group_overlap={f'{a}_{b}': overlap(groups[a], groups[b])
                                      for a, b in [('train', 'validation'), ('train', 'test'), ('validation', 'test')]},
                second_dns_overlap={split: overlap(dns, values) for split, values in labels.items()},
                second_dns_overlap_positive={split: overlap(dns, {label for label, y, _ in values if y})
                                              for split, values in rows.items()},
                first_second_capture_overlap=overlap(captures['benign-benign_1'], captures['benign-benign_2']),
                second_dns_total=len(dns))


def dns_overlap_breakdown(rows, labels, scores, threshold):
    """Post-hoc dependence check, never a replacement promotion evaluation."""
    if len(labels) != len(scores):
        raise ValueError('Every DNS diagnostic label must have a score')
    validation = {label for label, _, _ in rows['validation']}
    test = {label for label, _, _ in rows['test']}
    groups = defaultdict(list)
    for label, score in zip(labels, scores):
        category = 'validation_overlap' if label in validation else 'comparison_overlap' if label in test else 'disjoint_from_domain_splits'
        groups[category].append((label, score))
    return {category: evaluate([(label, 0, 'dns') for label, _ in values],
                                [score for _, score in values], threshold)
            for category, values in sorted(groups.items())}


def legacy_partitions():
    families = {family: set(domains(ROOT / 'data/raw/umudga' / (family + '.txt')))
                for family in ('legit', 'banjori', 'corebot', 'dircrypt', 'matsnu', 'necurs', 'ramnit')}
    positive = set().union(*(families[family] for family in ('banjori', 'corebot', 'dircrypt')))
    train = positive | {name for name in families['legit'] if legacy_split(name) < 6}
    validation = (families['matsnu'] - positive) | {name for name in families['legit'] if legacy_split(name) in (6, 7) and name not in positive}
    test = ((families['necurs'] | families['ramnit']) - positive) | {name for name in families['legit'] if legacy_split(name) in (8, 9) and name not in positive}
    splits = dict(train=train, validation=validation, test=test)
    return dict(fqdn_overlap={f'{a}_{b}': overlap(splits[a], splits[b])
                              for a, b in [('train', 'validation'), ('train', 'test'), ('validation', 'test')]},
                scored_label_overlap={f'{a}_{b}': overlap({domain_label(name) for name in splits[a]},
                                                         {domain_label(name) for name in splits[b]})
                                      for a, b in [('train', 'validation'), ('train', 'test'), ('validation', 'test')]})


def verify_metrics(actual, saved):
    for key in ('tp', 'fn', 'fp', 'tn'):
        if actual[key] != saved[key]:
            raise ValueError(f'Diagnostic differs from frozen report: {key}')


def main():
    watched = [ROOT / name for name in ('ml/artifact.json', 'ml/artifact.sha256', 'ml/dga_v2.json',
                'ml/dga_v2.sha256', 'ml/public_dga.json', 'ml/public_dga.sha256',
                'ml/dga_v2_evaluation.json', 'data/umudga_expanded_manifest.json')]
    before = {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in watched}
    model = DgaModel()
    saved = json.loads((ROOT / 'ml/dga_v2_evaluation.json').read_text())
    if model.enabled or model.threshold != saved['threshold'] or model.data['gate'] != GATE or saved['gate'] != GATE:
        raise ValueError('Diagnostic requires the unchanged, disabled candidate and fixed gates')
    if before['ml/dga_v2.json'] != saved['model_sha256']:
        raise ValueError('Frozen candidate/report hash mismatch')
    rows, provenance, captures = load_data()  # Includes publisher/file integrity checks.
    print('Verified existing sources and rebuilt frozen partitions.', flush=True)
    results = {}
    for split in ('validation', 'test'):
        print('Scoring existing ' + split + ' labels; no fitting.', flush=True)
        scores = [model._uncached_score(label) for label, _, _ in rows[split]]
        results[split] = summarize(rows[split], scores, model.threshold)
        verify_metrics(results[split]['metrics'], saved[split])
    dns = sorted(captures['benign-benign_2'] - {label for label, _, _ in rows['train']} - captures['benign-benign_1'])
    dns_scores = [model._uncached_score(label) for label in dns]
    results['second_dns'] = summarize([(label, 0, 'dns_reference') for label in dns], dns_scores, model.threshold)
    saved_dns = saved['benign_dns_second_capture_unseen_labels']
    if (results['second_dns']['metrics']['fp'] != saved_dns['fp']
            or results['second_dns']['metrics']['fp'] + results['second_dns']['metrics']['tn'] != saved_dns['total']):
        raise ValueError('Second DNS counts differ from the frozen report')

    # Recover observed query-name/type context for false positives. It is evidence
    # for diagnosis, not a new predictor or invented flow metadata.
    all_dns_fp = {label for label, score in zip(dns, dns_scores) if score >= model.threshold}
    context, dns_pattern_context = {}, defaultdict(Counter)
    catalog = json.loads((ROOT / 'data/dns_capture_catalog.json').read_text())
    second = next(item for item in catalog if item['id'] == 'benign-benign_2')
    observed = defaultdict(lambda: dict(names=set(), types=set()))
    for batch in PcapReader().read_packets(ROOT / second['file']):
        for _, dns_record, _ in batch:
            if dns_record and (label := domain_label(dns_record.query_name)) in all_dns_fp:
                entry = observed[label]
                entry['names'].add(dns_record.query_name)
                entry['types'].add(dns_record.query_type)
    for label, entry in sorted(observed.items()):
        names = sorted(entry['names'])
        category = 'reverse_dns' if any(name.endswith(('.in-addr.arpa', '.ip6.arpa')) for name in names) else 'other_dns'
        dns_pattern_context[category][shape(label)] += 1
        context[label] = dict(names=names[:3], query_types=sorted(entry['types']))
    # Public original FQDN examples retain context without changing first-label scoring.
    public_examples = {row['label'] for split in ('validation', 'test')
                       for outcome in ('fp', 'fn') for row in results[split]['error_examples'][outcome]}
    original_names = defaultdict(set)
    manifest = json.loads((ROOT / 'data/umudga_expanded_manifest.json').read_text())
    source_audit, all_positive, legitimate = {}, set(), set()
    for item in manifest['files']:
        names = list(domains(ROOT / item['file']))
        labels = [domain_label(name) for name in names]
        valid = {label for label in labels if label}
        if item['family'] == 'legit':
            legitimate = valid
        else:
            all_positive.update(valid)
        source_audit[item['family']] = dict(parsed_names=len(names), valid_first_labels=len(valid),
                                          unsupported_names=sum(not label for label in labels),
                                          split='benign_hash' if item['family'] == 'legit' else family_split(item['family']))
        for name, label in zip(names, labels):
            if label in public_examples and len(original_names[label]) < 3:
                original_names[label].add(name)
    training = dict(counts=provenance['split_counts']['train'],
                    family_counts=dict(Counter(family for _, y, family in rows['train'] if y)),
                    benign_patterns=dict(Counter(shape(label) for label, y, _ in rows['train'] if not y)),
                    positive_patterns=dict(Counter(shape(label) for label, y, _ in rows['train'] if y)))
    split_features = ['linear_logit', *NUMERIC_FEATURES]
    tree_splits = Counter(split_features[node[2]] for tree in model.data['trees'] for node in tree if node[0] != -1)
    after = {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in watched}
    if before != after:
        raise ValueError('A frozen input changed during diagnosis')
    report = dict(generated_at_utc=datetime.now(timezone.utc).isoformat(), scope='Diagnostic of existing inspected data; not a new final evaluation',
                  fixed_gate=GATE, fixed_threshold=model.threshold, candidate_enabled=model.enabled,
                  frozen_hashes_before=before, frozen_hashes_after=after,
                  source_sha256={name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                                 for name in ('datasets/diagnose_dga.py', 'datasets/train_dga_v2.py',
                                              'ml/dga.py', 'features/extractor.py', 'detection/pipeline.py')},
                  provenance=provenance, errors=results, partition_audit=partitions(rows, captures),
                  dns_overlap_diagnostic=dns_overlap_breakdown(rows, dns, dns_scores, model.threshold),
                  legacy_partition_audit=legacy_partitions(),
                  raw_conflicting_labels=sorted(all_positive & (legitimate | captures['benign-benign_1'])),
                  second_dns_raw_positive_overlap=overlap(dns, all_positive),
                  training_distribution=training, source_normalization=source_audit,
                  tree_split_counts=dict(tree_splits),
                  standardized_linear_coefficients={name: values[0] for name, values in model.data['numeric_weights'].items()},
                  dns_false_positive_context=context,
                  dns_false_positive_context_counts={k: dict(v) for k, v in dns_pattern_context.items()},
                  selected_public_names={label: sorted(names) for label, names in sorted(original_names.items())},
                  caveats=['Labels are publisher/reference assertions, not current network attack truth',
                           'Shape groups describe syntax; names do not establish service roles or maliciousness',
                           'Feature profiles and split counts are associations, not causal feature importance',
                           'Comparison test was inspected during earlier iterations; it is not untouched',
                           'DNS overlap strata are post-hoc diagnostics; they do not replace the original FPR gate',
                           'No training, threshold sweep, artifact replacement, activation or runtime changes performed'])
    path = ROOT / 'ml/dga_diagnostic.json'
    path.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print('Saved ' + str(path), flush=True)


if __name__ == '__main__':
    main()
