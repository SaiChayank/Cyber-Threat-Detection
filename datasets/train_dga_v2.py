"""Offline family-grouped lexical encoding and boosted trees; export safe JSON.

Run python -m datasets.train_dga_v2. Optional dependency: scikit-learn.
No packet timings, source addresses, suffixes or family names enter the model.
"""
import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone

from datasets.domains import domains
from datasets.download import ROOT
from datasets.validate_streaming import metrics
from ingest.pcap_reader import PcapReader
from ml.dga import ARTIFACT, FEATURE_VERSION, NUMERIC_FEATURES, DgaModel, domain_label, tokens, lexical_features

KNOWN_GROUPS = {'banjori', 'corebot', 'dircrypt', 'matsnu', 'necurs', 'ramnit'}
GATE = dict(min_recall=.8, min_precision=.95, max_false_positive_rate=.02)
THRESHOLDS = [.5, .6, .7, .8, .85, .9, .95, .975, .99]


def bucket(value, namespace, modulus):
    return int(hashlib.sha256((namespace + value).encode()).hexdigest()[:8], 16) % modulus


def family_split(family):
    group = family.split('_')[0]
    n = bucket(group, 'univect-dga-v2:', 5)
    return 'train' if group in KNOWN_GROUPS or n < 3 else 'validation' if n == 3 else 'test'


def benign_split(label, previous):
    n = bucket(label, 'univect-benign-v2:', 10)
    return 'train' if label in previous or n < 6 else 'validation' if n < 8 else 'test'


def capture_labels(path):
    return {label for batch in PcapReader().read_packets(path) for _, dns, _ in batch
            if dns and (label := domain_label(dns.query_name))}


def load_data():
    manifest_path = ROOT / 'data/umudga_expanded_manifest.json'
    manifest = json.loads(manifest_path.read_text())
    families = {}
    for file in manifest['files']:
        path = ROOT / file['file']
        if hashlib.sha256(path.read_bytes()).hexdigest() != file['sha256']:
            raise ValueError(f"Domain source integrity mismatch: {file['family']}")
        families[file['family']] = {label for d in domains(path) if (label := domain_label(d))}
    # First-label grouping also excludes duplicate feature vectors across splits.
    positive_groups = defaultdict(set)
    for family, labels in families.items():
        if family != 'legit':
            for label in labels:
                positive_groups[label].add(family_split(family))
    previous = {domain_label(d) for d in domains(ROOT / 'data/raw/umudga/legit.txt')}
    catalog = json.loads((ROOT / 'data/dns_capture_catalog.json').read_text())
    captures = {}
    for item in catalog:
        if item['category'] != 'benign':
            continue
        path = ROOT / item['file']
        if hashlib.sha256(path.read_bytes()).hexdigest() != item['sha256']:
            raise ValueError('Benign DNS source integrity mismatch')
        captures[item['id']] = capture_labels(path)
    hard_negatives = captures['benign-benign_1']
    benign_labels = families['legit'] | hard_negatives
    conflicts = set(positive_groups) & benign_labels
    crossing = {d for d, splits in positive_groups.items() if len(splits) > 1}
    excluded = conflicts | crossing
    rows = {'train': [], 'validation': [], 'test': []}
    for label in sorted(benign_labels - conflicts):
        split = 'train' if label in hard_negatives else benign_split(label, previous)
        rows[split].append((label, 0, 'legit'))
    for family, labels in sorted(families.items()):
        if family == 'legit':
            continue
        split = family_split(family)
        ordered = sorted(labels - excluded, key=lambda d: hashlib.sha256(d.encode()).hexdigest())
        # Keep training bounded and balanced across variants, use full held-out lists.
        selected = ordered[:2000] if split == 'train' else ordered
        rows[split].extend((d, 1, family) for d in selected)
    # Remove within-split positive duplicates while retaining one reporting family.
    for split, values in rows.items():
        rows[split] = list({d: (d, y, family) for d, y, family in values}.values())
    label_sets = {s: {d for d, _, _ in rs} for s, rs in rows.items()}
    assert not (label_sets['train'] & label_sets['validation'] or label_sets['train'] & label_sets['test']
                or label_sets['validation'] & label_sets['test'])
    provenance = dict(manifest_sha256=hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
                      excluded_conflicting_labels=len(conflicts), excluded_cross_split_labels=len(crossing),
                      dns_hard_negative_labels=len(hard_negatives),
                      family_splits={s: sorted(f for f in families if f != 'legit' and family_split(f) == s)
                                     for s in rows},
                      split_counts={s: dict(Counter('DGA' if y else 'BENIGN' for _, y, _ in rs)) for s, rs in rows.items()})
    return rows, provenance, captures


def evaluate(rows, scores, threshold):
    counts, families = Counter(), defaultdict(Counter)
    for (domain, actual, family), score in zip(rows, scores):
        predicted = score >= threshold
        key = 'tp' if actual and predicted else 'fn' if actual else 'fp' if predicted else 'tn'
        counts[key] += 1
        families[family][key] += 1
    return dict(**metrics(counts), per_family={f: metrics(c) for f, c in sorted(families.items())})


def passes(result):
    return (result['recall'] is not None and result['recall'] >= GATE['min_recall']
            and result['precision'] is not None and result['precision'] >= GATE['min_precision']
            and result['false_positive_rate'] is not None
            and result['false_positive_rate'] <= GATE['max_false_positive_rate'])


def main():
    import numpy as np
    import sklearn
    from scipy.sparse import csr_matrix, hstack
    from sklearn.feature_extraction import DictVectorizer
    from sklearn.feature_extraction.text import TfidfTransformer
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler
    from sklearn.ensemble import GradientBoostingClassifier

    rows, provenance, captures = load_data()
    print('Splits:', provenance['split_counts'], flush=True)
    # All vocabulary, IDF and coefficient fitting uses training labels only.
    vectorizer = DictVectorizer()
    counts = vectorizer.fit_transform(tokens(d) for d, _, _ in rows['train'])
    tfidf = TfidfTransformer(sublinear_tf=True)
    x = tfidf.fit_transform(counts)
    scaler = StandardScaler()
    def numeric_labels(labels):
        return [[values[name] for name in NUMERIC_FEATURES] for values in map(lexical_features, labels)]
    def numeric(split):
        return numeric_labels(d for d, _, _ in rows[split])
    numeric_train = scaler.fit_transform(numeric('train'))
    x = hstack((x, csr_matrix(numeric_train)), format='csr')
    classifier = LogisticRegression(C=1.0, solver='liblinear', class_weight='balanced',
                                    max_iter=300, random_state=26145)
    classifier.fit(x, [y for _, y, _ in rows['train']])
    if classifier.n_iter_[0] >= 300:
        raise ValueError('DGA model did not converge')
    def base_scores(split):
        ngrams = tfidf.transform(vectorizer.transform(tokens(d) for d, _, _ in rows[split]))
        return classifier.decision_function(hstack((ngrams, csr_matrix(scaler.transform(numeric(split)))), format='csr'))
    # Fixed settings, no test-driven parameter sweep. Only training rows fit trees.
    boosted = GradientBoostingClassifier(n_estimators=100, learning_rate=.08,
                                        max_depth=3, min_samples_leaf=1000, random_state=26145)
    train_y = [y for _, y, _ in rows['train']]
    tree_train = np.column_stack((classifier.decision_function(x), numeric('train')))
    boosted.fit(tree_train, train_y)
    def scores(split):
        return boosted.predict_proba(np.column_stack((base_scores(split), numeric(split))))[:, 1]
    validation_scores = scores('validation')
    candidates = [(t, evaluate(rows['validation'], validation_scores, t)) for t in THRESHOLDS]
    eligible = [(t, r) for t, r in candidates if passes(r)]
    # Never select a threshold using the test results. A failed gate stays disabled.
    threshold, validation = max(eligible, key=lambda p: (p[1]['recall'], -p[1]['false_positive_rate'])) if eligible else candidates[-1]
    test_scores = scores('test')
    test = evaluate(rows['test'], test_scores, threshold)
    hard_negative_test = captures['benign-benign_2'] - {d for d, _, _ in rows['train']} - set(captures['benign-benign_1'])
    dns_labels = sorted(hard_negative_test)
    dns_ngrams = tfidf.transform(vectorizer.transform(tokens(d) for d in dns_labels)) if dns_labels else None
    dns_numeric = scaler.transform(numeric_labels(dns_labels)) if dns_labels else None
    dns_base = classifier.decision_function(hstack((dns_ngrams, csr_matrix(dns_numeric)), format='csr')) if dns_labels else []
    dns_scores = boosted.predict_proba(np.column_stack((dns_base, numeric_labels(dns_labels))))[:, 1] if dns_labels else []
    dns_fp = int(sum(s >= threshold for s in dns_scores))
    dns_fpr = dns_fp / len(dns_labels) if dns_labels else None
    features = vectorizer.get_feature_names_out()
    data = dict(kind='lexical TF-IDF/logistic encoding with 100 depth-three boosted trees',
                feature_version=FEATURE_VERSION, decision_threshold=threshold,
                runtime_enabled=bool(eligible and passes(test) and dns_fpr is not None and dns_fpr <= GATE['max_false_positive_rate']),
                intercept=float(classifier.intercept_[0]),
                weights={t: [float(w), float(idf)] for t, w, idf in
                         zip(features, classifier.coef_[0][:len(features)], tfidf.idf_)},
                numeric_weights={name: [float(w), float(mean), float(scale)] for name, w, mean, scale in
                                 zip(NUMERIC_FEATURES, classifier.coef_[0][len(features):], scaler.mean_, scaler.scale_)},
                learning_rate=float(boosted.learning_rate),
                boosted_intercept=float(np.log(boosted.init_.class_prior_[1] / boosted.init_.class_prior_[0])),
                trees=[[[int(tree.tree_.children_left[i]), int(tree.tree_.children_right[i]),
                         int(tree.tree_.feature[i]), float(tree.tree_.threshold[i]), float(tree.tree_.value[i, 0, 0])]
                        for i in range(tree.tree_.node_count)] for tree in boosted.estimators_[:, 0]],
                confidence_kind='public-domain lexical model score; uncalibrated',
                gate=GATE, training_source='UMUDGA v1 + benign DNS capture reference',
                training_provenance=provenance)
    raw = json.dumps(data, sort_keys=True, separators=(',', ':')).encode()
    ARTIFACT.write_bytes(raw)
    ARTIFACT.with_suffix('.sha256').write_text(hashlib.sha256(raw).hexdigest() + '\n')
    # Confirm exported standard-library inference reproduces sklearn scores.
    model = DgaModel()
    step = max(1, len(rows['test']) // 200)
    verification = []
    max_export_error = 0.0
    for (domain, _, _), expected in zip(rows['test'][::step], test_scores[::step]):
        error = abs(model._uncached_score(domain) - expected)
        max_export_error = max(max_export_error, float(error))
        if error >= 1e-10:
            raise ValueError('Exported DGA inference differs from fitted sklearn model')
        verification.append(dict(domain=domain + '.example', expected_score=float(expected)))
    fixture = ROOT / 'tests/fixtures/dga_export_vectors.json'
    fixture.parent.mkdir(parents=True, exist_ok=True)
    fixture.write_text(json.dumps(dict(model_sha256=hashlib.sha256(raw).hexdigest(),
                                      scope='Public first-label strings with synthetic .example suffix; reference scores from sklearn',
                                      cases=verification), indent=2), encoding='utf-8')
    guard_scores = [float(len(d) >= 20 and _guard(d)) for d, _, _ in rows['test']]
    report = dict(generated_at_utc=datetime.now(timezone.utc).isoformat(), model_sha256=hashlib.sha256(raw).hexdigest(),
                  gate=GATE, threshold=threshold, runtime_enabled=data['runtime_enabled'], development_iteration=3,
                  **provenance, validation=validation, test=test,
                  validation_thresholds=[dict(threshold=t, **r) for t, r in candidates],
                  export_verification=dict(samples=len(verification), max_absolute_error=max_export_error),
                  activation_failures=(['Domain comparison recall/precision/FPR gate failed'] if not passes(test) else [])
                                      + (['Validation quality gate failed'] if not eligible else [])
                                      + (['Second benign DNS reference exceeds FPR gate or has no unseen labels']
                                         if dns_fpr is None or dns_fpr > GATE['max_false_positive_rate'] else []),
                  conservative_guard_on_same_test=evaluate(rows['test'], guard_scores, .5),
                  benign_dns_second_capture_unseen_labels=dict(total=len(hard_negative_test), fp=int(dns_fp),
                                                               false_positive_rate=dns_fpr),
                  training_versions=dict(sklearn=sklearn.__version__, numpy=np.__version__),
                  caveats=['Previously inspected six DGA families and 1,000 legitimate references are kept in training',
                           'Related variants are grouped; exact first-label vectors cannot cross splits',
                           'Fresh file subsets, same historical publisher: not independent contemporary traffic',
                           'First DNS label only; suffix and public-suffix lookup are deliberately absent',
                           'Source list labels and benign capture reference are not per-flow attack truth',
                           'No unseen word-based family group appears in the selected test split',
                           'Test-family results were inspected during the first model iteration; subsequent comparisons are development validation, not untouched final tests',
                           'Scores are uncalibrated; precision depends on test class prevalence'])
    (ROOT / 'ml/dga_v2_evaluation.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({k: report[k] for k in ('threshold', 'runtime_enabled', 'validation', 'test',
                                          'benign_dns_second_capture_unseen_labels')}, indent=2), flush=True)


def _guard(label):
    from features.extractor import COMMON_BIGRAMS, entropy
    bigrams = [label[i:i + 2] for i in range(len(label) - 1)]
    return entropy(label) >= 3.5 and sum(t not in COMMON_BIGRAMS for t in bigrams) / max(1, len(bigrams)) >= .8


if __name__ == '__main__':
    main()
