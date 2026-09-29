"""Fit one preregistered DGA candidate on training and tune on validation only.

The candidate is exported separately and always disabled. No comparison/test or
reserved-evaluation scores are calculated. Run python -m datasets.train_dga_candidate.
"""
import hashlib
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from datasets.download import ROOT
from datasets.train_dga_v2 import GATE, THRESHOLDS, evaluate, load_data, passes
from ml.dga import DgaModel, FEATURE_VERSION, NUMERIC_FEATURES, lexical_features, tokens

PLAN = ROOT / 'data/dga_candidate_plan.json'
OUTPUT = ROOT / 'ml/dga_weighted_candidate.json'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def extra_weight(label, actual):
    """Fixed training-only shape adjustment; no family or source predictors."""
    return 3.0 if not actual and len(label) >= 12 and label.isalpha() else 1.0


def f1(result):
    tp, fp, fn = (result[key] for key in ('tp', 'fp', 'fn'))
    return 2 * tp / (2 * tp + fp + fn) if tp or fp or fn else None


def counts(result):
    return {key: result[key] for key in ('tp', 'tn', 'fp', 'fn', 'precision', 'recall', 'false_positive_rate')} | {'f1': f1(result)}


def with_families(result):
    return counts(result) | {'per_family_recall': {family: value['recall']
                                                   for family, value in result['per_family'].items()
                                                   if value['recall'] is not None}}


def main():
    import numpy as np
    from scipy.sparse import csr_matrix, hstack
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.feature_extraction import DictVectorizer
    from sklearn.feature_extraction.text import TfidfTransformer
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler

    plan_hash = sha(PLAN)
    if plan_hash != PLAN.with_suffix('.sha256').read_text().strip():
        raise ValueError('Frozen candidate plan changed')
    plan = json.loads(PLAN.read_text())
    if sha(ROOT / 'data/dga_evaluation_protocol.json') != plan['evaluation_protocol_sha256']:
        raise ValueError('Frozen evaluation design changed')
    watched = [ROOT / name for name in ('ml/artifact.json', 'ml/dga_v2.json', 'ml/dga_v2.sha256',
               'ml/dga_v2_evaluation.json', 'data/umudga_expanded_manifest.json',
               'data/dga_evaluation_protocol.json')]
    before = {path.relative_to(ROOT).as_posix(): sha(path) for path in watched}
    if before['ml/dga_v2.json'] != plan['existing_candidate_sha256']:
        raise ValueError('Frozen public candidate changed')
    if before['data/umudga_expanded_manifest.json'] != plan['training_source_manifest_sha256']:
        raise ValueError('Frozen DGA training source changed')
    rows, provenance, _ = load_data()
    train = rows['train']
    validation = rows['validation']
    if (provenance['split_counts']['train'] != {'BENIGN': 67715, 'DGA': 69993}
            or provenance['split_counts']['validation'] != {'BENIGN': 15236, 'DGA': 80000}):
        raise ValueError('Frozen training/validation partition counts changed')
    print('Fitting only frozen DGA training labels.', flush=True)
    labels = [label for label, _, _ in train]
    targets = np.asarray([actual for _, actual, _ in train])
    weights = np.asarray([extra_weight(label, actual) for label, actual, _ in train])
    numeric_train = np.asarray([[f[name] for name in NUMERIC_FEATURES]
                                for f in map(lexical_features, labels)])
    vectorizer = DictVectorizer()
    counts_matrix = vectorizer.fit_transform(tokens(label) for label in labels)
    tfidf = TfidfTransformer(sublinear_tf=True)
    encoded_train = tfidf.fit_transform(counts_matrix)
    scaler = StandardScaler()
    scaled_train = scaler.fit_transform(numeric_train)
    x_train = hstack((encoded_train, csr_matrix(scaled_train)), format='csr')
    base = LogisticRegression(C=1.0, solver='liblinear', class_weight='balanced',
                              max_iter=300, random_state=26145)
    base.fit(x_train, targets, sample_weight=weights)
    if base.n_iter_[0] >= 300:
        raise ValueError('DGA base classifier did not converge')
    trees = GradientBoostingClassifier(n_estimators=100, learning_rate=.08,
                                       max_depth=3, min_samples_leaf=1000, random_state=26145)
    trees.fit(np.column_stack((base.decision_function(x_train), numeric_train)),
              targets, sample_weight=weights)
    print('Scoring existing validation labels; no comparison or reserved scoring.', flush=True)
    validation_labels = [label for label, _, _ in validation]
    numeric_validation = np.asarray([[f[name] for name in NUMERIC_FEATURES]
                                     for f in map(lexical_features, validation_labels)])
    encoded_validation = tfidf.transform(vectorizer.transform(tokens(label) for label in validation_labels))
    scaled_validation = scaler.transform(numeric_validation)
    x_validation = hstack((encoded_validation, csr_matrix(scaled_validation)), format='csr')
    base_validation = base.decision_function(x_validation)
    scores = trees.predict_proba(np.column_stack((base_validation, numeric_validation)))[:, 1]
    grid = [(threshold, evaluate(validation, scores, threshold)) for threshold in THRESHOLDS]
    eligible = [(threshold, result) for threshold, result in grid if passes(result)]
    threshold, selected = max(eligible, key=lambda pair: (pair[1]['recall'], -pair[1]['false_positive_rate'])) if eligible else grid[-1]

    feature_names = vectorizer.get_feature_names_out()
    data = dict(kind='preregistered weighted lexical TF-IDF/logistic encoding with 100 depth-three boosted trees',
                feature_version=FEATURE_VERSION, decision_threshold=threshold,
                runtime_enabled=False, intercept=float(base.intercept_[0]),
                weights={token: [float(coefficient), float(idf)] for token, coefficient, idf
                         in zip(feature_names, base.coef_[0][:len(feature_names)], tfidf.idf_)},
                numeric_weights={name: [float(coefficient), float(center), float(scale)]
                                 for name, coefficient, center, scale in
                                 zip(NUMERIC_FEATURES, base.coef_[0][len(feature_names):], scaler.mean_, scaler.scale_)},
                learning_rate=float(trees.learning_rate),
                boosted_intercept=float(np.log(trees.init_.class_prior_[1] / trees.init_.class_prior_[0])),
                trees=[[[int(tree.tree_.children_left[i]), int(tree.tree_.children_right[i]),
                         int(tree.tree_.feature[i]), float(tree.tree_.threshold[i]), float(tree.tree_.value[i, 0, 0])]
                        for i in range(tree.tree_.node_count)] for tree in trees.estimators_[:, 0]],
                confidence_kind='public-domain lexical model score; uncalibrated',
                gate=GATE, training_source='UMUDGA v1 + benign DNS capture reference',
                training_provenance=provenance, candidate_plan_sha256=plan_hash)
    raw = json.dumps(data, sort_keys=True, separators=(',', ':')).encode()
    candidate_hash = hashlib.sha256(raw).hexdigest()
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir) / 'candidate.json'
        temp_path.write_bytes(raw)
        temp_path.with_suffix('.sha256').write_text(candidate_hash)
        portable = DgaModel(temp_path)
        if portable.enabled:
            raise ValueError('Provisional candidate must remain disabled')
        step = max(1, len(validation) // 200)
        errors = [abs(portable._uncached_score(label) - float(expected))
                  for label, expected in zip(validation_labels[::step], scores[::step])]
        maximum_export_error = max(errors)
        if maximum_export_error >= 1e-10:
            raise ValueError('Portable candidate differs from sklearn validation scores')

    if {path.relative_to(ROOT).as_posix(): sha(path) for path in watched} != before:
        raise ValueError('A frozen model or input changed during training')
    OUTPUT.write_bytes(raw)
    OUTPUT.with_suffix('.sha256').write_text(candidate_hash + '\n')
    baselines = json.loads((ROOT / 'ml/dga_rule_validation.json').read_text())
    if baselines['candidate_sha256'] != before['ml/dga_v2.json']:
        raise ValueError('Frozen baseline candidate/report mismatch')
    baseline = {name: with_families(baselines['development_validation'][name])
                for name in ('old_rule', 'validation_rule', 'current_candidate_features')}
    # With a disabled public DGA model, the production pipeline requires the
    # conservative guard even when the synthetic classifier predicts DGA.
    baseline['deployed_synthetic_dga_effective'] = baseline['old_rule']
    if (ROOT / 'data/dga_reserved_materialization.json').exists():
        raise ValueError('Reserved materialization appeared during development-only training; do not score it here')
    decision = 'blocked_missing_reserved_evaluation' if eligible else 'failed_validation_gate'
    report = dict(generated_at_utc=datetime.now(timezone.utc).isoformat(),
                  scope='One frozen training/validation experiment only; no reserved or inspected comparison scoring',
                  plan_sha256=plan_hash, evaluation_protocol_sha256=plan['evaluation_protocol_sha256'],
                  source_manifest_sha256=provenance['manifest_sha256'],
                  candidate_artifact=OUTPUT.relative_to(ROOT).as_posix(), candidate_sha256=candidate_hash,
                  candidate_bytes=len(raw), candidate_enabled=False, threshold=threshold,
                  validation=with_families(selected),
                  validation_thresholds=[dict(threshold=value, **counts(result)) for value, result in grid],
                  baselines=baseline, validation_gate_passed=bool(eligible),
                  separate_benign_dns_fpr=None, reserved_evaluation=None,
                  promotion_decision=decision,
                  reasons=(['No reserved DGA algorithm/domain/DNS materialization is present; all four final gates cannot be assessed']
                           if eligible else ['The training/validation candidate failed a predeclared gate']),
                  portable_export_verification=dict(samples=len(errors), maximum_absolute_error=maximum_export_error),
                  caveats=['Candidate artifact is disabled and is not the deployed DGA model',
                           'The synthetic deployed DGA alert path is the conservative lexical guard on these public strings',
                           'Source labels and validation prevalence are not production threat truth or production precision',
                           'No family name, filename, address, dataset ID or scenario ID is a predictive feature'])
    report_path = ROOT / 'ml/dga_weighted_candidate_validation.json'
    report_path.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(dict(threshold=threshold, validation=report['validation'],
                          promotion_decision=decision, candidate_sha256=candidate_hash), indent=2), flush=True)


if __name__ == '__main__':
    main()
