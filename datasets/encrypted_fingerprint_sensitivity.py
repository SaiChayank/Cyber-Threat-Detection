"""Offline single-feature GNB sensitivity on 18 previously evaluated cases.

Observed predictions alone return to the real Pipeline. Counterfactual inputs
never become traffic events, rule evidence, alerts, a candidate or a new artifact.
"""
import argparse
import hashlib
import json
from pathlib import Path

from datasets.analyze_baseline_failures import generator_matches_report, stream_digest
from datasets.check_feature_contract import CONTRACT, ROOT, load_contract, text_hash
from datasets.validate_encrypted import CASES, events
from detection.pipeline import Pipeline
from features.extractor import FEATURES
from ml.model import ARTIFACT

TARGET = 'ENCRYPTED_MALWARE'
THRESHOLD = .8
REPORT = ROOT/'docs/verification/release-audit/encrypted_session_validation.json'


def paired_predictions(predict, features):
    observed = {name: features[name] for name in FEATURES}
    if observed['fingerprint_risk'] not in (0, 1):
        raise ValueError('Expected the frozen binary fingerprint-risk definition')
    counterfactual = observed | {'fingerprint_risk': 0.0}
    changed = [name for name in FEATURES if observed[name] != counterfactual[name]]
    before, after = predict(observed), predict(counterfactual)
    if not changed and before != after:
        raise ValueError('Negative-control predictions differ for identical model inputs')
    return observed, counterfactual, before, after


def prediction(label, posterior):
    return dict(top_label=label, top_posterior=posterior,
                target_hit=label == TARGET and posterior >= THRESHOLD)


def model_verdict(positive, first, total):
    if positive:
        return 'TP' if first is not None and first['event'] < total else 'FN'
    return 'FP' if first is not None else 'TN'


def metrics(rows, mode):
    counts = {key: sum(row[mode]['verdict'] == key for row in rows) for key in ('TP', 'TN', 'FP', 'FN')}
    tp, tn, fp, fn = (counts[key] for key in ('TP', 'TN', 'FP', 'FN'))
    return counts | dict(precision=tp/(tp+fp) if tp+fp else 0.0,
                         recall=tp/(tp+fn) if tp+fn else 0.0,
                         f1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else 0.0,
                         false_positive_rate=fp/(fp+tn) if fp+tn else 0.0)


def scenario(case, index, saved):
    stream = list(events(case, index))
    if (stream_digest(stream) != saved['stream_sha256'] or len(stream) != saved['events'] or
            case[1] != saved['ground_truth_malicious_like']):
        raise ValueError('Changed previously evaluated scenario/label')
    runtime = Pipeline()
    original = runtime.model.predict
    comparisons = []
    first_alert = None

    def observe(features):
        actual, hypothetical, before, after = paired_predictions(original, features)
        comparisons.append(dict(observed_features=actual,
                                counterfactual_fingerprint_risk=hypothetical['fingerprint_risk'],
                                changed_features=[name for name in FEATURES if actual[name] != hypothetical[name]],
                                observed=prediction(*before), counterfactual=prediction(*after),
                                observed_rule_hit=bool(features['encrypted'] and features['fingerprint_risk'])))
        return before  # The counterfactual result must NEVER drive runtime alerts.

    runtime.model.predict = observe
    for position, event in enumerate(stream, start=1):
        alerts = runtime.process(event)
        comparison = comparisons[-1]
        comparison.update(event=position, timestamp=event.timestamp,
                          elapsed_seconds=(event.timestamp-stream[0].timestamp)/1000)
        for alert in alerts:
            if alert.threat_class == TARGET and first_alert is None:
                first_alert = dict(event=position, elapsed_seconds=comparison['elapsed_seconds'],
                                   detection_source=alert.detection_source,
                                   evidence=alert.raw_evidence_metrics)
    expected = saved['first_alert']
    if (first_alert is None) != (expected is None):
        raise ValueError('Original runtime alert behavior changed')
    if expected and any(first_alert[key] != expected[key] for key in first_alert):
        raise ValueError('Original runtime first-alert evidence/timing changed')
    modes = {}
    for mode in ('observed', 'counterfactual'):
        hits = [item for item in comparisons if item[mode]['target_hit']]
        first = {key:hits[0][key] for key in ('event','elapsed_seconds')} if hits else None
        modes[mode] = dict(hit_events=len(hits), first_model_hit=first,
                           verdict=model_verdict(case[1], first, len(stream)))
    rule_hits = sum(item['observed_rule_hit'] for item in comparisons)
    if modes['observed']['hit_events'] != saved['model_hit_events'] or rule_hits != saved['rule_hit_events']:
        raise ValueError('Original model/rule event counts changed')
    original_verdict = model_verdict(case[1], first_alert, len(stream))
    if original_verdict != saved['verdict']:
        raise ValueError('Original hybrid verdict changed')
    return dict(scenario=case[0], positive=case[1], stream_sha256=saved['stream_sha256'],
                transport=case[3], observed_initial_ja3=case[4], events=len(stream),
                **modes, observed_runtime_first_alert=first_alert,
                observed_runtime_verdict=original_verdict, unchanged_rule_hit_events=rule_hits,
                changed_input_events=sum(bool(item['changed_features']) for item in comparisons),
                changed_top_label_events=sum(item['observed']['top_label'] != item['counterfactual']['top_label']
                                            for item in comparisons),
                comparisons=comparisons)


def run():
    contract = load_contract(CONTRACT)
    digest = hashlib.sha256(ARTIFACT.read_bytes()).hexdigest()
    if digest != contract['model_sha256']:
        raise ValueError('Frozen model changed')
    if any(text_hash(ROOT/name) != expected for name, expected in contract['current_source_sha256'].items()):
        raise ValueError('Current semantic source pins changed')
    raw = REPORT.read_bytes()
    reference = json.loads(raw)
    if reference['source_sha256']['ml/artifact.json'] != digest:
        raise ValueError('Reference report model changed')
    generator = ROOT/'datasets/validate_encrypted.py'
    if not generator_matches_report(generator.read_bytes(), reference['source_sha256']['datasets/validate_encrypted.py']):
        raise ValueError('Previously evaluated generator changed')
    saved = reference['rows']
    if len(CASES) != 18 or [case[0] for case in CASES] != [row['scenario'] for row in saved]:
        raise ValueError('Frozen 18-scenario inventory/order changed')
    rows = [scenario(case, index, saved[index]) for index, case in enumerate(CASES)]
    changed = sum(row['changed_input_events'] for row in rows)
    if changed != 80 or sum(row['events'] for row in rows) != 360:
        raise ValueError('Predeclared input/control counts changed')
    return dict(scope='Single-feature counterfactual GNB sensitivity on seen controlled metadata; not candidate or field accuracy',
                model_sha256=digest, feature_contract_sha256=text_hash(CONTRACT),
                reference_report_sha256=hashlib.sha256(raw).hexdigest(),
                top_posterior_cutoff=THRESHOLD, observed_model_only=metrics(rows,'observed'),
                counterfactual_model_only=metrics(rows,'counterfactual'),
                unchanged_observed_hybrid_counts=reference['counts'],
                changed_input_events=changed, unchanged_input_events=360-changed,
                changed_top_label_events=sum(row['changed_top_label_events'] for row in rows),
                counterfactual_alerts_emitted=0, rows=rows,
                policy=dict(fit=False,tuning=False,rule_changes=False,runtime_changes=False,
                            artifact_changes=False,reserved_data=False,promotion=False),
                source_sha256={name:text_hash(ROOT/name) for name in
                               ('datasets/encrypted_fingerprint_sensitivity.py','datasets/validate_encrypted.py',
                                'ml/model.py','detection/pipeline.py','features/extractor.py')})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = run()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as file:
        json.dump(report,file,indent=2,allow_nan=False)
        file.write('\n')
    print(json.dumps({key:report[key] for key in ('observed_model_only','counterfactual_model_only',
                                               'changed_input_events','unchanged_input_events',
                                               'changed_top_label_events')},indent=2))


if __name__ == '__main__':
    main()
