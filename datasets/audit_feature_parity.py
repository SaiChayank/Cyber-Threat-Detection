"""Read-only frozen-GNB feature diagnosis; training seeds only, never fit/evaluate.

Historical definitions are loaded from the pinned local Git commit. Git/network
fetches, reserved data, training entry points and model/report replacement are not
used. Prediction comparisons below are sensitivity diagnostics, not accuracy.
"""
import argparse
import hashlib
import json
import math
import subprocess
from pathlib import Path

from detection.pipeline import Pipeline
from features.extractor import FeatureExtractor, FEATURES
from ml.model import ARTIFACT, Model, vector
from ml.train import examples
from replay.scenarios import CLASSES, scenario
from schemas.traffic_event import TrafficEvent

ROOT = Path(__file__).resolve().parents[1]
BASELINE = '8c1b7cc70d3318a28f107fa2ca9f292e95e9a583'
TOLERANCE = 1e-10  # Floating arithmetic tolerance, not a detection/quality gate.


def blob(name):
    return subprocess.check_output(['git', '--no-optional-locks', 'show', f'{BASELINE}:{name}'], cwd=ROOT)


def historical_definitions():
    artifact = blob('ml/artifact.json')
    if hashlib.sha256(artifact).hexdigest() != hashlib.sha256(ARTIFACT.read_bytes()).hexdigest():
        raise ValueError('Frozen artifact differs from the pinned historical reference')
    definitions = []
    hashes = {}
    for name in ('features/extractor.py', 'replay/scenarios.py'):
        source = blob(name)
        hashes[name] = hashlib.sha256(source).hexdigest()
        namespace = {'__name__': 'historical_feature_diagnostic'}
        exec(compile(source, f'{BASELINE}:{name}', 'exec'), namespace)
        definitions.append(namespace)
    assert definitions[0]['FEATURES'] == FEATURES
    return definitions[0]['FeatureExtractor'], definitions[1]['scenario'], hashes


def changes(before, after):
    return {name: dict(before=before[name], after=after[name], delta=after[name] - before[name])
            for name in FEATURES
            if not math.isclose(before[name], after[name], rel_tol=TOLERANCE, abs_tol=TOLERANCE)}


def probe_events():
    def event(offset=0, **updates):
        return TrafficEvent(**(dict(timestamp=1700000000000 + offset,
                                   src_ip='192.0.2.1', dst_ip='198.51.100.1',
                                   protocol=17, bytes=100) | updates))
    return {
        'bucket_boundary': [event(900, packets=100), event(10901, src_ip='192.0.2.2')],
        'bounded_global_history': [event(i, bytes=60) for i in range(4097)],
        'reverse_unavailable': [event()],
        'reverse_observed_zero': [event(reverse_observed=True, reverse_bytes=0)],
        'reverse_observed_positive': [event(reverse_observed=True, reverse_bytes=25)],
    }


def run_probes(old_class):
    report = {}
    for name, events in probe_events().items():
        old, current = old_class(), FeatureExtractor()
        for event in events:
            before, after = old.update(event), current.update(event)
        report[name] = dict(events=len(events), changes=changes(before, after),
                            observed_ratio_before=before['observed_byte_ratio'],
                            observed_ratio_after=after['observed_byte_ratio'],
                            current_source_bytes_60s=after['source_forward_bytes_60s'],
                            current_ml_egress_bytes=after['egress_bytes'])
    # Same observed packets, two different metadata granularities. Both paths
    # use the current extractor; this is input shift, not training/serving code skew.
    streams = {
        'summaries': [TrafficEvent(timestamp=1700000000000, src_ip='192.0.2.1', dst_ip='198.51.100.1',
                                  protocol=17, packets=9, bytes=900),
                      TrafficEvent(timestamp=1700000000000, src_ip='192.0.2.2', dst_ip='198.51.100.1',
                                  protocol=17, bytes=100)],
        'packets': [TrafficEvent(timestamp=1700000000000, src_ip=f'192.0.2.{1 if i < 9 else 2}',
                                dst_ip='198.51.100.1', protocol=17, bytes=100) for i in range(10)],
    }
    observed = {}
    for name, events in streams.items():
        extractor = FeatureExtractor()
        for event in events:
            f = extractor.update(event)
        observed[name] = {k: f[k] for k in ('packet_rate', 'byte_rate', 'source_entropy')}
    report['packet_vs_summary'] = observed
    return report


def audit():
    old_class, old_scenario, historical_hashes = historical_definitions()
    model = Model()
    counts = {name: dict(changed_rows=0, max_absolute_delta=0.0) for name in FEATURES}
    rows = runtime_mismatches = changed_predictions = 0
    per_class = {label: dict(rows=0, historical_feature_changed_rows=0,
                            frozen_prediction_disagreement_rows=0) for label in CLASSES}
    for seed in range(1, 31):  # Already-used training inputs only.
        training_rows = iter(examples([seed]))
        for label in CLASSES:
            old, runtime = old_class(), Pipeline()
            captured = []
            original_predict = runtime.model.predict
            def capture(features):
                captured.append(features)
                return original_predict(features)
            runtime.model.predict = capture
            old_events = list(old_scenario(label, seed))
            new_events = list(scenario(label, seed))
            assert len(old_events) == len(new_events) == 32
            for before_event, event in zip(old_events, new_events):
                # The later explicit SYN count adds rule evidence, but the 20
                # model inputs otherwise observe the same generated metadata.
                assert before_event.model_dump(exclude={'syn_packets'}) == event.model_dump(exclude={'syn_packets'})
                truth, after = next(training_rows)
                assert truth == label
                before = old.update(before_event)
                runtime.process(event)
                assert captured
                runtime_mismatches += int(vector(captured.pop()) != vector(after))
                changed = changes(before, after)
                per_class[label]['historical_feature_changed_rows'] += bool(changed)
                for name, delta in changed.items():
                    counts[name]['changed_rows'] += 1
                    counts[name]['max_absolute_delta'] = max(counts[name]['max_absolute_delta'], abs(delta['delta']))
                disagreement = model.predict(before)[0] != model.predict(after)[0]
                per_class[label]['frozen_prediction_disagreement_rows'] += disagreement
                changed_predictions += disagreement
                rows += 1
                per_class[label]['rows'] += 1
    return dict(scope='Read-only feature parity/sensitivity on previously used training seeds and controlled probes; not accuracy or promotion',
                baseline_commit=BASELINE, historical_source_sha256=historical_hashes,
                model_sha256=hashlib.sha256(ARTIFACT.read_bytes()).hexdigest(),
                features=FEATURES, transform='log1p(max(0, value)) in the same fixed order',
                feature_semantic_version_in_artifact=False,
                input_policy=dict(training_seeds=[1, 30], rows=rows, validation_seeds_used=False,
                                  test_seeds_used=False, reserved_domain_or_dns_data_used=False,
                                  fit_called=False, thresholds_changed=False),
                current_training_runtime_vector_mismatches=runtime_mismatches,
                historical_vs_current_features=counts, per_class=per_class,
                historical_vs_current_prediction_disagreements=changed_predictions,
                controlled_probes=run_probes(old_class),
                source_sha256={name: hashlib.sha256((ROOT/name).read_bytes().replace(b'\r\n', b'\n')).hexdigest()
                               for name in ('ml/train.py', 'ml/model.py', 'features/extractor.py',
                                            'features/rate_window.py', 'detection/pipeline.py',
                                            'replay/scenarios.py', 'ingest/metadata.py',
                                            'datasets/audit_feature_parity.py')})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT/'docs/verification/feature-parity-20261003/report.json')
    args = parser.parse_args()
    report = audit()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({key: report[key] for key in ('input_policy', 'current_training_runtime_vector_mismatches',
                                                  'historical_vs_current_prediction_disagreements', 'controlled_probes')}, indent=2))


if __name__ == '__main__':
    main()
