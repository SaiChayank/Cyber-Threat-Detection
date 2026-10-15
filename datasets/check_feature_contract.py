"""Offline frozen-GNB semantic preflight; never train, activate or change runtime.

Exit 0: current conformance AND historical compatibility pass.
Exit 1: current conformance passes, but known historical incompatibility remains.
Exit 2: unexpected drift, integrity failure or incomplete verification.
"""
import argparse
import hashlib
import json
import math
import subprocess
from pathlib import Path

from datasets.audit_feature_parity import (
    BASELINE, ROOT, TOLERANCE, blob, historical_definitions, run_probes,
)
from features.extractor import FEATURES, FeatureExtractor
from features.rate_window import RateWindow
from ml.model import ARTIFACT, vector
from schemas.traffic_event import TrafficEvent

CONTRACT = ROOT / 'data/feature_semantic_contract.json'


def text_hash(path):
    """Source/manifest text hashes normalize CRLF; model bytes never normalize."""
    return hashlib.sha256(path.read_bytes().replace(b'\r\n', b'\n')).hexdigest()


def differences(expected, actual, path=''):
    """Strict shape/null/bool checks with the frozen numerical tolerance."""
    if isinstance(expected, dict) and isinstance(actual, dict):
        result = []
        for key in sorted(expected.keys() | actual.keys()):
            child = f'{path}.{key}' if path else key
            if key not in expected or key not in actual:
                result.append(child)
            else:
                result.extend(differences(expected[key], actual[key], child))
        return result
    if isinstance(expected, list) and isinstance(actual, list):
        if len(expected) != len(actual):
            return [path]
        return [item for i, (left, right) in enumerate(zip(expected, actual))
                for item in differences(left, right, f'{path}[{i}]')]
    if type(expected) in (int, float) and type(actual) in (int, float):
        same = (math.isfinite(expected) and math.isfinite(actual) and
                math.isclose(expected, actual, rel_tol=TOLERANCE, abs_tol=TOLERANCE))
    else:
        same = type(expected) is type(actual) and expected == actual
    return [] if same else [path]


def load_contract(path):
    expected = path.with_suffix('.sha256').read_text().strip()
    if text_hash(path) != expected:
        raise ValueError('Semantic contract checksum mismatch')
    contract = json.loads(path.read_text(encoding='utf-8'))
    if (contract['schema_version'] != 1 or contract['reference_commit'] != BASELINE or
            contract['numeric_tolerance'] != TOLERANCE):
        raise ValueError('Unsupported semantic contract reference/version/tolerance')
    if set(contract['feature_definitions']) != set(contract['feature_order']):
        raise ValueError('Semantic definitions must cover every model feature')
    return contract


def extra_probes():
    def event(offset=0, **updates):
        return TrafficEvent(**(dict(timestamp=1700000000000 + offset,
                                   src_ip='192.0.2.1', dst_ip='198.51.100.1',
                                   protocol=17, packets=1, bytes=60) | updates))
    # Expiration and identity overflow freeze the current window interpretation.
    window = RateWindow()
    window.update(event(900, packets=100))
    boundary = window.update(event(10901))
    expired = window.update(event(11000))
    reset = window.update(event(100000))
    overflow = RateWindow(max_sources=2)
    for i in range(1, 5):
        partial = overflow.update(event(i, src_ip=f'192.0.2.{i}', packets=i))
    recovered = overflow.update(event(20000))
    extractor = FeatureExtractor()
    before = extractor.update(event(2000, packets=100))
    dropped = extractor.update(event(1000, packets=1000000))
    after = extractor.update(event(3000))
    # Same peer: CV uses per-event mean packet size; SYN ML fraction is event-based.
    peer = FeatureExtractor()
    peer.update(event(protocol=6, packets=9, bytes=900, syn=True, syn_packets=9))
    f = peer.update(event(1000, protocol=6, bytes=200))
    return dict(
        expiration={name: {key: values[key] for key in ('packet_rate', 'byte_rate',
                        'source_entropy', 'rate_window_seconds', 'rate_window_resolution_ms')}
                    for name, values in (('boundary', boundary), ('expired', expired), ('reset', reset))},
        overflow={name: {key: values[key] for key in ('packet_rate', 'source_entropy',
                        'source_count_lower_bound', 'source_entropy_partial')}
                  for name, values in (('partial', partial), ('recovered', recovered))},
        late_event=dict(dropped=dropped is None, late_events=extractor.late_events,
                        packet_rate_before=before['packet_rate'], packet_rate_after=after['packet_rate']),
        peer={key: f[key] for key in ('size_cv', 'syn_fraction', 'iat_mean', 'iat_cv',
                                      'history_count', 'egress_bytes')},
        reverse={name: {key: FeatureExtractor().update(sample)[key]
                        for key in ('byte_ratio', 'reverse_available', 'observed_byte_ratio',
                                    'observed_byte_ratio_status')}
                 for name, sample in (('unavailable', event()),
                                      ('zero', event(reverse_observed=True, reverse_bytes=0)),
                                      ('positive', event(reverse_observed=True, reverse_bytes=25)))},
    )


def preflight(contract_path=CONTRACT):
    contract = load_contract(contract_path)
    issues = []
    raw = ARTIFACT.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != contract['model_sha256'] or ARTIFACT.with_suffix('.sha256').read_text().strip() != digest:
        issues.append('model_sha256')
    artifact = json.loads(raw)
    for name, actual in (('feature_order', FEATURES), ('artifact_feature_order', artifact['features'])):
        issues.extend(differences(contract['feature_order'], actual, name))
    probe_vector = vector(dict(zip(FEATURES, [-1, 0] + list(range(1, len(FEATURES) - 1)))))
    expected_vector = [0.0, 0.0] + [math.log1p(i) for i in range(1, len(FEATURES) - 1)]
    issues.extend(differences(expected_vector, probe_vector, 'transform'))
    sources = {name: text_hash(ROOT/name) for name in contract['current_source_sha256']}
    issues.extend(differences(contract['current_source_sha256'], sources, 'current_source_sha256'))
    reference = {name: hashlib.sha256(blob(name)).hexdigest()
                 for name in contract['historical_source_sha256']}
    issues.extend(differences(contract['historical_source_sha256'], reference, 'historical_source_sha256'))
    result = dict(
        scope='Offline semantic conformance/compatibility; not model quality or promotion',
        contract_version=contract['contract_version'], contract_sha256=text_hash(contract_path),
        model_sha256=digest, reference_commit=BASELINE,
        current_conformance='FAIL' if issues else 'PASS', historical_compatibility='UNVERIFIED',
        issues=issues, current_source_sha256=sources, historical_source_sha256=reference,
        data_policy=dict(controlled_metadata_only=True, training_data_used=False,
                         validation_data_used=False, reserved_data_used=False,
                         fit_called=False, predictions_called=False, runtime_changed=False),
    )
    if issues:
        return result  # Never execute an unverified historical reference.
    old_class, _, _ = historical_definitions()
    probes = run_probes(old_class)
    extra = extra_probes()
    issues.extend(differences(contract['expected_probes'], probes, 'probes'))
    issues.extend(differences(contract['expected_extra_probes'], extra, 'extra_probes'))
    drift = {name: item['changes'] for name, item in probes.items()
             if 'changes' in item and item['changes']}
    drift_features = sorted({feature for item in drift.values() for feature in item})
    issues.extend(differences(sorted(contract['declared_incompatible_features']),
                              drift_features, 'declared_incompatible_features'))
    result.update(current_conformance='FAIL' if issues else 'PASS',
                  historical_compatibility='UNVERIFIED' if issues else 'FAIL' if drift else 'PASS',
                  historical_drift=drift, incompatible_features=drift_features,
                  probes=probes, extra_probes=extra)
    return result


def exit_code(report):
    if report['current_conformance'] != 'PASS' or report['historical_compatibility'] == 'UNVERIFIED':
        return 2
    return int(report['historical_compatibility'] != 'PASS')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='Optional new report path; existing reports are never overwritten')
    args = parser.parse_args(argv)
    try:
        report = preflight()
    except (OSError, ValueError, KeyError, TypeError, AssertionError, subprocess.CalledProcessError) as exc:
        report = dict(current_conformance='ERROR', historical_compatibility='UNVERIFIED',
                      issues=[f'{type(exc).__name__}: {exc}'])
    rendered = json.dumps(report, indent=2, allow_nan=False) + '\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open('x', encoding='utf-8') as file:
            file.write(rendered)
    print(rendered, end='')
    return exit_code(report)


if __name__ == '__main__':
    raise SystemExit(main())
