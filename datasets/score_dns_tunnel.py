"""Offline, session-level DNS candidate scoring; no training or activation.

Development mode uses only the existing exposed scenarios. Reserved mode fails
closed against the current frozen readiness flag, before opening a manifest.
"""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = 'data/dns_tunnel_evaluation_contract.json'
CONTRACT_SHA256 = '0d87b97f83d7ccb099816562eadb8a7cbbe0f3edb87296cc46e5a2db3206e774'
RECEIPT = 'data/dns_tunnel_reserved_pass.json'
PREREQUISITES = ('permission_verified', 'labels_verified', 'visibility_verified',
                 'disjointness_verified', 'roles_frozen', 'client_questions_verified')
REQUIRED_EVENT_FIELDS = {'timestamp', 'src_ip', 'dst_ip', 'protocol', 'dst_port',
                         'dns_name', 'dns_type'}


class EvaluationBlocked(ValueError):
    """Data/configuration not qualified; never a passing model decision."""


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def load_contract(root=ROOT):
    path = root / CONTRACT
    if sha256(path) != CONTRACT_SHA256 or path.with_suffix('.sha256').read_text().strip() != CONTRACT_SHA256:
        raise EvaluationBlocked('Frozen DNS contract identity changed')
    data = json.loads(path.read_text())
    for name, digest in data['source_sha256'].items():
        if sha256(root / name) != digest:
            raise EvaluationBlocked(f'Frozen source identity changed: {name}')
    if sha256(root / data['historical_protocol']) != data['historical_protocol_sha256']:
        raise EvaluationBlocked('Historical protocol changed')
    return data


def classify(positive, queries, first_query, first_delay_ms, gates):
    if type(positive) is not bool or type(queries) is not int or queries < 1:
        raise ValueError('A nonempty session and explicit boolean label are required')
    if first_query is not None:
        if (type(first_query) is not int or not 1 <= first_query <= queries
                or first_delay_ms is None or not 0 <= first_delay_ms < float('inf')):
            raise ValueError('Invalid first-alert position or capture delay')
    elif first_delay_ms is not None:
        raise ValueError('Delay requires an alert')
    before_end = first_query is not None and first_query < queries
    outcome = ('TP' if before_end else 'FN') if positive else ('FP' if first_query is not None else 'TN')
    early = (outcome == 'TP' and first_query <= gates['early_query_index_max']
             and first_delay_ms <= gates['early_delay_ms_max'])
    return {'outcome': outcome, 'detected_before_end': before_end, 'early': early}


def summarize(rows, gates):
    counts = Counter(row['outcome'] for row in rows)
    tp, tn, fp, fn = (counts[key] for key in ('TP', 'TN', 'FP', 'FN'))
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    fpr = fp / (fp + tn) if fp + tn else None
    f1 = (2 * precision * recall / (precision + recall) if precision + recall else 0.0
          ) if precision is not None and recall is not None else None
    early = sum(row['early'] for row in rows) / tp if tp else None
    def passes(value, target, minimum=True):
        return value is not None and (value >= target if minimum else value <= target)
    checks = {'recall': passes(recall, gates['recall_min']),
              'precision': passes(precision, gates['precision_min']),
              'fpr': passes(fpr, gates['benign_session_fpr_max'], False),
              'timing': passes(early, gates['early_true_positive_fraction_min'])
                        and all(r['detected_before_end'] for r in rows if r['outcome'] == 'TP')}
    return {'TP': tp, 'TN': tn, 'FP': fp, 'FN': fn, 'precision': precision,
            'recall': recall, 'F1': f1, 'FPR': fpr, 'early_tp_fraction': early,
            'numerical_checks': checks}


def score_session(spec, records, gates, pipeline_factory=None):
    from detection.pipeline import Pipeline
    from schemas.traffic_event import TrafficEvent
    pipeline = (pipeline_factory or (lambda: Pipeline(dns_tunnel_candidate=True)))()
    pipeline.model.predict = lambda _: ('BENIGN', 1.0)
    count = 0
    first = delay = started = None
    first_evidence = None
    qtypes = Counter()
    rate_groups = Counter()
    previous = None
    for raw in records:
        if not isinstance(raw, dict) or not REQUIRED_EVENT_FIELDS <= raw.keys():
            raise EvaluationBlocked('Missing observed DNS query fields; defaults cannot supply truth')
        event = TrafficEvent(**raw)
        name = (event.dns_name or '').lower().rstrip('.')
        namespace = spec['namespace'].lower().rstrip('.')
        if (event.protocol not in (6, 17) or event.dst_port != 53 or not name
                or not namespace or not (name == namespace or name.endswith('.' + namespace))
                or str(event.src_ip) != spec['source_ip'] or event.packets != 1):
            raise EvaluationBlocked('Input is outside the annotated complete-question session')
        if ('start_ms' in spec and not spec['start_ms'] <= event.timestamp <= spec['end_ms']):
            raise EvaluationBlocked('Query timestamp is outside its independently labelled interval')
        count += 1
        if started is None:
            started = event.timestamp
        if previous is not None and event.timestamp >= previous:
            interval = (event.timestamp - previous) / 1000
            rate_groups['low' if interval > 2 else 'medium' if interval >= .5 else 'high'] += 1
        previous = event.timestamp
        qtypes[str(event.dns_type)] += 1
        alerts = [a for a in pipeline.process(event) if a.threat_class == 'DNS_TUNNELLING']
        if alerts and first is None:
            first, delay = count, event.timestamp - started
            first_evidence = alerts[0].raw_evidence_metrics
    return {key: spec[key] for key in ('session_id', 'positive', 'tool', 'benign_category')} | {
        'queries': count, 'first_alert_query': first, 'first_alert_delay_ms': delay,
        'first_alert_evidence': first_evidence,
        'late_questions_dropped': pipeline.extractor.late_events,
        'query_types': dict(qtypes), 'nonnegative_interval_groups': dict(rate_groups),
        **classify(spec['positive'], count, first, delay, gates)}


def validate_manifest(manifest, contract):
    """Verify frozen qualification metadata; does not infer provenance from names."""
    if manifest.get('role') != 'reserved' or manifest.get('contract_sha256') != CONTRACT_SHA256:
        raise EvaluationBlocked('Manifest role/contract is not frozen for this scorer')
    if manifest.get('scorer_sha256') != sha256(Path(__file__)):
        raise EvaluationBlocked('Scorer version is not pinned in the manifest')
    if any(manifest.get(key) is not True for key in PREREQUISITES):
        raise EvaluationBlocked('Source permission, labels, visibility or split qualification incomplete')
    if not isinstance(manifest.get('qualification_reports'), dict) or not manifest['qualification_reports']:
        raise EvaluationBlocked('Missing source qualification report identities')
    sessions = manifest.get('sessions', [])
    identities, ids, hashes, fragments = set(), set(), set(), set()
    categories, tools = set(), set()
    positive = benign = 0
    for spec in sessions:
        if type(spec.get('positive')) is not bool:
            raise EvaluationBlocked('Session label must be explicitly boolean')
        for key in ('session_id', 'independence_id', 'run_id', 'fragment_group', 'source_ip',
                    'namespace', 'events_file', 'events_sha256', 'label_reference'):
            if not isinstance(spec.get(key), str) or not spec[key]:
                raise EvaluationBlocked(f'Missing session provenance: {key}')
        for key in ('start_ms', 'end_ms'):
            value = spec.get(key)
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                raise EvaluationBlocked('Missing or invalid labelled session time interval')
        if spec['start_ms'] > spec['end_ms']:
            raise EvaluationBlocked('Reversed labelled session interval')
        # fragment_group denotes exports/fragments of one annotated session, not
        # an entire capture containing several independently documented sessions.
        # Independence must be reviewed in pinned reports, not guessed here.
        if (spec['session_id'] in ids or spec['independence_id'] in identities
                or spec['events_sha256'] in hashes or spec['fragment_group'] in fragments):
            raise EvaluationBlocked('Duplicate session/independence group/event artifact')
        ids.add(spec['session_id']); identities.add(spec['independence_id']); hashes.add(spec['events_sha256'])
        fragments.add(spec['fragment_group'])
        if spec['positive']:
            if not spec.get('tool') or spec.get('benign_category') is not None:
                raise EvaluationBlocked('Positive tool identity missing or conflicting label')
            tools.add(spec['tool'].lower()); positive += 1
        else:
            categories.add(spec.get('benign_category')); benign += 1
    g = contract['quality_gates']
    if (positive < g['minimum_positive_sessions'] or benign < g['minimum_benign_sessions']
            or not set(contract['coverage']['benign_categories']) <= categories
            or not tools & {'dnscat2', 'iodine'}):
        raise EvaluationBlocked('Required independent session/tool/benign coverage missing')
    return sessions


def claim_once(path, manifest_sha):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump({'state': 'CONSUMED_BEFORE_SCORING', 'manifest_sha256': manifest_sha,
                   'contract_sha256': CONTRACT_SHA256}, stream)


def _local_file(root, name):
    path = (root / name).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        raise EvaluationBlocked('Manifest artifact must be an existing local file within repository')
    return path


def run_reserved(output, root=ROOT):
    contract = load_contract(root)
    controls = contract['scoring_controls']
    if controls['reserved_set_ready'] is not True or not controls['reserved_manifest']:
        raise EvaluationBlocked('Reserved evaluation blocked: qualified frozen data is unavailable')
    # Current immutable contract cannot reach here. Future readiness requires a
    # separately approved contract/scorer freeze; no CLI switch bypasses it.
    output = Path(output)
    if output.exists():
        raise FileExistsError('Preserve existing evaluation output')
    manifest_path = _local_file(root, controls['reserved_manifest'])
    manifest_sha = sha256(manifest_path)
    if manifest_path.with_suffix('.sha256').read_text().strip() != manifest_sha:
        raise EvaluationBlocked('Reserved manifest hash mismatch')
    manifest = json.loads(manifest_path.read_text())
    sessions = validate_manifest(manifest, contract)
    for name, digest in manifest['qualification_reports'].items():
        if sha256(_local_file(root, name)) != digest:
            raise EvaluationBlocked('Qualification report hash mismatch')
    # Check file presence/path containment without opening reserved question rows.
    paths = [_local_file(root, spec['events_file']) for spec in sessions]
    if not output.parent.is_dir():
        raise EvaluationBlocked('Create the report directory before claiming the reserved pass')
    claim_once(root / RECEIPT, manifest_sha)
    rows = []
    try:
        for spec, path in zip(sessions, paths):
            if sha256(path) != spec['events_sha256']:
                raise EvaluationBlocked('Session artifact hash mismatch; reserved pass stays consumed')
            with path.open(encoding='utf-8') as stream:
                rows.append(score_session(spec, (json.loads(line) for line in stream), contract['quality_gates']))
    except Exception as exc:
        # Preserve the consumed receipt and an explicit incomplete decision. A
        # failed run must not silently disappear or become retryable.
        with output.open('x', encoding='utf-8') as stream:
            json.dump({'scope':'Reserved run incomplete; not accuracy evidence',
                       'promotion_decision':'NO_PROMOTION', 'evaluation_error':str(exc),
                       'completed_sessions':rows, 'reserved_pass_consumed':True}, stream, indent=2)
        raise
    metrics = summarize(rows, contract['quality_gates'])
    passed = all(metrics['numerical_checks'].values())
    result = {'scope': 'Qualified reserved complete-question sessions only', 'manifest_sha256': manifest_sha,
              'metrics': metrics, 'sessions': rows, 'promotion_decision': 'PASS' if passed else 'NO_PROMOTION',
              'runtime_activated': False}
    with output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2, allow_nan=False); stream.write('\n')
    return result


def run_development(output):
    contract = load_contract()
    output = Path(output)
    if output.exists():
        raise FileExistsError('Preserve existing development output')
    from datasets.dns_tunnel_development import SCENARIOS, events
    rows = []
    for spec in SCENARIOS:
        name, split, positive, pattern, qtype, seed, base, interval = spec
        session = {'session_id': name, 'positive': positive, 'tool': 'synthetic' if positive else None,
                   'benign_category': pattern if not positive else None,
                   'namespace': base, 'source_ip': '192.0.2.10'}
        rows.append(score_session(session, (e.model_dump(mode='json') for e in events(spec)),
                                  contract['quality_gates']) | {'split': split})
    result = {'scope': 'Already exposed synthetic development only; not independent accuracy',
              'contract_sha256': CONTRACT_SHA256, 'promotion_decision': 'NOT_EVALUATED_DATA_BLOCKED',
              'runtime_activated': False, 'sessions': rows,
              'metrics_by_split': {split: summarize([r for r in rows if r['split'] == split], contract['quality_gates'])
                                   for split in ('training', 'validation')}}
    with output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2, allow_nan=False); stream.write('\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('development', 'reserved'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = run_development(args.output) if args.mode == 'development' else run_reserved(args.output)
    except (EvaluationBlocked, FileExistsError) as exc:
        parser.exit(2, str(exc) + '\n')
    print(json.dumps({'scope': result['scope'], 'promotion_decision': result['promotion_decision']}))


if __name__ == '__main__':
    main()
