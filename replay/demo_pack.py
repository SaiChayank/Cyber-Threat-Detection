"""Read-only preflight for frozen demo fixtures using the existing runtime.

No training, candidate activation, database writes or network IO. UUIDs and
creation wall clocks are intentionally excluded from reproducibility checks.
"""
import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from detection.pipeline import Pipeline
from replay.cli import metadata
from replay.scenarios import CLASSES, mixed_demo, scenario

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'data/demo/manifest.json'


def sha256(path, normalize_newlines=False):
    raw = path.read_bytes()
    if normalize_newlines:
        raw = raw.replace(b'\r\n', b'\n')
    return hashlib.sha256(raw).hexdigest()


def normalized(value):
    """Round evidence floats to nine decimals for portable comparison."""
    if isinstance(value, float):
        return round(value, 9)
    if isinstance(value, dict):
        return {key: normalized(item) for key, item in value.items()}
    if isinstance(value, list):
        return [normalized(item) for item in value]
    return value


def stable_alert(alert):
    row = alert.to_dict() if hasattr(alert, 'to_dict') else dict(alert)
    for key in ('alert_id', 'created_at_ms', 'sequence'):
        row.pop(key, None)
    return normalized(row)


def summarize(records):
    pipeline = Pipeline()
    if pipeline.dga_model.enabled or pipeline.dns_tunnel_candidate:
        raise ValueError('Demo requires disabled DGA and DNS tunnelling candidates')
    counts = Counter()
    first = {}
    output = []
    for index, event in enumerate(records, 1):
        for alert in pipeline.process(event):
            row = stable_alert(alert)
            counts[alert.threat_class] += 1
            output.append({'event_position': index, 'alert': row})
            first.setdefault(alert.threat_class, dict(
                event_position=index,
                observed_delay_seconds=round((event.timestamp - records[0].timestamp) / 1000, 9),
                alert=row))
    digest = hashlib.sha256(json.dumps(output, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return dict(events=len(records), alert_count=sum(counts.values()),
                alerts_by_class=dict(sorted(counts.items())), first_alerts=first,
                observed_duration_seconds=round((records[-1].timestamp - records[0].timestamp) / 1000, 9),
                stable_alert_trace_sha256=digest)


def verify(manifest_path=MANIFEST, root=ROOT):
    if sha256(manifest_path) != manifest_path.with_suffix('.sha256').read_text().strip():
        raise ValueError('Demo manifest SHA256 mismatch')
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    if manifest['demonstration_order'] != CLASSES:
        raise ValueError('Demo order differs from runtime')
    for relative, pin in manifest['provenance'].items():
        if sha256(root / relative, pin['newline_normalized']) != pin['sha256']:
            raise ValueError(f'Demo provenance SHA256 mismatch: {relative}')
    rows = manifest['scenarios']
    if [row['preset'] for row in rows] != CLASSES + ['ALL']:
        raise ValueError('Demo must contain each required preset and ALL exactly once')
    results = []
    for row in rows:
        path = root / row['artifact']
        if sha256(path) != row['sha256']:
            raise ValueError(f'Demo artifact SHA256 mismatch: {row["artifact"]}')
        records = list(metadata(path))
        generated = list(mixed_demo() if row['preset'] == 'ALL' else scenario(row['preset'], seed=100))
        if [event.model_dump(mode='json') for event in records] != [event.model_dump(mode='json') for event in generated]:
            raise ValueError(f'Demo generator differs: {row["preset"]}')
        actual = summarize(records)
        if actual != row['expected']:
            raise ValueError(f'Demo alert trace/evidence/timing differs: {row["preset"]}')
        if row['preset'] == 'BENIGN' and actual['alert_count']:
            raise ValueError('Benign demo emitted an alert')
        required = CLASSES[1:] if row['preset'] == 'ALL' else [row['preset']]
        for label in required:
            if label == 'BENIGN':
                continue
            first = actual['first_alerts'].get(label)
            end_position = (CLASSES.index(label) + 1) * 32 if row['preset'] == 'ALL' else len(records)
            if not first or first['event_position'] >= end_position:
                raise ValueError(f'Demo lacks incremental {label} alert')
        results.append(dict(preset=row['preset'], events=actual['events'],
                            alert_count=actual['alert_count'], verified=True))
    return dict(scope=manifest['scope'], results=results, passed=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    try:
        result = verify()
    except (OSError, ValueError, KeyError) as exc:
        parser.exit(1, f'Demo preflight failed: {exc}\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
