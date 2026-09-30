"""One-shot, offline audit of passive suspected-spoof indicators.

Labels describe controlled generator provenance; no packet is transmitted.
"""
from collections import Counter, defaultdict, deque
import hashlib
import json
import math
from pathlib import Path

from detection.pipeline import Pipeline
from schemas.traffic_event import TrafficEvent


ROOT = Path(__file__).resolve().parents[1]
START = 1_700_000_000_000.0
VICTIM = '198.51.100.10'


def events(kind):
    if kind == 'spread':
        for index in range(32):
            yield make_event(index, index % 32, target=f'198.51.100.{index + 10}')
        return
    count = 64 if kind == 'once_64' else 32
    repeats = 4 if kind == 'repeat_32' else 1
    packets = 100 if kind == 'low_32' else 200 if kind == 'once_64' else 400
    for index in range(count * repeats):
        yield make_event(index, index % count, packets=packets,
                         size=256 if kind == 'telemetry_32' else 1200)
        if kind == 'mixed_32' and index % 4 == 3:
            yield make_event(index, index % count, target='198.51.100.200',
                             timestamp=START + index * 100 + 50)


def make_event(index, source_index, *, target=VICTIM, packets=400,
               size=1200, timestamp=None):
    return TrafficEvent(timestamp=START + index * 100 if timestamp is None else timestamp,
                        src_ip=f'10.1.0.{source_index + 1}', dst_ip=target,
                        src_port=49152, dst_port=9000, protocol=17,
                        packets=packets, bytes=packets * size)


CASES = (
    ('forged_32_once', True, 'once_32'),
    ('forged_64_once', True, 'once_64'),
    ('forged_32_repeat', True, 'repeat_32'),
    ('forged_32_mixed', True, 'mixed_32'),
    ('genuine_distributed_32', False, 'once_32'),
    ('flash_crowd_64', False, 'once_64'),
    ('genuine_repeat_32', False, 'repeat_32'),
    ('authorised_telemetry_32', False, 'telemetry_32'),
    ('authorised_spread', False, 'spread'),
    ('genuine_low_rate_32', False, 'low_32'),
)


def snapshot(pipeline, flow_observations):
    window = pipeline.extractor.udp_targets.get(VICTIM)
    if window is None:
        return None
    total = sum(window.sources.values())
    entropy = (-sum(weight / total * math.log2(weight / total)
                    for weight in window.sources.values()) if total else 0.0)
    observations = Counter(source for _, source in flow_observations)
    singleton_fraction = (sum(count == 1 for count in observations.values()) / len(observations)
                          if observations else 0.0)
    return {'target_packet_rate': window.packets / window.seconds,
            'target_flow_summary_rate': len(flow_observations) / window.seconds,
            'source_entropy': max(0.0, entropy),
            'unique_source_count_lower_bound': len(window.sources),
            'source_entropy_partial': bool(window.sources.get(None)),
            'singleton_source_fraction': singleton_fraction,
            'destination_concentration': window.packets / pipeline.extractor.global_rates.packets}


def diagnostic_indicator(features):
    return (features['target_packet_rate'] >= 1000
            and features['unique_source_count_lower_bound'] >= 16
            and features['source_entropy'] >= 3.5
            and features['singleton_source_fraction'] >= .75
            and features['destination_concentration'] >= .8
            and not features['source_entropy_partial'])


def verdict(positive, first, total):
    early = first is not None and first['event'] < total
    return 'TP' if positive and early else 'FN' if positive else 'FP' if first else 'TN'


def score(name, positive, kind):
    stream = list(events(kind))
    pipeline = Pipeline()
    observations = defaultdict(deque)
    first_ddos = first_indicator = None
    final = None
    for index, event in enumerate(stream, start=1):
        alerts = pipeline.process(event)
        target = str(event.dst_ip)
        second = int(event.timestamp // 1000)
        history = observations[target]
        while history and history[0][0] < second - 10:
            history.popleft()
        history.append((second, str(event.src_ip)))
        features = snapshot(pipeline, observations[VICTIM])
        final = features
        if target == VICTIM:
            if first_indicator is None and diagnostic_indicator(features):
                first_indicator = {'event': index, 'timestamp': event.timestamp,
                                   'features': features,
                                   'wording': 'consistent with suspected spoofed-source flood'}
        if first_ddos is None:
            for alert in alerts:
                if alert.threat_class == 'DDOS' and str(alert.dst_ip) == VICTIM:
                    first_ddos = {'event': index, 'timestamp': alert.timestamp,
                                  'evidence': alert.raw_evidence_metrics,
                                  'wording': alert.supporting_evidence}
                    break
    event_digest = hashlib.sha256(json.dumps(
        [event.model_dump(mode='json') for event in stream],
        sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {'scenario': name, 'ground_truth_forged': positive,
            'generator_provenance': ('one simulated emitter assigns the visible source addresses'
                                     if positive else 'authorised actors own the visible source addresses'),
            'observed_stream_sha256': event_digest, 'events': len(stream),
            'final_visible_features': final,
            'existing_ddos': {'verdict': verdict(positive, first_ddos, len(stream)),
                              'first': first_ddos},
            'diagnostic_only_indicator': {'verdict': verdict(positive, first_indicator, len(stream)),
                                          'first': first_indicator}}


def main():
    rows = [score(*case) for case in CASES]
    report = {'scope': 'One-shot controlled synthetic flow-summary audit; no source verification or production claim',
              'source_sha256': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                                for name in ('datasets/validate_spoofed_source.py',
                                             'detection/pipeline.py', 'features/extractor.py',
                                             'features/rate_window.py')},
              'scenarios': rows}
    for mechanism in ('existing_ddos', 'diagnostic_only_indicator'):
        report[mechanism + '_counts'] = {
            key: sum(row[mechanism]['verdict'] == key for row in rows)
            for key in ('TP', 'TN', 'FP', 'FN')}
    output = ROOT / 'ml/spoofed_source_validation.json'
    output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'existing_ddos': report['existing_ddos_counts'],
                      'diagnostic_only_indicator': report['diagnostic_only_indicator_counts'],
                      'first_indicators': {row['scenario']: row['diagnostic_only_indicator']['first']['event']
                                           if row['diagnostic_only_indicator']['first'] else None
                                           for row in rows}}, indent=2))


if __name__ == '__main__':
    main()
