"""Repeatable core + SQLite benchmark. Excludes HTTP/browser/network overhead."""
import argparse
import hashlib
import json
import platform
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from detection.pipeline import Pipeline
from persistence.store import AlertStore
from replay.scenarios import mixed_demo
from benchmarks.environment import hardware


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--events', type=int, default=20000)
    parser.add_argument('--output', type=Path, default=Path(__file__).with_name('latest.json'),
                        help='Report destination; use a separate path for scoped regression runs')
    args = parser.parse_args()
    if args.events < 256:
        parser.error('Use at least 256 events')
    environment = hardware()
    template = list(mixed_demo())
    pipeline = Pipeline()
    durations = []
    alerts = 0
    with tempfile.TemporaryDirectory() as directory:
        store = AlertStore(Path(directory) / 'benchmark.sqlite3')
        started = time.perf_counter()
        for i in range(args.events):
            event = template[i % len(template)].model_copy(update={'timestamp': template[i % len(template)].timestamp + (i // len(template)) * 1000000})
            tick = time.perf_counter()
            for alert in pipeline.process(event):
                store.append(alert)
                alerts += 1
            durations.append((time.perf_counter()-tick)*1000)
        elapsed = time.perf_counter()-started
        store.close()
    durations.sort()
    rate = args.events/elapsed
    p95 = durations[int(len(durations)*.95)]
    p50 = durations[int(len(durations)*.50)]
    root = Path(__file__).resolve().parent.parent
    report = dict(generated_at_utc=datetime.now(timezone.utc).isoformat(),
                  runtime_source_sha256={file: hashlib.sha256((root / file).read_bytes()).hexdigest()
                                         for file in ('detection/pipeline.py', 'features/extractor.py',
                                                      'features/rate_window.py', 'ml/model.py', 'ml/dga.py',
                                                      'persistence/store.py', 'detection/dga_rules.py',
                                                      'detection/dns_tunnel_candidate.py', 'features/dns_tunnel.py',
                                                      'schemas/traffic_event.py', 'schemas/alert.py',
                                                      'schemas/flow_record.py', 'schemas/enums.py',
                                                      'replay/scenarios.py')},
                  benchmark_source_sha256={file: hashlib.sha256((root / file).read_bytes()).hexdigest()
                                           for file in ('benchmarks/run.py', 'benchmarks/environment.py')},
                  model_sha256=hashlib.sha256((root / 'ml/artifact.json').read_bytes()).hexdigest(),
                  events=args.events, alerts=alerts, elapsed_seconds=elapsed,
                  metadata_events_per_second=rate, throughput_target=2000, throughput_pass=rate >= 2000,
                  processing_and_persistence_p50_ms=p50,
                  processing_and_persistence_p95_ms=p95, latency_target_ms=50, latency_pass=p95 < 50,
                  percentile_method='Sorted zero-based index floor(n * fraction); unchanged core convention',
                  workload='Repeated eight-class synthetic metadata sessions with SQLite alert commits',
                  scope='Core event processing + persistence; excludes capture, HTTP, SSE and rendering',
                  python=platform.python_version(), platform=platform.platform(),
                  hardware=environment,
                  telemetry=pipeline.telemetry())
    args.output.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
