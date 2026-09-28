"""Repeatable core + SQLite benchmark. Excludes HTTP/browser/network overhead."""
import argparse
import json
import platform
import tempfile
import time
from pathlib import Path
from detection.pipeline import Pipeline
from persistence.store import AlertStore
from replay.scenarios import mixed_demo


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--events', type=int, default=20000)
    args = parser.parse_args()
    if args.events < 256:
        parser.error('Use at least 256 events')
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
    report = dict(events=args.events, alerts=alerts, elapsed_seconds=elapsed,
                  metadata_events_per_second=rate, throughput_target=2000, throughput_pass=rate >= 2000,
                  processing_and_persistence_p95_ms=p95, latency_target_ms=50, latency_pass=p95 < 50,
                  workload='Repeated eight-class synthetic metadata sessions with SQLite alert commits',
                  scope='Core event processing + persistence; excludes capture, HTTP, SSE and rendering',
                  python=platform.python_version(), platform=platform.platform(),
                  telemetry=pipeline.telemetry())
    Path('benchmarks/latest.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
