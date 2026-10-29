"""Live passive collector: receive flow-export datagrams and print alerts. No replies, no history.

Run: python -m replay.collector --port 2055 [--bind 127.0.0.1] [--allow 192.0.2.1 ...]
Alerts are printed as JSON lines (like replay.cli) and nothing is written to analyst history.
Stop with Ctrl+C. Binding a non-loopback address is an explicit choice: use --allow so only
your exporters are accepted.
"""
import argparse
import json

from detection.pipeline import Pipeline
from ingest.flow_collector import FlowCollector


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--bind', default='127.0.0.1', help='address to listen on (default loopback)')
    parser.add_argument('--port', type=int, default=2055)
    parser.add_argument('--allow', nargs='*', help='accept datagrams only from these exporter addresses')
    parser.add_argument('--max-datagrams', type=int, help='stop after this many accepted datagrams')
    parser.add_argument('--idle-timeout', type=float, help='stop after this many idle seconds')
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error('port must be 1-65535')
    try:
        collector = FlowCollector(args.bind, args.port, args.allow)
    except (OSError, ValueError) as exc:
        parser.exit(2, f'error: cannot listen on {args.bind}:{args.port}: {exc}\n')
    pipeline = Pipeline()
    print(f'listening (receive-only) on {collector.address[0]}:{collector.address[1]}', flush=True)
    try:
        with collector:
            for event in collector.events(args.max_datagrams, args.idle_timeout):
                for alert in pipeline.process(event):
                    print(json.dumps(alert.to_dict()), flush=True)
    except KeyboardInterrupt:
        pass
    print(json.dumps(dict(collector=collector.stats, decoder=collector.decoder.stats)), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
