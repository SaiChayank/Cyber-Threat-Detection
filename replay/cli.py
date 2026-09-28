"""Offline PCAP/JSONL inference without an HTTP ingest return channel."""
import argparse
import json
import time
from pathlib import Path
from detection.pipeline import Pipeline
from ingest.metadata import from_packet
from ingest.pcap_reader import PcapReader
from schemas.traffic_event import TrafficEvent


def metadata(path):
    if path.suffix.lower() == '.pcap':
        for batch in PcapReader().read_packets(path):
            for flow, dns, tls in batch:
                yield from_packet(flow, dns, tls)
    else:
        with path.open() as file:
            for line in file:
                if line.strip():
                    yield TrafficEvent.model_validate_json(line)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input', type=Path)
    parser.add_argument('--speed', type=float, default=0, help='0: unpaced; otherwise event-time speed multiplier')
    args = parser.parse_args()
    if args.speed < 0:
        parser.error('speed must be nonnegative')
    pipeline = Pipeline()
    previous = None
    for event in metadata(args.input):
        if args.speed and previous is not None:
            time.sleep(max(0, (event.timestamp-previous)/1000/args.speed))
        for alert in pipeline.process(event):
            print(json.dumps(alert.to_dict()), flush=True)
        previous = event.timestamp


if __name__ == '__main__':
    main()
