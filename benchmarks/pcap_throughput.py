"""End-to-end PCAP throughput: read + parse + feature extraction + inference.

Excludes SQLite, HTTP, SSE and rendering. Generates a deterministic benign
synthetic Ethernet PCAP in a temporary directory and times two passes over it.
"""
import argparse
import hashlib
import json
import platform
import random
import socket
import struct
import tempfile
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from detection.pipeline import Pipeline
from ingest.metadata import from_packet
from ingest.pcap_reader import PcapReader
from benchmarks.environment import hardware

DEFAULT_OUTPUT = Path(__file__).with_name('pcap_throughput_latest.json')
BASE_SECONDS = 1700000000
STEP_US = 100
CLIENTS = 200
SERVERS = 20
SERVICE_PORTS = (80, 443, 22)
RESOLVER = '198.51.100.250'
DNS_NAMES = ('www.example.org', 'mail.example.com', 'docs.example.org', 'api.example.com')
WORKLOAD = ('Benign synthetic traffic: TCP data/ACK between 200 clients and 20 servers on ports 80/443/22, '
            'about 2% TCP SYN, some UDP DNS queries for ordinary names; no floods, scans or attack patterns')
SCOPE = 'PCAP read + parse + feature extraction + inference; excludes SQLite, HTTP, SSE and rendering'


def _ipv4(src, dst, proto, l4):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), 0, 0x4000, 64, proto, 0,
                     socket.inet_aton(src), socket.inet_aton(dst)) + l4
    ethernet = b'\x02\x00\x00\x00\x00\x01' + b'\x02\x00\x00\x00\x00\x02' + b'\x08\x00'
    return ethernet + ip


def _tcp_frame(src, dst, sport, dport, flags, size, seq):
    payload = b'\x00' * (size - 14 - 20 - 20)
    tcp = struct.pack('!HHIIHHHH', sport, dport, seq & 0xFFFFFFFF, 0, (5 << 12) | flags, 65535, 0, 0)
    return _ipv4(src, dst, 6, tcp + payload)


def _dns_frame(src, dst, sport, name, txid):
    query = struct.pack('!HHHHHH', txid, 0x0100, 1, 0, 0, 0)
    for label in name.split('.'):
        query += bytes([len(label)]) + label.encode('ascii')
    query += b'\x00' + struct.pack('!HH', 1, 1)
    udp = struct.pack('!HHHH', sport, 53, 8 + len(query), 0) + query
    return _ipv4(src, dst, 17, udp)


def write_capture(path, packets):
    """Write a deterministic benign PCAP; return total frame bytes on the wire."""
    rng = random.Random(1)
    clients = [f'10.1.{i // 250}.{i % 250 + 1}' for i in range(CLIENTS)]
    servers = [f'198.51.100.{i + 1}' for i in range(SERVERS)]
    wire_bytes = 0
    with path.open('wb') as file:
        file.write(struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i in range(packets):
            ts_us = BASE_SECONDS * 1000000 + i * STEP_US
            index = rng.randrange(CLIENTS)
            client = clients[index]
            server = servers[index % SERVERS]
            service = SERVICE_PORTS[index % len(SERVICE_PORTS)]
            cport = 49152 + rng.randrange(4)
            roll = rng.random()
            if roll < 0.02:
                frame = _tcp_frame(client, server, cport, service, 0x02, 60, i)
            elif roll < 0.05:
                name = rng.choice(DNS_NAMES)
                frame = _dns_frame(client, RESOLVER, 40000 + rng.randrange(1000), name, i & 0xFFFF)
            else:
                size = rng.randint(60, 1514)
                flags = 0x18 if size > 60 else 0x10
                if rng.random() < 0.6:
                    frame = _tcp_frame(client, server, cport, service, flags, size, i)
                else:
                    frame = _tcp_frame(server, client, service, cport, flags, size, i)
            length = len(frame)
            wire_bytes += length
            file.write(struct.pack('<IIII', ts_us // 1000000, ts_us % 1000000, length, length) + frame)
    return wire_bytes


def _parse_only(path):
    count = 0
    for batch in PcapReader().read_packets(path):
        for flow, dns, tls in batch:
            from_packet(flow, dns, tls)
            count += 1
    return count


def _full_path(path, pipeline):
    packets, alerts, flows, threats = 0, 0, set(), Counter()
    for batch in PcapReader().read_packets(path):
        for flow, dns, tls in batch:
            event = from_packet(flow, dns, tls)
            flows.add((str(event.src_ip), str(event.dst_ip), event.src_port, event.dst_port, event.protocol))
            packets += 1
            for alert in pipeline.process(event):
                alerts += 1
                threats[getattr(alert.threat_class, 'value', alert.threat_class)] += 1
    return packets, len(flows), alerts, threats


def run(packets=50000, output=DEFAULT_OUTPUT):
    if packets < 1000:
        raise ValueError('Use at least 1000 packets')
    environment = hardware()
    with tempfile.TemporaryDirectory() as directory:
        capture = Path(directory) / 'benign_synthetic.pcap'
        wire_bytes = write_capture(capture, packets)
        capture_bytes = capture.stat().st_size
        sha256 = hashlib.sha256(capture.read_bytes()).hexdigest()
        duration = (packets - 1) * STEP_US / 1e6

        started = time.perf_counter()
        parsed = _parse_only(capture)
        parse_elapsed = time.perf_counter() - started

        pipeline = Pipeline()
        started = time.perf_counter()
        seen, flows, alerts, threats = _full_path(capture, pipeline)
        elapsed = time.perf_counter() - started

    report = dict(generated_at_utc=datetime.now(timezone.utc).isoformat(),
                  python=platform.python_version(), platform=platform.platform(), hardware=environment,
                  workload=WORKLOAD, scope=SCOPE,
                  packets=seen, capture_bytes=capture_bytes, capture_sha256=sha256,
                  capture_duration_seconds=duration, wire_bytes=wire_bytes,
                  elapsed_seconds=elapsed, packets_per_second=seen / elapsed,
                  flows=flows, flows_per_second=flows / elapsed,
                  sustained_mbps=wire_bytes * 8 / elapsed / 1e6,
                  alerts=alerts, alerts_by_class=dict(threats),
                  realtime_factor=duration / elapsed,
                  parse_only_elapsed_seconds=parse_elapsed,
                  parse_only_packets_per_second=parsed / parse_elapsed,
                  parse_only_sustained_mbps=wire_bytes * 8 / parse_elapsed / 1e6)
    Path(output).write_text(json.dumps(report, indent=2))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--packets', type=int, default=50000)
    parser.add_argument('--output', type=Path, default=DEFAULT_OUTPUT,
                        help='Report destination; defaults to benchmarks/pcap_throughput_latest.json')
    args = parser.parse_args(argv)
    if args.packets < 1000:
        parser.error('Use at least 1000 packets')
    report = run(args.packets, args.output)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
