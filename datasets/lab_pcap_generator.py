"""Scripted lab traffic written straight to a labelled PCAP. Nothing is ever sent on any network.

Crafts Ethernet/IPv4/TCP/UDP frames for scenarios the project has no open real capture for: single-client
slow-HTTP, slow-read, UDP reflection/amplification and bulk-upload exfiltration, plus benign look-alikes (a backup
and a large download) and light web background. Addresses come from reserved documentation, benchmark and private
ranges. The generator and the detectors are written by the same project, so results measure the packet-parsing path
and the tuned rules on scripted traffic, not independent real-world accuracy.

Usage: python -m datasets.lab_pcap_generator [--out-dir data]
"""
import argparse
import json
import random
import struct
from pathlib import Path

T0 = 1_700_000_000.0
MAC_A, MAC_B = bytes.fromhex('020000000001'), bytes.fromhex('020000000002')
SYN, ACK, PSH, FIN, RST = 0x02, 0x10, 0x08, 0x01, 0x04


def ip4(text):
    return bytes(int(p) for p in text.split('.'))


def checksum(data):
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


class Frames:
    def __init__(self):
        self.rows = []
        self.ident = 0

    def _ip(self, src, dst, proto, payload):
        self.ident = (self.ident + 1) & 0xFFFF
        head = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), self.ident, 0x4000, 64, proto, 0,
                           ip4(src), ip4(dst))
        head = head[:10] + struct.pack('!H', checksum(head)) + head[12:]
        return MAC_B + MAC_A + b'\x08\x00' + head + payload

    def tcp(self, t, src, sport, dst, dport, flags, payload=b'', window=65535):
        seg = struct.pack('!HHIIBBHHH', sport, dport, 1000, 1000, 0x50, flags, window, 0, 0) + payload
        self.rows.append((t, self._ip(src, dst, 6, seg)))

    def udp(self, t, src, sport, dst, dport, payload):
        seg = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
        self.rows.append((t, self._ip(src, dst, 17, seg)))

    def handshake(self, t, client, cport, server, sport):
        self.tcp(t, client, cport, server, sport, SYN)
        self.tcp(t + .001, server, sport, client, cport, SYN | ACK)
        self.tcp(t + .002, client, cport, server, sport, ACK)

    def write(self, path):
        self.rows.sort(key=lambda r: r[0])
        with open(path, 'wb') as out:
            out.write(struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for t, frame in self.rows:
                sec = int(t)
                out.write(struct.pack('<IIII', sec, int((t - sec) * 1_000_000), len(frame), len(frame)) + frame)
        return len(self.rows)


def web_background(frames, rng, start, end):
    """Short web exchanges from a few clients to one server: ordinary, quick, closed connections."""
    t = start
    while t < end:
        client = '10.20.1.%d' % rng.randint(10, 14)
        port = rng.randint(30000, 60000)
        frames.handshake(t, client, port, '203.0.113.10', 80)
        frames.tcp(t + .01, client, port, '203.0.113.10', 80, PSH | ACK, b'G' * 300)
        for i in range(2):
            frames.tcp(t + .03 + i * .005, '203.0.113.10', 80, client, port, PSH | ACK, b'R' * 1400)
        frames.tcp(t + .06, client, port, '203.0.113.10', 80, FIN | ACK)
        frames.tcp(t + .061, '203.0.113.10', 80, client, port, FIN | ACK)
        t += rng.uniform(.2, .5)


def slow_http(frames, rng, start, end, attacker='198.51.100.77', connections=120):
    """One client holds many connections open: a full request line, then a few bytes every ~10 s."""
    for i in range(connections):
        t, port = start + i * .25, 20000 + i
        frames.handshake(t, attacker, port, '203.0.113.10', 80)
        frames.tcp(t + .1, attacker, port, '203.0.113.10', 80, PSH | ACK, b'GET / HTTP/1.1\r\nHost: lab\r\n' + b'U' * 40)
        t += 10 + rng.uniform(0, 2)
        while t < end:
            frames.tcp(t, attacker, port, '203.0.113.10', 80, PSH | ACK, b'X-a: %d\r\n' % rng.randint(1000, 9999))
            frames.tcp(t + .001, '203.0.113.10', 80, attacker, port, ACK)
            t += 10 + rng.uniform(0, 2)


def slow_read(frames, rng, start, end, attacker='198.51.100.88', connections=100):
    """One client requests a large object, then advertises a tiny receive window and drains it slowly."""
    for i in range(connections):
        t, port = start + i * .3, 21000 + i
        frames.handshake(t, attacker, port, '203.0.113.10', 80)
        frames.tcp(t + .1, attacker, port, '203.0.113.10', 80, PSH | ACK, b'GET /big.iso HTTP/1.1\r\nHost: lab\r\n\r\n')
        t += 4
        while t < end:
            frames.tcp(t, '203.0.113.10', 80, attacker, port, PSH | ACK, b'D' * 64)
            frames.tcp(t + .002, attacker, port, '203.0.113.10', 80, ACK, window=64)
            t += 4 + rng.uniform(0, 1)


def udp_amplification(frames, rng, start, seconds, victim='192.0.2.50', reflectors=300, pps=1500):
    """Many reflectors send large UDP answers from port 53 to one victim, as seen at the victim's link."""
    hosts = ['198.18.%d.%d' % (i // 250, i % 250 + 1) for i in range(reflectors)]
    for n in range(int(seconds * pps)):
        frames.udp(start + n / pps, rng.choice(hosts), 53, victim, rng.randint(1024, 65000), b'A' * 480)


def bulk_upload(frames, start, client, server, port, megabytes=24, seconds=60, reverse_window=65535):
    """Steady one-way bulk transfer from `client` with sparse acknowledgements from `server`."""
    frames.handshake(start, client, 50000, server, port)
    packets = int(megabytes * 1_000_000 / 1448)
    for n in range(packets):
        t = start + .1 + n * seconds / packets
        frames.tcp(t, client, 50000, server, port, PSH | ACK, b'B' * 1448)
        if n % 2:
            frames.tcp(t + .0005, server, port, client, 50000, ACK, window=reverse_window)
    frames.tcp(start + seconds + .2, client, 50000, server, port, FIN | ACK)


def build(out_dir):
    rng = random.Random(26145)
    frames = Frames()
    web_background(frames, rng, T0, T0 + 960)
    slow_http(frames, rng, T0 + 60, T0 + 240)
    slow_read(frames, rng, T0 + 300, T0 + 420)
    udp_amplification(frames, rng, T0 + 480, 20)
    bulk_upload(frames, T0 + 600, '10.20.0.15', '203.0.113.99', 443)           # exfiltration-like upload
    bulk_upload(frames, T0 + 780, '10.20.0.30', '10.20.0.250', 445)            # nightly backup (benign)
    bulk_upload(frames, T0 + 900 - 30, '203.0.113.60', '10.20.0.40', 443)      # large download (benign)
    raw = Path(out_dir) / 'raw' / 'lab-generated'
    raw.mkdir(parents=True, exist_ok=True)
    pcap = raw / 'loopback-lab-v1.pcap'
    count = frames.write(pcap)

    def ep(identifier, label, scenario, start, end, hosts, tool='lab_pcap_generator'):
        return dict(id=identifier, label=label, scenario=scenario, tool=tool,
                    start_ms=int((T0 + start) * 1000), end_ms=int((T0 + end) * 1000), hosts=hosts)

    labels = dict(format='ps26145-lab-labels/1', capture='../../raw/lab-generated/loopback-lab-v1.pcap',
                  split='unassigned', episodes=[
                      ep('slow-http-1', 'DDOS', 'slow_http_single_client', 60, 250, ['198.51.100.77']),
                      ep('slow-read-1', 'DDOS', 'slow_read_single_client', 300, 430, ['198.51.100.88']),
                      ep('udp-amp-1', 'DDOS', 'udp_reflection_amplification', 480, 505, ['192.0.2.50']),
                      ep('exfil-1', 'DATA_EXFILTRATION', 'bulk_upload_exfiltration_like', 600, 670, ['10.20.0.15']),
                      ep('backup-1', 'BENIGN', 'nightly_backup', 780, 850, ['10.20.0.30']),
                      ep('download-1', 'BENIGN', 'large_download', 870, 940, ['10.20.0.40'])])
    lab = Path(out_dir) / 'lab' / 'generated'
    lab.mkdir(parents=True, exist_ok=True)
    (lab / 'loopback-lab-v1.labels.json').write_text(json.dumps(labels, indent=2) + '\n', encoding='utf-8')
    return pcap, count


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--out-dir', default='data')
    args = parser.parse_args()
    path, n = build(args.out_dir)
    print(f'wrote {path} ({n} frames, {path.stat().st_size} bytes)')
