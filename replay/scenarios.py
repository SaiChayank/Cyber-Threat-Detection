"""Offline lab metadata simulation. No sockets, probes, or attack packets are sent."""
import random
from schemas.traffic_event import TrafficEvent
from features.extractor import DEMO_FINGERPRINT

CLASSES = ['BENIGN', 'DDOS', 'BOTNET_C2', 'DGA_DOMAINS', 'DNS_TUNNELLING',
           'ENCRYPTED_MALWARE', 'RECONNAISSANCE', 'DATA_EXFILTRATION']


def scenario(label, seed=1, start=1700000000000.0, count=32):
    rng = random.Random(seed)
    t = start
    for i in range(count):
        t += rng.uniform(100, 2000)
        d = dict(timestamp=t, src_ip='10.0.0.10', dst_ip='198.51.100.20',
                 src_port=49152, dst_port=443, bytes=rng.randint(100, 1600))
        if label == 'BENIGN':
            d.update(dst_port=rng.choice([80, 443, 53]), encrypted=rng.random() < .5,
                     dns_name=rng.choice(['www.example.org', 'mail.company.test', None]))
        elif label == 'DDOS':
            d.update(packets=rng.randint(2000, 6000), bytes=rng.randint(100000, 300000),
                     syn=rng.random() < .8, src_ip=f'10.1.{i % 4}.{i+1}')
        elif label == 'BOTNET_C2':
            t = start + (i + 1) * 2500 + rng.uniform(-30, 30)
            d.update(timestamp=t, bytes=rng.randint(120, 140), encrypted=True)
        elif label == 'DGA_DOMAINS':
            name = ''.join(rng.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(rng.randint(16, 28)))
            d.update(dst_port=53, protocol=17, dns_name=name + '.test', bytes=90)
        elif label == 'DNS_TUNNELLING':
            name = ''.join(rng.choice('abcdef0123456789') for _ in range(rng.randint(45, 62)))
            d.update(dst_port=53, protocol=17, dns_name=name + '.tunnel.test', dns_type=16, bytes=700)
        elif label == 'ENCRYPTED_MALWARE':
            d.update(encrypted=True, transport=rng.choice(['TLS', 'QUIC']),
                     tls_fingerprint=DEMO_FINGERPRINT if rng.random() < .5 else None,
                     bytes=rng.randint(510, 530))
        elif label == 'RECONNAISSANCE':
            d.update(dst_ip=f'198.51.100.{i+1}', dst_port=1000+i, syn=True, bytes=40)
        elif label == 'DATA_EXFILTRATION':
            d.update(bytes=rng.randint(1000000, 3000000), reverse_bytes=rng.randint(100, 500),
                     reverse_observed=True, encrypted=True)
        else:
            raise ValueError(f'Unknown scenario: {label}')
        yield TrafficEvent(**d)


def mixed_demo(seed=100):
    start = 1700000000000.0
    for index, label in enumerate(CLASSES):
        yield from scenario(label, seed + index, start + index * 120000)
