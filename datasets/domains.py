"""Raw public domain strings wrapped in explicitly simulated DNS observations."""
from pathlib import Path
from schemas.traffic_event import TrafficEvent


def domains(path: Path):
    with path.open(encoding='utf-8-sig') as source:
        for line in source:
            name = line.strip().lower().rstrip('.')
            if 0 < len(name) <= 253 and '.' in name and all(c.isalnum() or c in '.-' for c in name):
                yield name


def replay_domains(path: Path):
    for i, domain in enumerate(domains(path)):
        # Domain names are the only public observations. Tuples, packet counts,
        # byte sizes and time are simulated, not recovered network measurements.
        yield TrafficEvent(timestamp=1700000000000 + i * 1000,
                           src_ip='192.0.2.10', dst_ip='192.0.2.53',
                           src_port=50000 + i % 1000, dst_port=53, protocol=17,
                           dns_name=domain, bytes=80, flow_id=f'UMUDGA-lab-{i}')
