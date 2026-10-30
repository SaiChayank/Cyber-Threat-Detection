"""Periodic UDP queries to a private DNS resolver are not botnet C2; the same cadence to a public host still is."""
from detection.pipeline import Pipeline
from schemas.traffic_event import TrafficEvent

START = 1_700_000_000_000.0


def c2(dst, port=53, protocol=17):
    pipeline = Pipeline()
    events = [TrafficEvent(timestamp=START + i * 5000, src_ip='192.168.1.195', dst_ip=dst, src_port=40000 + i,
                           dst_port=port, protocol=protocol, packets=1, bytes=80) for i in range(14)]
    return [a for e in events for a in pipeline.process(e) if a.threat_class == 'BOTNET_C2']


def test_fixed_cadence_dns_to_the_local_resolver_is_not_c2():
    assert c2('192.168.1.1') == []


def test_same_cadence_to_a_public_server_or_another_port_still_alerts():
    assert c2('203.0.113.50', port=6667, protocol=6)
    assert c2('203.0.113.50', port=8443)
