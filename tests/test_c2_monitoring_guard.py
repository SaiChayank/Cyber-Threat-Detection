"""Internal SNMP polling and ICMP echo are monitoring, not C2; the same cadence elsewhere still alerts."""
from detection.pipeline import Pipeline
from schemas.traffic_event import TrafficEvent

START = 1_700_000_000_000.0


def c2(src, dst, port, protocol):
    pipeline = Pipeline()
    events = [TrafficEvent(timestamp=START + i * 5000, src_ip=src, dst_ip=dst, src_port=40000 + i,
                           dst_port=port, protocol=protocol, packets=1, bytes=80) for i in range(14)]
    return [a for e in events for a in pipeline.process(e) if a.threat_class == 'BOTNET_C2']


def test_internal_snmp_polling_and_ping_are_not_c2():
    assert c2('10.0.0.5', '10.0.0.9', 161, 17) == []
    assert c2('10.0.0.5', '10.0.0.9', 0, 1) == []


def test_same_subnet_public_range_hosts_are_internal_too():
    assert c2('147.32.84.59', '147.32.84.193', 161, 17) == []
    assert c2('147.32.84.59', '147.32.85.193', 8443, 17)


def test_same_cadence_on_another_port_still_alerts():
    assert c2('10.0.0.5', '10.0.0.9', 6667, 6)
    assert c2('10.0.0.5', '10.0.0.9', 8443, 17)
    assert c2('10.0.0.5', '203.0.113.50', 8443, 17)
