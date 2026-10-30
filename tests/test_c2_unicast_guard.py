"""A multicast or broadcast destination is never a botnet C2 server (found on real LLMNR/mDNS traffic)."""
import pytest

from detection.pipeline import Pipeline
from schemas.traffic_event import TrafficEvent

START = 1_700_000_000_000.0


def polls(dst, port, count=14, gap_ms=1200):
    return [TrafficEvent(timestamp=START + i * gap_ms, src_ip='10.0.0.7', dst_ip=dst, src_port=51000, dst_port=port,
                         protocol=17, bytes=60) for i in range(count)]


def c2(events, model=None):
    pipeline = Pipeline()
    if model:
        pipeline.model.predict = lambda _: ('BOTNET_C2', .99)
    return [a for e in events for a in pipeline.process(e) if a.threat_class == 'BOTNET_C2']


@pytest.mark.parametrize('dst, port', [('224.0.0.252', 5355), ('224.0.0.251', 5353), ('239.255.255.250', 1900),
                                       ('255.255.255.255', 137), ('ff02::fb', 5353)])
def test_multicast_and_broadcast_destinations_never_raise_c2(dst, port):
    events = polls(dst, port)
    assert c2(events) == []             # Regular timing: the rule would have fired.
    assert c2(events, model=True) == []  # A confident model posterior does not override it.


def test_unicast_beacons_still_alert_by_rule_and_model():
    events = polls('203.0.113.9', 8080)
    assert any(a.detection_source in ('RULE', 'HYBRID') for a in c2(events))
    assert c2(events, model=True)
