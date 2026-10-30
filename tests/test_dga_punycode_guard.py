"""Punycode (IDN) first labels must not be flagged as DGA (found on real benign DNS)."""
import pytest

from detection.pipeline import Pipeline
from schemas.traffic_event import TrafficEvent

START = 1_700_000_000_000.0


def query(name, offset=0):
    return TrafficEvent(timestamp=START + offset, src_ip='10.0.0.5', dst_ip='8.8.8.8', src_port=53000, dst_port=53,
                        protocol=17, dns_name=name, bytes=80)


def dga(name, model=None):
    pipeline = Pipeline()
    if model:
        pipeline.model.predict = lambda _: ('DGA_DOMAINS', .99)
    return [a for a in pipeline.process(query(name)) if a.threat_class == 'DGA_DOMAINS']


@pytest.mark.parametrize('name', ['xn--80aalwclyias7g0b.xn--p1ai', 'XN--QCK5F1A9AY843AE01AIU5E.jp',
                                  'xn--c79as89aj0e29b77z.xn--3e0b707e'])
def test_punycode_labels_are_never_dga_even_with_a_confident_model(name):
    assert dga(name) == [] and dga(name, model=True) == []


def test_random_ascii_labels_still_alert_by_rule_and_model():
    name = 'q8f3k2x9z1m7v4b6n0w5j2.example.test'
    assert any(a.detection_source in ('RULE', 'HYBRID') for a in dga(name))
    assert dga(name, model=True)
    assert dga('q8f3k2x9z1m7v4b6n0w5j2.xn--p1ai', model=True)  # Only a FIRST label starting with xn-- is exempt.
