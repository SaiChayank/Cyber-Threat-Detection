"""The DGA guard judges the registrable label: cloud/CDN subdomains and tunnel subdomains are not generated domains."""
import pytest

from detection.dga_rules import registrable_name
from detection.pipeline import Pipeline
from schemas.traffic_event import TrafficEvent

START = 1_700_000_000_000.0


def dga(name):
    pipeline = Pipeline()
    event = TrafficEvent(timestamp=START, src_ip='10.0.0.5', dst_ip='8.8.8.8', src_port=53000, dst_port=53,
                         protocol=17, dns_name=name, bytes=80)
    return [a for a in pipeline.process(event) if a.threat_class == 'DGA_DOMAINS']


@pytest.mark.parametrize('name, expected', [
    ('example.com', 'example.com'), ('www.example.com', 'example.com'), ('a.b.c.example.org', 'example.org'),
    ('shop.bbc.co.uk', 'bbc.co.uk'), ('x.y.example.com.au', 'example.com.au'), ('abc.test', 'abc.test'),
    ('single', 'single'), ('', ''), ('Trailing.Example.COM.', 'example.com'),
])
def test_registrable_name(name, expected):
    assert registrable_name(name) == expected


@pytest.mark.parametrize('name', [
    'dcs-edge-irl1-876252164.eu-west-1.elb.amazonaws.com',          # Real AWS load-balancer name (AIT capture).
    'f3965bfc947799de816df19a9742d4d7.safeframe.googlesyndication.com',
    'a55978850331a4770ade1d9ccd460761-117616169.eu-west-1.elb.amazonaws.com',
    'q8f3k2x9z1m7v4b6n0w5j2x8c1v3b5n7m9.tunnel.example.test',       # Tunnel subdomain: a tunnelling signal, not DGA.
])
def test_random_subdomains_of_a_stable_domain_are_not_dga(name):
    assert dga(name) == []


@pytest.mark.parametrize('name', [
    'q8f3k2x9z1m7v4b6n0w5j2.test',               # Random registrable label, two labels: judged as before.
    'www.q8f3k2x9z1m7v4b6n0w5j2.example.test'.replace('.example.test', '.test'),  # Random registrable under a subdomain.
    'q8f3k2x9z1m7v4b6n0w5j2.com',
])
def test_random_registrable_labels_still_alert(name):
    alerts = dga(name)
    assert alerts and alerts[0].detection_source in ('RULE', 'HYBRID')
