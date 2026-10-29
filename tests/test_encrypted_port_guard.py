"""Port 443 alone must not let the synthetic model raise encrypted-malware suspicion."""
from detection.pipeline import Pipeline
from schemas.traffic_event import TrafficEvent
from replay.scenarios import scenario

START = 1_700_000_000_000.0


def encrypted_alerts(pipeline, events):
    return [a for e in events for a in pipeline.process(e) if a.threat_class == 'ENCRYPTED_MALWARE']


def port_only(offset, transport):
    return TrafficEvent(timestamp=START + offset * 1000, src_ip='10.0.0.10', dst_ip='198.51.100.20',
                        src_port=49152, dst_port=443, bytes=520, encrypted=True, transport=transport)


def test_model_hit_on_port_only_flows_is_suppressed_but_observed_tls_is_not():
    for transport, expect in (('IP', False), ('TLS', True)):
        pipeline = Pipeline()
        pipeline.model.predict = lambda _: ('ENCRYPTED_MALWARE', .99)
        alerts = encrypted_alerts(pipeline, [port_only(i, transport) for i in range(6)])
        assert bool(alerts) is expect, transport


def test_rule_paths_and_the_frozen_demo_are_unaffected():
    pipeline = Pipeline()
    assert encrypted_alerts(pipeline, list(scenario('ENCRYPTED_MALWARE', seed=100)))
    ip_events = [e.model_copy(update={'transport': 'IP'}) for e in scenario('ENCRYPTED_MALWARE', seed=100)]
    listed = Pipeline()
    listed.tls_indicators['ja3']['0123456789abcdef0123456789abcdef'] = 'lab family'
    first = ip_events[0].model_copy(update={'tls_fingerprint': '0123456789abcdef0123456789abcdef'})
    assert encrypted_alerts(listed, [first, ip_events[1]])  # Indicator list still fires.
