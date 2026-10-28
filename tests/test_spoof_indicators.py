"""Reserved-source evidence on flood alerts; evidence only, never changes detection."""
from detection.pipeline import Pipeline
from detection.spoof_indicators import MIN_SOURCES, reserved_sources
from schemas.traffic_event import TrafficEvent

START = 1_700_000_000_000.0


def udp_flood(sources, repeat=40):
    return [TrafficEvent(timestamp=START + i * 5, src_ip=sources[i % len(sources)], dst_ip='203.0.113.10',
                         src_port=4000, dst_port=9000, protocol=17, packets=400, bytes=480000)
            for i in range(repeat)]


def ddos_alerts(events):
    pipeline = Pipeline()
    return [a for e in events for a in pipeline.process(e) if a.threat_class == 'DDOS']


def test_reserved_sources_are_counted_but_private_and_global_are_not():
    mixed = ['0.0.0.0', '127.0.0.1', '224.0.0.5', '240.0.0.9', '169.254.1.1', '10.0.0.1', '8.8.8.8', '192.168.1.1', None]
    evidence = reserved_sources(mixed)
    assert evidence['source_reserved_count'] == 5
    assert evidence['source_reserved_fraction'] == round(5 / 8, 4)
    assert reserved_sources(['10.0.0.1', '192.168.0.2', '8.8.8.8', '1.1.1.1', '100.64.0.1']) is None
    assert reserved_sources(['0.0.0.0'] * (MIN_SOURCES - 1)) is None


def test_flood_with_reserved_sources_gets_evidence_and_wording():
    sources = [f'240.0.{i}.1' for i in range(12)]
    alerts = ddos_alerts(udp_flood(sources))
    assert alerts
    evidence = alerts[0].raw_evidence_metrics
    assert evidence['source_reserved_fraction'] == 1.0
    assert 'cannot prove forgery' in alerts[0].supporting_evidence


def test_private_source_flood_is_unchanged_and_detection_does_not_depend_on_indicator():
    private = ddos_alerts(udp_flood([f'10.1.0.{i}' for i in range(1, 13)]))
    reserved = ddos_alerts(udp_flood([f'240.1.0.{i}' for i in range(1, 13)]))
    assert private and reserved
    assert 'source_reserved_fraction' not in private[0].raw_evidence_metrics
    assert len(private) == len(reserved)
