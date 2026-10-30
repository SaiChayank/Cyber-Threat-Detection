"""A flood of SYN+ACK-flagged packets (seen from a Mirai-family bot on IoT-23) is a DDoS; ordinary replies are not."""
from detection.pipeline import Pipeline
from schemas.traffic_event import TrafficEvent

START = 1_700_000_000_000.0


def packets(count, syn_packets, syn=True, step_ms=1.0, dst='203.0.113.9'):
    return [TrafficEvent(timestamp=START + i * step_ms, src_ip='192.168.1.195', dst_ip=dst, src_port=65279,
                         dst_port=80, protocol=6, packets=1, bytes=1078, syn=syn, syn_packets=syn_packets)
            for i in range(count)]


def ddos(events):
    pipeline = Pipeline()
    return [a for e in events for a in pipeline.process(e) if a.threat_class == 'DDOS']


def test_syn_ack_flood_alerts_with_its_subtype():
    alerts = ddos(packets(12_000, syn_packets=0))
    assert len(alerts) == 1
    evidence = alerts[0].raw_evidence_metrics
    assert evidence['ddos_subtype'] == 'syn_ack_flood' and evidence['syn_ack_fraction'] >= .7


def test_pure_syn_flood_is_unchanged_and_not_labelled_syn_ack():
    alerts = ddos(packets(12_000, syn_packets=1))
    assert len(alerts) == 1 and 'ddos_subtype' not in alerts[0].raw_evidence_metrics


def test_low_rate_syn_ack_replies_do_not_alert():
    assert ddos(packets(900, syn_packets=0, step_ms=100)) == []  # 10 packets/s: ordinary server replies.


def test_high_rate_established_traffic_is_not_a_syn_ack_flood():
    assert ddos(packets(12_000, syn_packets=0, syn=False)) == []  # ACK/data packets, no SYN flag.
