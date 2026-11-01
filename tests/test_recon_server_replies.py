"""A server answering many clients (SYN+ACK replies) is not reconnaissance; real SYN probes still alert."""
from detection.pipeline import Pipeline
from schemas.traffic_event import TrafficEvent

START = 1_700_000_000_000.0


def recon(syn_ack):
    pipeline = Pipeline()
    events = []
    for i in range(60):
        events.append(TrafficEvent(timestamp=START + i * 100, src_ip='203.0.113.10' if syn_ack else '10.0.0.5',
                                   dst_ip=f'10.20.1.{10 + i % 12}', src_port=80 if syn_ack else 40000,
                                   dst_port=30000 + i if syn_ack else 1000 + i, protocol=6, packets=1, bytes=60,
                                   syn=True, syn_packets=0 if syn_ack else 1))
    return [a for e in events for a in pipeline.process(e) if a.threat_class == 'RECONNAISSANCE']


def test_server_syn_ack_replies_are_not_recon():
    assert recon(syn_ack=True) == []


def test_real_syn_probes_still_alert():
    assert recon(syn_ack=False)
