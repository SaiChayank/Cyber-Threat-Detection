"""False-positive classes found on real benign traffic: ICMP model hits, service-port replies, multicast."""
from detection.pipeline import Pipeline
from schemas.traffic_event import TrafficEvent

START = 1_700_000_000_000.0


def run(events, model=None):
    pipeline = Pipeline()
    if model:
        pipeline.model.predict = lambda _: (model, .99)
    return [a for e in events for a in pipeline.process(e)]


def icmp(count=12):
    return [TrafficEvent(timestamp=START + i * 50, src_ip='10.0.0.5', dst_ip='10.0.0.1', protocol=1, packets=2, bytes=120)
            for i in range(count)]


def fan_out(src_port, syn, dst='198.51.100.7', count=30, ports=True):
    return [TrafficEvent(timestamp=START + i * 100, src_ip='10.0.0.9', dst_ip=dst, src_port=src_port,
                         dst_port=(30000 + i) if ports else 443, protocol=17 if not syn else 6, packets=1, bytes=60,
                         syn=syn, syn_packets=int(syn) if syn else None)
            for i in range(count)]


def test_model_only_ddos_on_low_rate_icmp_is_suppressed():
    assert [a for a in run(icmp(), model='DDOS') if a.threat_class == 'DDOS'] == []


def test_icmp_flood_by_rate_rule_still_alerts():
    flood = [TrafficEvent(timestamp=START + i, src_ip='10.0.0.5', dst_ip='10.0.0.1', protocol=1, packets=500, bytes=40000)
             for i in range(40)]
    assert any(a.threat_class == 'DDOS' for a in run(flood))


def recon(events, model=None):
    return [a for a in run(events, model) if a.threat_class == 'RECONNAISSANCE']


def test_replies_from_a_service_port_and_multicast_targets_are_not_scans():
    assert recon(fan_out(53, syn=False)) == []                       # Resolver replying to many client ports.
    assert recon(fan_out(5355, syn=False, dst='224.0.0.252')) == []  # Multicast LLMNR.
    assert recon(fan_out(40000, syn=False, dst='224.0.0.251'), model='RECONNAISSANCE') == []


def test_real_scans_from_ephemeral_ports_still_alert():
    assert recon(fan_out(49152, syn=True))
    assert recon(fan_out(49152, syn=False))  # UDP scan from an ephemeral port.


def test_tcp_fan_out_with_almost_no_syn_packets_is_browsing_not_recon():
    browsing = [TrafficEvent(timestamp=START + i * 100, src_ip='10.0.0.9', dst_ip=f'198.51.100.{i % 30 + 1}', src_port=50000,
                             dst_port=443, protocol=6, packets=1, bytes=1200, syn=False, syn_packets=0) for i in range(60)]
    assert recon(browsing) == [] and recon(browsing, model='RECONNAISSANCE') == []


def test_syn_probe_fan_out_still_alerts():
    scan = [TrafficEvent(timestamp=START + i * 100, src_ip='10.0.0.9', dst_ip=f'198.51.100.{i % 30 + 1}', src_port=50000 + i,
                         dst_port=23, protocol=6, packets=1, bytes=60, syn=True, syn_packets=1) for i in range(60)]
    assert recon(scan)


def test_mixed_source_with_mostly_established_tcp_is_not_recon_but_pure_udp_scan_is():
    tcp = [TrafficEvent(timestamp=START + i * 10, src_ip='10.0.0.9', dst_ip='198.51.100.1', src_port=50000, dst_port=443,
                        protocol=6, packets=1, bytes=1200, syn=i < 4, syn_packets=int(i < 4)) for i in range(200)]
    queries = [TrafficEvent(timestamp=START + 2000 + i * 100, src_ip='10.0.0.9', dst_ip=f'198.51.100.{i % 30 + 1}',
                            src_port=50000 + i, dst_port=53, protocol=17, packets=1, bytes=80) for i in range(60)]
    assert recon(tcp + queries) == []
    assert recon(queries)


def test_quic_fan_out_is_not_recon():
    quic = [TrafficEvent(timestamp=START + i * 100, src_ip='10.0.0.9', dst_ip=f'198.51.100.{i % 30 + 1}', src_port=50000 + i,
                         dst_port=443, protocol=17, packets=1, bytes=1200, transport='QUIC') for i in range(60)]
    assert recon(quic) == [] and recon(quic, model='RECONNAISSANCE') == []
