"""Adapt observed packet records to the shared metadata contract."""
from schemas.traffic_event import TrafficEvent


def from_packet(flow, dns=None, tls=None):
    return TrafficEvent(timestamp=flow.timestamp_start, src_ip=flow.src_ip, dst_ip=flow.dst_ip,
                        src_port=flow.src_port or 0, dst_port=flow.dst_port or 0, protocol=flow.protocol,
                        packets=max(1, flow.packets_forward), bytes=flow.bytes_forward,
                        syn=bool(flow.tcp_flags_forward & 2),
                        dns_name=dns.query_name if dns else None, dns_type=dns.query_type if dns else 1,
                        encrypted=bool(tls) or flow.dst_port == 443 or flow.src_port == 443,
                        tls_fingerprint=tls.ja3_hash if tls else None,
                        transport='TLS' if tls else 'QUIC' if flow.protocol == 17 and flow.dst_port == 443 else 'IP')
