"""Adapt observed packet records to the shared metadata contract."""
from schemas.traffic_event import TrafficEvent


def from_packet(flow, dns=None, tls=None):
    client = tls if tls and tls.role == 'client' else None
    server = tls if tls and tls.role == 'server' else None
    return TrafficEvent(timestamp=flow.timestamp_start, src_ip=flow.src_ip, dst_ip=flow.dst_ip,
                        src_port=flow.src_port or 0, dst_port=flow.dst_port or 0, protocol=flow.protocol,
                        packets=max(1, flow.packets_forward), bytes=flow.bytes_forward,
                        syn=bool(flow.tcp_flags_forward & 2),
                        syn_packets=(int(bool(flow.tcp_flags_forward & 2) and
                                         not bool(flow.tcp_flags_forward & 16))
                                     if flow.protocol == 6 and flow.packets_forward == 1 else None),
                        dns_name=dns.query_name if dns else None, dns_type=dns.query_type if dns else 1,
                        encrypted=bool(tls) or flow.dst_port == 443 or flow.src_port == 443,
                        tls_fingerprint=client.ja3_hash if client else None,
                        tls_server_fingerprint=server.ja3s_hash if server else None,
                        tls_ja4=client.ja4 if client else None,
                        tcp_fin_rst=True if flow.protocol == 6 and flow.tcp_flags_forward & 0x05 else None,
                        transport='TLS' if tls else 'QUIC' if flow.protocol == 17 and flow.dst_port == 443 else 'IP')
