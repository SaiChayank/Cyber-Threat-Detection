"""
High-Performance Zero-Copy Protocol Parsers
Parses raw packet bytes into canonical schemas without payload decryption.
Extracts: Ethernet, IPv4/v6, TCP/UDP, DNS, and TLS ClientHello (JA3 fingerprinting).
"""

import socket
import struct
from typing import Optional, Tuple, List, Dict, Any

from schemas.flow_record import FlowRecord
from schemas.dns_record import DNSRecord
from schemas.tls_metadata import TLSMetadataRecord
from ingest.dead_letter import DeadLetterQueue


class ProtocolParser:
    """Fast, zero-copy binary parser for network frames"""

    def __init__(self, dlq: Optional[DeadLetterQueue] = None):
        self.dlq = dlq or DeadLetterQueue()

    def parse_packet(
        self,
        raw_data: bytes,
        timestamp_sec: float
    ) -> Tuple[Optional[FlowRecord], Optional[DNSRecord], Optional[TLSMetadataRecord]]:
        """
        Parses raw Layer 2/3 frame into canonical record tuples.
        Guarantees zero crashes on malformed inputs.
        """
        try:
            timestamp_ms = timestamp_sec * 1000.0
            if len(raw_data) < 14:
                self.dlq.record_corrupt_packet("SHORT_FRAME", "Packet shorter than Ethernet header", len(raw_data))
                return None, None, None

            # 1. Parse Ethernet Header (14 bytes)
            eth_type = struct.unpack("!H", raw_data[12:14])[0]
            ip_offset = 14

            # Handle 802.1Q VLAN Tagging
            if eth_type == 0x8100:
                eth_type = struct.unpack("!H", raw_data[16:18])[0]
                ip_offset = 18

            # 2. Parse IP Layer
            src_ip: str = ""
            dst_ip: str = ""
            protocol: int = 0
            l4_offset: int = 0
            total_ip_len: int = len(raw_data)

            if eth_type == 0x0800:  # IPv4
                if len(raw_data) < ip_offset + 20:
                    self.dlq.record_corrupt_packet("SHORT_IPV4", "Truncated IPv4 header", len(raw_data))
                    return None, None, None
                
                version_ihl, _, total_len, _, _, ttl, protocol, _, src_bytes, dst_bytes = struct.unpack(
                    "!BBHHHBBH4s4s", raw_data[ip_offset:ip_offset + 20]
                )
                ihl = (version_ihl & 0x0F) * 4
                if ihl < 20:
                    self.dlq.record_corrupt_packet("INVALID_IHL", f"Invalid IHL {ihl}", len(raw_data))
                    return None, None, None

                src_ip = socket.inet_ntoa(src_bytes)
                dst_ip = socket.inet_ntoa(dst_bytes)
                l4_offset = ip_offset + ihl
                total_ip_len = min(total_len, len(raw_data) - ip_offset)

            elif eth_type == 0x86DD:  # IPv6
                if len(raw_data) < ip_offset + 40:
                    self.dlq.record_corrupt_packet("SHORT_IPV6", "Truncated IPv6 header", len(raw_data))
                    return None, None, None
                
                payload_len, protocol, _ = struct.unpack("!HBB", raw_data[ip_offset + 4:ip_offset + 8])
                src_ip = socket.inet_ntop(socket.AF_INET6, raw_data[ip_offset + 8:ip_offset + 24])
                dst_ip = socket.inet_ntop(socket.AF_INET6, raw_data[ip_offset + 24:ip_offset + 40])
                l4_offset = ip_offset + 40
                total_ip_len = 40 + payload_len

            else:
                # Non-IP packet (ARP, etc.)
                self.dlq.unsupported_protocol_count += 1
                return None, None, None

            # 3. Parse Layer 4 (TCP / UDP / ICMP)
            src_port: Optional[int] = None
            dst_port: Optional[int] = None
            tcp_flags: int = 0
            payload_data: bytes = b""

            if protocol == 6:  # TCP
                if len(raw_data) < l4_offset + 20:
                    self.dlq.record_corrupt_packet("SHORT_TCP", "Truncated TCP header", len(raw_data))
                    return None, None, None
                
                src_port, dst_port, seq, ack, data_offset_flags = struct.unpack(
                    "!HHIIH", raw_data[l4_offset:l4_offset + 14]
                )
                tcp_flags = data_offset_flags & 0x01FF
                tcp_header_len = ((data_offset_flags >> 12) & 0x0F) * 4
                payload_offset = l4_offset + tcp_header_len
                payload_data = raw_data[payload_offset:]

            elif protocol == 17:  # UDP
                if len(raw_data) < l4_offset + 8:
                    self.dlq.record_corrupt_packet("SHORT_UDP", "Truncated UDP header", len(raw_data))
                    return None, None, None
                
                src_port, dst_port, udp_len, _ = struct.unpack("!HHHH", raw_data[l4_offset:l4_offset + 8])
                payload_data = raw_data[l4_offset + 8:l4_offset + udp_len]

            # 4. Construct Core FlowRecord
            flow_id = FlowRecord.compute_flow_id(
                src_ip, dst_ip, src_port, dst_port, protocol, timestamp_ms
            )
            flow_record = FlowRecord(
                flow_id=flow_id,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                timestamp_start=timestamp_ms,
                timestamp_end=timestamp_ms,
                packets_forward=1,
                packets_backward=0,
                bytes_forward=total_ip_len,
                bytes_backward=0,
                tcp_flags_forward=tcp_flags,
                tcp_flags_backward=0,
                inter_arrival_times=[0.0],
                is_unidirectional=True
            )

            # 5. Extract Sidecars (DNS / TLS)
            dns_record: Optional[DNSRecord] = None
            tls_record: Optional[TLSMetadataRecord] = None

            # Check for DNS (Port 53)
            if (src_port == 53 or dst_port == 53) and payload_data:
                dns_record = self._try_parse_dns(payload_data, flow_id, src_ip, dst_ip, timestamp_ms)

            # Check for TLS ClientHello (Port 443 / TLS handshake)
            if protocol == 6 and payload_data:
                tls_record = self._try_parse_tls_client_hello(payload_data, flow_id, total_ip_len)

            return flow_record, dns_record, tls_record

        except Exception as exc:
            self.dlq.record_corrupt_packet("UNHANDLED_EXCEPTION", str(exc), len(raw_data))
            return None, None, None

    def _try_parse_dns(
        self,
        payload: bytes,
        flow_id: str,
        src_ip: str,
        dst_ip: str,
        timestamp_ms: float
    ) -> Optional[DNSRecord]:
        """Parses basic DNS query/response without external libraries"""
        try:
            if len(payload) < 12:
                return None
            
            tx_id, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", payload[:12])
            is_response = (flags & 0x8000) != 0
            rcode = flags & 0x000F

            if qdcount == 0:
                return None

            # Read first Query Name
            idx = 12
            labels = []
            while idx < len(payload):
                length = payload[idx]
                if length == 0:
                    idx += 1
                    break
                if (length & 0xC0) == 0xC0:  # Pointer
                    idx += 2
                    break
                idx += 1
                if idx + length > len(payload):
                    return None
                labels.append(payload[idx:idx + length].decode("ascii", errors="ignore"))
                idx += length

            if not labels or idx + 4 > len(payload):
                return None

            qtype, _ = struct.unpack("!HH", payload[idx:idx + 4])
            query_name = ".".join(labels)

            return DNSRecord.from_query(
                query_id=tx_id,
                flow_id=flow_id,
                query_name=query_name,
                query_type=qtype,
                src_ip=src_ip,
                dst_ip=dst_ip,
                timestamp=timestamp_ms,
                response_code=rcode if is_response else None,
                response_bytes=len(payload) if is_response else 0,
                is_response=is_response
            )
        except Exception:
            return None

    def _try_parse_tls_client_hello(
        self,
        payload: bytes,
        flow_id: str,
        packet_len: int
    ) -> Optional[TLSMetadataRecord]:
        """
        Extracts TLS ClientHello parameters for JA3 calculation.
        Operates purely on metadata, strictly with NO payload decryption.
        """
        try:
            # TLS Record Layer: ContentType (1 byte = 0x16 Handshake), Version (2 bytes), Length (2 bytes)
            if len(payload) < 5 or payload[0] != 0x16:
                return None

            record_version, record_len = struct.unpack("!HH", payload[1:5])
            if len(payload) < 5 + record_len or record_len < 40:
                return None

            handshake_offset = 5
            handshake_type = payload[handshake_offset]
            if handshake_type != 0x01:  # Must be ClientHello
                return None

            idx = handshake_offset + 4  # Skip type (1) + length (3)
            client_version = struct.unpack("!H", payload[idx:idx + 2])[0]
            idx += 2 + 32  # Skip client_version (2) + random (32)

            # Session ID
            if idx >= len(payload):
                return None
            session_id_len = payload[idx]
            idx += 1 + session_id_len

            # Cipher Suites
            if idx + 2 > len(payload):
                return None
            cipher_len = struct.unpack("!H", payload[idx:idx + 2])[0]
            idx += 2
            ciphers = []
            for _ in range(0, cipher_len, 2):
                if idx + 2 <= len(payload):
                    ciphers.append(struct.unpack("!H", payload[idx:idx + 2])[0])
                    idx += 2

            # Compression Methods
            if idx >= len(payload):
                return None
            compression_len = payload[idx]
            idx += 1 + compression_len

            # Extensions
            extensions: List[int] = []
            elliptic_curves: List[int] = []
            point_formats: List[int] = []
            sni_hostname: Optional[str] = None

            if idx + 2 <= len(payload):
                ext_total_len = struct.unpack("!H", payload[idx:idx + 2])[0]
                idx += 2
                ext_end = min(idx + ext_total_len, len(payload))

                while idx + 4 <= ext_end:
                    ext_type, ext_len = struct.unpack("!HH", payload[idx:idx + 4])
                    idx += 4
                    extensions.append(ext_type)
                    ext_data = payload[idx:idx + ext_len]

                    # SNI (Extension 0)
                    if ext_type == 0 and len(ext_data) > 5:
                        name_len = struct.unpack("!H", ext_data[3:5])[0]
                        sni_hostname = ext_data[5:5 + name_len].decode("utf-8", errors="ignore")

                    # Supported Groups / Elliptic Curves (Extension 10)
                    elif ext_type == 10 and len(ext_data) >= 2:
                        curves_len = struct.unpack("!H", ext_data[:2])[0]
                        for c_i in range(2, min(2 + curves_len, len(ext_data)), 2):
                            elliptic_curves.append(struct.unpack("!H", ext_data[c_i:c_i + 2])[0])

                    # EC Point Formats (Extension 11)
                    elif ext_type == 11 and len(ext_data) >= 1:
                        num_pts = ext_data[0]
                        for p_i in range(1, min(1 + num_pts, len(ext_data))):
                            point_formats.append(ext_data[p_i])

                    idx += ext_len

            # Compute JA3 string and hash
            ja3_str, ja3_hash = TLSMetadataRecord.generate_ja3(
                client_version, ciphers, extensions, elliptic_curves, point_formats
            )

            return TLSMetadataRecord(
                flow_id=flow_id,
                tls_version=client_version,
                ja3_string=ja3_str,
                ja3_hash=ja3_hash,
                cipher_suites=ciphers,
                extension_count=len(extensions),
                sni=sni_hostname,
                splt_sequence=[packet_len]
            )

        except Exception:
            return None
