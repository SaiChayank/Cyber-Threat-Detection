"""
High-Performance Zero-Copy Protocol Parsers
Parses raw packet bytes into canonical schemas without payload decryption.
Extracts: Ethernet, IPv4/v6, TCP/UDP, DNS, and TLS ClientHello (JA3 fingerprinting).
"""

import socket
import struct
from collections import OrderedDict
from typing import Optional, Tuple, List, Dict, Any

from schemas.flow_record import FlowRecord
from schemas.dns_record import DNSRecord
from schemas.tls_metadata import TLSMetadataRecord
from ingest.dead_letter import DeadLetterQueue


MAX_STREAMS = 256
MAX_STREAM_BYTES = 16 * 1024 + 5
STREAM_IDLE_SECONDS = 10.0


class ProtocolParser:
    """Fast, zero-copy binary parser for network frames"""

    def __init__(self, dlq: Optional[DeadLetterQueue] = None):
        self.dlq = dlq or DeadLetterQueue()
        self.streams = OrderedDict()  # (src, dst, sport, dport) -> [next_seq, bytes, needed, last_seen]

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
                
                version_ihl, _, total_len, _, fragment, ttl, protocol, _, src_bytes, dst_bytes = struct.unpack(
                    "!BBHHHBBH4s4s", raw_data[ip_offset:ip_offset + 20]
                )
                ihl = (version_ihl & 0x0F) * 4
                if ihl < 20 or version_ihl >> 4 != 4 or total_len < ihl or len(raw_data) < ip_offset + ihl:
                    self.dlq.record_corrupt_packet("INVALID_IHL", f"Invalid IHL {ihl}", len(raw_data))
                    return None, None, None
                if fragment & 0x3FFF:
                    self.dlq.unsupported_protocol_count += 1
                    return None, None, None  # No speculative parsing of IP fragments.

                src_ip = socket.inet_ntoa(src_bytes)
                dst_ip = socket.inet_ntoa(dst_bytes)
                l4_offset = ip_offset + ihl
                total_ip_len = min(total_len, len(raw_data) - ip_offset)
                raw_data = raw_data[:ip_offset + total_ip_len]

            elif eth_type == 0x86DD:  # IPv6
                if len(raw_data) < ip_offset + 40:
                    self.dlq.record_corrupt_packet("SHORT_IPV6", "Truncated IPv6 header", len(raw_data))
                    return None, None, None
                
                payload_len, protocol, _ = struct.unpack("!HBB", raw_data[ip_offset + 4:ip_offset + 8])
                src_ip = socket.inet_ntop(socket.AF_INET6, raw_data[ip_offset + 8:ip_offset + 24])
                dst_ip = socket.inet_ntop(socket.AF_INET6, raw_data[ip_offset + 24:ip_offset + 40])
                l4_offset = ip_offset + 40
                total_ip_len = 40 + payload_len
                raw_data = raw_data[:ip_offset + total_ip_len]

            else:
                # Non-IP packet (ARP, etc.)
                self.dlq.unsupported_protocol_count += 1
                return None, None, None

            # 3. Parse Layer 4 (TCP / UDP / ICMP)
            src_port: Optional[int] = None
            dst_port: Optional[int] = None
            tcp_flags: int = 0
            tcp_window: Optional[int] = None
            tcp_seq: int = 0
            quic_fingerprint: Optional[str] = None
            payload_data: bytes = b""

            if protocol == 6:  # TCP
                if len(raw_data) < l4_offset + 20:
                    self.dlq.record_corrupt_packet("SHORT_TCP", "Truncated TCP header", len(raw_data))
                    return None, None, None
                
                src_port, dst_port, seq, ack, data_offset_flags = struct.unpack(
                    "!HHIIH", raw_data[l4_offset:l4_offset + 14]
                )
                tcp_flags = data_offset_flags & 0x01FF
                tcp_seq = seq
                if len(raw_data) >= l4_offset + 16:
                    tcp_window = struct.unpack("!H", raw_data[l4_offset + 14:l4_offset + 16])[0]
                tcp_header_len = ((data_offset_flags >> 12) & 0x0F) * 4
                if tcp_header_len < 20 or l4_offset + tcp_header_len > len(raw_data):
                    self.dlq.record_corrupt_packet('INVALID_TCP_LENGTH', 'Invalid TCP header length', len(raw_data))
                    return None, None, None
                payload_offset = l4_offset + tcp_header_len
                payload_data = raw_data[payload_offset:]

            elif protocol == 17:  # UDP
                if len(raw_data) < l4_offset + 8:
                    self.dlq.record_corrupt_packet("SHORT_UDP", "Truncated UDP header", len(raw_data))
                    return None, None, None
                
                src_port, dst_port, udp_len, _ = struct.unpack("!HHHH", raw_data[l4_offset:l4_offset + 8])
                if udp_len < 8 or l4_offset + udp_len > len(raw_data):
                    self.dlq.record_corrupt_packet('INVALID_UDP_LENGTH', 'Invalid UDP length', len(raw_data))
                    return None, None, None
                payload_data = raw_data[l4_offset + 8:l4_offset + udp_len]
                if 443 in (src_port, dst_port):
                    quic_fingerprint = self._quic_initial_fingerprint(payload_data)

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
                is_unidirectional=True,
                tcp_window_forward=tcp_window,
                quic_fingerprint=quic_fingerprint
            )

            # 5. Extract Sidecars (DNS / TLS)
            dns_record: Optional[DNSRecord] = None
            tls_record: Optional[TLSMetadataRecord] = None

            # DNS/TCP prefixes each message with a two-byte length. Parse only a
            # complete first message; TCP stream reassembly is deliberately absent.
            # Bounded in-order TCP reassembly of one TLS record or DNS message that spans segments.
            stream_payload = payload_data
            if protocol == 6 and payload_data:
                stream_payload = self._tcp_stream_payload(src_ip, dst_ip, src_port, dst_port, tcp_seq,
                                                          tcp_flags, payload_data, timestamp_sec)
            elif protocol == 6 and tcp_flags & 0x05:
                self.streams.pop((src_ip, dst_ip, src_port, dst_port), None)
            if protocol in (6, 17) and (src_port == 53 or dst_port == 53) and stream_payload:
                payload_data_dns = stream_payload if protocol == 6 else payload_data
                dns_payload = payload_data_dns
                if protocol == 6:
                    if len(payload_data_dns) < 2:
                        dns_payload = b''
                    else:
                        message_length = struct.unpack('!H', payload_data_dns[:2])[0]
                        dns_payload = payload_data_dns[2:2 + message_length] if len(payload_data_dns) >= 2 + message_length else b''
                dns_record = self._try_parse_dns(dns_payload, flow_id, src_ip, dst_ip, timestamp_ms)

            # TLS ClientHello (JA3/JA4) or ServerHello (JA3S) in one segment, any port
            if protocol == 6 and stream_payload:
                tls_record = (self._try_parse_tls_client_hello(stream_payload, flow_id, total_ip_len)
                              or self._try_parse_tls_server_hello(stream_payload, flow_id, total_ip_len))

            return flow_record, dns_record, tls_record

        except Exception as exc:
            self.dlq.record_corrupt_packet("UNHANDLED_EXCEPTION", str(exc), len(raw_data))
            return None, None, None

    @staticmethod
    def _message_length(payload: bytes, dns: bool) -> int:
        """Total bytes of the TLS record or DNS/TCP message starting this payload; 0 if neither."""
        if dns:
            return 2 + struct.unpack('!H', payload[:2])[0] if len(payload) >= 2 else 0
        if len(payload) >= 5 and payload[0] == 0x16 and payload[1] == 0x03:
            return 5 + struct.unpack('!H', payload[3:5])[0]
        return 0

    def _tcp_stream_payload(self, src, dst, sport, dport, seq, flags, payload, now):
        """Payload to parse for this segment, or None while a message is still incomplete.

        Only a TLS record or DNS message that begins in a segment and does not fit it is
        buffered (at most MAX_STREAMS flows, MAX_STREAM_BYTES each, STREAM_IDLE_SECONDS idle).
        Out-of-order or lost segments abandon the buffer rather than guess; retransmits are
        ignored. No payload is decrypted; only record/message framing is read.
        """
        key = (src, dst, sport, dport)
        if flags & 0x05:  # FIN or RST ends the stream.
            self.streams.pop(key, None)
            return payload
        entry = self.streams.get(key)
        if entry is not None and now - entry[3] > STREAM_IDLE_SECONDS:
            self.streams.pop(key, None)
            entry = None
        if entry is not None:
            gap = (seq - entry[0]) & 0xFFFFFFFF
            if gap == 0:
                entry[1] += payload
                entry[0] = (entry[0] + len(payload)) & 0xFFFFFFFF
                entry[3] = now
                if len(entry[1]) >= entry[2]:
                    del self.streams[key]
                    return bytes(entry[1][:entry[2]])
                self.streams.move_to_end(key)
                return None
            if gap > 0x7FFFFFFF:  # Retransmission of bytes already buffered.
                return None
            del self.streams[key]  # Gap: a segment is missing or reordered; never guess.
            return payload
        needed = self._message_length(payload, dns=53 in (sport, dport))
        if needed > len(payload) and needed <= MAX_STREAM_BYTES:
            self.streams[key] = [(seq + len(payload)) & 0xFFFFFFFF, bytearray(payload), needed, now]
            while len(self.streams) > MAX_STREAMS:
                self.streams.popitem(last=False)
            return None
        return payload

    @staticmethod
    def _quic_initial_fingerprint(payload: bytes) -> Optional[str]:
        """Fingerprint from the UNENCRYPTED QUIC Initial long header only. No decryption.

        Uses version, connection-ID lengths, token presence and the datagram size. The
        protected ClientHello (and so JA3/JA4) is never derived or read.
        """
        try:
            if len(payload) < 7 or payload[0] & 0xF0 != 0xC0:  # Long header, fixed bit, Initial type.
                return None
            version = struct.unpack('!I', payload[1:5])[0]
            if version == 0:  # Version negotiation.
                return None
            dcid_len = payload[5]
            pos = 6 + dcid_len
            scid_len = payload[pos]
            pos += 1 + scid_len
            token_len = payload[pos] & 0x3F  # First varint byte; only presence matters.
            token_present = int(payload[pos] & 0xC0 != 0 or token_len > 0)
            if dcid_len > 20 or scid_len > 20:
                return None
            return f'q{version:08x}.d{dcid_len}.s{scid_len}.t{token_present}.l{len(payload)}'
        except IndexError:
            return None

    @staticmethod
    def _read_dns_name(payload: bytes, offset: int) -> Tuple[str, int]:
        """Decode one bounded DNS wire name, including compression pointers."""
        labels, visited = [], set()
        next_offset = None
        wire_length = 1  # Root terminator, including the expanded name.
        while True:
            if offset < 0 or offset >= len(payload) or offset in visited:
                raise ValueError('Truncated or cyclic DNS name')
            if len(visited) >= 128:
                raise ValueError('DNS compression traversal limit exceeded')
            visited.add(offset)
            length = payload[offset]
            if length & 0xC0 == 0xC0:
                if offset + 1 >= len(payload):
                    raise ValueError('Truncated DNS pointer')
                target = ((length & 0x3F) << 8) | payload[offset + 1]
                if target >= offset:
                    raise ValueError('DNS pointer must reference an earlier name')
                if next_offset is None:
                    next_offset = offset + 2
                offset = target
                continue
            if length & 0xC0:
                raise ValueError('Unsupported DNS label encoding')
            offset += 1
            if length == 0:
                return '.'.join(labels), next_offset if next_offset is not None else offset
            if offset + length > len(payload):
                raise ValueError('Truncated DNS label')
            label = payload[offset:offset + length].decode('ascii')
            if '.' in label or any(ord(c) < 33 or ord(c) > 126 for c in label):
                raise ValueError('DNS label cannot be represented as a plain ASCII name')
            wire_length += length + 1
            if wire_length > 255:
                raise ValueError('DNS name exceeds wire length limit')
            labels.append(label)
            offset += length

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

            # Read the first question without silently dropping compressed labels.
            query_name, idx = self._read_dns_name(payload, 12)
            if not query_name or idx + 4 > len(payload):
                return None

            qtype, _ = struct.unpack("!HH", payload[idx:idx + 4])
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
            supported_versions: List[int] = []
            signature_algorithms: List[int] = []
            alpn: Optional[bytes] = None
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

                    # Signature Algorithms (Extension 13), offered order
                    elif ext_type == 13 and len(ext_data) >= 2:
                        sigs_len = struct.unpack("!H", ext_data[:2])[0]
                        for s_i in range(2, min(2 + sigs_len, len(ext_data) - 1), 2):
                            signature_algorithms.append(struct.unpack("!H", ext_data[s_i:s_i + 2])[0])

                    # ALPN (Extension 16): first protocol name only
                    elif ext_type == 16 and len(ext_data) >= 3 and alpn is None:
                        alpn = ext_data[3:3 + ext_data[2]]

                    # Supported Versions (Extension 43)
                    elif ext_type == 43 and len(ext_data) >= 1:
                        for v_i in range(1, min(1 + ext_data[0], len(ext_data) - 1), 2):
                            supported_versions.append(struct.unpack("!H", ext_data[v_i:v_i + 2])[0])

                    idx += ext_len

            # Compute JA3 string and hash
            ja3_str, ja3_hash = TLSMetadataRecord.generate_ja3(
                client_version, ciphers, extensions, elliptic_curves, point_formats
            )
            ja4 = TLSMetadataRecord.generate_ja4(
                't', client_version, ciphers, extensions, supported_versions,
                0 in extensions, alpn, signature_algorithms
            )

            return TLSMetadataRecord(
                flow_id=flow_id,
                tls_version=client_version,
                ja3_string=ja3_str,
                ja3_hash=ja3_hash,
                ja4=ja4,
                cipher_suites=ciphers,
                extension_count=len(extensions),
                sni=sni_hostname,
                splt_sequence=[packet_len]
            )

        except Exception:
            return None

    def _try_parse_tls_server_hello(
        self,
        payload: bytes,
        flow_id: str,
        packet_len: int
    ) -> Optional[TLSMetadataRecord]:
        """Extracts the cleartext ServerHello for JA3S. Metadata only, NO decryption."""
        try:
            if len(payload) < 5 or payload[0] != 0x16:
                return None
            _, record_len = struct.unpack("!HH", payload[1:5])
            if len(payload) < 5 + record_len or record_len < 38 or payload[5] != 0x02:
                return None
            end = 5 + record_len
            idx = 9  # Skip handshake type (1) + length (3)
            server_version = struct.unpack("!H", payload[idx:idx + 2])[0]
            idx += 2 + 32  # Skip version (2) + random (32)
            idx += 1 + payload[idx]  # Session ID
            if idx + 3 > end:
                return None
            cipher = struct.unpack("!H", payload[idx:idx + 2])[0]
            idx += 3  # Selected cipher (2) + compression method (1)
            extensions: List[int] = []
            if idx + 2 <= end:
                ext_end = min(idx + 2 + struct.unpack("!H", payload[idx:idx + 2])[0], end)
                idx += 2
                while idx + 4 <= ext_end:
                    ext_type, ext_len = struct.unpack("!HH", payload[idx:idx + 4])
                    extensions.append(ext_type)
                    idx += 4 + ext_len
            ja3s_str, ja3s_hash = TLSMetadataRecord.generate_ja3s(server_version, cipher, extensions)
            return TLSMetadataRecord(
                flow_id=flow_id,
                tls_version=server_version,
                ja3_string='',
                ja3_hash='',
                cipher_suites=[cipher],
                extension_count=len(extensions),
                splt_sequence=[packet_len],
                role='server',
                ja3s_string=ja3s_str,
                ja3s_hash=ja3s_hash
            )
        except Exception:
            return None
