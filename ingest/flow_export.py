"""Passive import of exported flow records: NetFlow v5/v9, IPFIX and sFlow v5.

Input is a classic Ethernet PCAP of the export datagrams a collector port
received (UDP 2055/2056/9025/9995/9996 NetFlow, 4739/4740 IPFIX, 6343 sFlow).
Nothing is sent back to exporters. Each flow record becomes one TrafficEvent
stamped at the flow's end time; sFlow packet samples are decoded from their
sampled headers and scaled by the sampling rate. Templates are cached per
exporter and observation domain, bounded, and never trusted across exporters.
"""
import ipaddress
import struct
from collections import OrderedDict

from ingest.pcap_reader import validate_header
from ingest.protocol_parsers import ProtocolParser
from schemas.traffic_event import TrafficEvent

EXPORT_PORTS = frozenset({2055, 2056, 9025, 9995, 9996, 4739, 4740, 6343})
MAX_TEMPLATES = 1024
MAX_PACKETS, MAX_BYTES = 1_000_000, 1_000_000_000
VARIABLE = 0xFFFF
REVERSE_PEN = 29305  # RFC 5103 reverse information elements

# NetFlow v9 field types and IPFIX information elements share these numbers.
OCTETS, PACKETS, PROTOCOL, TCP_FLAGS, SRC_PORT, SRC_V4, DST_PORT, DST_V4 = 1, 2, 4, 6, 7, 8, 11, 12
END_UPTIME, SRC_V6, DST_V6, OCTETS_TOTAL, PACKETS_TOTAL = 21, 27, 28, 85, 86
END_SECONDS, END_MILLISECONDS, SYSTEM_INIT_MS = 151, 153, 160


def _uint(raw):
    return int.from_bytes(raw, 'big') if raw is not None else None


def _address(raw):
    return str(ipaddress.ip_address(raw)) if raw is not None and len(raw) in (4, 16) else None


def frame_fields(frame):
    """Addresses, protocol, ports, TCP flags and L4 payload of an Ethernet frame.

    Tolerates truncated captures (sFlow samples carry only the first bytes),
    unlike the full packet parser. Returns None for non-IP or fragmented frames.
    """
    if len(frame) < 14:
        return None
    eth_type, offset = struct.unpack('!H', frame[12:14])[0], 14
    if eth_type == 0x8100 and len(frame) >= 18:
        eth_type, offset = struct.unpack('!H', frame[16:18])[0], 18
    if eth_type == 0x0800 and len(frame) >= offset + 20:
        ihl = (frame[offset] & 0x0F) * 4
        total, fragment = struct.unpack('!H', frame[offset + 2:offset + 4])[0], struct.unpack('!H', frame[offset + 6:offset + 8])[0]
        if frame[offset] >> 4 != 4 or ihl < 20 or fragment & 0x3FFF:
            return None
        proto, src, dst, l4 = frame[offset + 9], frame[offset + 12:offset + 16], frame[offset + 16:offset + 20], offset + ihl
    elif eth_type == 0x86DD and len(frame) >= offset + 40:
        total = 40 + struct.unpack('!H', frame[offset + 4:offset + 6])[0]
        proto, src, dst, l4 = frame[offset + 6], frame[offset + 8:offset + 24], frame[offset + 24:offset + 40], offset + 40
    else:
        return None
    fields = dict(src=_address(src), dst=_address(dst), proto=proto, ip_bytes=total, sport=0, dport=0, flags=0, payload=b'')
    if proto in (6, 17) and len(frame) >= l4 + 4:
        fields['sport'], fields['dport'] = struct.unpack('!HH', frame[l4:l4 + 4])
    if proto == 6 and len(frame) >= l4 + 14:
        fields['flags'] = struct.unpack('!H', frame[l4 + 12:l4 + 14])[0] & 0x01FF
    if proto == 17 and len(frame) >= l4 + 8:
        length = struct.unpack('!H', frame[l4 + 4:l4 + 6])[0]
        fields['payload'] = frame[l4 + 8:l4 + max(8, length)]
    return fields


def flow_event(timestamp, src, dst, sport, dport, proto, packets, octets, flags, reverse=None, **extra):
    """One TrafficEvent from aggregate flow counters; None when unusable."""
    if not src or not dst or not packets or timestamp is None or timestamp < 0:
        return None
    packets, flags = min(packets, MAX_PACKETS), flags & 0x01FF
    syn = bool(flags & 0x02)
    # Cumulative flags: SYN without ACK means every counted packet was a bare SYN.
    syn_packets = (packets if syn and not flags & 0x10 else 0 if not syn else None) if proto == 6 else None
    encrypted = 443 in (sport, dport)
    return TrafficEvent(timestamp=timestamp, src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
                        protocol=proto, packets=packets, bytes=min(octets or 0, MAX_BYTES), syn=syn,
                        syn_packets=syn_packets, tcp_fin_rst=True if proto == 6 and flags & 0x05 else None,
                        encrypted=encrypted, transport='QUIC' if proto == 17 and encrypted else 'IP',
                        reverse_bytes=None if reverse is None else min(reverse, MAX_BYTES),
                        reverse_observed=reverse is not None, **extra)


class FlowExportDecoder:
    def __init__(self):
        self.templates = OrderedDict()  # (exporter, version, domain, template id) -> fields
        self.packet_parser = ProtocolParser()
        self.stats = dict(datagrams=0, records=0, skipped_records=0, missing_template=0,
                          malformed=0, unsupported=0, other_packets=0)

    def decode(self, payload, exporter, arrival_ms):
        """Events from one export datagram, in flow end-time order."""
        self.stats['datagrams'] += 1
        try:
            if len(payload) >= 4 and struct.unpack('!I', payload[:4])[0] == 5:
                events = self._sflow(payload, arrival_ms)
            else:
                version = struct.unpack('!H', payload[:2])[0] if len(payload) >= 2 else None
                decoder = {5: self._netflow5, 9: self._netflow9, 10: self._ipfix}.get(version)
                if decoder is None:
                    self.stats['unsupported'] += 1
                    return []
                events = decoder(payload, exporter)
        except (struct.error, ValueError, IndexError):
            self.stats['malformed'] += 1
            return []
        self.stats['records'] += len(events)
        return sorted(events, key=lambda event: event.timestamp)

    def _keep(self, event):
        if event is None:
            self.stats['skipped_records'] += 1
        return event is not None

    def _netflow5(self, data, exporter):
        count, uptime, secs, nsecs = struct.unpack('!HIII', data[2:16])
        if len(data) < 24 + 48 * count:
            raise ValueError('Truncated NetFlow v5 datagram')
        boot_ms = secs * 1000 + nsecs / 1e6 - uptime
        events = []
        for index in range(count):
            r = data[24 + 48 * index:72 + 48 * index]
            packets, octets, _, last = struct.unpack('!IIII', r[16:32])
            sport, dport = struct.unpack('!HH', r[32:36])
            event = flow_event(boot_ms + last, _address(r[0:4]), _address(r[4:8]), sport, dport,
                               r[38], packets, octets, r[37])
            if self._keep(event):
                events.append(event)
        return events

    def _netflow9(self, data, exporter):
        _, uptime, secs, _, source_id = struct.unpack('!HIIII', data[2:20])
        return self._sets(data, 20, len(data), (exporter, 9, source_id), 0, 1,
                          boot_ms=secs * 1000 - uptime, export_ms=secs * 1000, ipfix=False)

    def _ipfix(self, data, exporter):
        length, export_time, _, domain = struct.unpack('!HIII', data[2:16])
        if not 16 <= length <= len(data):
            raise ValueError('Invalid IPFIX message length')
        return self._sets(data, 16, length, (exporter, 10, domain), 2, 3,
                          boot_ms=None, export_ms=export_time * 1000, ipfix=True)

    def _sets(self, data, offset, end, scope, template_set, options_set, boot_ms, export_ms, ipfix):
        events = []
        while offset + 4 <= end:
            set_id, set_length = struct.unpack('!HH', data[offset:offset + 4])
            if set_length < 4 or offset + set_length > end:
                raise ValueError('Invalid flow set length')
            body = data[offset + 4:offset + set_length]
            if set_id == template_set:
                self._templates(body, scope, ipfix)
            elif set_id >= 256:
                fields = self.templates.get(scope + (set_id,))
                if fields is None:
                    self.stats['missing_template'] += 1
                else:
                    events.extend(self._records(body, fields, boot_ms, export_ms))
            # Options templates/records describe the exporter, not observed flows.
            offset += set_length
        return events

    def _templates(self, body, scope, ipfix):
        pos = 0
        while pos + 4 <= len(body):
            template_id, count = struct.unpack('!HH', body[pos:pos + 4])
            pos += 4
            if template_id < 256:
                break  # Set padding.
            fields = []
            for _ in range(count):
                field_id, length = struct.unpack('!HH', body[pos:pos + 4])
                pos += 4
                enterprise = 0
                if ipfix and field_id & 0x8000:
                    field_id &= 0x7FFF
                    enterprise = struct.unpack('!I', body[pos:pos + 4])[0]
                    pos += 4
                fields.append((field_id, enterprise, length))
            key = scope + (template_id,)
            self.templates.pop(key, None)
            if fields:  # IPFIX withdraws a template with zero fields.
                self.templates[key] = tuple(fields)
                if len(self.templates) > MAX_TEMPLATES:
                    self.templates.popitem(last=False)

    def _records(self, body, fields, boot_ms, export_ms):
        minimum = max(1, sum(length if length != VARIABLE else 1 for _, _, length in fields))
        events, pos = [], 0
        while len(body) - pos >= minimum:
            values = {}
            for field_id, enterprise, length in fields:
                if length == VARIABLE:
                    length, pos = body[pos], pos + 1
                    if length == 255:
                        length, pos = struct.unpack('!H', body[pos:pos + 2])[0], pos + 2
                raw = body[pos:pos + length]
                if len(raw) < length:
                    raise ValueError('Truncated flow record')
                values[(enterprise, field_id)] = raw
                pos += length
            event = self._record_event(values, boot_ms, export_ms)
            if self._keep(event):
                events.append(event)
        return events

    @staticmethod
    def _record_event(values, boot_ms, export_ms):
        def get(field_id, enterprise=0):
            return values.get((enterprise, field_id))
        if get(END_MILLISECONDS) is not None:
            end = _uint(get(END_MILLISECONDS))
        elif get(END_SECONDS) is not None:
            end = _uint(get(END_SECONDS)) * 1000
        elif get(END_UPTIME) is not None and (boot_ms is not None or get(SYSTEM_INIT_MS) is not None):
            end = (boot_ms if boot_ms is not None else _uint(get(SYSTEM_INIT_MS))) + _uint(get(END_UPTIME))
        else:
            end = export_ms
        packets = _uint(get(PACKETS)) if get(PACKETS) is not None else _uint(get(PACKETS_TOTAL))
        octets = _uint(get(OCTETS)) if get(OCTETS) is not None else _uint(get(OCTETS_TOTAL))
        return flow_event(end, _address(get(SRC_V4) or get(SRC_V6)), _address(get(DST_V4) or get(DST_V6)),
                          _uint(get(SRC_PORT)) or 0, _uint(get(DST_PORT)) or 0, _uint(get(PROTOCOL)) or 0,
                          packets, octets, _uint(get(TCP_FLAGS)) or 0,
                          reverse=_uint(get(OCTETS, REVERSE_PEN)))

    def _sflow(self, data, arrival_ms):
        address_type = struct.unpack('!I', data[4:8])[0]
        if address_type not in (1, 2):
            raise ValueError('Unknown sFlow agent address type')
        pos = 8 + (4 if address_type == 1 else 16) + 12  # Agent, sub-agent, sequence, uptime.
        samples = struct.unpack('!I', data[pos:pos + 4])[0]
        pos += 4
        events = []
        for _ in range(samples):
            sample_format, length = struct.unpack('!II', data[pos:pos + 8])
            body = data[pos + 8:pos + 8 + length]
            if len(body) < length:
                raise ValueError('Truncated sFlow sample')
            pos += 8 + length
            if sample_format in (1, 3):  # Flow samples; counter samples carry no flows.
                events.extend(self._sflow_flow_sample(body, sample_format == 3, arrival_ms))
        return events

    def _sflow_flow_sample(self, body, expanded, arrival_ms):
        rate_at, count_at, pos = (12, 40, 44) if expanded else (8, 28, 32)
        rate = max(1, struct.unpack('!I', body[rate_at:rate_at + 4])[0])
        events = []
        for _ in range(struct.unpack('!I', body[count_at:count_at + 4])[0]):
            record_format, length = struct.unpack('!II', body[pos:pos + 8])
            record = body[pos + 8:pos + 8 + length]
            pos += 8 + length
            if record_format != 1 or len(record) < 16:
                continue  # Only raw packet header records are decoded.
            header_protocol, _, _, header_length = struct.unpack('!IIII', record[:16])  # Frame/stripped lengths unused.
            header = record[16:16 + header_length]
            fields = frame_fields(header) if header_protocol == 1 else None
            if fields is None:
                self.stats['skipped_records'] += 1
                continue
            # DNS/TLS sidecars only when the sampled header holds them completely.
            _, dns, tls = self.packet_parser.parse_packet(header, arrival_ms / 1000)
            client = tls if tls and tls.role == 'client' else None
            server = tls if tls and tls.role == 'server' else None
            # The sampled IP header's total length is exact even when the header is truncated.
            event = flow_event(arrival_ms, fields['src'], fields['dst'], fields['sport'], fields['dport'],
                               fields['proto'], rate, fields['ip_bytes'] * rate, fields['flags'],
                               dns_name=dns.query_name if dns else None, dns_type=dns.query_type if dns else 1,
                               tls_fingerprint=client.ja3_hash if client else None,
                               tls_ja4=client.ja4 if client else None,
                               tls_server_fingerprint=server.ja3s_hash if server else None)
            if self._keep(event):
                events.append(event.model_copy(update=dict(encrypted=event.encrypted or bool(tls),
                                                           transport='TLS' if tls else event.transport)))
        return events


def iter_frames(path):
    """(epoch ms, frame) for each complete packet of a classic Ethernet PCAP."""
    with open(path, 'rb') as capture:
        header = capture.read(24)
        snaplen = validate_header(header)
        magic = struct.unpack('!I', header[:4])[0]
        endian = '>' if magic in (0xA1B2C3D4, 0xA1B23C4D) else '<'
        fraction = 1e-6 if magic in (0xA1B2C3D4, 0xD4C3B2A1) else 1e-9
        while len(record := capture.read(16)) == 16:
            seconds, part, included, original = struct.unpack(f'{endian}IIII', record)
            if included > snaplen or included > original:
                raise ValueError('Invalid PCAP packet length')
            frame = capture.read(included)
            if len(frame) < included:
                raise ValueError('Truncated PCAP packet')
            yield (seconds + part * fraction) * 1000, frame
        if record:
            raise ValueError('Truncated PCAP packet header')


def read_flow_export(path, decoder=None, ports=EXPORT_PORTS):
    """TrafficEvents from a PCAP of received flow-export datagrams."""
    decoder = decoder or FlowExportDecoder()
    for arrival_ms, frame in iter_frames(path):
        fields = frame_fields(frame)
        if fields is None or fields['proto'] != 17 or fields['dport'] not in ports:
            decoder.stats['other_packets'] += 1
            continue
        yield from decoder.decode(fields['payload'], fields['src'], arrival_ms)
