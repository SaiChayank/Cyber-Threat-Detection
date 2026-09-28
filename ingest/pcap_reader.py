"""
High-Speed Streaming PCAP Reader
Streams raw packet captures in chunked generators without loading the full file into memory.
"""

from pathlib import Path
import struct
import time
from typing import Generator, Tuple, Optional, List

from schemas.flow_record import FlowRecord
from schemas.dns_record import DNSRecord
from schemas.tls_metadata import TLSMetadataRecord
from ingest.protocol_parsers import ProtocolParser
from ingest.dead_letter import DeadLetterQueue


def validate_header(header):
    if len(header) != 24:
        raise ValueError('PCAP requires a complete 24-byte header')
    magic = struct.unpack('!I', header[:4])[0]
    if magic not in (0xA1B2C3D4, 0xD4C3B2A1, 0xA1B23C4D, 0x4D3CB2A1):
        raise ValueError('Unsupported capture format; upload classic Ethernet PCAP')
    endian = '>' if magic in (0xA1B2C3D4, 0xA1B23C4D) else '<'
    major, minor, _, _, snaplen, linktype = struct.unpack(f'{endian}HHiIII', header[4:])
    if (major, minor) != (2, 4) or linktype != 1:
        raise ValueError('Only PCAP v2.4 Ethernet captures are supported')
    if not 1 <= snaplen <= 16 * 1024 * 1024:
        raise ValueError('Invalid PCAP snap length')
    return snaplen


class PcapReader:
    """Zero-overhead binary streaming PCAP reader"""

    def __init__(self, parser: Optional[ProtocolParser] = None):
        self.parser = parser or ProtocolParser()

    def read_packets(
        self,
        pcap_path: str | Path,
        batch_size: int = 256
    ) -> Generator[List[Tuple[Optional[FlowRecord], Optional[DNSRecord], Optional[TLSMetadataRecord]]], None, None]:
        """
        Yields batches of parsed records directly from standard PCAP files.
        """
        pcap_file = Path(pcap_path)
        if not pcap_file.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        with open(pcap_file, "rb") as f:
            # 1. Read Global Header (24 bytes)
            global_header = f.read(24)
            snaplen = validate_header(global_header)
            if len(global_header) < 24:
                raise ValueError("Corrupt PCAP: File smaller than 24-byte global header")

            magic = struct.unpack("!I", global_header[:4])[0]
            if magic == 0xA1B2C3D4:
                endian = ">"
                nano_mult = 1e-6
            elif magic == 0xD4C3B2A1:
                endian = "<"
                nano_mult = 1e-6
            elif magic == 0xA1B23C4D:
                endian = ">"
                nano_mult = 1e-9
            elif magic == 0x4D3CB2A1:
                endian = "<"
                nano_mult = 1e-9
            else:
                raise ValueError(f"Unsupported PCAP magic number: {hex(magic)}")

            batch: List[Tuple[Optional[FlowRecord], Optional[DNSRecord], Optional[TLSMetadataRecord]]] = []

            # 2. Iterate Packet Headers (16 bytes)
            while True:
                pkt_hdr = f.read(16)
                if len(pkt_hdr) < 16:
                    if pkt_hdr:
                        raise ValueError('Truncated PCAP packet header')
                    break  # Normal EOF

                ts_sec, ts_frac, incl_len, orig_len = struct.unpack(f"{endian}IIII", pkt_hdr)
                if incl_len > snaplen or incl_len > 16 * 1024 * 1024 or incl_len > orig_len:
                    raise ValueError('Invalid PCAP packet length')
                pkt_data = f.read(incl_len)
                if len(pkt_data) < incl_len:
                    self.parser.dlq.record_truncated_packet(len(pkt_data), incl_len)
                    break

                timestamp_sec = ts_sec + (ts_frac * nano_mult)
                records = self.parser.parse_packet(pkt_data, timestamp_sec)

                if records[0] is not None:
                    batch.append(records)
                    if len(batch) >= batch_size:
                        yield batch
                        batch = []

            if batch:
                yield batch
