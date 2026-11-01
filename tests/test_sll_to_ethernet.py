"""Linux cooked (link type 113) captures convert to Ethernet PCAPs the runtime reader accepts."""
import struct

import pytest

from datasets.sll_to_ethernet import convert
from ingest.pcap_reader import PcapReader


def ipv4_udp():
    payload = b'hello'
    udp = struct.pack('!HHHH', 5000, 53, 8 + len(payload), 0) + payload
    return struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0x4000, 64, 17, 0,
                       bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])) + udp


def cooked_pcap(path, linktype=113):
    cooked = struct.pack('!HHH8sH', 0, 1, 6, b'\x00' * 8, 0x0800) + ipv4_udp()
    with open(path, 'wb') as out:
        out.write(struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        out.write(struct.pack('<IIII', 1_700_000_000, 0, len(cooked), len(cooked)) + cooked)
    return cooked


def test_cooked_capture_becomes_readable_ethernet(tmp_path):
    source, target = tmp_path / 'in.pcap', tmp_path / 'out.pcap'
    cooked_pcap(source)
    with pytest.raises(ValueError):
        list(PcapReader().read_packets(source))
    assert convert(source, target) == (1, 0)
    batches = list(PcapReader().read_packets(target))
    assert sum(len(b) for b in batches) == 1


def test_non_cooked_input_is_refused(tmp_path):
    source = tmp_path / 'eth.pcap'
    cooked_pcap(source, linktype=1)
    with pytest.raises(ValueError):
        convert(source, tmp_path / 'out.pcap')
