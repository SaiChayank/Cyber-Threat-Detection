import struct

import pytest

from datasets import slice_capture
from ingest.pcap_reader import PcapReader


def capture(path, times, byte_order='<'):
    header = struct.pack(f'{byte_order}IHHiIII', 0xA1B2C3D4 if byte_order == '>' else 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    if byte_order == '<':
        header = struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    frame = (b'\x00' * 12 + b'\x08\x00' + struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40, 1, 0, 64, 6, 0, b'\x0a\x00\x00\x01', b'\x0a\x00\x00\x02')
             + struct.pack('!HHIIHHHH', 40000, 80, 1, 1, (5 << 12) | 0x10, 1000, 0, 0))
    body = b''.join(struct.pack(f'{byte_order}IIII', int(t), int((t % 1) * 1e6), len(frame), len(frame)) + frame for t in times)
    path.write_bytes(header + body)


def test_slices_are_equal_in_time_lossless_and_readable(tmp_path):
    source = tmp_path / 'in' / 'run.pcap'
    source.parent.mkdir()
    times = [1_700_000_000 + i for i in range(30)]
    capture(source, times)
    before = source.read_bytes()
    windows = slice_capture.slice_capture(source, tmp_path / 'out', parts=3)
    assert [w['packets'] for w in windows] == [10, 10, 10]
    assert windows[0]['end_ms'] <= windows[1]['start_ms'] + 1000 and windows[1]['end_ms'] <= windows[2]['start_ms'] + 1000
    total = 0
    for window in windows:
        flows = [f for b in PcapReader().read_packets(tmp_path / 'out' / window['file']) for f, _, _ in b]
        total += len(flows)
        assert all(window['start_ms'] <= f.timestamp_start < window['end_ms'] for f in flows)
    assert total == 30 and source.read_bytes() == before  # Input untouched.


def test_rejects_bad_arguments(tmp_path):
    source = tmp_path / 'in' / 'run.pcap'
    source.parent.mkdir()
    capture(source, [1_700_000_000, 1_700_000_001])
    with pytest.raises(ValueError, match='at least 2'):
        slice_capture.slice_capture(source, tmp_path / 'o', parts=1)
    with pytest.raises(ValueError, match='fewer packets'):
        slice_capture.slice_capture(source, tmp_path / 'o', parts=5)
    with pytest.raises(SystemExit):
        slice_capture.main([str(source), str(source.parent)])
