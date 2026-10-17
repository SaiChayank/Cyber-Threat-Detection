"""Output bounds on optional evidence tooling, not runtime PCAPNG support."""
import importlib.util
from pathlib import Path
import struct
from types import SimpleNamespace
import zlib

import pytest

pytest.importorskip('stream_inflate', reason='Optional dataset header tooling')

TOOL = Path(__file__).resolve().parents[1] / 'docs/verification/uma-header-transport-20261018/read_prefix.py'
spec = importlib.util.spec_from_file_location('uma_header_prefix_tool', TOOL)
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


def archive_fixture(tmp_path, *, payload=b'\x0a\x0d\x0d\x0a' + b'x' * 1024, flags=0):
    # A stored block is shared by Deflate and Deflate64. No traffic/model is generated.
    compressed = b'\x01' + struct.pack('<HH', len(payload), len(payload) ^ 0xffff) + payload
    name = b'capture.pcapng'
    local = struct.pack('<IHHHHHIIIHH', 0x04034b50, 21, flags, 9, 0, 0,
                        zlib.crc32(payload), len(compressed), len(payload), len(name), 0)
    path = tmp_path / 'opaque.zip'
    path.write_bytes(local + name + compressed)
    info = SimpleNamespace(compress_type=9, flag_bits=flags, header_offset=0,
                           filename=name.decode(), compress_size=len(compressed))
    return path, info


def test_only_four_output_bytes_and_no_file_extraction(tmp_path):
    path, info = archive_fixture(tmp_path)
    r = tool.read_method9_prefix(path, info)
    assert r['header_hex'] == '0a0d0d0a' and r['logical_output_bytes'] == 4
    assert r['compressed_input_bytes'] <= 128
    assert not r['packet_blocks_read'] and not r['member_extracted']
    assert not r['full_member_crc_verified']
    assert list(tmp_path.iterdir()) == [path]


def test_input_cap_refuses_before_unbounded_decompression(tmp_path):
    path, info = archive_fixture(tmp_path)
    with pytest.raises(ValueError, match='bound exhausted'):
        tool.read_method9_prefix(path, info, max_compressed=1)


@pytest.mark.parametrize('field,value,message', [
    ('flag_bits', 1, 'unencrypted'), ('compress_type', 8, 'method 9'),
    ('filename', 'wrong.pcapng', 'name differs'), ('header_offset', 1, 'header missing'),
    ('compress_size', 999999, 'exceeds original'),
])
def test_catalogue_identity_mismatch_or_encryption_is_rejected(tmp_path, field, value, message):
    path, info = archive_fixture(tmp_path)
    setattr(info, field, value)
    with pytest.raises(ValueError, match=message):
        tool.read_method9_prefix(path, info)


def test_short_uncompressed_data_is_not_invented_as_complete_magic(tmp_path):
    path, info = archive_fixture(tmp_path, payload=b'\x0a\x0d')
    r = tool.read_method9_prefix(path, info)
    assert r['logical_output_bytes'] == 2 and r['header_hex'] == '0a0d'
