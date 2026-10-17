"""Evidence-local ZIP transport only; no packet parsing or archive extraction."""
from pathlib import Path
import struct

from stream_inflate import stream_inflate64


def read_method9_prefix(path, info, *, max_compressed=1024 * 1024):
    """Return at most four decompressed bytes from an unencrypted pinned entry."""
    if info.compress_type != 9 or info.flag_bits & 1:
        raise ValueError('Only unencrypted ZIP method 9 is allowed')
    if max_compressed < 1:
        raise ValueError('Positive compressed-input bound required')
    with Path(path).open('rb') as handle:
        handle.seek(info.header_offset)
        local = handle.read(30)
        if len(local) != 30 or local[:4] != b'PK\x03\x04':
            raise ValueError('Local ZIP header missing')
        fields = struct.unpack('<IHHHHHIIIHH', local)
        flags, method, name_length, extra_length = fields[2], fields[3], fields[9], fields[10]
        if flags != info.flag_bits or method != 9:
            raise ValueError('Local ZIP method/flags differ from catalogue')
        name = handle.read(name_length)
        encoding = 'utf-8' if flags & 0x800 else 'cp437'
        if name.decode(encoding) != info.filename:
            raise ValueError('Local ZIP name differs from catalogue')
        handle.seek(extra_length, 1)
        if handle.tell() + info.compress_size > Path(path).stat().st_size:
            raise ValueError('Compressed entry exceeds original archive')
        read_count = 0

        def compressed_chunks():
            nonlocal read_count
            while read_count < info.compress_size:
                remaining = min(info.compress_size - read_count, max_compressed - read_count)
                if remaining <= 0:
                    raise ValueError('Compressed-input bound exhausted before prefix')
                data = handle.read(min(128, remaining))
                if not data:
                    raise ValueError('Truncated compressed entry')
                read_count += len(data)
                yield data

        inflate, _, _ = stream_inflate64(chunk_size=4)
        output = iter(inflate(compressed_chunks()))
        try:
            first = next(output, b'')
            if len(first) > 4:
                raise ValueError('Decoder exceeded four-byte output bound')
        finally:
            output.close()
    return dict(header_hex=first.hex(), logical_output_bytes=len(first),
                compressed_input_bytes=read_count, full_member_crc_verified=False,
                packet_blocks_read=False, member_extracted=False)
