"""Bounded streaming reader for PCAPNG captures (Ethernet interfaces only).

Yields (epoch seconds, frame) for each Enhanced Packet Block. Simple Packet
Blocks carry no timestamp and are skipped; name-resolution, statistics and
unknown blocks are ignored. Every length is validated before it is trusted, so a
malformed file raises ValueError with a fixed diagnostic and never allocates an
attacker-chosen amount of memory. Input is read-only.
"""
import struct

MAGIC = b'\x0a\x0d\x0d\x0a'
BYTE_ORDER_MAGIC = 0x1A2B3C4D
MAX_BLOCK = 16 * 1024 * 1024 + 4096
BLOCK_SHB, BLOCK_IDB, BLOCK_EPB = 0x0A0D0D0A, 1, 6
LINKTYPE_ETHERNET = 1


def is_pcapng(head):
    return head[:4] == MAGIC


def validate_section_header(head):
    """Check the first 12-28 bytes of a PCAPNG file as an upload pre-flight."""
    if len(head) < 28:
        raise ValueError('PCAPNG requires a complete section header')
    order = _byte_order(head[8:12])
    length = struct.unpack(f'{order}I', head[4:8])[0]
    major, minor = struct.unpack(f'{order}HH', head[12:16])
    if length < 28 or length % 4 or length > MAX_BLOCK or (major, minor) != (1, 0):
        raise ValueError('Invalid PCAPNG block')


def _byte_order(magic):
    if struct.unpack('<I', magic)[0] == BYTE_ORDER_MAGIC:
        return '<'
    if struct.unpack('>I', magic)[0] == BYTE_ORDER_MAGIC:
        return '>'
    raise ValueError('Invalid PCAPNG block')


def _timestamp_divisor(options, order):
    """Ticks per second from an Interface Description Block's if_tsresol option."""
    resolution, pos = 6, 0
    while pos + 4 <= len(options):
        code, length = struct.unpack(f'{order}HH', options[pos:pos + 4])
        pos += 4
        if code == 0:
            break
        if code == 9 and length >= 1 and pos < len(options):
            resolution = options[pos]
        pos += (length + 3) & ~3
    base, exponent = (2, resolution & 0x7F) if resolution & 0x80 else (10, resolution)
    if exponent > 63:
        raise ValueError('Invalid PCAPNG block')
    return float(base ** exponent)


def iter_pcapng(stream):
    """Packets of one PCAPNG stream; sections may repeat and reset interfaces."""
    order, interfaces = None, []
    while True:
        head = stream.read(8)
        if not head:
            if order is None:
                raise ValueError('Invalid PCAPNG block')
            return
        if len(head) < 8:
            raise ValueError('Truncated PCAPNG block')
        if order is None or head[:4] == MAGIC:
            if head[:4] != MAGIC:
                raise ValueError('Invalid PCAPNG block')
            peek = stream.read(4)
            if len(peek) < 4:
                raise ValueError('Truncated PCAPNG block')
            order, interfaces = _byte_order(peek), []
            block_type, total = BLOCK_SHB, struct.unpack(f'{order}I', head[4:8])[0]
            body_prefix = peek
        else:
            block_type, total = struct.unpack(f'{order}II', head)
            body_prefix = b''
        if total < 12 or total % 4 or total > MAX_BLOCK or len(body_prefix) > total - 12:
            raise ValueError('Invalid PCAPNG block')
        rest = stream.read(total - 8 - len(body_prefix))
        if len(rest) < total - 8 - len(body_prefix):
            raise ValueError('Truncated PCAPNG block')
        body = (body_prefix + rest)[:-4]
        if struct.unpack(f'{order}I', rest[-4:])[0] != total:
            raise ValueError('Invalid PCAPNG block')
        if block_type == BLOCK_IDB:
            if len(body) < 8:
                raise ValueError('Invalid PCAPNG block')
            linktype = struct.unpack(f'{order}H', body[:2])[0]
            if linktype != LINKTYPE_ETHERNET:
                raise ValueError('Only Ethernet captures are supported')
            interfaces.append(_timestamp_divisor(body[8:], order))
        elif block_type == BLOCK_EPB:
            if len(body) < 20:
                raise ValueError('Invalid PCAPNG block')
            interface, high, low, captured, original = struct.unpack(f'{order}IIIII', body[:20])
            if interface >= len(interfaces) or captured > original or 20 + captured > len(body):
                raise ValueError('Invalid PCAPNG block')
            yield ((high << 32 | low) / interfaces[interface], body[20:20 + captured])
