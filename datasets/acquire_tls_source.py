"""Obtain one frozen development PCAP member without fetching a large ZIP.

Administrative publisher download only; no runtime ingest/network changes.
Catalogue selection precedes packet-content retrieval. Whole ZIP SHA256 cannot
be verified by this partial archive retrieval; the complete member CRC can.
"""
import argparse
import binascii
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import struct
import zlib

import httpx


MAX_COMPRESSED = 256 * 1024 * 1024
MAX_RAW = 1024 * 1024 * 1024


def range_bytes(client, url, value, expected_total=None):
    with client.stream('GET', url, headers={'Range': value}) as response:
        response.raise_for_status()
        match = re.fullmatch(r'bytes (\d+)-(\d+)/(\d+)', response.headers.get('content-range', ''))
        if response.status_code != 206 or match is None:
            raise ValueError('Publisher does not support verified HTTP byte ranges')
        start, end, total = map(int, match.groups())
        if expected_total is not None and total != expected_total:
            raise ValueError('Archive length changed during acquisition')
        if end < start or end >= total or end - start + 1 > MAX_COMPRESSED:
            raise ValueError('Invalid or oversized publisher range')
        expected, received, chunks = end - start + 1, 0, []
        for chunk in response.iter_bytes(65536):
            received += len(chunk)
            if received > expected:
                raise ValueError('Publisher body exceeds declared byte range')
            chunks.append(chunk)
        body = b''.join(chunks)
        if len(body) != end - start + 1:
            raise ValueError('Incomplete publisher byte range')
        return start, total, body


def catalogue(client, url):
    start, total, tail = range_bytes(client, url, 'bytes=-65557')
    position = tail.rfind(b'PK\x05\x06')
    if position < 0 or len(tail) < position + 22:
        raise ValueError('No complete ZIP end-of-directory')
    _, disk, cd_disk, entries_disk, entries, size, offset, comment = struct.unpack_from('<4s4H2IH', tail, position)
    if (disk or cd_disk or entries_disk != entries or entries == 65535 or
            size == 0xffffffff or offset == 0xffffffff or position + 22 + comment != len(tail)):
        raise ValueError('Unsupported split/ZIP64/invalid archive catalogue')
    if size > 1024 * 1024 or offset + size > start + position:
        raise ValueError('Invalid or oversized ZIP catalogue')
    if offset >= start:
        directory = tail[offset - start:offset - start + size]
    else:
        actual, _, directory = range_bytes(client, url, f'bytes={offset}-{offset + size - 1}', total)
        if actual != offset:
            raise ValueError('Wrong ZIP catalogue range')
    cursor, members = 0, []
    for _ in range(entries):
        if cursor + 46 > len(directory):
            raise ValueError('Truncated ZIP catalogue')
        fields = struct.unpack_from('<4s6H3I5H2I', directory, cursor)
        if fields[0] != b'PK\x01\x02':
            raise ValueError('Invalid ZIP catalogue entry')
        flags, method, crc, compressed, raw = fields[3], fields[4], fields[7], fields[8], fields[9]
        name_size, extra_size, comment_size, local_offset = fields[10], fields[11], fields[12], fields[16]
        name_end = cursor + 46 + name_size
        cursor_end = name_end + extra_size + comment_size
        if cursor_end > len(directory) or 0xffffffff in (compressed, raw, local_offset):
            raise ValueError('Truncated/ZIP64 member is unsupported')
        name = directory[cursor + 46:name_end].decode('utf-8' if flags & 0x800 else 'cp437')
        members.append({'name': name, 'compressed_bytes': compressed, 'raw_bytes': raw,
                        'crc32': crc, 'method': method, 'flags': flags, 'local_offset': local_offset})
        cursor = cursor_end
    if cursor != len(directory):
        raise ValueError('Unaccounted ZIP catalogue bytes')
    choices = sorted((m for m in members if m['name'].lower().endswith('.pcap')),
                     key=lambda m: (m['compressed_bytes'], m['name']))
    if not choices:
        raise ValueError('Archive has no PCAP member')
    selected = choices[0]
    if selected['compressed_bytes'] > MAX_COMPRESSED or selected['raw_bytes'] > MAX_RAW:
        raise ValueError('Selected PCAP exceeds frozen acquisition caps')
    return {'role': 'development-only', 'url': url, 'archive_bytes': total,
            'archive_sha256_locally_verified': False, 'members': members, 'selected': selected}


def download_member(client, selection, output):
    if selection['role'] != 'development-only':
        raise ValueError('Only frozen development acquisition is supported')
    member, total, url = selection['selected'], selection['archive_bytes'], selection['url']
    name = PurePosixPath(member['name'])
    if name.is_absolute() or '..' in name.parts or not member['name'].lower().endswith('.pcap'):
        raise ValueError('Unsafe selected member name')
    if (member['flags'] & 1 or member['method'] not in (0, 8) or
            member['compressed_bytes'] > MAX_COMPRESSED or member['raw_bytes'] > MAX_RAW):
        raise ValueError('Unsupported or oversized selected member')
    offset = member['local_offset']
    actual, _, header = range_bytes(client, url, f'bytes={offset}-{offset + 29}', total)
    if actual != offset or len(header) != 30:
        raise ValueError('Wrong local ZIP header range')
    fields = struct.unpack('<4s5H3I2H', header)
    if fields[0] != b'PK\x03\x04' or fields[2] != member['flags'] or fields[3] != member['method']:
        raise ValueError('ZIP local header disagrees with frozen catalogue')
    length = fields[-2] + fields[-1]
    actual, _, extra = range_bytes(client, url, f'bytes={offset + 30}-{offset + 29 + length}', total)
    encoding = 'utf-8' if member['flags'] & 0x800 else 'cp437'
    if actual != offset + 30 or extra[:fields[-2]].decode(encoding) != member['name']:
        raise ValueError('ZIP local filename disagrees with frozen selection')
    data_offset = offset + 30 + length
    actual, _, compressed = range_bytes(client, url,
        f"bytes={data_offset}-{data_offset + member['compressed_bytes'] - 1}", total)
    if actual != data_offset or len(compressed) != member['compressed_bytes']:
        raise ValueError('Incomplete selected ZIP member')
    decoder = zlib.decompressobj(-15) if member['method'] == 8 else None
    raw = decoder.decompress(compressed, MAX_RAW + 1) if decoder else compressed
    if decoder and (not decoder.eof or decoder.unused_data or decoder.unconsumed_tail):
        raise ValueError('Incomplete or trailing compressed member')
    if len(raw) != member['raw_bytes'] or binascii.crc32(raw) & 0xffffffff != member['crc32']:
        raise ValueError('Selected PCAP size/CRC mismatch')
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('xb') as handle:
        handle.write(raw)
    return {'member': member['name'], 'file': str(output), 'bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest(), 'zip_member_crc32_verified': True,
            'whole_archive_sha256_verified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    cat = sub.add_parser('catalogue')
    cat.add_argument('--url', required=True)
    cat.add_argument('--output', type=Path, required=True)
    get = sub.add_parser('download')
    get.add_argument('--selection', type=Path, required=True)
    get.add_argument('--output', type=Path, required=True)
    get.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    with httpx.Client(timeout=120, follow_redirects=True) as client:
        if args.mode == 'catalogue':
            report = catalogue(client, args.url)
            with args.output.open('x', encoding='utf-8') as handle:
                json.dump(report, handle, indent=2)
            print(json.dumps(report['selected']))
        else:
            selection = json.loads(args.selection.read_text(encoding='utf-8'))
            if args.output.exists() or args.report.exists():
                raise ValueError('Refusing to overwrite existing acquisition')
            report = download_member(client, selection, args.output)
            with args.report.open('x', encoding='utf-8') as handle:
                json.dump(report, handle, indent=2)
            print(json.dumps(report))


if __name__ == '__main__':
    main()
