"""Cut one classic Ethernet PCAP into equal time slices (read-only on the input).

Run: python -m datasets.slice_capture INPUT.pcap OUT_DIR [--parts 3]

Writes OUT_DIR/<stem>.part1.pcap ... and prints each slice's [start_ms, end_ms] window so
label files can name it. Packets keep their original bytes and timestamps. A time slice of
one recording is NOT an independent run (same hosts, same malware): use it for development
splits when only one capture exists, and say so wherever results are reported.
"""
import argparse
import struct
import sys
from pathlib import Path

from ingest.pcap_reader import validate_header

MAGICS = {0xA1B2C3D4: ('>', 1e-6), 0xD4C3B2A1: ('<', 1e-6), 0xA1B23C4D: ('>', 1e-9), 0x4D3CB2A1: ('<', 1e-9)}


def packets(path):
    """(header bytes, endian, resolution, iterator of (timestamp seconds, record bytes))."""
    with open(path, 'rb') as stream:
        header = stream.read(24)
        validate_header(header)
        endian, resolution = MAGICS[struct.unpack('!I', header[:4])[0]]
        records = []
        while len(record_header := stream.read(16)) == 16:
            seconds, fraction, included, _ = struct.unpack(f'{endian}IIII', record_header)
            data = stream.read(included)
            if len(data) < included:
                break
            records.append((seconds + fraction * resolution, record_header + data))
    return header, records


def slice_capture(path, out_dir, parts=3):
    if parts < 2:
        raise ValueError('Use at least 2 parts')
    header, records = packets(path)
    if len(records) < parts:
        raise ValueError('Capture has fewer packets than parts')
    start, end = records[0][0], records[-1][0]
    width = (end - start) / parts or 1.0
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    buckets = [[] for _ in range(parts)]
    for timestamp, record in records:
        buckets[min(parts - 1, int((timestamp - start) / width))].append((timestamp, record))
    windows = []
    for index, bucket in enumerate(buckets, 1):
        target = out_dir / f'{Path(path).stem}.part{index}.pcap'
        target.write_bytes(header + b''.join(record for _, record in bucket))
        windows.append(dict(file=target.name, packets=len(bucket),
                            start_ms=int(bucket[0][0] * 1000) if bucket else None,
                            end_ms=int(bucket[-1][0] * 1000) + 1 if bucket else None))
    return windows


def main(argv=None):
    parser = argparse.ArgumentParser(description='Cut a classic PCAP into equal time slices.')
    parser.add_argument('capture', type=Path)
    parser.add_argument('out_dir', type=Path)
    parser.add_argument('--parts', type=int, default=3)
    args = parser.parse_args(argv)
    if args.out_dir.resolve() == args.capture.resolve().parent:
        parser.error('write slices to a different directory than the input')
    try:
        windows = slice_capture(args.capture, args.out_dir, args.parts)
    except (ValueError, OSError) as exc:
        parser.exit(2, f'error: {exc}\n')
    for window in windows:
        print(window)
    return 0


if __name__ == '__main__':
    sys.exit(main())
