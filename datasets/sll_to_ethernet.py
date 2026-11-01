"""Rewrite a classic PCAP captured on a Linux 'any' interface (link type 113) as an Ethernet PCAP.

The runtime reader accepts Ethernet captures only, so this offline step maps each cooked frame (16-byte header whose
last two bytes are the EtherType) to a synthetic Ethernet frame with zero MAC addresses. Packet bytes after the cooked
header and all timestamps are copied unchanged. The input is read-only.

Usage: python -m datasets.sll_to_ethernet IN.pcap OUT.pcap
"""
import struct
import sys

MAGICS = {0xA1B2C3D4: '>', 0xD4C3B2A1: '<', 0xA1B23C4D: '>', 0x4D3CB2A1: '<'}
COOKED = 113
ETHERNET = 1


def convert(source, target):
    with open(source, 'rb') as src, open(target, 'wb') as out:
        head = src.read(24)
        endian = MAGICS.get(struct.unpack('!I', head[:4])[0])
        if endian is None or len(head) != 24:
            raise ValueError('Not a classic PCAP')
        linktype = struct.unpack(f'{endian}I', head[20:24])[0]
        if linktype != COOKED:
            raise ValueError(f'Expected link type {COOKED}, found {linktype}')
        out.write(head[:20] + struct.pack(f'{endian}I', ETHERNET))
        kept = dropped = 0
        while True:
            hdr = src.read(16)
            if len(hdr) < 16:
                break
            sec, frac, incl, orig = struct.unpack(f'{endian}IIII', hdr)
            frame = src.read(incl)
            if len(frame) < incl:
                break
            if incl < 16:
                dropped += 1
                continue
            new = b'\x00' * 12 + frame[14:16] + frame[16:]
            out.write(struct.pack(f'{endian}IIII', sec, frac, len(new), max(orig - 2, len(new))) + new)
            kept += 1
    return kept, dropped


if __name__ == '__main__':
    print('frames written %d, too short %d' % convert(sys.argv[1], sys.argv[2]))
