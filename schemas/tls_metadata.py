"""
Canonical TLSMetadataRecord Schema
Zero-payload decryption: extracts ClientHello fingerprints (JA3/JA4) and SPLT sequence
"""

from dataclasses import dataclass, field
import hashlib
from typing import List, Optional


@dataclass(slots=True)
class TLSMetadataRecord:
    """TLS/QUIC handshake metadata and packet sequence dynamics without payload decryption"""
    flow_id: str                      # Association back to parent FlowRecord
    tls_version: int                  # Negotiated/offered version (0x0303=TLS 1.2, 0x0304=TLS 1.3)
    ja3_string: str                   # Raw JA3 string: SSLVersion,Ciphers,Extensions,EllipticCurves,PointFormats
    ja3_hash: str                     # md5(ja3_string)
    ja4: Optional[str] = None         # Modern JA4 fingerprint format if available
    cipher_suites: List[int] = field(default_factory=list)
    extension_count: int = 0
    sni: Optional[str] = None         # Server Name Indication hostname if unencrypted
    splt_sequence: List[int] = field(default_factory=list)  # First 20 signed packet lengths for SPLT profiling
    is_quic: bool = False
    role: str = 'client'              # 'client' (ClientHello: JA3/JA4) or 'server' (ServerHello: JA3S)
    ja3s_string: Optional[str] = None  # Raw JA3S string: SSLVersion,Cipher,Extensions
    ja3s_hash: Optional[str] = None    # md5(ja3s_string)

    @staticmethod
    def generate_ja3s(ssl_version: int, cipher: int, extensions: List[int]) -> tuple[str, str]:
        """JA3S from a ServerHello: version, selected cipher and extension order."""
        clean_exts = [str(e) for e in extensions if (e & 0x0F0F) != 0x0A0A]
        ja3s_str = f"{ssl_version},{cipher},{'-'.join(clean_exts)}"
        return ja3s_str, hashlib.md5(ja3s_str.encode("utf-8")).hexdigest()

    @staticmethod
    def generate_ja4(
        transport: str,
        legacy_version: int,
        ciphers: List[int],
        extensions: List[int],
        supported_versions: List[int],
        has_sni: bool,
        alpn: Optional[bytes],
        signature_algorithms: List[int]
    ) -> str:
        """JA4 client fingerprint (FoxIO JA4 specification, BSD 3-Clause).

        a: transport, highest offered version, SNI flag, cipher/extension counts,
        first/last ALPN characters; b: truncated SHA256 of sorted ciphers;
        c: truncated SHA256 of sorted extensions (without SNI/ALPN) and
        signature algorithms in offered order. GREASE values are ignored.
        """
        def clean(values):
            return [v for v in values if (v & 0x0F0F) != 0x0A0A]

        def digest(text):
            return hashlib.sha256(text.encode()).hexdigest()[:12] if text else '000000000000'

        versions = clean(supported_versions)
        version = max(versions) if versions else legacy_version
        version_code = {0x0304: '13', 0x0303: '12', 0x0302: '11', 0x0301: '10', 0x0300: 's3',
                        0x0002: 's2', 0xFEFF: 'd1', 0xFEFD: 'd2', 0xFEFC: 'd3'}.get(version, '00')
        ciphers, extensions = clean(ciphers), clean(extensions)
        if not alpn:
            alpn_code = '00'
        elif chr(alpn[0]).isascii() and chr(alpn[0]).isalnum() and chr(alpn[-1]).isascii() and chr(alpn[-1]).isalnum():
            alpn_code = chr(alpn[0]) + chr(alpn[-1])
        else:
            alpn_hex = alpn.hex()
            alpn_code = alpn_hex[0] + alpn_hex[-1]
        part_a = (f"{transport}{version_code}{'d' if has_sni else 'i'}"
                  f"{min(len(ciphers), 99):02d}{min(len(extensions), 99):02d}{alpn_code}")
        part_b = digest(','.join(f'{c:04x}' for c in sorted(ciphers)))
        sorted_exts = ','.join(f'{e:04x}' for e in sorted(e for e in extensions if e not in (0x0000, 0x0010)))
        signatures = ','.join(f'{s:04x}' for s in clean(signature_algorithms))
        part_c = digest(sorted_exts + (f'_{signatures}' if sorted_exts and signatures else ''))
        return f'{part_a}_{part_b}_{part_c}'

    @staticmethod
    def generate_ja3(
        ssl_version: int,
        ciphers: List[int],
        extensions: List[int],
        elliptic_curves: List[int],
        point_formats: List[int]
    ) -> tuple[str, str]:
        """
        Builds RFC-standardized JA3 string and MD5 hash.
        Ignores GREASE values per the JA3 standard specification.
        """
        # Filter GREASE values (0x?a?a where ? in 0..f)
        def is_grease(val: int) -> bool:
            return (val & 0x0F0F) == 0x0A0A

        clean_ciphers = [str(c) for c in ciphers if not is_grease(c)]
        clean_exts = [str(e) for e in extensions if not is_grease(e)]
        clean_curves = [str(crv) for crv in elliptic_curves if not is_grease(crv)]
        clean_points = [str(p) for p in point_formats if not is_grease(p)]

        ja3_str = (
            f"{ssl_version},"
            f"{'-'.join(clean_ciphers)},"
            f"{'-'.join(clean_exts)},"
            f"{'-'.join(clean_curves)},"
            f"{'-'.join(clean_points)}"
        )
        ja3_md5 = hashlib.md5(ja3_str.encode("utf-8")).hexdigest()
        return ja3_str, ja3_md5
