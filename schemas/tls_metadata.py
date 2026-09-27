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
