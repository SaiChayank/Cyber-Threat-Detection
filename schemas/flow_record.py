"""
Canonical FlowRecord Schema
Supports unidirectional diode links (bytes_backward = 0 safe)
"""

from dataclasses import dataclass, field
import hashlib
from typing import List, Optional


@dataclass(slots=True)
class FlowRecord:
    """Core canonical flow object populated across all ingestion formats"""
    flow_id: str                      # Unique 32-char hex hash of (src_ip, dst_ip, src_port, dst_port, proto, start_ms)
    src_ip: str
    dst_ip: str
    src_port: Optional[int]           # Nullable for portless protocols (e.g. ICMP)
    dst_port: Optional[int]           # Nullable for portless protocols
    protocol: int                     # IANA protocol number (e.g. TCP=6, UDP=17, ICMP=1)
    timestamp_start: float            # Millisecond epoch timestamp of first packet
    timestamp_end: float              # Millisecond epoch timestamp of latest packet
    packets_forward: int = 0
    packets_backward: int = 0         # Maintained at 0 on unidirectional diode links
    bytes_forward: int = 0
    bytes_backward: int = 0           # Maintained at 0 on unidirectional diode links
    tcp_flags_forward: int = 0        # Bitwise OR cumulative TCP flags seen
    tcp_flags_backward: int = 0
    inter_arrival_times: List[float] = field(default_factory=list)  # Inter-packet arrival deltas in seconds
    is_unidirectional: bool = True    # Explicitly flags unidirectional capture invariant

    @staticmethod
    def compute_flow_id(
        src_ip: str,
        dst_ip: str,
        src_port: Optional[int],
        dst_port: Optional[int],
        protocol: int,
        start_ms: float
    ) -> str:
        """Deterministically generates a stable 32-character flow ID hash"""
        raw_key = f"{src_ip}:{src_port or 0}->{dst_ip}:{dst_port or 0}:{protocol}:{start_ms:.1f}"
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:32]

    @property
    def duration_seconds(self) -> float:
        """Calculates total flow duration in seconds"""
        if self.timestamp_end >= self.timestamp_start:
            return (self.timestamp_end - self.timestamp_start) / 1000.0
        return 0.0

    @property
    def total_packets(self) -> int:
        return self.packets_forward + self.packets_backward

    @property
    def total_bytes(self) -> int:
        return self.bytes_forward + self.bytes_backward
