"""
Canonical Standardized Alert Schema (AlertEvent)
Strictly satisfies NTRO / SIH requirement:
- timestamp, flow_id, threat_class, confidence_score, supporting_evidence
- severity, detector_source, 5-tuple, occurrence_count, alert_id
"""

from dataclasses import dataclass, asdict
import time
import uuid
from typing import Optional, Dict, Any

from schemas.enums import ThreatClass, Severity, DetectorType


@dataclass(slots=True)
class AlertEvent:
    """Standardized Alert JSON Record"""
    timestamp: float                  # Millisecond UTC epoch when threat occurred
    flow_id: str                      # Identifier of the flow
    threat_class: str                 # Member of ThreatClass enum
    confidence_score: float           # Model posterior or heuristic strength; see evidence confidence_kind
    severity: str                     # LOW, MEDIUM, HIGH, CRITICAL
    supporting_evidence: str          # Deterministic narrative and key feature metrics
    alert_id: str                     # UUID or deterministic alert identifier
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: int
    detection_source: str             # RULE, ML, HYBRID
    occurrence_count: int = 1         # Incremented during in-place deduplication
    created_at_ms: float = 0.0        # System timestamp when alert was generated
    raw_evidence_metrics: Optional[Dict[str, Any]] = None  # Underlying numeric feature values

    def __post_init__(self):
        if not self.created_at_ms:
            self.created_at_ms = time.time() * 1000.0
        if not self.alert_id:
            self.alert_id = str(uuid.uuid4())

    def to_dict(self) -> Dict[str, Any]:
        """Serializes alert to JSON-compatible dictionary"""
        return asdict(self)

    @classmethod
    def create(
        cls,
        flow_id: str,
        threat_class: ThreatClass,
        confidence_score: float,
        severity: Severity,
        supporting_evidence: str,
        src_ip: str,
        dst_ip: str,
        protocol: int,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        detection_source: DetectorType = DetectorType.RULE,
        timestamp: Optional[float] = None,
        raw_evidence_metrics: Optional[Dict[str, Any]] = None
    ) -> "AlertEvent":
        now_ms = timestamp if timestamp is not None else time.time() * 1000.0
        return cls(
            timestamp=now_ms,
            flow_id=flow_id,
            threat_class=threat_class.value,
            confidence_score=round(max(0.0, min(1.0, confidence_score)), 3),
            severity=severity.value,
            supporting_evidence=supporting_evidence,
            alert_id=str(uuid.uuid4()),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            detection_source=detection_source.value,
            occurrence_count=1,
            created_at_ms=time.time() * 1000.0,
            raw_evidence_metrics=raw_evidence_metrics or {}
        )
