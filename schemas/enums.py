"""
Canonical Enums for PS26145 Cyber Threat Detection
"""

from enum import Enum, IntEnum


class ThreatClass(str, Enum):
    """The 7 official & internal threat categories"""
    DDOS = "DDOS"
    BOTNET_C2 = "BOTNET_C2"
    DGA_DOMAINS = "DGA_DOMAINS"
    DNS_TUNNELLING = "DNS_TUNNELLING"
    ENCRYPTED_MALWARE = "ENCRYPTED_MALWARE"
    RECONNAISSANCE = "RECONNAISSANCE"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"


class Severity(str, Enum):
    """Operational urgency tiers"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DetectorType(str, Enum):
    """Architecture source of the alert"""
    RULE = "RULE"
    ML = "ML"
    HYBRID = "HYBRID"


class FeatureReadiness(str, Enum):
    """Causal window readiness state"""
    NOT_READY = "NOT_READY"   # Insufficient history (passed as null)
    PARTIAL = "PARTIAL"       # Computable but shorter than nominal window
    READY = "READY"           # Full nominal window elapsed


class ProtocolNumber(IntEnum):
    """IANA Layer 4 Protocol Numbers"""
    HOPOPT = 0
    ICMP = 1
    IGMP = 2
    TCP = 6
    UDP = 17
    IPV6_ROUTE = 43
    IPV6_FRAG = 44
    GRE = 47
    ESP = 50
    AH = 51
    ICMPV6 = 58
    SCTP = 132
