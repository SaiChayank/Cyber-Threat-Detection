"""
Canonical DNSRecord Schema
Linked to parent FlowRecord via flow_id
"""

from dataclasses import dataclass
from typing import Optional


@dataclass(slots=True)
class DNSRecord:
    """Represents an observed DNS query or response transaction"""
    query_id: int                     # DNS transaction ID header
    flow_id: str                      # Association back to parent FlowRecord
    query_name: str                   # FQDN query name (e.g. "sub.example.com")
    query_length: int                 # Character length of query_name
    query_type: int                   # IANA record type (1=A, 16=TXT, 28=AAAA, 10=NULL)
    response_code: Optional[int]      # 0=NOERROR, 3=NXDOMAIN, None if only query seen
    response_bytes: int               # Byte length of DNS response
    src_ip: str                       # Querying client IP
    dst_ip: str                       # Queried DNS resolver IP
    timestamp: float                  # Millisecond epoch timestamp of transaction
    is_response: bool = False

    @classmethod
    def from_query(
        cls,
        query_id: int,
        flow_id: str,
        query_name: str,
        query_type: int,
        src_ip: str,
        dst_ip: str,
        timestamp: float,
        response_code: Optional[int] = None,
        response_bytes: int = 0,
        is_response: bool = False
    ) -> "DNSRecord":
        clean_name = query_name.strip(".").lower()
        return cls(
            query_id=query_id,
            flow_id=flow_id,
            query_name=clean_name,
            query_length=len(clean_name),
            query_type=query_type,
            response_code=response_code,
            response_bytes=response_bytes,
            src_ip=src_ip,
            dst_ip=dst_ip,
            timestamp=timestamp,
            is_response=is_response
        )
