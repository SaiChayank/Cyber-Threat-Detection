"""
Dead-Letter & Malformed Packet Handler
Logs dropped/corrupt packets and tracks statistics without crashing the pipeline
"""

import logging
from typing import Dict, Any

logger = logging.getLogger("ps26145.dead_letter")


class DeadLetterQueue:
    """Tracks and records malformed or unparseable packets"""

    def __init__(self, max_retained_errors: int = 1000):
        self.corrupt_packet_count: int = 0
        self.unsupported_protocol_count: int = 0
        self.truncated_packet_count: int = 0
        self.recent_errors: list[Dict[str, Any]] = []
        self.max_retained = max_retained_errors

    def record_corrupt_packet(self, error_type: str, details: str, raw_len: int = 0):
        """Records a parsing failure and increments metrics"""
        self.corrupt_packet_count += 1
        entry = {
            "error_type": error_type,
            "details": details,
            "raw_len": raw_len
        }
        if len(self.recent_errors) < self.max_retained:
            self.recent_errors.append(entry)
        logger.debug("Dropped malformed packet: %s (%s)", error_type, details)

    def record_truncated_packet(self, caplen: int, wirelen: int):
        self.truncated_packet_count += 1
        self.record_corrupt_packet("TRUNCATED", f"Capture length {caplen} < Wire length {wirelen}", caplen)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_corrupt_packets": self.corrupt_packet_count,
            "truncated_packets": self.truncated_packet_count,
            "unsupported_protocols": self.unsupported_protocol_count,
        }
