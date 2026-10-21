"""Neutral original-PCAP visibility counts; no detector/feature/model invocation."""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from datasets.audit_dns_visibility import transport, wire_dns
from ingest.pcap_reader import validate_header
from ingest.protocol_parsers import ProtocolParser
from ml.dga import domain_label


def records(path):
    with path.open("rb") as stream:
        header = stream.read(24)
        snaplen = validate_header(header)
        endian = ">" if header[:4] in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d") else "<"
        nano = header[:4] in (b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1")
        while raw := stream.read(16):
            if len(raw) != 16:
                raise ValueError("Truncated original record header")
            seconds, fraction, size, original = struct.unpack(endian + "IIII", raw)
            if size > snaplen or size > original or fraction >= (1000000000 if nano else 1000000):
                raise ValueError("Invalid original record length/timestamp")
            frame = stream.read(size)
            if len(frame) != size:
                raise ValueError("Truncated original frame")
            yield seconds * 1000000000 + fraction * (1 if nano else 1000), frame, original, nano


def inspect(path):
    parser = ProtocolParser()
    counts, services, types, sources = (Counter() for _ in range(4))
    previous = first = last = minimum = maximum = None
    seen, exposures = set(), set()
    question_lengths = []
    for timestamp_ns, frame, original, nano in records(path):
        counts["frames"] += 1
        counts["capture_truncated_frames"] += len(frame) < original
        counts["backwards_timestamp_steps"] += previous is not None and timestamp_ns < previous
        previous = last = timestamp_ns
        if first is None: first = timestamp_ns
        minimum = timestamp_ns if minimum is None else min(minimum, timestamp_ns)
        maximum = timestamp_ns if maximum is None else max(maximum, timestamp_ns)
        identity = hashlib.sha256(frame).digest()
        counts["repeated_frame_bytes"] += identity in seen
        seen.add(identity)
        packet = transport(frame, allow_truncated=True)
        if packet is None:
            counts["non_transport_or_unsupported"] += 1
            continue
        protocol, source_port, destination_port, source, _, payload, complete = packet
        counts["transport_complete" if complete else "transport_incomplete"] += 1
        service = next((port for port in (53, 5353, 5355) if port in (source_port, destination_port)), None)
        if service is None:
            continue
        services[f"{'udp' if protocol == 17 else 'tcp'}/{service}"] += 1
        if service != 53:
            continue
        if not complete:
            counts["dns_transport_incomplete"] += 1
            continue
        wire = wire_dns(payload, tcp=protocol == 6, questions_only=True)
        if wire is None:
            counts["dns_wire_incomplete_or_unparseable"] += 1
            continue
        counts["dns_responses" if wire["response"] else "dns_query_messages"] += 1
        if wire["response"] or destination_port != 53 or not wire["questions"]:
            continue
        counts["complete_client_question_messages"] += 1
        counts["multiple_question_messages"] += len(wire["questions"]) > 1
        name, kind = wire["questions"][0]  # Match current runtime's first-question semantics.
        types[str(kind)] += 1
        sources[hashlib.sha256(source.encode()).hexdigest()] += 1
        question_lengths.append(len(name))
        exposures.add(hashlib.sha256(domain_label(name).encode()).hexdigest())
        flow, dns, _ = parser.parse_packet(frame, timestamp_ns / 1000000000)
        if flow is not None and dns is not None and not dns.is_response:
            counts["runtime_client_question_sidecars"] += 1
            counts["runtime_question_mismatches"] += dns.query_name != name or dns.query_type != kind
        else:
            counts["wire_complete_runtime_missing"] += 1
    def utc(value):
        return datetime.fromtimestamp(value / 1000000000, timezone.utc).isoformat() if value is not None else None
    return dict(sha256=hashlib.sha256(path.read_bytes()).hexdigest(), bytes=path.stat().st_size,
        counts=dict(counts), services=dict(services), observed_client_qtypes=dict(types),
        source_question_counts_sha256=dict(sources), unique_question_sources=len(sources),
        timestamp_encoding="nanoseconds" if counts["frames"] and nano else "microseconds",
        first_timestamp_utc=utc(first), last_timestamp_utc=utc(last), minimum_timestamp_utc=utc(minimum), maximum_timestamp_utc=utc(maximum),
        observed_span_seconds=(maximum - minimum) / 1000000000 if minimum is not None else None,
        complete_question_name_length_min=min(question_lengths) if question_lengths else None,
        complete_question_name_length_max=max(question_lengths) if question_lengths else None,
        observed_first_label_exposures_sha256=sorted(exposures),
        runtime_parser_errors=parser.dlq.get_stats(), runtime_question_parser_only=True,
        detector_called=False, candidate_scored=False, certified_independent_dns_sessions=None,
        certified_benign_categories=[], role=None)


if __name__ == "__main__":
    manifest = HERE / "visibility-freeze.json"
    assert hashlib.sha256(manifest.read_bytes()).hexdigest() == (HERE / "visibility-freeze.sha256").read_text().strip()
    freeze = json.loads(manifest.read_text())
    for name, expected in freeze["sources_sha256"].items():
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != expected:
            raise ValueError("Frozen visibility source changed")
    target = ROOT / freeze["artifact"]
    if hashlib.sha256(target.read_bytes()).hexdigest() != freeze["artifact_sha256"]:
        raise ValueError("Verified original changed")
    destination = HERE / "visibility.json"
    if destination.exists():
        raise FileExistsError("Preserve earlier visibility evidence")
    result = inspect(target)
    assert result["sha256"] == freeze["artifact_sha256"]
    destination.write_bytes((json.dumps(result, indent=2) + "\n").encode())
    print(json.dumps({key: value for key, value in result.items()
        if key not in ("source_question_counts_sha256", "observed_first_label_exposures_sha256")}))
