"""Original DNS/receiver metadata join only. No detection, fitting or scoring."""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = "10.143.0.103"
NAMESPACE = "email-19.kennedy-mendoza.info"
START = int(datetime(2022, 1, 21, tzinfo=timezone.utc).timestamp())
END = int(datetime(2022, 1, 25, tzinfo=timezone.utc).timestamp())
PREFIX = re.compile(r"^(?P<stamp>[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}) dnsmasq\[\d+\]: (?P<message>.*)$")
QUERY = re.compile(r"^query\[(?P<type>[^\]\s]+)\] (?P<name>\S+) from (?P<source>\S+)$")
FILE = re.compile(r"^b'([^'\\\r\n]+)'$")


def canonical_name(name):
    bare = name[:-1] if name.endswith(".") else name
    if not bare:
        return "."
    try:
        labels = [label.encode("ascii") for label in bare.split(".")]
    except UnicodeEncodeError:
        raise ValueError("Unsupported non-ASCII log name") from None
    if any(not label or len(label) > 63 for label in labels) or 1 + sum(len(s) + 1 for s in labels) > 255:
        raise ValueError("Incomplete/invalid DNS name lengths")
    return bare.casefold()


def parse_question(line, year=2022):
    """Return None for non-query records; malformed query records raise."""
    prefix = PREFIX.fullmatch(line.rstrip("\r\n"))
    if prefix is None:
        if "query[" in line:
            raise ValueError("Unrecognized query prefix")
        return None
    message = prefix["message"]
    if not message.startswith("query["):
        return None
    match = QUERY.fullmatch(message)
    if match is None:
        raise ValueError("Unrecognized client query syntax")
    second = int(datetime.strptime(f"{year} {prefix['stamp']}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp())
    source = str(ipaddress.ip_address(match["source"]))
    return dict(second=second, source=source, qtype=match["type"].upper(), name=canonical_name(match["name"]))


def summarize(lines, receiver):
    events = []
    unsupported = 0
    for number, row in enumerate(receiver, 1):
        if row.get("event") != "Received file end marker":
            continue
        file_match = FILE.fullmatch(str(row.get("file", "")))
        value = row.get("timestamp")
        if file_match is None or isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value):
            unsupported += 1
            continue
        literal = file_match[1]
        try:
            expected = canonical_name("3x7-.0-." + literal + "." + NAMESPACE)
        except ValueError:
            unsupported += 1
            continue
        events.append(dict(receiver_line=number, receiver_second=math.floor(value),
            receiver_in_simulation=START <= value < END,
            file_id_sha256=hashlib.sha256(str(row["file"]).encode()).hexdigest(),
            expected=expected, eligible_matches=0, time_matches_other_source=0,
            time_matches_wrong_type=0, source_matches_other_second=0, observed_lines=[]))
    index = {}
    receiver_keys = Counter((e["expected"], e["receiver_second"]) for e in events)
    for event in events:
        event["receiver_key_multiplicity"] = receiver_keys[(event["expected"], event["receiver_second"])]
        index.setdefault(event["expected"], []).append(event)
    stats = Counter()
    types = Counter()
    sources = Counter()
    associated_sources = Counter()
    associated_types = Counter()
    previous = None
    watermark = None
    first = None
    last = None
    for number, line in enumerate(lines, 1):
        stats["source_lines"] += 1
        try:
            question = parse_question(line)
        except ValueError:
            stats["malformed_query_records"] += 1
            continue
        if question is None:
            stats["non_query_records"] += 1
            continue
        stats["complete_client_questions"] += 1
        second = question["second"]
        first = second if first is None else min(first, second)
        last = second if last is None else max(last, second)
        stats["outside_simulation_questions"] += not (START <= second < END)
        stats["backward_adjacent_question_steps"] += previous is not None and second < previous
        stats["questions_behind_watermark"] += watermark is not None and second < watermark
        previous = second
        watermark = max(second, watermark) if watermark is not None else second
        types[question["qtype"]] += 1
        sources[question["source"]] += 1
        if question["name"].endswith("." + NAMESPACE):
            stats["namespace_associated_questions"] += 1
            associated_sources[question["source"]] += 1
            associated_types[question["qtype"]] += 1
        for event in index.get(question["name"], []):
            same_second = second == event["receiver_second"]
            if same_second and question["qtype"] != "A":
                event["time_matches_wrong_type"] += 1
            elif same_second and question["source"] != SOURCE:
                event["time_matches_other_source"] += 1
            elif same_second:
                event["eligible_matches"] += 1
                if len(event["observed_lines"]) < 8:
                    event["observed_lines"].append(number)
            elif question["source"] == SOURCE:
                event["source_matches_other_second"] += 1
    for event in events:
        event.pop("expected")
        if event["eligible_matches"] and (event["eligible_matches"] > 1 or event["receiver_key_multiplicity"] > 1):
            event["status"] = "AMBIGUOUS"
        else:
            event["status"] = "EXACT_MARKER_JOIN" if event["eligible_matches"] == 1 else "UNMATCHED"
    return dict(scope="Development-only DNS visibility/receiver marker join; not accuracy or independent sessions",
        counts=dict(stats), qtypes=dict(types), question_sources=dict(sources), namespace_sources=dict(associated_sources),
        namespace_qtypes=dict(associated_types),
        first_question_second=first, last_question_second=last, original_timestamp_precision_seconds=1,
        original_order_and_duplicates_preserved=True, receiver_end_markers=len(events),
        unsupported_receiver_end_markers=unsupported, marker_status_counts=dict(Counter(e["status"] for e in events)),
        marker_status_counts_in_simulation=dict(Counter(e["status"] for e in events if e["receiver_in_simulation"])),
        markers=events, diagnostic_role="development_qualification_only", reserved_eligible=False,
        independent_session_count=None, detector_scored=False)


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            digest.update(block)
    return digest.hexdigest()


def main():
    receipt = json.loads((HERE / "stage-b-receipt.json").read_bytes())
    source = ROOT / receipt["cache"]
    assert sha(source) == receipt["sha256"]
    receiver_receipt = json.loads((HERE.parent / "dns-session-provenance-search-20261021/ait-receiver-metadata.json").read_bytes())
    receiver_file = ROOT / receiver_receipt["cache"]
    assert sha(receiver_file) == receiver_receipt["sha256"]
    receiver = [json.loads(row) for row in receiver_file.read_text(encoding="utf-8").splitlines() if row.strip()]
    with source.open(encoding="utf-8") as stream:
        result = summarize(stream, receiver)
    result["input_sha256"] = {receipt["cache"]: receipt["sha256"], receiver_receipt["cache"]: receiver_receipt["sha256"]}
    result["diagnostic_source_sha256"] = sha(Path(__file__))
    (HERE / "join-results.json").write_bytes((json.dumps(result, indent=2) + "\n").encode())
    print(json.dumps({k: v for k, v in result.items() if k not in ("markers", "input_sha256")}))


if __name__ == "__main__":
    main()
