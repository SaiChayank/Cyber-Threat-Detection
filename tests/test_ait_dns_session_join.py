"""Source qualification must not manufacture packet truth or independent sessions."""
import importlib.util
from pathlib import Path

import pytest

PATH = Path(__file__).resolve().parents[1] / "docs/verification/ait-session-join-20261021/diagnose_join.py"
spec = importlib.util.spec_from_file_location("ait_join_diagnostic", PATH)
join = importlib.util.module_from_spec(spec)
spec.loader.exec_module(join)
spec = importlib.util.spec_from_file_location("ait_benign_context", PATH.with_name("summarize_benign_context.py"))
context = importlib.util.module_from_spec(spec)
spec.loader.exec_module(context)


def question(second=9, source=join.SOURCE, kind="A", name=None):
    name = name or "3x7-.0-.file.xlsx." + join.NAMESPACE
    return f"Jan 21 00:00:{second:02d} dnsmasq[3468]: query[{kind}] {name} from {source}\n"


def receiver(second=9, filename="b'file.xlsx'"):
    return {"event": "Received file end marker", "file": filename, "timestamp": join.START + second + 0.9}


def test_original_opaque_name_and_second_precision_are_preserved():
    q = join.parse_question(question(name="A*/opaque-.123.example."))
    assert q == dict(second=join.START + 9, source=join.SOURCE, qtype="A", name="a*/opaque-.123.example")
    assert join.parse_question(question(name="."))["name"] == "."


@pytest.mark.parametrize("message", ["forwarded example.test to 192.0.2.1", "reply example.test is 192.0.2.2", "cached example.test is 192.0.2.2"])
def test_responses_and_forwarding_are_not_extra_client_questions(message):
    assert join.parse_question("Jan 21 00:00:09 dnsmasq[1]: " + message) is None


@pytest.mark.parametrize("line", [
    question(source="not-an-address"), question(name="bad..example"),
    question(name="x" * 64 + ".example"), question(name=".".join(["x" * 63] * 4)),
    "unknown prefix query[A] example.test from 10.0.0.1",
    "Jan 21 00:00:09 dnsmasq[1]: query[A] incomplete",
])
def test_unusable_questions_refuse_without_filling_missing_fields(line):
    with pytest.raises(ValueError):
        join.parse_question(line)


def test_exact_original_marker_join_does_not_create_an_independent_session():
    result = join.summarize([question()], [receiver()])
    assert result["marker_status_counts"] == {"EXACT_MARKER_JOIN": 1}
    assert result["markers"][0]["observed_lines"] == [1]
    assert result["independent_session_count"] is None
    assert not result["reserved_eligible"] and not result["detector_scored"]


@pytest.mark.parametrize("line,key", [
    (question(second=10), "source_matches_other_second"),
    (question(source="10.0.0.2"), "time_matches_other_source"),
    (question(kind="TXT"), "time_matches_wrong_type"),
])
def test_time_source_type_disagreement_is_not_forced_to_match(line, key):
    result = join.summarize([line], [receiver()])
    assert result["marker_status_counts"] == {"UNMATCHED": 1}
    assert result["markers"][0][key] == 1


def test_duplicate_dns_attempts_are_preserved_and_mark_join_ambiguous():
    result = join.summarize([question(), question()], [receiver()])
    assert result["counts"]["complete_client_questions"] == 2
    assert result["marker_status_counts"] == {"AMBIGUOUS": 1}
    assert result["markers"][0]["observed_lines"] == [1, 2]


def test_duplicate_receiver_markers_cannot_reuse_one_question_as_two_exact_joins():
    result = join.summarize([question()], [receiver(), receiver()])
    assert result["marker_status_counts"] == {"AMBIGUOUS": 2}
    assert all(r["receiver_key_multiplicity"] == 2 for r in result["markers"])


def test_original_question_order_is_not_sorted_to_hide_lateness():
    result = join.summarize([question(second=10), question(second=9)], [receiver()])
    assert result["counts"]["backward_adjacent_question_steps"] == 1
    assert result["counts"]["questions_behind_watermark"] == 1
    assert result["markers"][0]["observed_lines"] == [2]


def test_similar_suffix_is_not_the_documented_namespace():
    result = join.summarize([question(name="3x7-.0-.file.xlsx." + join.NAMESPACE + ".example")], [receiver()])
    assert result["counts"].get("namespace_associated_questions", 0) == 0
    assert result["marker_status_counts"] == {"UNMATCHED": 1}


@pytest.mark.parametrize("value", [True, "1642723209", float("nan")])
def test_invalid_receiver_time_is_disclosed_without_defaulting(value):
    r = receiver()
    r["timestamp"] = value
    result = join.summarize([question()], [r])
    assert result["unsupported_receiver_end_markers"] == 1
    assert result["receiver_end_markers"] == 0


def test_pre_capture_marker_is_not_called_an_in_window_missed_detection():
    result = join.summarize([question()], [receiver(second=-10)])
    assert result["marker_status_counts"] == {"UNMATCHED": 1}
    assert result["marker_status_counts_in_simulation"] == {}


@pytest.mark.parametrize("filename", ["file.xlsx", "b'" + "x" * 64 + ".xlsx'", "b'caf\u00e9.xlsx'"])
def test_unsupported_receiver_filename_is_disclosed_without_inventing_a_name(filename):
    result = join.summarize([question()], [receiver(filename=filename)])
    assert result["unsupported_receiver_end_markers"] == 1
    assert result["receiver_end_markers"] == 0


def test_repeated_transition_messages_are_not_completed_mail_or_dns_sessions():
    result = context.summarize([
        dict(run="one-run", timestamp=1, transition="horde_send_mail", message="Starting"),
        dict(run="one-run", timestamp=2, transition="horde_send_mail", message="Sent mail"),
        dict(run="one-run", timestamp=3, transition="horde_send_mail", message="Moved to new state"),
    ])
    assert result["transition_counts"]["horde_send_mail"] == 3
    assert result["completed_mail_messages"] == 1
    assert result["original_run_id_count"] == 1
    assert result["independent_benign_sessions"] is None
    assert result["qualified_benign_categories"] == []


def test_pre_and_post_window_application_actions_are_not_capture_controls():
    result = context.summarize([
        dict(run="one", timestamp=join.START - 1),
        dict(run="one", timestamp=join.START),
        dict(run="one", timestamp=join.END - 1),
        dict(run="one", timestamp=join.END),
    ])
    assert result["records_in_dns_observation_window"] == 2
    assert result["independent_benign_sessions"] is None
