"""Documentary intake must fail closed and never open DNS observations."""
import importlib.util
import io
import json
from pathlib import Path
import sys
import zipfile

import pytest

HERE = Path(__file__).resolve().parents[1] / "docs/verification/dns-session-provenance-search-20261021"
spec = importlib.util.spec_from_file_location("ait_intake_diagnostic", HERE / "acquire_ait.py")
intake = importlib.util.module_from_spec(spec)
spec.loader.exec_module(intake)
# Resolve the dated sibling without permanently adding a search path.
spec = importlib.util.spec_from_file_location("ait_finish_diagnostic", HERE / "finish_ait.py")
finish = importlib.util.module_from_spec(spec)
previous = sys.modules.get("acquire_ait")
sys.modules["acquire_ait"] = intake
try:
    spec.loader.exec_module(finish)
finally:
    if previous is None:
        del sys.modules["acquire_ait"]
    else:
        sys.modules["acquire_ait"] = previous


class Response(io.BytesIO):
    def __init__(self, body, status=206, content_range="bytes 2-4/10", encoding="identity"):
        super().__init__(body)
        self.status = status
        self.headers = {"Content-Range": content_range, "Content-Encoding": encoding}


@pytest.mark.parametrize("kwargs", [
    {"status": 200}, {"content_range": "bytes 2-4/11"}, {"encoding": "gzip"},
])
def test_changed_or_full_response_is_rejected_without_writing(tmp_path, monkeypatch, kwargs):
    monkeypatch.setattr(finish, "urlopen", lambda *a, **k: Response(b"abc", **kwargs))
    target = tmp_path / "part"
    with pytest.raises(ValueError):
        finish.fetch_segment(({"size": 10, "links": {"self": "https://example.invalid/fixture"}}, 2, 5, target))
    assert not target.exists()


@pytest.mark.parametrize("body", [b"ab", b"abcd"])
def test_wrong_response_length_is_not_reported_as_verified(tmp_path, monkeypatch, body):
    monkeypatch.setattr(finish, "urlopen", lambda *a, **k: Response(body))
    with pytest.raises(ValueError):
        finish.fetch_segment(({"size": 10, "links": {"self": "https://example.invalid/fixture"}}, 2, 5, tmp_path / "part"))


def test_metadata_allowlist_never_opens_observation_member(tmp_path, monkeypatch):
    target = tmp_path / "fixture.zip"
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("russellmitchell/dataset.yml", "start: 2022-01-21\n")
        archive.writestr("russellmitchell/gather/firewall/logs/dnsmasq.log", "DO NOT OPEN")
    monkeypatch.setattr(intake, "HERE", tmp_path)
    monkeypatch.setattr(intake, "ROOT", tmp_path)
    monkeypatch.setattr(intake, "CACHE", tmp_path)
    monkeypatch.setattr(intake, "TARGET", target)
    opened = []
    original = zipfile.ZipFile.open

    def guarded(self, name, *args, **kwargs):
        opened.append(name.filename if isinstance(name, zipfile.ZipInfo) else name)
        assert not opened[-1].endswith("dnsmasq.log")
        return original(self, name, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "open", guarded)
    receipt = {"query_rows_read": False, "role": None, "metadata": []}
    intake.inspect_metadata(receipt)
    assert opened == ["russellmitchell/dataset.yml"]
    assert receipt["query_rows_read"] is False and receipt["role"] is None
    assert sum(m["present"] for m in receipt["metadata"]) == 1
    assert json.loads((tmp_path / "ait-acquisition.json").read_bytes())["role"] is None


def test_ambiguous_document_is_not_arbitrarily_selected(tmp_path, monkeypatch):
    target = tmp_path / "fixture.zip"
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("run1/dataset.yml", "one")
        archive.writestr("run2/dataset.yml", "two")
    monkeypatch.setattr(intake, "HERE", tmp_path)
    monkeypatch.setattr(intake, "CACHE", tmp_path)
    monkeypatch.setattr(intake, "TARGET", target)
    with pytest.raises(AssertionError, match="Ambiguous"):
        intake.inspect_metadata({"metadata": []})
    assert not (tmp_path / "ait-dataset.yml").exists()
