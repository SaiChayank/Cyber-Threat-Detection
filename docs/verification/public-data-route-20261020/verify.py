"""Verify source-screen metadata and preservation; never parse dataset values."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    route = json.loads((ROOT / "data/public_source_route.json").read_text())
    assert route["policy"]["public_direct_download_only"]
    assert route["policy"]["email_gated_sources_skipped"]
    assert not any(route["policy"][key] for key in (
        "new_messages", "institutional_details_required", "lab_collection", "training",
        "scoring", "promotion", "reserved_data_access", "frozen_gates_changed"
    ))
    assert route["new_qualified_replacements"] == route["runtime_integrations"] == 0
    assert len(route["new_leads"]) == 4
    assert all(s["role"] is None and not s["data_downloaded"] for s in route["new_leads"])
    for short, source in zip(("beacon", "domainator", "moe"), (route["new_leads"][0], route["new_leads"][1], route["new_leads"][3])):
        tree = json.loads((HERE / f"{short}-tree.json").read_text())
        reference = json.loads((HERE / f"{short}-ref.json").read_text())
        assert not tree["truncated"]
        assert reference["object"]["sha"] == source["commit"]
    article = json.loads((HERE / "stockholm-article.json").read_text())
    assert article["is_public"] and not article["download_disabled"]
    assert article["license"]["name"] == "CC BY 4.0"
    assert article["files"][0]["size"] == route["new_leads"][2]["advertised_bytes"]
    assert article["files"][0]["computed_md5"] == route["new_leads"][2]["publisher_md5"]
    receipts = json.loads((HERE / "retrieval-receipts.json").read_text())
    assert all("error" not in entry for entry in receipts)
    local_documents = 0
    for entry in receipts:
        path = ROOT / entry["path"]
        if path.exists():
            assert path.stat().st_size == entry["bytes"] and sha(path) == entry["sha256"]
            local_documents += 1
        else:
            assert entry["path"].startswith("data/raw/"), "Tracked metadata missing"
    pins = json.loads((ROOT / "docs/verification/udp-alternative-sources-20261019/protected-hashes.json").read_text())
    assert len(pins) == 130
    changed = [name for name, digest in pins.items() if sha(ROOT / name) != digest]
    assert not changed, changed
    print(json.dumps({"status": "PASS", "new_leads": 4, "qualified_replacements": 0,
                      "receipt_count": len(receipts), "local_receipts_verified": local_documents,
                      "protected_originals": 130, "protected_changes": 0,
                      "application_tests_rerun": False, "build_rerun": False,
                      "source_screen_dod": "PASS", "replacement_qualification_dod": "NOT_MET"}, indent=2))


if __name__ == "__main__":
    main()
