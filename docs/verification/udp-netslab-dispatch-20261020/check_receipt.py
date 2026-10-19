"""Offline dispatch-evidence integrity check; does not access email or packets."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main():
    receipt = json.loads((HERE / "receipt.json").read_text(encoding="utf-8"))
    request = ROOT / receipt["request_file"]
    assert sha(request) == receipt["request_sha256"] == (
        "41c248479b21a1cb0cbac995a258059f752c810e361d417ac4af795a98caec75"
    )
    body = request.read_text(encoding="utf-8").split("## Exact prepared body\n\n", 1)[1].strip()
    assert hashlib.sha256(body.encode()).hexdigest() == receipt["approved_body_sha256"]
    assert sha(ROOT / receipt["screenshot"]) == receipt["screenshot_sha256"]
    assert receipt["from"] == "saichayank07@gmail.com"
    assert receipt["to"] == ["abeysinghe.sandeepa@ucdconnect.ie"]
    assert receipt["cc"] == receipt["bcc"] == receipt["attachments"] == []
    assert receipt["subject"] == next(
        line.removeprefix("Subject: ") for line in request.read_text(encoding="utf-8").splitlines()
        if line.startswith("Subject: ")
    )
    assert receipt["send_clicks"] == 1 and receipt["gmail_confirmation"] == "Message sent"
    assert receipt["pre_send_body_match"] and receipt["sent_body_match"]
    assert receipt["public_datasets_only"]
    assert not any(receipt[key] for key in (
        "delivery_confirmed", "reply_confirmed", "packet_values_inspected", "detector_changes"
    ))
    assert receipt["qualification_status"] == "BLOCKED_NOT_QUALIFIED"
    pins_path = ROOT / "docs/verification/udp-alternative-sources-20261019/protected-hashes.json"
    pins = json.loads(pins_path.read_text(encoding="utf-8"))
    assert len(pins) == 130
    changed = [name for name, expected in pins.items() if sha(ROOT / name) != expected]
    assert not changed, f"Protected originals changed: {changed}"
    progress = json.loads((ROOT / "docs/verification/session-20261019/progress.json").read_text(encoding="utf-8"))
    assert "Public datasets only; no isolated-lab collection" in progress["constraints"]
    assert "isolated-lab" not in progress["remaining_queue"][0]
    print("PASS: dispatch receipt/request/body/screenshot/scope; public-only route; 130 protected originals unchanged")


if __name__ == "__main__":
    main()
