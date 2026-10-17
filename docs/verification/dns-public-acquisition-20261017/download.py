"""Acquire the two approved ZIPs; never extract, inspect rows or run models."""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import urllib.request
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = Path(__file__).resolve().parent


def save(path, value):
    path.write_bytes((json.dumps(value, indent=2) + "\n").encode())


def acquire(item):
    destination = ROOT / item["path"]
    partial = destination.with_suffix(".zip.part")
    with urllib.request.urlopen(
        "https://zenodo.org/api/records/" + item["record_id"], timeout=60
    ) as response:
        raw = response.read(1_000_001)
    if len(raw) > 1_000_000:
        raise ValueError("Publisher metadata exceeds bound")
    release = json.loads(raw)
    entry = next(f for f in release["files"] if f["key"] == destination.name)
    if (release["metadata"]["license"]["id"] != "cc-by-4.0"
            or release["metadata"]["access_right"] != "open"
            or entry["size"] != item["bytes"]
            or entry["checksum"] != item["publisher_checksum"]
            or entry["links"]["self"] != item["url"]):
        raise ValueError("Publisher release differs from approved acquisition plan")
    (destination.parent / "release.json").write_bytes(raw)
    if not destination.exists():
        command = [
            "curl.exe", "--fail", "--location", "--proto", "=https",
            "--proto-redir", "=https", "--max-redirs", "5",
            "--retry", "4", "--retry-delay", "5", "--retry-all-errors",
            "--connect-timeout", "30", "--speed-limit", "1024",
            "--speed-time", "90", "--continue-at", "-",
            "--max-filesize", str(item["bytes"]), "--no-progress-meter",
            "--output", str(partial), item["url"],
        ]
        with (destination.parent / "download.log").open("ab") as log:
            process = subprocess.Popen(command, stdout=log, stderr=log)
            while process.poll() is None:
                received = partial.stat().st_size if partial.exists() else 0
                print(f"{destination.name}: {received:,}/{item['bytes']:,} bytes", flush=True)
                time.sleep(15)
            if process.returncode:
                raise RuntimeError(f"curl failed for {destination.name}; see local download.log; partial retained")
    source = destination if destination.exists() else partial
    md5, sha256 = hashlib.md5(), hashlib.sha256()
    count = 0
    with source.open("rb") as handle:
        while chunk := handle.read(8 * 1024 * 1024):
            count += len(chunk)
            md5.update(chunk)
            sha256.update(chunk)
    if count != item["bytes"] or "md5:" + md5.hexdigest() != item["publisher_checksum"]:
        raise ValueError(f"Publisher size/checksum mismatch for {destination.name}; not admitted")
    if source == partial:
        # Windows rename refuses an existing destination; preserve existing raw files.
        os.rename(partial, destination)
    result = dict(item, downloaded=True, verified_bytes=count,
                  publisher_checksum_verified=True, sha256=sha256.hexdigest(),
                  acquired_utc=datetime.now(timezone.utc).isoformat(),
                  extracted=False, values_inspected=False,
                  final_evaluation_ready=False)
    save(destination.parent / "acquisition-receipt.json", result)
    print(f"VERIFIED {destination.name}: {count:,} bytes; SHA256 {result['sha256']}", flush=True)
    return result


def main():
    raw = (EVIDENCE / "acquisition-plan.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != (EVIDENCE / "acquisition-plan.sha256").read_text().strip():
        raise ValueError("Acquisition plan hash mismatch")
    plan = json.loads(raw)
    if shutil.disk_usage(ROOT).free < plan["total_bytes"] + 2_000_000_000:
        raise ValueError("Insufficient disk space for the pinned acquisition")
    if len(plan["files"]) != 2:
        raise ValueError("Only the two approved releases are in scope")
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(acquire, plan["files"]))
    save(EVIDENCE / "download-report.json", {
        "scope": "Archive acquisition/checksums only; no extraction or inference",
        "files": results, "final_evaluation_ready": False,
    })


if __name__ == "__main__":
    main()
