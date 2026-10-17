"""Byte-range transport for the same two pinned original archives, no extraction."""
import concurrent.futures
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time

E = Path(__file__).resolve().parent
ROOT = E.parents[2]


def pinned(name):
    raw = (E / (name + ".json")).read_bytes()
    if hashlib.sha256(raw).hexdigest() != (E / (name + ".sha256")).read_text().strip():
        raise ValueError("Pinned plan changed")
    return json.loads(raw)


def transfer(item, chunk):
    folder = (ROOT / item["path"]).parent / "archive-byte-parts"
    folder.mkdir(exist_ok=True)
    part = folder / f"{chunk['index']:03d}.bin"
    receipt = part.with_suffix(".json")
    if not receipt.exists():
        command = [
            "curl.exe", "--fail", "--location", "--proto", "=https",
            "--proto-redir", "=https", "--max-redirs", "5", "--retry", "3",
            "--retry-delay", "10", "--connect-timeout", "30",
            "--speed-limit", "1024", "--speed-time", "90", "--no-progress-meter",
            "--range", f"{chunk['start']}-{chunk['end']}",
            "--max-filesize", str(chunk["bytes"]), "--output", str(part),
            "--write-out", "%{http_code}", item["url"],
        ]
        with part.with_suffix(".log").open("ab") as log:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=log, check=True)
        if result.stdout.strip() != b"206" or part.stat().st_size != chunk["bytes"]:
            raise ValueError("Incomplete or non-range response; not admitted")
        h = hashlib.sha256()
        with part.open("rb") as handle:
            while data := handle.read(8 * 1024 * 1024):
                h.update(data)
        receipt.write_bytes((json.dumps(dict(chunk, sha256=h.hexdigest()), indent=2) + "\n").encode())
    saved = json.loads(receipt.read_text())
    if any(saved[k] != chunk[k] for k in ["index", "start", "end", "bytes"]):
        raise ValueError("Transport receipt differs from range plan")
    return part, saved


def main():
    plan, transport = pinned("acquisition-plan"), pinned("transport-plan")
    if transport["parent_plan_sha256"] != hashlib.sha256((E / "acquisition-plan.json").read_bytes()).hexdigest():
        raise ValueError("Transport parent mismatch")
    pairs = list(zip(plan["files"], transport["files"], strict=True))
    tasks = [(item, chunk) for item, t in pairs for chunk in t["chunks"]]
    with concurrent.futures.ThreadPoolExecutor(max_workers=transport["parallel_max"]) as pool:
        futures = [pool.submit(transfer, item, chunk) for item, chunk in tasks]
        while not all(f.done() for f in futures):
            for item, t in pairs:
                folder = (ROOT / item["path"]).parent / "archive-byte-parts"
                got = t["prefix_bytes"] + sum(p.stat().st_size for p in folder.glob("*.bin"))
                print(f"{Path(item['path']).name}: {got:,}/{item['bytes']:,} bytes", flush=True)
            time.sleep(15)
        parts = [f.result() for f in futures]
    position = 0
    for item, t in pairs:
        destination = ROOT / item["path"]
        if destination.exists():
            raise FileExistsError("Do not replace an existing dataset")
        prefix = ROOT / t["prefix_path"]
        assembled = destination.with_suffix(".zip.assembled.part")
        md5, sha = hashlib.md5(), hashlib.sha256()
        inputs = [(prefix, t["prefix_bytes"], t["prefix_sha256"])]
        for _ in t["chunks"]:
            path, receipt = parts[position]
            inputs.append((path, receipt["bytes"], receipt["sha256"]))
            position += 1
        with assembled.open("xb") as output:
            for path, expected_size, expected_sha in inputs:
                actual = hashlib.sha256()
                if path.stat().st_size != expected_size:
                    raise ValueError("Transport part size changed")
                with path.open("rb") as handle:
                    while data := handle.read(8 * 1024 * 1024):
                        output.write(data)
                        md5.update(data)
                        sha.update(data)
                        actual.update(data)
                if actual.hexdigest() != expected_sha:
                    raise ValueError("Transport part hash changed")
        if assembled.stat().st_size != item["bytes"] or "md5:" + md5.hexdigest() != item["publisher_checksum"]:
            raise ValueError("Whole publisher archive checksum mismatch")
        os.rename(assembled, destination)
        print(f"WHOLE ARCHIVE VERIFIED {destination.name}: SHA256 {sha.hexdigest()}", flush=True)
    spec = importlib.util.spec_from_file_location("approved_acquisition", E / "download.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.main()


if __name__ == "__main__":
    main()
