"""Finish the identical opaque checksum-pinned archive with bounded concurrency."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
from urllib.request import Request, urlopen

from acquire_ait import HERE, TARGET, inspect_metadata


def fetch_segment(item):
    selection, start, finish, destination = item
    headers = {"Range": f"bytes={start}-{finish - 1}", "Accept-Encoding": "identity"}
    size = 0
    sha = hashlib.sha256()
    with urlopen(Request(selection["links"]["self"], headers=headers), timeout=30) as response:
        if response.status != 206 or response.headers.get("Content-Range") != f"bytes {start}-{finish - 1}/{selection['size']}":
            raise ValueError("Refuse a non-range/changed response")
        if response.headers.get("Content-Encoding", "identity") != "identity":
            raise ValueError("Unexpected response encoding")
        with destination.open("xb") as output:
            while block := response.read(1048576):
                size += len(block)
                if size > finish - start:
                    raise ValueError("Range exceeds fixed end")
                output.write(block)
                sha.update(block)
    if size != finish - start:
        raise ValueError("Incomplete range")
    return dict(start=start, end_exclusive=finish, bytes=size, sha256=sha.hexdigest())


def main():
    if TARGET.exists():
        raise FileExistsError(TARGET)
    selection = json.loads((HERE / "ait-directory-selection.json").read_bytes())["item"]
    assert selection["size"] == 522084364
    assert selection["checksum"] == "md5:abb43a46c70939ad9f98669e3510d2b7"
    prefix = TARGET.with_suffix(".zip.partial")
    start = prefix.stat().st_size
    assert 0 < start < selection["size"]
    chunk = (selection["size"] - start + 7) // 8
    items = [(selection, p, min(p + chunk, selection["size"]), TARGET.with_suffix(f".zip.segment-{i}"))
             for i, p in enumerate(range(start, selection["size"], chunk))]
    with ThreadPoolExecutor(max_workers=8) as pool:
        receipts = list(pool.map(fetch_segment, items))
    sha = hashlib.sha256()
    md5 = hashlib.md5(usedforsecurity=False)
    parts = [prefix] + [item[-1] for item in items]
    assert sum(p.stat().st_size for p in parts) == selection["size"]
    for p in parts:
        with p.open("rb") as stream:
            while block := stream.read(1048576):
                sha.update(block)
                md5.update(block)
    assert f"md5:{md5.hexdigest()}" == selection["checksum"], "Archive identity failed; do not inspect"
    with TARGET.open("xb") as output:
        for p in parts:
            with p.open("rb") as stream:
                while block := stream.read(1048576):
                    output.write(block)
    receipt = dict(artifact=TARGET.relative_to(HERE.parents[2]).as_posix(), bytes=selection["size"],
        md5=md5.hexdigest(), sha256=sha.hexdigest(), publisher_checksum_verified=True,
        query_rows_read=False, role=None, metadata=[], prefix_bytes=start, continuation_ranges=receipts)
    inspect_metadata(receipt)


if __name__ == "__main__":
    main()
