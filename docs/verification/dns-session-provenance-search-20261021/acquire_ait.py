"""One opaque checksummed archive; only three predeclared documentary members."""
import hashlib
import json
from pathlib import Path
from urllib.request import Request, urlopen
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
CACHE = ROOT / "data/raw/dns-session-provenance-documents-20261021"
TARGET = ROOT / "data/raw/ait-dns-intake-20261021/russellmitchell_no-pcaps.zip"


def main():
    selected = json.loads((HERE / "ait-directory-selection.json").read_bytes())["item"]
    assert selected["key"] == TARGET.name and selected["size"] == 522084364
    assert selected["checksum"] == "md5:abb43a46c70939ad9f98669e3510d2b7"
    partial = TARGET.with_suffix(".zip.partial")
    if TARGET.exists() or partial.exists():
        raise FileExistsError("Preserve existing intake")
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    size = 0
    sha = hashlib.sha256()
    md5 = hashlib.md5(usedforsecurity=False)
    with urlopen(Request(selected["links"]["self"], headers={"Accept-Encoding": "identity"}), timeout=30) as response:
        assert response.status == 200
        assert response.headers.get("Content-Encoding", "identity") == "identity"
        if response.headers.get("Content-Length") is not None:
            assert int(response.headers["Content-Length"]) == selected["size"]
        with partial.open("xb") as output:
            while block := response.read(1048576):
                size += len(block)
                if size > selected["size"]:
                    raise ValueError("Archive exceeds frozen size")
                output.write(block)
                sha.update(block)
                md5.update(block)
    assert size == selected["size"] and f"md5:{md5.hexdigest()}" == selected["checksum"]
    partial.rename(TARGET)
    receipt = dict(artifact=TARGET.relative_to(ROOT).as_posix(), bytes=size,
        md5=md5.hexdigest(), sha256=sha.hexdigest(), publisher_checksum_verified=True,
        query_rows_read=False, role=None, metadata=[])
    inspect_metadata(receipt)


def inspect_metadata(receipt):
    with zipfile.ZipFile(TARGET) as archive:
        members = archive.infolist()
        (HERE / "ait-local-catalogue.json").write_bytes((json.dumps([
            dict(name=m.filename, bytes=m.file_size, compressed_bytes=m.compress_size,
                 crc32=f"{m.CRC:08x}", compression=m.compress_type) for m in members], indent=2) + "\n").encode())
        for suffix, name in [("dataset.yml", "ait-dataset.yml"),
                ("gather/attacker_0/logs/attacks.log", "ait-attacks.log"),
                ("processing/config/servers.yml", "ait-servers.yml")]:
            matches = [m for m in members if m.filename == suffix or m.filename.endswith("/" + suffix)]
            assert len(matches) <= 1, "Ambiguous metadata selection"
            if not matches:
                receipt["metadata"].append(dict(suffix=suffix, present=False))
                continue
            m = matches[0]
            assert m.file_size <= 1048576 and not m.flag_bits & 1
            body = archive.read(m)  # zipfile verifies this selected member's CRC.
            target = CACHE / name
            with target.open("xb") as output:
                output.write(body)
            receipt["metadata"].append(dict(suffix=suffix, member=m.filename,
                present=True, cache=target.relative_to(ROOT).as_posix(), bytes=len(body),
                crc32=f"{m.CRC:08x}", sha256=hashlib.sha256(body).hexdigest()))
    (HERE / "ait-acquisition.json").write_bytes((json.dumps(receipt, indent=2) + "\n").encode())
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
