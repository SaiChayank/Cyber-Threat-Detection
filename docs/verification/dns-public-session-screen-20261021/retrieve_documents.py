"""Dated public documentation receipts; never fetch query rows or packet data."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
CACHE = ROOT / "data/raw/dns-public-session-documents-20261021"
SOURCES = (
    ("ziza-record.json", "https://data.mendeley.com/public-api/datasets/c4n7fckkz3"),
    ("ac-dnscat2.html", "https://www.activecountermeasures.com/malware-of-the-day-dnscat2-dns-tunneling/"),
    ("burgos-record.html", "https://riubu.ubu.es/handle/10259/11037"),
    ("burgos-readme.txt", "https://riubu.ubu.es/bitstream/10259/11037/4/readme.txt"),
    ("netrack-ref.json", "https://api.github.com/repos/netrack/learn/git/ref/heads/master"),
)


def fetch(item):
    name, url = item
    target = CACHE / name
    if target.exists():
        raise FileExistsError(f"Preserve {name}")
    result = dict(name=name, requested_url=url, retrieved_utc=datetime.now(timezone.utc).isoformat())
    try:
        with urlopen(Request(url, headers={"User-Agent": "Univect-public-document-review/1.0"}), timeout=30) as response:
            body = response.read(2 * 1024 * 1024 + 1)
            if len(body) > 2 * 1024 * 1024:
                raise ValueError("Document exceeds fixed 2 MiB bound")
            result.update(status=response.status, final_url=response.url,
                content_type=response.headers.get("Content-Type"),
                bytes=len(body), sha256=hashlib.sha256(body).hexdigest())
        target.write_bytes(body)
    except Exception as error:
        result.update(error_type=type(error).__name__, error=str(error))
    return result


if __name__ == "__main__":
    CACHE.mkdir(parents=True, exist_ok=True)
    destination = HERE / "retrievals.json"
    if destination.exists():
        raise FileExistsError("Preserve previous receipts")
    with ThreadPoolExecutor(max_workers=5) as pool:
        records = list(pool.map(fetch, SOURCES))
    destination.write_bytes((json.dumps(records, indent=2) + "\n").encode())
    print(json.dumps([dict(name=r["name"], status=r.get("status"), error=r.get("error_type")) for r in records]))
