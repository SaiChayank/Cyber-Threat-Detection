"""Retrieve bounded public human documentation/catalogue metadata, never captures."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
CACHE = ROOT / "data/raw/ufu-do53-documents-20261021"
REPO = "CborgesUFU/DNS-360-Dataset"
REVISION = "1b3e59ffc3d14f41ccbf143be155cf791eb5e7ae"
DOCUMENTS = (
    "CITATION.cff",
    "data/CSV/UFU-Do53-EXF/Readme",
    "Pipe/dns_exfil_samples/Readme",
)


def retrieve(item):
    name, url, source_path = item
    target = CACHE / name
    if target.exists():
        raise FileExistsError(f"Preserve previous retrieval: {target}")
    with urlopen(Request(url, headers={"User-Agent": "Univect-public-document-review/1.0"}), timeout=30) as response:
        body = response.read(1024 * 1024 + 1)
        if len(body) > 1024 * 1024:
            raise ValueError("Public metadata exceeded the fixed 1 MiB bound")
        receipt = dict(name=name, url=url, source_path=source_path,
            status=response.status, final_url=response.url,
            bytes=len(body), sha256=hashlib.sha256(body).hexdigest())
    target.write_bytes(body)
    return receipt


if __name__ == "__main__":
    CACHE.mkdir(parents=True, exist_ok=True)
    destination = HERE / "retrievals.json"
    if destination.exists():
        raise FileExistsError("Keep existing receipts; use a new dated package")
    items = [(f"document-{i}.txt", f"https://raw.githubusercontent.com/{REPO}/{REVISION}/{quote(path)}", path)
             for i, path in enumerate(DOCUMENTS)]
    items += [("current-head.json", f"https://api.github.com/repos/{REPO}/commits/main", None),
              ("releases.json", f"https://api.github.com/repos/{REPO}/releases?per_page=20", None)]
    with ThreadPoolExecutor(max_workers=5) as pool:
        receipts = list(pool.map(retrieve, items))
    destination.write_text(json.dumps(receipts, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(dict(retrieved=len(receipts), dataset_values_opened=False)))
