"""Dated documentary-only search; reuse the existing bounded receipt fetcher."""
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCES = (
    ("ait-record.json", "https://zenodo.org/api/records/19483937"),
    ("splunk-ref.json", "https://api.github.com/repos/splunk/attack_data/git/ref/heads/master"),
    ("uwf-index.html", "https://datasets.uwf.edu/"),
    ("uwf-techniques.html", "https://datasets.uwf.edu/tables/table5.html"),
    ("uwf-files.html", "https://datasets.uwf.edu/tables/table1.html"),
    ("uwf-file-descriptions.html", "https://datasets.uwf.edu/tables/list.html"),
    ("multisource-paper.html", "https://arxiv.org/html/2606.18190v1"),
    ("korving-issue.json", "https://api.github.com/repos/Korving-F/dns-tunnel-dataset/issues/3"),
    ("korving-comments.json", "https://api.github.com/repos/Korving-F/dns-tunnel-dataset/issues/3/comments?per_page=100"),
)


def main():
    spec = importlib.util.spec_from_file_location("prior_receipts", HERE.parent / "dns-public-session-screen-20261021/retrieve_documents.py")
    prior = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(prior)
    prior.CACHE = ROOT / "data/raw/dns-session-provenance-documents-20261021"
    prior.CACHE.mkdir(parents=True, exist_ok=True)
    destination = HERE / "retrievals.json"
    if destination.exists():
        raise FileExistsError(destination)
    with ThreadPoolExecutor(max_workers=5) as pool:
        records = list(pool.map(prior.fetch, SOURCES))
    destination.write_bytes((json.dumps(records, indent=2) + "\n").encode())
    print(json.dumps([{k: r[k] for k in ("name", "status", "bytes", "error") if k in r} for r in records]))


if __name__ == "__main__":
    main()
