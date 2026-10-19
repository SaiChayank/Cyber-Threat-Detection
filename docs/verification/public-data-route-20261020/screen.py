"""Bounded public metadata retrieval only: no capture/domain rows or execution."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
CACHE = ROOT / "data/raw/public-source-documents-20261020"
LIMIT = 4 * 1024 * 1024


def main():
    if (OUT / "retrieval-receipts.json").exists():
        raise FileExistsError("Historical receipt exists; use a new dated evidence directory")
    CACHE.mkdir(parents=True, exist_ok=True)
    receipts = []

    def get(name, url, tracked=False):
        request = Request(url, headers={"User-Agent": "Univect-public-metadata-screen", "Accept": "application/json"})
        try:
            with urlopen(request, timeout=45) as response:
                body = response.read(LIMIT + 1)
                if len(body) > LIMIT:
                    raise ValueError("Metadata response exceeded cap")
                path = (OUT if tracked else CACHE) / name
                with path.open("xb") as stream:
                    stream.write(body)
                receipts.append({"url": url, "final_url": response.url, "status": response.status,
                                 "path": path.relative_to(ROOT).as_posix(), "bytes": len(body),
                                 "sha256": hashlib.sha256(body).hexdigest(),
                                 "retrieved_utc": datetime.now(timezone.utc).isoformat()})
                return body
        except Exception as error:
            receipts.append({"url": url, "error": str(error)})
            return None
        finally:
            (OUT / "retrieval-receipts.json").write_bytes((json.dumps(receipts, indent=2) + "\n").encode())

    for short, repo in [("beacon", "mrcord77/beacon-hunter"),
                        ("domainator", "dreamingdust/domainator-dataset"),
                        ("moe", "reypapin/MoE-word-list-dga-detection")]:
        base = "https://api.github.com/repos/" + repo
        metadata = get(short + "-repository.json", base, True)
        if metadata is None:
            continue
        branch = json.loads(metadata)["default_branch"]
        reference = get(short + "-ref.json", base + "/git/ref/heads/" + branch, True)
        if reference is None:
            continue
        commit = json.loads(reference)["object"]["sha"]
        tree = get(short + "-tree.json", base + "/git/trees/" + commit + "?recursive=1", True)
        if tree is None:
            continue
        entries = json.loads(tree)
        if entries.get("truncated"):
            raise ValueError("Truncated metadata tree cannot establish absence")
        docs = [entry["path"] for entry in entries["tree"] if entry["type"] == "blob" and
                (entry["path"] in ("README.md", "LICENSE", "LICENSE.txt", "CITATION.cff", "Dataset/README.md"))]
        for index, path in enumerate(docs):
            get(f"{short}-document-{index}.txt", f"https://raw.githubusercontent.com/{repo}/{commit}/{path}")
        print(short, commit, "files", sum(e["type"] == "blob" for e in entries["tree"]), "docs", docs)
    metadata = get("stockholm-article.json", "https://api.figshare.com/v2/articles/4229399", True)
    if metadata:
        article = json.loads(metadata)
        print("stockholm", article.get("license"), [(f["name"], f["size"]) for f in article.get("files", [])])


if __name__ == "__main__":
    main()
