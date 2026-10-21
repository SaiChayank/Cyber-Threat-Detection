"""Check public document identity and preservation without reading dataset values."""
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
PRIOR = ROOT / "data/raw/dga-benign-public-documents-20261020"
CACHE = ROOT / "data/raw/ufu-do53-documents-20261021"
REVISION = "1b3e59ffc3d14f41ccbf143be155cf791eb5e7ae"
sys.path.insert(0, str(ROOT))
from ml.dga import domain_label


def sha256(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def save(name, content):
    (HERE / name).write_text(json.dumps(content, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    old_receipts = json.loads((ROOT / "docs/verification/dga-benign-public-screen-20261020/retrievals.json").read_text())
    receipts = json.loads((HERE / "retrievals.json").read_text())
    assert len(receipts) == 5
    # Verify the entire reused receipt set, not a newly fetched moving branch.
    for folder, records in ((PRIOR, old_receipts), (CACHE, receipts)):
        for record in records:
            assert record["status"] == 200
            file = folder / record["name"]
            assert file.stat().st_size == record["bytes"]
            assert sha256(file) == record["sha256"]
    tree = json.loads((PRIOR / "tree.json").read_text())
    assert tree["truncated"] is False
    by_path = {entry["path"]: entry for entry in tree["tree"]}
    current = json.loads((CACHE / "current-head.json").read_text())
    assert current["sha"] == REVISION, "New revision needs a separate pre-value review"
    releases = json.loads((CACHE / "releases.json").read_text())
    assert releases == [], "Review newly published release assets before this decision"
    documents = []
    for record in receipts:
        if record["source_path"] is not None:
            body = (CACHE / record["name"]).read_bytes()
            blob = hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()
            assert blob == by_path[record["source_path"]]["sha"]
            documents.append(dict(path=record["source_path"], git_blob_sha1=blob,
                                  sha256=record["sha256"]))
    parts = sorted([entry for entry in tree["tree"]
        if re.fullmatch(r"data/PCAP/UFU-Do53-EXF/Do53\.7z\.\d{3}", entry["path"])],
        key=lambda entry: entry["path"])
    assert len(parts) == 34
    assert [int(entry["path"].rsplit(".", 1)[1]) for entry in parts] == list(range(1, 35))
    assert sum(entry["size"] for entry in parts) == 880_360_679
    save("source-inventory.json", dict(repository="CborgesUFU/DNS-360-Dataset",
        revision=REVISION, tree_sha256=sha256(PRIOR / "tree.json"), tree_truncated=False,
        published_releases=0, documents=documents,
        public_tree_paths=[entry["path"] for entry in tree["tree"]],
        do53_archive_parts=parts, archive_member_inventory=None,
        native_capture_headers=None, executed_session_manifest=None,
        note="Git tree paths are not inner archive members or evidence of session count"))
    # Supplemental development exposures; do not overwrite the frozen registry.
    pattern = re.compile(r"(?<![a-zA-Z0-9_-])(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}(?![a-zA-Z0-9_-])")
    labels = set()
    for record in receipts:
        if record["source_path"] is not None:
            for text in pattern.findall((CACHE / record["name"]).read_text(encoding="utf-8")):
                label = domain_label(text)
                if label:
                    labels.add(hashlib.sha256(label.encode()).hexdigest())
    save("documentation-exclusions.json", dict(scope="Supplemental development-document first-label exposures only; not a complete final exclusion registry",
        canonicalizer="ml.dga.domain_label", labels_sha256=sorted(labels)))
    protected = json.loads((ROOT / "docs/verification/monitor-replay-error-20261020/integrity-after.json").read_text())
    assert len(protected) == 130
    actual = {name: sha256(ROOT / name) for name in protected}
    assert actual == protected, "Protected raw data/history/model/gate changed"
    save("integrity-after.json", actual)
    checks = dict(status="PASS_METADATA_INTEGRITY_ONLY", reused_receipts=len(old_receipts),
        new_receipts=len(receipts), new_git_blobs=len(documents),
        protected_files_matching=len(protected), do53_parts=len(parts),
        archive_bytes=sum(entry["size"] for entry in parts),
        dataset_values_opened=False, archives_downloaded=0, training_or_scoring=False,
        qualified_evaluation_roles=0, required_evaluation_dod="BLOCKED")
    save("checks.json", checks)
    print(json.dumps(checks))
