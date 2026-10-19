"""One scoped API source-pin correction, only after frozen trace equality."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from replay.cli import metadata
from replay.demo_pack import sha256, summarize

HERE = Path(__file__).resolve().parent


def main():
    path = ROOT / 'data/demo/manifest.json'
    checksum = path.with_suffix('.sha256')
    raw = path.read_bytes()
    before = sha256(path)
    assert before == checksum.read_text().strip()
    assert before == '63f5405d6b0cbcf85d1e6dcd2ac96b74c7284004162601f1675d2ebf49606fa9'
    manifest = json.loads(raw)
    traces = []
    for row in manifest['scenarios']:
        assert sha256(ROOT / row['artifact']) == row['sha256']
        actual = summarize(list(metadata(ROOT / row['artifact'])))
        assert actual == row['expected'], row['preset']
        traces.append(dict(preset=row['preset'], expected_unchanged=True,
                           trace_sha256=actual['stable_alert_trace_sha256']))
    assert len(traces) == 9
    pin = manifest['provenance']['backend/application.py']
    old = pin['sha256']
    new = sha256(ROOT / 'backend/application.py', pin['newline_normalized'])
    assert old != new and raw.count(old.encode()) == 1
    updated = raw.replace(old.encode(), new.encode())
    pin['sha256'] = new
    assert json.loads(updated) == manifest
    path.write_bytes(updated)
    checksum.write_bytes((sha256(path) + '\n').encode())
    receipt = dict(reason='SQLite read-boundary error repair; frozen detector outputs preserved',
        previous_git_reference='47a09f6:data/demo/manifest.json',
        before_manifest_sha256=before, after_manifest_sha256=sha256(path),
        old_api_source_sha256=old, new_api_source_sha256=new,
        only_api_source_pin_changed=True, all_nine_traces_unchanged=traces)
    (HERE / 'demo-provenance-update.json').write_bytes((json.dumps(receipt, indent=2) + '\n').encode())
    print('All nine frozen traces unchanged; only API source pin and checksum refreshed')


if __name__ == '__main__':
    main()
