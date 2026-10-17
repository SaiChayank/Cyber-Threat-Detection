"""Execute only the frozen four-byte transport check against the original ZIP."""
import hashlib
import importlib.metadata
import json
from pathlib import Path
import zipfile

import stream_inflate
from read_prefix import read_method9_prefix


def sha(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def main():
    here = Path(__file__).resolve().parent
    root = here.parents[2]
    plan_path = here / 'selection-plan.json'
    assert sha(plan_path) == (here / 'selection-plan.sha256').read_text().split()[0]
    protocol = root / 'docs/UMA_HEADER_TRANSPORT_PROTOCOL.md'
    assert sha(protocol) == (here / 'protocol.sha256').read_text().split()[0]
    plan = json.loads(plan_path.read_text())
    archive = root / plan['archive']
    assert archive.stat().st_size == plan['archive_bytes']
    assert sha(archive) == plan['archive_sha256']
    assert importlib.metadata.version(plan['decoder']['distribution']) == plan['decoder']['version']
    assert sha(stream_inflate.__file__) == plan['decoder']['sha256']
    results = []
    with zipfile.ZipFile(archive) as container:
        infos = container.infolist()
        assert len(infos) == len(plan['entries']) == 45
        for pinned, info in zip(plan['entries'], infos):
            actual = dict(index=len(results), name=info.filename, file_bytes=info.file_size,
                          compressed_bytes=info.compress_size, crc32=f'{info.CRC:08x}',
                          method=info.compress_type, flags=info.flag_bits,
                          local_header_offset=info.header_offset)
            assert actual == pinned
            try:
                result = read_method9_prefix(archive, info,
                                             max_compressed=plan['max_compressed_bytes_per_member'])
                result['classification'] = ('PCAPNG_SIGNATURE_RUNTIME_UNSUPPORTED'
                                            if result['header_hex'] == '0a0d0d0a' else 'UNKNOWN')
            except Exception as error:
                result = dict(classification='UNVERIFIED', error_type=type(error).__name__,
                              error=str(error))
            results.append(dict(member=info.filename, **result))
    output = dict(protocol_sha256=sha(protocol), selection_plan_sha256=sha(plan_path),
                  original_archive_sha256=plan['archive_sha256'], entries=results,
                  full_member_crc_verified=False, packet_values_inspected=False,
                  evaluation_roles_assigned=False)
    (here / 'results.json').write_bytes((json.dumps(output, indent=2) + '\n').encode())
    print(json.dumps(dict(attempts=len(results), classifications={
        label: sum(r['classification'] == label for r in results)
        for label in sorted({r['classification'] for r in results})},
        total_logical_output_bytes=sum(r.get('logical_output_bytes', 0) for r in results),
        total_compressed_input_bytes=sum(r.get('compressed_input_bytes', 0) for r in results))))


if __name__ == '__main__':
    main()
