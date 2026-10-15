"""Selected-member downloads must retain raw bytes and verify complete members."""
import io
import zipfile

import httpx
import pytest

from datasets.acquire_tls_source import catalogue, download_member, range_bytes


def archive():
    handle = io.BytesIO()
    with zipfile.ZipFile(handle, 'w', zipfile.ZIP_DEFLATED) as output:
        output.writestr('large/source.pcap', bytes(range(256)) * 20)
        output.writestr('small/source.pcap', b'unchanged original bytes' * 10)
    return handle.getvalue()


def range_client(body):
    def respond(request):
        value = request.headers['Range'].removeprefix('bytes=')
        if value.startswith('-'):
            first, last = max(0, len(body) - int(value[1:])), len(body) - 1
        else:
            first, last = map(int, value.split('-'))
        return httpx.Response(206, content=body[first:last + 1],
                              headers={'Content-Range': f'bytes {first}-{last}/{len(body)}'})
    return httpx.Client(transport=httpx.MockTransport(respond))


def test_catalogue_selection_precedes_complete_raw_member_crc_verification(tmp_path):
    with range_client(archive()) as client:
        selection = catalogue(client, 'https://publisher.invalid/data.zip')
        assert selection['selected']['name'] == 'small/source.pcap'
        assert selection['role'] == 'development-only'
        output = tmp_path / 'source.pcap'
        report = download_member(client, selection, output)
    assert output.read_bytes() == b'unchanged original bytes' * 10
    assert report['zip_member_crc32_verified'] is True
    assert report['whole_archive_sha256_verified'] is False


def test_ignored_range_does_not_download_full_archive():
    with httpx.Client(transport=httpx.MockTransport(lambda request:
                       httpx.Response(200, content=b'full archive'))) as client:
        with pytest.raises(ValueError, match='does not support'):
            range_bytes(client, 'https://publisher.invalid/data.zip', 'bytes=0-3')


def test_stale_archive_length_rejected():
    with range_client(archive()) as client:
        with pytest.raises(ValueError, match='length changed'):
            range_bytes(client, 'https://publisher.invalid/data.zip', 'bytes=0-3', 1)


def test_incomplete_publisher_range_rejected():
    with httpx.Client(transport=httpx.MockTransport(lambda request:
                       httpx.Response(206, content=b'abc', headers={
                           'Content-Range': 'bytes 0-3/100'}))) as client:
        with pytest.raises(ValueError, match='Incomplete'):
            range_bytes(client, 'https://publisher.invalid/data.zip', 'bytes=0-3')


def test_body_exceeding_declared_range_is_rejected_before_use():
    with httpx.Client(transport=httpx.MockTransport(lambda request:
                       httpx.Response(206, content=b'abcde', headers={
                           'Content-Range': 'bytes 0-3/100'}))) as client:
        with pytest.raises(ValueError, match='exceeds declared'):
            range_bytes(client, 'https://publisher.invalid/data.zip', 'bytes=0-3')


def test_mismatched_member_crc_never_creates_capture(tmp_path):
    with range_client(archive()) as client:
        selection = catalogue(client, 'https://publisher.invalid/data.zip')
        selection['selected']['crc32'] ^= 1
        output = tmp_path / 'bad.pcap'
        with pytest.raises(ValueError, match='CRC mismatch'):
            download_member(client, selection, output)
    assert not output.exists()
