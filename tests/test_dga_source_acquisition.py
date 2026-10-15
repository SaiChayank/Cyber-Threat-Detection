"""No network or domain-row reading: acquisition integrity boundaries."""
import hashlib

import httpx
import pytest

from datasets.acquire_dga_evaluation import download_one, PREFIX


def item(body):
    return dict(path='raw_including_TLD/T25_dga.parquet', bytes=len(body),
                sha256=hashlib.sha256(body).hexdigest(),
                url='https://huggingface.co' + PREFIX + 'T25_dga.parquet')


def client(body, status=200):
    return httpx.Client(transport=httpx.MockTransport(
        lambda request: httpx.Response(status, content=body)))


def test_verified_bytes_are_preserved_and_existing_download_not_overwritten(tmp_path):
    body = b'PAR1offline-test-fixturePAR1'
    with client(body) as connection:
        result = download_one(connection, item(body), tmp_path)
        assert result['publisher_sha256_verified']
        assert (tmp_path / 'T25_dga.parquet').read_bytes() == body
        assert not (tmp_path / 'T25_dga.parquet.part').exists()
        with pytest.raises(FileExistsError):
            download_one(connection, item(body), tmp_path)


@pytest.mark.parametrize('problem', ['short', 'oversize', 'checksum'])
def test_invalid_download_never_becomes_complete(tmp_path, problem):
    body = b'fixture'
    expected = item(body)
    delivered = body[:-1] if problem == 'short' else body + b'x' if problem == 'oversize' else b'damaged'
    with client(delivered) as connection, pytest.raises(ValueError):
        download_one(connection, expected, tmp_path)
    assert not (tmp_path / 'T25_dga.parquet').exists()
    assert (tmp_path / 'T25_dga.parquet.part').exists()


def test_unapproved_source_or_path_is_rejected_before_network(tmp_path):
    expected = item(b'fixture')
    expected['url'] = 'https://example.com/arbitrary'
    with client(b'fixture') as connection, pytest.raises(ValueError, match='pinned'):
        download_one(connection, expected, tmp_path)
    assert not list(tmp_path.iterdir())


def test_invalid_size_is_rejected_before_network(tmp_path):
    expected = item(b'fixture')
    expected['bytes'] = True
    with client(b'fixture') as connection, pytest.raises(ValueError, match='size'):
        download_one(connection, expected, tmp_path)
