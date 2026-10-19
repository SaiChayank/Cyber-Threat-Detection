"""Public-source metadata reads must stay bounded and fail closed."""
import importlib.util
import io
from pathlib import Path
import re
import struct
import zipfile

import pytest

MODULE=Path(__file__).resolve().parents[1]/'docs/verification/udp-alternative-sources-20261019/catalogue_netslab.py'
spec=importlib.util.spec_from_file_location('udp_source_catalogue',MODULE)
catalogue_module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(catalogue_module)


def archive():
    buffer=io.BytesIO()
    with zipfile.ZipFile(buffer,'w',compression=zipfile.ZIP_DEFLATED) as output:
        output.writestr('Benign/Network_data/iperf_benign.pcap',b'opaque unit fixture; not traffic')
        output.writestr('README.txt',b'fixture metadata')
    return buffer.getvalue()


class Response:
    def __init__(self,data,headers,status):
        self.data=data;self.headers=headers;self.status_code=status;self.body_read=False

    def __enter__(self):return self
    def __exit__(self,*args):return False
    def iter_bytes(self):
        self.body_read=True
        yield self.data


class Client:
    def __init__(self,raw,mode=None):
        self.raw=raw;self.mode=mode;self.requests=[];self.responses=[]

    def stream(self,method,url,headers):
        match=re.fullmatch(r'bytes=(\d+)-(\d+)',headers['Range'])
        assert match and method=='GET'
        start,end=map(int,match.groups())
        self.requests.append((start,end,headers))
        data=self.raw[start:end+1]
        result_headers={'content-range':f'bytes {start}-{end}/{len(self.raw)}','etag':'"fixed"'}
        status=206
        if self.mode=='full-response':status=200
        if self.mode=='wrong-range':result_headers['content-range']='bytes 0-0/1'
        if self.mode=='short-body':data=data[:-1]
        if self.mode=='long-body':data+=b'!'
        if self.mode=='changing-etag' and len(self.requests)>1:result_headers['etag']='"changed"'
        if self.mode=='missing-etag':result_headers.pop('etag')
        if self.mode=='last-modified':
            result_headers.pop('etag')
            result_headers['last-modified']='Thu, 12 Mar 2026 13:01:36 GMT'
        response=Response(data,result_headers,status);self.responses.append(response)
        return response


def item(raw):
    return dict(key='Benign.zip',size=len(raw),checksum='md5:publisher-only',
                links={'self':'https://example.test/public-source.zip'})


def test_catalogue_preserves_names_and_checksums_without_decompressing_members(monkeypatch):
    raw=archive();client=Client(raw)
    def forbidden(*args,**kwargs):raise AssertionError('Member decompression is outside scope')
    monkeypatch.setattr(zipfile.ZipFile,'open',forbidden)
    result=catalogue_module.catalogue(client,item(raw))
    assert [x['name'] for x in result['members']]==['Benign/Network_data/iperf_benign.pcap','README.txt']
    assert all(end-start+1<=1048576 for start,end,_ in client.requests)
    assert result['traffic_members_decompressed']==0 and result['packet_values_read'] is False
    assert result['full_checksum_locally_verified'] is False
    assert client.requests[1][2]['If-Match']=='"fixed"'


@pytest.mark.parametrize('mode',['full-response','wrong-range','short-body','long-body','changing-etag'])
def test_invalid_http_range_or_changed_source_is_rejected(mode):
    raw=archive();client=Client(raw,mode)
    with pytest.raises(AssertionError):catalogue_module.catalogue(client,item(raw))
    if mode in ['full-response','wrong-range']:
        assert not client.responses[0].body_read


def test_broken_directory_is_not_accepted_as_a_catalogue():
    raw=archive().replace(b'PK\x01\x02',b'BAD!',1)
    with pytest.raises(AssertionError):catalogue_module.catalogue(Client(raw),item(raw))


def test_metadata_without_identity_headers_is_explicitly_unqualified():
    raw=archive();client=Client(raw,'missing-etag')
    result=catalogue_module.catalogue(client,item(raw))
    assert result['conditional_identity_verified'] is False
    assert result['full_checksum_locally_verified'] is False
    assert result['qualification_evidence_complete'] is False
    assert result['packet_values_read'] is False


def test_zip64_end_metadata_produces_the_same_member_names():
    raw=archive();end=raw[-22:]
    count=struct.unpack_from('<H',end,10)[0]
    length,offset=struct.unpack_from('<LL',end,12)
    record=struct.pack('<4sQ2H2L4Q',b'PK\x06\x06',44,45,45,0,0,count,count,length,offset)
    locator=struct.pack('<4sLQL',b'PK\x06\x07',0,len(raw)-22,1)
    legacy=struct.pack('<4s4H2LH',b'PK\x05\x06',0,0,65535,65535,0xffffffff,0xffffffff,0)
    zip64=raw[:-22]+record+locator+legacy
    result=catalogue_module.catalogue(Client(zip64),item(zip64))
    assert [x['name'] for x in result['members']]==['Benign/Network_data/iperf_benign.pcap','README.txt']
    assert any(r['length']==56 for r in result['ranges'])


def test_publisher_last_modified_guards_ranges_when_etag_is_not_supplied():
    raw=archive();client=Client(raw,'last-modified')
    result=catalogue_module.catalogue(client,item(raw))
    assert result['last_modified']=='Thu, 12 Mar 2026 13:01:36 GMT'
    assert client.requests[1][2]['If-Unmodified-Since']==result['last_modified']
    assert result['full_checksum_locally_verified'] is False
