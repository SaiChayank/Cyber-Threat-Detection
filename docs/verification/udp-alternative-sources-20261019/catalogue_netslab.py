"""Bounded public ZIP directory metadata only; never decompress a traffic member."""
import hashlib
import json
from pathlib import Path
import struct

import httpx

HERE=Path(__file__).resolve().parent
RECORD='https://zenodo.org/api/records/18923275'


def catalogue(client, item):
    url=item['links']['self']; size=item['size']; ranges=[]; etag=None; modified=None
    def fetch(start,length):
        nonlocal etag,modified
        assert 0<=start<size and 0<length<=1048576 and start+length<=size
        headers={'Range':f'bytes={start}-{start+length-1}','Accept-Encoding':'identity'}
        if etag:headers['If-Match']=etag
        elif modified:headers['If-Unmodified-Since']=modified
        with client.stream('GET',url,headers=headers) as response:
            assert response.status_code==206, 'Refuse an unbounded/full-file response'
            assert response.headers.get('content-range')==f'bytes {start}-{start+length-1}/{size}'
            current=response.headers.get('etag')
            current_modified=response.headers.get('last-modified')
            if etag:assert current==etag
            elif modified:assert current_modified==modified
            else:etag=current;modified=current_modified
            chunks=[]; received=0
            for chunk in response.iter_bytes():
                received+=len(chunk); assert received<=length
                chunks.append(chunk)
            data=b''.join(chunks); assert len(data)==length
        ranges.append(dict(start=start,length=length,sha256=hashlib.sha256(data).hexdigest()))
        return data
    tail=fetch(max(0,size-65557),min(size,65557))
    end=tail.rfind(b'PK\x05\x06'); assert end>=0
    header=struct.unpack_from('<4s4H2LH',tail,end)
    assert header[1]==header[2]==0 and end+22+header[7]==len(tail)
    count=header[4]; length=header[5]; offset=header[6]
    if count==65535 or length==0xffffffff or offset==0xffffffff:
        locator=struct.unpack_from('<4sLQL',tail,end-20)
        assert locator[0]==b'PK\x06\x07' and locator[1]==0 and locator[3]==1
        record=struct.unpack('<4sQ2H2L4Q',fetch(locator[2],56))
        assert record[0]==b'PK\x06\x06' and record[4]==record[5]==0
        count=record[7];length=record[8];offset=record[9]
    assert 0<length<=1048576, 'Directory-only scope exceeds the frozen request bound'
    directory=fetch(offset,length); position=0; members=[]
    while position<len(directory):
        values=struct.unpack_from('<4s6H3L5H2L',directory,position)
        assert values[0]==b'PK\x01\x02'
        name_end=position+46+values[10]
        finish=name_end+values[11]+values[12]
        assert finish<=len(directory)
        name=directory[position+46:name_end].decode('utf-8' if values[3]&0x800 else 'cp437')
        members.append(dict(name=name,compression=values[4],crc32=f'{values[7]:08x}',
                            compressed_size_32bit=values[8],uncompressed_size_32bit=values[9],
                            zip64_sizes_require_extra_fields=values[8]==0xffffffff or values[9]==0xffffffff))
        position=finish
    assert len(members)==count and position==length
    return dict(archive=item['key'],archive_bytes=size,publisher_checksum=item['checksum'],
        full_checksum_locally_verified=False,conditional_identity_verified=bool(etag or modified),
        qualification_evidence_complete=False,url=url,etag=etag,last_modified=modified,ranges=ranges,members=members,
        traffic_members_decompressed=0,packet_values_read=False)


def main():
    with httpx.Client(timeout=30,follow_redirects=True) as client:
        with client.stream('GET',RECORD) as response:
            response.raise_for_status(); raw=bytearray()
            for part in response.iter_bytes():
                raw.extend(part); assert len(raw)<=1048576
        metadata=json.loads(raw)
        assert metadata['metadata']['license']['id']=='cc-by-4.0'
        entries={row['key']:row for row in metadata['files']}
        output=dict(record=RECORD,record_metadata_sha256=hashlib.sha256(raw).hexdigest(),
            licence=metadata['metadata']['license'],record_files=[dict(key=row['key'],size=row['size'],
                checksum=row['checksum']) for row in metadata['files']],catalogues=[])
        for name in ['Benign.zip','DDOS.zip']:
            # These public download links are explicitly listed on the producer
            # record. Missing conditional identity headers stay an explicit limitation.
            item=entries[name] | {'links':{'self':f'https://zenodo.org/records/18923275/files/{name}?download=1'}}
            result=catalogue(client,item); output['catalogues'].append(result)
            print(name,json.dumps([row['name'] for row in result['members']]),flush=True)
        (HERE/'netslab-catalogues.json').write_bytes((json.dumps(output,indent=2)+'\n').encode())


if __name__=='__main__':main()
