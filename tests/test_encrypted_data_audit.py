"""Feasibility diagnostics preserve missingness and excluded partitions."""
import zipfile

import pytest

from datasets.audit_encrypted_data import ANNOTATIONS, HANDSHAKE, array_status, audit_archive, partition, sample_day
from datasets.train_tls import bucket


@pytest.mark.parametrize('value,status',[
    (None,'missing'),([],'present_empty'),([4865,49195],'present_nonempty'),
    (['DADA','1301','C02B','0000'],'present_nonempty'),
    ([True],'invalid'),([-1],'invalid'),([65536],'invalid'),
    (['not-an-id'],'invalid'),('1301','invalid'),
])
def test_ids_and_missingness_are_classified_without_fabricated_zero(value,status):
    assert array_status(value)==status


def test_annotation_labels_are_never_invented_from_collection_or_missing_family():
    assert partition({'meta.malware.family':None},'malware')=='unlabelled'
    assert partition({'meta.malware.family':'known','meta.system.service':'updater'},'malware')=='unlabelled'
    assert partition({'meta.application.name':None},'winapps')=='unlabelled'
    assert partition({'meta.malware.family':'known'},'soho')=='unlabelled'


def test_sample_dates_are_metadata_not_an_assumed_network_timeline():
    assert sample_day('250901-example')=='2025-09-01'
    assert sample_day('20240716_Application')=='2024-07-16'
    assert sample_day('20240230_Invalid') is None
    assert sample_day(None) is None


def test_historical_test_and_mixed_members_never_read_features(tmp_path,monkeypatch):
    pq=pytest.importorskip('pyarrow.parquet')
    names={}
    for suffix in range(100):
        app=f'app{suffix}'
        b=bucket('winapps:'+app)
        names.setdefault('train' if b<6 else 'validation' if b<8 else 'historical_test',app)
    archive=tmp_path/'fixture.zip'
    with zipfile.ZipFile(archive,'w') as z:
        for name in ['train','mixed','historical_test']:
            z.writestr(name+'.parquet',b'fixture')
    calls=[]
    class Batch:
        def __init__(self,rows):self.rows=rows
        def to_pylist(self):return self.rows
    class Parquet:
        def __init__(self,file):
            self.name=file.name.split('.')[0]
            self.metadata=type('Meta',(),{'num_rows':2 if self.name=='mixed' else 1})()
            self.schema_arrow=type('Schema',(),{'names':ANNOTATIONS+HANDSHAKE})()
        def iter_batches(self,**kwargs):
            cols=kwargs['columns'];calls.append((self.name,cols))
            apps=([names['train'],names['historical_test']] if self.name=='mixed'
                  else [names[self.name]])
            yield Batch([{'meta.application.name':app,'meta.sample.id':'20240716_test',
                          'tls.ccs':['1301'],'tls.cext':['0000'],'tls.ja3':'observed'} for app in apps])
    monkeypatch.setattr(pq,'ParquetFile',Parquet)
    result=audit_archive(archive,'winapps')
    assert result['totals']['members_excluded_from_feature_read']==2
    assert result['totals']['members_feature_read']==1
    assert [(name,cols) for name,cols in calls if cols==ANNOTATIONS+HANDSHAKE]==[('train',ANNOTATIONS+HANDSHAKE)]
    assert result['development_coverage']['train:BENIGN_REFERENCE']['tls.ccs:hex_encoded_rows']==1
    assert result['sample_overlap_counts']['train:historical_test']==1


def test_soho_is_footer_only_not_a_supervised_benign_class(tmp_path,monkeypatch):
    pq=pytest.importorskip('pyarrow.parquet')
    archive=tmp_path/'soho.zip'
    with zipfile.ZipFile(archive,'w') as z:z.writestr('soho.parquet',b'fixture')
    class Parquet:
        def __init__(self,_):
            self.metadata=type('Meta',(),{'num_rows':10})()
            self.schema_arrow=type('Schema',(),{'names':['tls.ccs']})()
        def iter_batches(self,**kwargs):pytest.fail('Unlabelled SOHO row values must remain unread')
    monkeypatch.setattr(pq,'ParquetFile',Parquet)
    result=audit_archive(archive,'soho')
    assert result['totals']['footer_rows']==10
    assert result['development_coverage']=={}
