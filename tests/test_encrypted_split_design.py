from datasets.design_encrypted_split import Components, design
from datasets.train_tls import bucket


def app_for(role):
    return next(f'app{i}' for i in range(100) if
                ('train' if bucket('winapps:'+f'app{i}')<6 else
                 'validation' if bucket('winapps:'+f'app{i}')<8 else 'test')==role)


def test_transitive_links_keep_shared_samples_captures_and_groups_together():
    records=[('winapps','a',{'meta.application.name':app_for('train'),'meta.sample.id':'shared'}),
             ('winapps','b',{'meta.application.name':app_for('validation'),'meta.sample.id':'shared'}),
             ('winapps','b',{'meta.application.name':app_for('train'),'meta.sample.id':'other'})]
    result=design(records)
    assert len(result['components'])==1
    assert all(v==0 for checks in result['overlap_checks'].values() for v in checks.values())
    assert result['gate_passed'] is False  # Single-class support is not enough.


def test_any_historical_test_connection_quarantines_entire_component():
    result=design([('winapps','a',{'meta.application.name':app_for('train'),'meta.sample.id':'shared'}),
                   ('winapps','b',{'meta.application.name':app_for('test'),'meta.sample.id':'shared'})])
    assert result['component_counts']=={'quarantine_historical_test':1}
    assert result['development_counts']['train']['BENIGN_REFERENCE']==0
    assert result['development_counts']['validation']['BENIGN_REFERENCE']==0


def test_assignment_is_order_independent_and_never_searches_for_a_passing_salt():
    records=[('winapps',f'm{i}',{'meta.application.name':app_for('train'),'meta.sample.id':f's{i}'}) for i in range(5)]
    assert design(records)==design(list(reversed(records)))


def test_missing_sample_uses_real_capture_identity_without_inventing_observations():
    result=design([('winapps','a',{'meta.application.name':app_for('train')}),
                   ('winapps','a',{'meta.application.name':app_for('validation')})])
    assert len(result['components'])==1
    assert result['components'][0]['sample_ids_sha256']==[]


def test_unlabelled_rows_never_become_positive_training_truth():
    result=design([('malware','a',{'meta.sample.id':'id','meta.malware.family':'x','meta.system.service':'update'})])
    assert result['component_counts']=={'unlabelled':1}
    assert result['development_counts']['unlabelled']['MALWARE_RELATED']==0


def test_component_links_do_not_lose_transitive_identity():
    components=Components()
    components.link('c','b');components.link('a','c')
    assert components.find('a')==components.find('b')==components.find('c')
