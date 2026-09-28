import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from datasets.domains import replay_domains
from datasets.tls import label, vector


def test_domains_wrapper_is_explicit_and_labels_are_not_predictors(tmp_path):
    path = tmp_path/'domains.txt'
    path.write_text('example.com\ninvalid input\nabc.example.org\n')
    records = list(replay_domains(path))
    assert len(records) == 2
    assert records[0].flow_id.startswith('UMUDGA-lab-')
    assert not records[0].reverse_observed
    assert records[1].timestamp > records[0].timestamp


def test_tls_forward_view_never_uses_labels_or_reverse_measurements():
    row = {'bs':100, 'ps':2, 'td':1, 'tls.rec':[100,-9000,200], 'tls.ccs':['1301'], 'tls.cext':['0023']}
    expected = vector(row)
    row.update({'br':999999,'pr':8000,'tls.rec':[100,-20,200], 'meta.malware.family':'leaked-label','meta.sample.id':'sample'})
    assert vector(row) == expected
    assert label(row,'malware') == 'MALWARE_RELATED'
    row['meta.system.service'] = 'microsoft_telemetry'
    assert label(row,'malware') == 'UNLABELLED'
    assert label(row,'soho') == 'UNLABELLED'
    row['bs'] = None
    with pytest.raises(ValueError):
        vector(row)


def test_public_presets_do_not_accept_arbitrary_paths(tmp_path,monkeypatch):
    monkeypatch.setenv('ALERT_DB',str(tmp_path/'alerts.sqlite3'))
    from backend.application import app
    with TestClient(app) as client:
        assert client.get('/api/datasets').status_code == 200
        assert client.post('/api/replay/start',json={'scenario':'../../secrets'}).status_code == 422
