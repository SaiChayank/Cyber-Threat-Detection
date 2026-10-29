"""Threshold sweep: train/validation only, whitelisted knobs, always restores the runtime."""
import json

import pytest

from datasets import tune_lab
from datasets.lab_labels import FORMAT
from features import slow_http
from tests.test_slow_http import START, tcp, trickle

CAP = 'capture.jsonl'


def write_run(tmp_path, split, name='run', trickle_connections=60):
    events = trickle(connections=trickle_connections)
    (tmp_path / f'{name}.jsonl').write_text(''.join(e.model_dump_json() + '\n' for e in events))
    labels = tmp_path / f'{name}.json'
    labels.write_text(json.dumps(dict(format=FORMAT, capture=f'{name}.jsonl', split=split, episodes=[
        dict(id=f'{name}-flood', label='DDOS', scenario='slow_http', start_ms=START - 1000, end_ms=START + 10**9,
             hosts=['192.0.2.80'])])))
    return labels


def write_grid(tmp_path, grid):
    path = tmp_path / 'grid.json'
    path.write_text(json.dumps(grid))
    return path


def test_sweep_ranks_settings_and_restores_originals(tmp_path):
    before = slow_http.MIN_SLOW_CONNECTIONS
    grid = write_grid(tmp_path, {'slow_http.MIN_SLOW_CONNECTIONS': [30, 50, 500]})
    report = tune_lab.sweep(tune_lab.parse_grid(grid), [write_run(tmp_path, 'train')], 1.0)
    assert slow_http.MIN_SLOW_CONNECTIONS == before
    by_value = {r['settings']['slow_http.MIN_SLOW_CONNECTIONS']: r for r in report['ranked']}
    assert by_value[30]['mean_episode_recall'] == by_value[50]['mean_episode_recall'] == 1.0
    assert by_value[500]['mean_episode_recall'] == 0.0
    assert report['best']['settings']['slow_http.MIN_SLOW_CONNECTIONS'] in (30, 50)
    assert report['ranked'][-1]['settings']['slow_http.MIN_SLOW_CONNECTIONS'] == 500
    assert report['splits'] == ['train'] and report['combinations'] == 3


def test_test_split_is_refused_and_validation_is_allowed(tmp_path):
    grid = tune_lab.parse_grid(write_grid(tmp_path, {'slow_http.MIN_AGE_S': [30]}))
    with pytest.raises(tune_lab.SweepError, match='never swept'):
        tune_lab.sweep(grid, [write_run(tmp_path, 'train', 'a'), write_run(tmp_path, 'test', 'b')], 1.0)
    assert tune_lab.sweep(grid, [write_run(tmp_path, 'validation', 'c')], 1.0)['splits'] == ['validation']


@pytest.mark.parametrize('grid, message', [
    ({'os.system': [1]}, 'not tunable'),
    ({'slow_http.MIN_AGE_S': []}, 'nonempty list'),
    ({'slow_http.MIN_AGE_S': ['x']}, 'list of numbers'),
    ({'slow_http.MIN_SLOW_CONNECTIONS': list(range(1, 16)), 'slow_http.MIN_AGE_S': list(range(1, 16))}, 'limit is'),
    ([], 'nonempty object'),
])
def test_unsafe_or_oversized_grids_are_rejected(tmp_path, grid, message):
    with pytest.raises(tune_lab.SweepError, match=message):
        tune_lab.parse_grid(write_grid(tmp_path, grid))


def test_cap_marks_settings_that_raise_too_many_false_alerts(tmp_path):
    grid = tune_lab.parse_grid(write_grid(tmp_path, {'slow_http.MIN_SLOW_CONNECTIONS': [50]}))
    # An unlabelled benign flow of the same shape is benign background: every alert is a false alert.
    events = trickle(connections=60)
    (tmp_path / 'bg.jsonl').write_text(''.join(e.model_dump_json() + '\n' for e in events))
    labels = tmp_path / 'bg.json'
    labels.write_text(json.dumps(dict(format=FORMAT, capture='bg.jsonl', split='train', episodes=[
        dict(id='ok', label='BENIGN', scenario='long_poll', start_ms=START - 1000, end_ms=START + 10**9, hosts=['192.0.2.80'])])))
    report = tune_lab.sweep(grid, [labels], 0.5)
    assert report['best'] is None and 'relax' in report['note']
    assert report['ranked'][0]['within_false_alert_cap'] is False


def test_cli_writes_report_and_never_overwrites_inputs(tmp_path, capsys):
    labels = write_run(tmp_path, 'train')
    grid = write_grid(tmp_path, {'slow_http.MIN_SLOW_CONNECTIONS': [50, 500]})
    out = tmp_path / 'sweep.json'
    assert tune_lab.main([str(grid), str(labels), '--out', str(out)]) == 0
    assert json.loads(out.read_text())['format'] == 'ps26145-lab-sweep/1'
    assert 'recall' in capsys.readouterr().out
    with pytest.raises(SystemExit) as refused:
        tune_lab.main([str(grid), str(labels), '--out', str(grid)])
    assert refused.value.code == 2
    with pytest.raises(SystemExit):
        tune_lab.main([str(grid), str(write_run(tmp_path, 'test', 't'))])
