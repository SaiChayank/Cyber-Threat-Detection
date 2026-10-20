"""Owned integration process only; real API/detection/persistence, one source fault."""
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from backend import application
from schemas.traffic_event import TrafficEvent
from tests.test_replay_controls import alert_event
import uvicorn

original = application.scenario
marker = Path(os.environ['TEST_REPLAY_MARKER'])


def controlled_scenario(label, *args, **kwargs):
    if label == 'BENIGN' and marker.exists():
        marker.unlink()
        yield TrafficEvent(**alert_event(2))
        raise RuntimeError('private-monitor-sentinel C:/private/analyst/runbook.txt')
    yield from original(label, *args, **kwargs)


application.scenario = controlled_scenario
if __name__ == '__main__':
    uvicorn.run(application.app, host='127.0.0.1', port=18533, log_level='warning', access_log=False)
