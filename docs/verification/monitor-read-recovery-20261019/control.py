"""Control only the owned marker and real loopback fixture API; no product mode."""
import json
from pathlib import Path
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import httpx
from tests.test_sse_resume import event


def main():
    action=sys.argv[1]
    ready=json.loads((HERE/'ready.json').read_text())
    marker=Path(ready['marker']).resolve()
    assert marker.parent.parent==Path(tempfile.gettempdir()).resolve()
    assert marker.parent.name.startswith('univect-monitor-read-') and marker.name=='read-fault'
    with httpx.Client(base_url='http://127.0.0.1:13529',trust_env=False,timeout=5) as client:
        if action in ('fault','initial-fault'):
            marker.write_bytes(b'Controlled verification read fault')
            statuses={}
            for route in ('/api/alerts','/api/telemetry','/api/stream'):
                response=client.get(route)
                assert response.status_code==503 and response.json()['detail']=='Alert history temporarily unavailable; retry after storage recovery'
                statuses[route]=response.status_code
            if action=='fault':
                accepted=json.loads((HERE/'accepted.json').read_text())
                for index in range(len(accepted),len(accepted)+2):
                    response=client.post('/api/events',json=event(index))
                    response.raise_for_status(); assert len(response.json())==1
                    accepted.extend(response.json())
                (HERE/'accepted.json').write_bytes((json.dumps(accepted,indent=2)+'\n').encode())
            print(json.dumps(dict(action=action,statuses=statuses)))
        elif action=='recover':
            marker.unlink()
            accepted=json.loads((HERE/'accepted.json').read_text())
            assert client.get('/api/alerts').json()==accepted
            print(json.dumps(dict(action=action,durable_alerts=len(accepted))))
        else:raise SystemExit('Unknown action')


if __name__=='__main__':main()
