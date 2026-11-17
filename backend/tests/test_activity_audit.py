import csv
import io
import json

from sqlalchemy import select

from app import api, security, worker
from app.db import Audit, AuditExportRows, session
from test_api_security_export import imported


PERIOD = {'start': '2000-01-01T00:00:00Z', 'end': '2100-01-01T00:00:00Z'}
ACTIVITY = '/api/admin/audit/activity'
REPORT = '/api/admin/audit/report'


def test_export_audit_survives_job_removal(client, users, sample):
    jid = imported(client, sample)
    url = f'/api/jobs/{jid}'
    record = client.get(url + '/rows').json()['items'][1]
    query = {'format': 'json', 'fields': [['id', 'Numer'], ['pesel', 'Identyfikator']],
             'ids': [record['row_id']]}
    exported = client.post(url + '/export', json=query)
    assert exported.status_code == 200
    assert client.post(ACTIVITY, json=PERIOD).status_code == 403
    assert client.post(REPORT, json=PERIOD).status_code == 403

    api.app.dependency_overrides[security.current_user] = lambda: users[2]
    assert client.request('DELETE', url, json={'confirm': True}).status_code == 200
    event, = client.post(ACTIVITY, json=PERIOD).json()['items']
    assert event['username'] == users[0].username
    assert event['row_count'] == 1
    details = client.post(f'{ACTIVITY}/{event["id"]}/details').json()
    assert details['rows'] == [{'source_row': 2, 'data': exported.json()[0]}]
    assert sample['pesel'] not in json.dumps(details)
    assert client.post(ACTIVITY, json={**PERIOD, 'operation': 'search'}).json()['total'] == 0
    assert client.post(ACTIVITY, json={**PERIOD, 'end': PERIOD['start']}).status_code == 422
    report = client.post(REPORT, json=PERIOD)
    rows = list(csv.DictReader(io.StringIO(report.content.decode('utf-8-sig')), delimiter=';'))
    assert {row['Login'] for row in rows} == {users[0].username}
    assert json.loads(rows[1]['Szczegóły JSON']) == details['rows'][0]
    with session() as db:
        assert '0002' not in db.scalar(select(AuditExportRows)).payload
        assert db.scalar(select(Audit).where(Audit.action == 'audit.report')).actor_id == users[2].id


def test_search_audit_uses_scheduler_and_exact_criteria(client, users, sample, monkeypatch):
    jid = imported(client, sample)
    api.app.dependency_overrides[security.current_user] = lambda: users[2]
    monkeypatch.setattr(api, 'readiness', lambda cfg: {'ready': True})
    monkeypatch.setattr(worker, 'readiness', lambda cfg: {'ready': True})
    monkeypatch.setattr(worker, 'pacing', lambda *args: None)
    class Adapter:
        def __init__(self, cfg):
            pass

        def search(self, criteria):
            return {'status': 'not_found', 'ade': None}

        def close(self):
            pass

    assert client.post(f'/api/jobs/{jid}/action', json={'action': 'start'}).status_code == 200
    assert worker.tick(Adapter)
    event, = client.post(ACTIVITY, json=PERIOD).json()['items']
    assert event['username'] == users[2].username
    assert event['outcome'] == 'not_found'
    details = client.post(f'{ACTIVITY}/{event["id"]}/details').json()['details']
    assert details['owner_id'] == users[0].id
    assert details['criteria'] == {key: sample[key] for key in ('imie', 'nazwisko', 'pesel')}
    with session() as db:
        assert sample['pesel'] not in db.get(Audit, event['id']).details
    api.app.dependency_overrides[security.current_user] = lambda: users[3]
    assert client.post(f'{ACTIVITY}/{event["id"]}/details').status_code == 403


def test_legacy_audit_and_half_open_period(client, users):
    from datetime import datetime

    start = datetime.fromisoformat(PERIOD['start']).timestamp()
    end = datetime.fromisoformat(PERIOD['end']).timestamp()
    with session() as db:
        db.add(Audit(actor_id=users[0].id, action='export.csv', at=start, outcome='masked'))
        db.add(Audit(actor_id=users[0].id, action='export.csv', at=end, outcome='masked'))
    api.app.dependency_overrides[security.current_user] = lambda: users[2]
    result = client.post(ACTIVITY, json=PERIOD).json()
    event, = result['items']
    assert result['total'] == 1
    assert event['username'] == users[0].username
    assert not event['details_available']
