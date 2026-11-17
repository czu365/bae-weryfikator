"""Regressions for manual verification and visible authentication diagnostics."""
from sqlalchemy import event, select
from app import api, adapter, security, worker
from app.adapter import DEFAULTS, BaeError
from app.db import engine, session, Job, Row, Search
from app.security import unseal


def enforce_foreign_keys():
    # SQLite does not enforce FKs by default. The server's PostgreSQL does.
    if engine.dialect.name == 'sqlite':
        with engine.connect() as connection:
            connection.exec_driver_sql('PRAGMA foreign_keys=ON')
            connection.commit()


def test_manual_verify_persists_search_before_row(client, users, sample, monkeypatch):
    enforce_foreign_keys()
    monkeypatch.setattr(api, 'readiness', lambda cfg: {'ready': True})
    response = client.post('/api/verify', json=sample)
    assert response.status_code == 200, response.text
    jid = response.json()['job_id']
    with session() as db:
        job = db.get(Job, jid)
        row = db.scalar(select(Row).where(Row.job_id == jid))
        search = db.get(Search, row.search_id)
        assert job.state == 'queued' and job.total == 1
        assert search.job_id == jid and search.state == 'pending'
        assert unseal(search.payload)['pesel'] == sample['pesel']
    assert client.get('/api/jobs/' + jid).json()['pending'] == 1


def configured(monkeypatch, users, enabled=True):
    cfg={**DEFAULTS,'environment':'PROD','sender_eda':'AE:PL-00000-00000-TESTA-00',
         'system_name':'TEST-SYSTEM','audience':'https://ow.edoreczenia.gov.pl/auth/realms/EDOR',
         'login_hint':'ADE.AE:PL-00000-00000-TESTA-00','enabled':enabled,'limits_confirmed':enabled}
    api.app.dependency_overrides[security.current_user]=lambda:users[2]
    monkeypatch.setattr(api,'configuration',lambda db:cfg)
    monkeypatch.setattr(adapter,'certificate_info',lambda env:{'ready':True,'expires':'2099-01-01','issue':''})
    return cfg


def test_diagnostics_keeps_401_visible_and_distinct_from_configuration(client,users,monkeypatch):
    cfg=configured(monkeypatch,users)
    class Denied:
        def __init__(self,c):assert c==cfg
        def token(self):raise BaeError('unauthorized','http_401')
        def close(self):pass
    monkeypatch.setattr(api,'SEAdapter',Denied)
    response=client.post('/api/admin/diagnostics')
    assert response.status_code==200
    result=response.json()
    assert result['authentication']=='http_401'
    assert 'HTTP 401' in result['message'] and '.SYSTEM.' in result['message']
    assert result['ready'] # Configuration completeness is not a successful auth test.
    assert result['search']=='not_tested' and result['environment']=='PROD'
    assert result['client_id']==cfg['sender_eda']+'.SYSTEM.TEST-SYSTEM'


def test_auth_test_can_run_with_queries_disabled_and_limits_unconfirmed(client,users,monkeypatch):
    configured(monkeypatch,users,enabled=False)
    called=[]
    class Accepted:
        def __init__(self,c):pass
        def token(self):called.append('token');return 'SYNTHETIC'
        def close(self):pass
    monkeypatch.setattr(api,'SEAdapter',Accepted)
    result=client.post('/api/admin/diagnostics').json()
    assert result['authentication']=='ok' and called==['token']
    assert not result['ready'] and result['search']=='not_tested'
    assert 'nie potwierdza uprawnień' in result['message']
    assert client.post('/api/verify',json={'imie':'Testowa','nazwisko':'Weryfikacyjna','nr_budynku':'1','kod_pocztowy':'00-000','miejscowosc':'Testowo'}).status_code==503


def test_diagnostics_rejects_incomplete_credentials_before_token_request(client,users,monkeypatch):
    cfg=configured(monkeypatch,users);cfg['system_name']=''
    def unexpected(c):raise AssertionError('No token request with incomplete credentials')
    monkeypatch.setattr(api,'SEAdapter',unexpected)
    result=client.post('/api/admin/diagnostics').json()
    assert result['authentication']=='incomplete' and 'system_name' in result['missing']
    assert result['search']=='not_tested'


def test_manual_queued_record_runs_through_worker(client,users,sample,monkeypatch):
    from test_queue import enable,TestAdapter
    enforce_foreign_keys();monkeypatch.setattr(api,'readiness',lambda cfg:{'ready':True})
    jid=client.post('/api/verify',json=sample).json()['job_id']
    enable(monkeypatch)
    assert worker.tick(TestAdapter)
    result=client.get('/api/jobs/'+jid).json()
    assert result['state']=='completed' and result['checked']==1
    rows=client.get('/api/jobs/'+jid+'/rows').json()['items']
    assert rows[0]['status']=='not_found' and rows[0]['pesel'].startswith('*******')


def test_manual_address_verification_persists_with_foreign_keys(client,sample,monkeypatch):
    enforce_foreign_keys();monkeypatch.setattr(api,'readiness',lambda cfg:{'ready':True})
    body={**sample,'pesel':'','miejscowosc':'Testowo','nr_budynku':'1','kod_pocztowy':'00-000'}
    result=client.post('/api/verify',json=body)
    assert result.status_code==200,result.text
    assert client.get('/api/jobs/'+result.json()['job_id']).json()['total']==1


def test_import_mapping_and_edit_keep_parent_search_before_row(client,sample):
    from test_api_security_export import imported
    enforce_foreign_keys()
    jid=imported(client,sample)
    rows=client.get('/api/jobs/'+jid+'/rows').json()['items']
    # New search criteria create a new Search that must exist before the FK update.
    changed={**sample,'imie':'Innatestowa'}
    response=client.put('/api/jobs/'+jid+'/rows/'+rows[0]['row_id'],json={'person':changed,'note':'QA','review':True})
    assert response.status_code==200,response.text
    with session() as db:
        row=db.get(Row,rows[0]['row_id']);search=db.get(Search,row.search_id)
        assert unseal(search.payload)['imie']=='Innatestowa'
    assert client.get('/api/jobs/'+jid).json()['duplicates']==0


def test_safe_error_reference_never_logs_exception_payload(client,monkeypatch,caplog):
    from fastapi.testclient import TestClient
    def fail(db):raise RuntimeError('SYNTHETIC-SENSITIVE-MARKER-DO-NOT-LOG')
    monkeypatch.setattr(api,'configuration',fail)
    with TestClient(api.app,base_url='https://testserver',raise_server_exceptions=False) as browser:
        response=browser.get('/api/connection')
    assert response.status_code==500
    reference=response.json()['reference']
    assert len(reference)==16 and reference in caplog.text
    assert 'SYNTHETIC-SENSITIVE-MARKER' not in caplog.text+response.text


import pytest
@pytest.mark.parametrize('kind,expected',[('timeout','token_timeout'),('connect','token_transport'),('401','http_401')])
def test_token_transport_failures_are_safe_and_structured(tmp_path,monkeypatch,kind,expected):
    import httpx
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from app.config import settings
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    key_file=tmp_path/'synthetic.key'
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    monkeypatch.setitem(settings().key_files,'INT',str(key_file))
    cfg={**DEFAULTS,'sender_eda':'AE:PL-00000-00000-TESTA-00','system_name':'TEST',
         'audience':'https://int-ow.edoreczenia.gov.pl/auth/realms/EDOR','login_hint':'ADE.AE:PL-00000-00000-TESTA-00'}
    def transport(request):
        if kind=='timeout':raise httpx.ReadTimeout('SYNTHETIC-SENSITIVE-MARKER')
        if kind=='connect':raise httpx.ConnectError('SYNTHETIC-SENSITIVE-MARKER')
        return httpx.Response(401,json={'error':'invalid_client','error_description':'SYNTHETIC-SENSITIVE-MARKER'})
    instance=adapter.SEAdapter(cfg,transport=httpx.MockTransport(transport))
    try:
        with pytest.raises(BaeError) as failure:instance.token()
        assert failure.value.code==expected
        assert 'SYNTHETIC-SENSITIVE-MARKER' not in str(failure.value)
    finally:instance.close()
