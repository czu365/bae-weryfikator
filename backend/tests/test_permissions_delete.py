import io,json,time
import pytest
from sqlalchemy import select,func
from app import api,security,worker
from app.db import session,User,Job,Row,Search,Attempt,Audit,LoginSession
from app.security import seal,unseal
from app.adapter import BaeError
from test_api_security_export import imported
from test_queue import setup_job,enable,TestAdapter


def as_user(users,index):
    def current():
        with session() as db:return db.get(User,users[index].id)
    api.app.dependency_overrides[security.current_user]=current


def test_only_admin_deletes_job_and_retains_related_audit(client,users,sample):
    jid=imported(client,sample)
    with session() as db:
        search=db.scalar(select(Search).where(Search.job_id==jid))
        db.add(Attempt(job_id=jid,search_id=search.id,number=1,state='technical_error',result=seal({'status':'technical_error'})))
        db.add(Audit(actor_id=users[0].id,action='row.reveal',job_id=jid,outcome='ok'))
        db.add(Audit(actor_id=users[0].id,action='login',outcome='ok'))
    for index in [0,1,3]:
        as_user(users,index)
        assert client.request('DELETE','/api/jobs/'+jid,json={'confirm':True}).status_code==403
    as_user(users,2)
    assert client.request('DELETE','/api/jobs/'+jid,json={'confirm':False}).status_code==422
    assert client.request('DELETE','/api/jobs/'+jid,json={'confirm':True}).status_code==200
    for suffix in ['', '/rows','/attempts','/preview']:
        assert client.get('/api/jobs/'+jid+suffix).status_code==404
    assert client.get('/api/jobs').json()['total']==0
    assert client.get('/api/stats').json()['total']==0
    with session() as db:
        for model in [Row,Search,Attempt]:
            assert db.scalar(select(func.count()).select_from(model).where(model.job_id==jid))==0
        assert set(db.scalars(select(Audit.action).where(Audit.job_id==jid)))=={'import','import.mapped','row.reveal','job.deleted'}
        assert db.scalar(select(func.count()).select_from(Audit).where(Audit.action=='login'))==1


def test_active_and_inflight_jobs_cannot_be_deleted(client,users,sample):
    jid=imported(client,sample);as_user(users,2)
    with session() as db:db.get(Job,jid).state='queued'
    assert client.request('DELETE','/api/jobs/'+jid,json={'confirm':True}).status_code==409
    with session() as db:
        db.get(Job,jid).state='paused';s=db.scalar(select(Search).where(Search.job_id==jid));s.state='running';s.lease_until=time.time()+30
    assert client.request('DELETE','/api/jobs/'+jid,json={'confirm':True}).status_code==409
    with session() as db:db.scalar(select(Search).where(Search.job_id==jid)).lease_until=0
    assert client.request('DELETE','/api/jobs/'+jid,json={'confirm':True}).status_code==200


def test_regular_account_default_single_and_explicit_bulk_grant(client,users,sample,monkeypatch):
    as_user(users,2)
    assert client.post('/api/admin/users',json={'username':'new-operator','password':'Synthetic-test-pass-789'}).status_code==200
    with session() as db:
        account=db.scalar(select(User).where(User.username=='new-operator'));uid=account.id
        assert not account.bulk_allowed
    def current():
        with session() as db:return db.get(User,uid)
    api.app.dependency_overrides[security.current_user]=current
    client.cookies.set('bae_session','qa')
    assert client.get('/api/auth/me').json()['bulk_allowed'] is False
    assert client.post('/api/import',files={'file':('qa.json',json.dumps([sample]).encode(),'application/json')}).status_code==403
    monkeypatch.setattr(api,'readiness',lambda cfg:{'ready':True})
    assert client.post('/api/verify',json=sample).status_code==200
    assert client.get('/api/admin/users').status_code==403
    as_user(users,2)
    assert client.put('/api/admin/users/'+uid,json={'role':'operator','active':True,'bulk_allowed':True}).status_code==200
    api.app.dependency_overrides[security.current_user]=current
    assert client.post('/api/import',files={'file':('qa.json',json.dumps([sample]).encode(),'application/json')}).status_code==200


def test_bulk_revocation_stops_existing_tasks_and_all_write_paths(client,users,sample,monkeypatch):
    jid=imported(client,sample)
    with session() as db:
        db.get(Job,jid).state='queued'
        db.add(LoginSession(id='qa-session',user_id=users[0].id,expires=time.time()+60))
    as_user(users,2)
    assert client.put('/api/admin/users/'+users[0].id,json={'role':'operator','active':True,'bulk_allowed':False}).status_code==200
    with session() as db:
        assert db.get(Job,jid).state=='paused'
        assert db.get(LoginSession,'qa-session') is None
    as_user(users,0)
    row=client.get('/api/jobs/'+jid+'/rows').json()['items'][0]
    for path,body in [('/action',{'action':'resume'}),('/action',{'action':'start'}),('/action',{'action':'retry_errors'}),('/mapping',{'mapping':{'imie':'imie','nazwisko':'nazwisko'}}),('/selection',{'action':'retry','ids':[row['row_id']]})]:
        assert client.post('/api/jobs/'+jid+path,json=body).status_code==403,path
    assert client.put('/api/jobs/'+jid+'/rows/'+row['row_id'],json={'person':sample}).status_code==403
    # A direct DB-queued task is blocked by the worker too, independently of API.
    with session() as db:db.get(Job,jid).state='queued'
    enable(monkeypatch)
    class Unexpected(TestAdapter):
        def search(self,p):raise AssertionError('Revoked bulk must never query BAE')
    assert worker.tick(Unexpected)
    with session() as db:assert db.get(Job,jid).state=='blocked'


def test_revocation_during_pacing_prevents_outgoing_query(client,users,sample,monkeypatch):
    jid=setup_job(users,sample);enable(monkeypatch)
    def revoke(*args):
        with session() as db:db.get(User,users[0].id).bulk_allowed=False
    monkeypatch.setattr(worker,'pacing',revoke)
    class Unexpected(TestAdapter):
        def search(self,p):raise AssertionError('No BAE request after permission revoked')
    assert worker.tick(Unexpected)
    with session() as db:assert db.get(Job,jid).state=='paused'


def test_worker_retains_safe_validation_details_and_marks_failure(client,users,sample,monkeypatch):
    jid=setup_job(users,sample);enable(monkeypatch)
    class Invalid(TestAdapter):
        def search(self,p):raise BaeError(code='invalid_response',diagnostics=[{'path':'baeSearchResponses/0/baeSearchData/0/isPublic','rule':'type','actual_type':'NoneType','expected_type':'boolean'}])
    assert worker.tick(Invalid)
    row=client.get('/api/jobs/'+jid+'/rows').json()['items'][0]
    assert row['error_code']=='invalid_response' and row['adapter_version']==api.VERSION
    assert row['diagnostics'][0]['actual_type']=='NoneType'
    assert 'isPublic' in row['note']
    assert client.get('/api/jobs/'+jid).json()['message'].startswith('Przetwarzanie zakończone z błędami')


def test_role_change_does_not_silently_grant_bulk(client,users):
    as_user(users,2)
    uid=users[1].id
    assert client.put('/api/admin/users/'+uid,json={'role':'auditor','active':True,'bulk_allowed':True}).status_code==200
    with session() as db:assert not db.get(User,uid).bulk_allowed
    assert client.put('/api/admin/users/'+uid,json={'role':'operator','active':True}).status_code==200
    with session() as db:assert not db.get(User,uid).bulk_allowed


def test_deletion_requires_session_csrf(client,users,sample):
    from app.db import uid,now
    from app.security import digest,csrf
    jid=imported(client,sample)
    token='synthetic-admin-session-for-delete'
    with session() as db:db.add(LoginSession(id=digest(token),user_id=users[2].id,expires=now()+60))
    api.app.dependency_overrides.clear()
    client.cookies.set('bae_session',token)
    assert client.request('DELETE','/api/jobs/'+jid,json={'confirm':True}).status_code==403
    assert client.request('DELETE','/api/jobs/'+jid,json={'confirm':True},headers={'X-CSRF-Token':csrf(token)}).status_code==200
