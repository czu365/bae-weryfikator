import io,json,time
from sqlalchemy import select
from app.db import session,Job,Search,uid
from app.security import seal,unseal
from app.importer import import_file,apply_mapping
from app import worker
from app.adapter import BaeError,DEFAULTS

def setup_job(users,sample):
    with session() as db:
        j=Job(id=uid(),owner_id=users[0].id,label=seal('Test'));db.add(j);db.flush()
        r=import_file(db,j,io.BytesIO(json.dumps([sample]).encode()),'.json');apply_mapping(db,j,r['mapping']);j.state='queued';return j.id

class TestAdapter:
    __test__=False
    def __init__(self,c):pass
    def search(self,p):return {'status':'not_found','ade':None,'source':'TEST MOCK ONLY'}
    def close(self):pass

def enable(monkeypatch):
    monkeypatch.setattr(worker,'readiness',lambda c:{'ready':True})
    monkeypatch.setattr(worker,'configuration',lambda db:DEFAULTS)
    monkeypatch.setattr(worker,'pacing',lambda *a:None)

def test_resume_expired_lease(users,sample,monkeypatch):
    jid=setup_job(users,sample);enable(monkeypatch)
    with session() as db:claim=worker.claim(db);assert claim
    assert not worker.tick(TestAdapter) # active lease is not stolen
    with session() as db:s=db.get(Search,claim[0]);s.lease_until=0
    assert worker.tick(TestAdapter)
    with session() as db:
        s=db.get(Search,claim[0]);assert s.state=='not_found' and s.attempts==2
        assert db.get(Job,jid).state=='completed'

def test_pause_and_cancel_do_not_claim(users,sample):
    jid=setup_job(users,sample)
    for state in ['paused','cancelled']:
        with session() as db:db.get(Job,jid).state=state
        with session() as db:assert worker.claim(db) is None

def test_retry_after_is_not_no_match(users,sample,monkeypatch):
    jid=setup_job(users,sample);enable(monkeypatch)
    class Limited(TestAdapter):
        def search(self,p):raise BaeError(code='http_429',retry=True,retry_after=120)
    worker.tick(Limited)
    with session() as db:
        s=db.scalar(select(Search).where(Search.job_id==jid));assert s.state=='pending'
        assert s.next_at>time.time()+110 and s.checked is None
        assert unseal(s.result)['status']=='technical_error'

def test_auth_error_blocks_job(users,sample,monkeypatch):
    jid=setup_job(users,sample);enable(monkeypatch)
    class Denied(TestAdapter):
        def search(self,p):raise BaeError('unauthorized','http_403')
    worker.tick(Denied)
    with session() as db:assert db.get(Job,jid).state=='blocked'

def test_selection_retries_only_selected(client,users,sample,monkeypatch):
    from app import api
    payload=[sample,{**sample,'id':'0002','imie':'Innatestowa'}]
    r=client.post('/api/import',files={'file':('test.json',json.dumps(payload).encode(),'application/json')}).json()
    jid=r['job_id'];client.post('/api/jobs/'+jid+'/mapping',json={'mapping':r['mapping']})
    with session() as db:db.get(Job,jid).state='paused'
    rows=client.get('/api/jobs/'+jid+'/rows').json()['items']
    enable(monkeypatch);monkeypatch.setattr(api,'readiness',lambda c:{'ready':True})
    r=client.post('/api/jobs/'+jid+'/selection',json={'action':'retry','ids':[rows[0]['row_id']]});assert r.status_code==200,r.text
    worker.tick(TestAdapter)
    assert not worker.tick(TestAdapter)
    with session() as db:
        searches=db.scalars(select(Search).where(Search.job_id==jid)).all()
        assert sum(s.state=='not_found' for s in searches)==1
        assert sum(s.state=='pending' for s in searches)==1
        assert db.get(Job,jid).state=='paused'
