import threading,time
from concurrent.futures import ThreadPoolExecutor
import pytest
from sqlalchemy import select,func
from app import worker
from app.adapter import DEFAULTS,BaeError
from app.db import engine,session,Search,Job,Row,Attempt,User,uid
from app.security import seal

def test_search_pacing_after_token_before_http(sample,monkeypatch):
    import httpx
    from app.adapter import SEAdapter
    events=[]
    def handle(request):
        events.append('search')
        return httpx.Response(200,json={'baeSearchResponses':[],'totalResults':0})
    client=SEAdapter(DEFAULTS,transport=httpx.MockTransport(handle))
    monkeypatch.setattr(client,'token',lambda:events.append('token') or 'SYNTHETIC')
    client.before_search=lambda:events.append('pace')
    try:assert client.search(sample)['status']=='not_found'
    finally:client.close()
    assert events==['token','pace','search']

def test_revocation_during_token_refresh_prevents_search(users,sample,monkeypatch):
    import httpx
    from app.adapter import SEAdapter
    from test_queue import setup_job,enable
    jid=setup_job(users,sample);enable(monkeypatch)
    outgoing=[]
    adapter=SEAdapter(DEFAULTS,transport=httpx.MockTransport(lambda request:outgoing.append(request)))
    def token():
        with session() as db:db.get(User,users[0].id).bulk_allowed=False
        return 'SYNTHETIC'
    monkeypatch.setattr(adapter,'token',token)
    worker.tick(lambda cfg:adapter)
    assert outgoing==[]
    with session() as db:
        assert db.get(Job,jid).state=='paused'
        s=db.scalar(select(Search).where(Search.job_id==jid))
        assert s.state=='pending' and s.attempts==0


def test_reuses_client_and_closes_when_configuration_changes(monkeypatch):
    clients=[]
    class Client:
        def __init__(self,cfg):self.closed=False;clients.append(self)
        def close(self):self.closed=True
    lane=worker.WorkerLane(Client)
    assert lane.adapter(DEFAULTS) is lane.adapter(dict(DEFAULTS))
    assert len(clients)==1 and not clients[0].closed
    changed={**DEFAULTS,'environment':'PROD'}
    assert lane.adapter(changed) is not clients[0] and clients[0].closed
    lane.close();assert all(c.closed for c in clients)


def test_pool_is_bounded_and_obeys_live_parallelism_setting(monkeypatch):
    gate=threading.Event();lock=threading.Lock();active=0;peak=0;started=0
    def task(self):
        nonlocal active,peak,started
        with lock:active+=1;started+=1;peak=max(peak,active)
        gate.wait(3)
        with lock:active-=1
        return False
    monkeypatch.setattr(worker.WorkerLane,'run',task)
    pool=worker.WorkerPool()
    try:
        pool.step(3)
        deadline=time.monotonic()+2
        while started<3 and time.monotonic()<deadline:time.sleep(.01)
        assert active==peak==3
        pool.step(1);assert started==3
        gate.set()
    finally:pool.close()


def test_global_pacing_between_threads_and_cooldown(database,monkeypatch):
    monkeypatch.setattr(worker,'stop',False)
    starts=[];guard=threading.Lock()
    def request():
        worker.pacing('INT',10)
        with guard:starts.append(time.monotonic())
    begin=time.monotonic();database.set('se-cooldown:INT',str(worker.now()+.15),ex=2)
    with ThreadPoolExecutor(max_workers=3) as pool:list(pool.map(lambda _:request(),range(3)))
    starts.sort()
    assert starts[0]-begin>=.14
    assert all(b-a>=.085 for a,b in zip(starts,starts[1:]))


@pytest.mark.skipif(engine.dialect.name!='postgresql',reason='Real row-lock and parallel completion test requires PostgreSQL')
def test_parallel_real_queue_no_duplicates_completes_once(users,sample,monkeypatch):
    cfg={**DEFAULTS,'max_concurrency':3,'requests_per_second':10}
    monkeypatch.setattr(worker,'configuration',lambda db:dict(cfg))
    monkeypatch.setattr(worker,'readiness',lambda cfg:{'ready':True})
    monkeypatch.setattr(worker,'stop',False)
    with session() as db:
        job=Job(id=uid(),owner_id=users[0].id,label=seal('Parallel QA'),state='queued',total=12,kind='bulk');db.add(job);db.flush();jid=job.id
        for i in range(12):
            s=Search(id=uid(),job_id=jid,fingerprint=str(i),payload=seal({**sample,'id':str(i)}));db.add(s);db.flush()
            db.add(Row(job_id=jid,position=i+1,raw=seal(sample),person=seal(sample),search_id=s.id))
    lock=threading.Lock();seen=[];active=0;peak=0;clients=[]
    class Adapter:
        def __init__(self,cfg):self.closed=False;clients.append(self)
        def search(self,p):
            nonlocal active,peak
            with lock:seen.append(p['id']);active+=1;peak=max(peak,active)
            time.sleep(.25)
            with lock:active-=1
            return {'status':'not_found','ade':None,'source':'SYNTHETIC ONLY'}
        def close(self):self.closed=True
    pool=worker.WorkerPool(Adapter)
    try:
        deadline=time.monotonic()+12
        while time.monotonic()<deadline:
            pool.step(3)
            with session() as db:
                if db.get(Job,jid).state=='completed':break
            time.sleep(.02)
        else:pytest.fail('Queue did not finish')
    finally:pool.close()
    assert len(seen)==len(set(seen))==12 and peak==3
    assert len(clients)<=3 and all(c.closed for c in clients)
    with session() as db:
        searches=db.scalars(select(Search).where(Search.job_id==jid)).all()
        assert all(s.state=='not_found' and s.attempts==1 for s in searches)
        assert db.scalar(select(func.count()).select_from(Attempt))==12
