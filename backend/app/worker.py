"""Durable SQL queue. PostgreSQL owns work; Redis owns global pacing and auth cache."""
import logging, random, signal, time
from concurrent.futures import ThreadPoolExecutor
from sqlalchemy import select, update, delete, or_, func
from .db import Attempt, Config, session, Job, Search, Row, Audit, LoginSession, now, uid, audit, User
from .security import cache, seal, unseal
from .version import VERSION
from .adapter import configuration, readiness, SEAdapter, BaeError

log=logging.getLogger('bae.worker')
stop=False
TERMINAL=['found','not_found','ambiguous','invalid','technical_error','unauthorized']

def claim(db):
    t=now()
    # Row leases are persisted and compare-and-set on completion. A dead worker's
    # request can be repeated, but cannot overwrite a newer attempt's result.
    due=or_((Search.state=='pending') & (Search.next_at<=t),(Search.state=='running') & (Search.lease_until<t))
    jid=db.scalar(select(Search.job_id).join(Job).where(Job.state.in_(['queued','running']),Search.scheduled==True,due)
        .order_by(Job.created,Search.next_at).limit(1))
    if not jid:return None
    # Match API control operations: lock the job before a search row. No locks
    # are held during HTTP, and pause/resume cannot deadlock with completion.
    j=db.scalar(select(Job).where(Job.id==jid).with_for_update().execution_options(populate_existing=True))
    if j.state not in ['queued','running']:return None
    s=db.scalar(select(Search).where(Search.job_id==jid,Search.scheduled==True,due)
        .order_by(Search.next_at).with_for_update(skip_locked=True).limit(1))
    if not s:return None
    j.state='running'
    s.state='running';s.lease_until=t+180;s.lease_token=uid();s.attempts+=1
    db.flush()
    return s.id,s.lease_token,j.id,j.environment,unseal(s.payload),s.attempts,s.scheduled_by

def pacing(env,rps,heartbeat=None):
    # Atomic across all processes. Shared Redis TIME prevents clock skew.
    script="""
    local t=redis.call('TIME');local now=t[1]*1000+t[2]/1000
    local prior=tonumber(redis.call('GET',KEYS[1]) or '0')
    if prior>now then return math.ceil(prior-now) end
    redis.call('SET',KEYS[1],now+tonumber(ARGV[1]),'PX',math.ceil(tonumber(ARGV[1])+1000))
    return 0
    """
    while not stop:
        if heartbeat:rps=heartbeat() or rps
        with session() as db:
            persisted=db.get(Config,'cooldown_'+env)
            until=unseal(persisted.value)['until'] if persisted else 0
        delay=max(float(cache.get('se-cooldown:'+env) or 0),until)-now()
        if delay>0:
            time.sleep(min(delay,0.5));continue
        wait=cache.eval(script,1,'se-pace:'+env,1000/rps)
        if wait==0:return
        time.sleep(min(float(wait)/1000,0.5))
    raise BaeError(code='worker_stopping',retry=True)

def finish_job(db,j):
    # Serialize finalization with other requests and pause/resume operations.
    db.flush()
    j=db.scalar(select(Job).where(Job.id==j.id).with_for_update().execution_options(populate_existing=True))
    remaining=db.scalar(select(Search.id).where(Search.job_id==j.id,Search.scheduled==True,Search.state.in_(['pending','running'])).limit(1))
    if not remaining and j.state in ['queued','running']:
        deferred=db.scalar(select(Search.id).where(Search.job_id==j.id,Search.scheduled==False,Search.state.in_(['pending','running'])).limit(1))
        j.state='paused' if deferred else 'completed';j.updated=now()
        failures=db.scalar(select(func.count()).select_from(Search).where(Search.job_id==j.id,Search.state.in_(['technical_error','unauthorized'])))
        if failures:j.message=f'Przetwarzanie zakończone z błędami: {failures}. Otwórz Szczegóły błędu przy wyniku. Błąd nie oznacza braku ADE.'
        audit(db,None,'job.'+j.state,j.id)

def tick(adapter_factory=SEAdapter,close_adapter=True):
    with session() as db:
        cfg=configuration(db);work=claim(db)
    if not work:
        with session() as db:
            for j in db.scalars(select(Job).where(Job.state.in_(['queued','running'])).limit(50)):finish_job(db,j)
        return False
    sid,lease,jid,env,p,attempt,scheduled_by=work
    ready=readiness(cfg)
    with session() as db:
        job=db.get(Job,jid);owner=db.get(User,job.owner_id)
        allowed=owner and owner.active and owner.role in ['admin','operator'] and (job.kind!='bulk' or owner.role=='admin' or owner.bulk_allowed)
    if not ready['ready'] or cfg['environment']!=env or not allowed:
        with session() as db:
            s=db.get(Search,sid);j=db.get(Job,jid)
            if s.lease_token==lease:s.state='pending';s.lease_token=None
            if j.state in ['running','queued']:
                j.state='blocked';j.message='Brak uprawnień właściciela do przetwarzania zadania.' if not allowed else 'Brak konfiguracji lub zmiana środowiska. Sprawdź administrację i wznów.'
                audit(db,None,'job.blocked',jid,'configuration')
        return True
    slot=None
    for i in range(cfg.get('max_concurrency',1)):
        candidate=cache.lock(f'se-slot:{env}:{i}',timeout=180,blocking=False)
        if candidate.acquire(blocking=False):slot=candidate;break
    if slot is None:
        with session() as db:
            s=db.get(Search,sid)
            if s.lease_token==lease:s.state='pending';s.lease_token=None;s.next_at=now()+1;s.attempts-=1
        return True
    retry=None;result=None
    try:
        renewed=0
        def heartbeat():
            nonlocal renewed
            if now()-renewed<5:return None
            check_control()
            with session() as db:
                current=configuration(db)
                db.execute(update(Search).where(Search.id==sid,Search.lease_token==lease).values(lease_until=now()+180))
            slot.extend(180,replace_ttl=True);renewed=now()
            return current['requests_per_second']
        def check_control():
            with session() as db:
                j=db.scalar(select(Job).where(Job.id==jid).with_for_update())
                owner=db.get(User,j.owner_id)
                s=db.get(Search,sid)
                current=configuration(db)
                config_changed=any(current.get(key)!=cfg.get(key) for key in ['environment','enabled','limits_confirmed','sender_eda','system_name','audience','login_hint'])
                permitted=owner and owner.active and owner.role in ['admin','operator'] and (j.kind!='bulk' or owner.role=='admin' or owner.bulk_allowed)
                changed=j.state not in ['queued','running'] or not permitted or config_changed or s.lease_token!=lease
                if changed:
                    if s.lease_token==lease:s.state='pending';s.lease_token=None;s.attempts-=1
                    if not permitted:j.state='paused';j.message='Weryfikacja masowa lub dostęp użytkownika zostały wyłączone'
                    elif config_changed and j.state in ['running','queued']:
                        j.state='blocked';j.message='Zmieniono konfigurację połączenia. Sprawdź ustawienia i wznów zadanie.'
            if changed:raise BaeError(code='worker_control_changed')
        def before_request():
            pacing(env,cfg['requests_per_second'],heartbeat)
            check_control()
        check_control()
        adapter=adapter_factory(cfg)
        try:
            if hasattr(adapter,'before_search'):adapter.before_search=before_request
            else:before_request()
            result=adapter.search(p)
        finally:
            if hasattr(adapter,'before_search'):adapter.before_search=None
            if close_adapter:adapter.close()
    except BaeError as e:
        if e.code=='worker_control_changed':return True
        if e.retry and attempt<5:retry=max(e.retry_after,min(300,2**attempt)+random.random())
        note=e.code
        if e.diagnostics:
            issue=e.diagnostics[0];note+=': '+issue['path']+' — '+issue['rule']
        result={'status':e.status,'ade':None,'note':note,'error_code':e.code,'diagnostics':e.diagnostics,'source':'SE API 4.0.5 / '+env,'request_id':e.request_id}
        if e.code=='http_429' or e.retry_after:
            # All jobs honor Retry-After, including other worker processes.
            delay=max(e.retry_after,2**attempt)
            cache.eval("local old=tonumber(redis.call('GET',KEYS[1]) or '0'); local value=math.max(old,tonumber(ARGV[1])); redis.call('SET',KEYS[1],value,'PX',math.ceil((value-tonumber(ARGV[2]))*1000)+1000); return 1",
                       1,'se-cooldown:'+env,now()+delay,now())
    except Exception:
        # Never log exceptions containing HTTP bodies, query data or credentials.
        retry=30 if attempt<5 else None
        result={'status':'technical_error','ade':None,'note':'worker_failure','source':'SE API 4.0.5 / '+env}
    finally:
        try:slot.release()
        except Exception:pass
    result['adapter_version']=VERSION
    with session() as db:
        j=db.scalar(select(Job).where(Job.id==jid).with_for_update())
        s=db.scalar(select(Search).where(Search.id==sid).with_for_update())
        if not s or s.lease_token!=lease:return True
        s.lease_token=None;s.lease_until=0
        if retry is not None:
            s.state='pending';s.next_at=now()+retry;s.result=seal(result)
        else:
            s.state=result['status'];s.result=seal(result);s.checked=now()
        db.add(Attempt(job_id=jid,search_id=sid,number=attempt,state=result['status'],result=seal(result)))
        if result.get('note')=='http_429' or retry and retry>=120:
            key='cooldown_'+env
            until=now()+(retry or 60)
            # Concurrent throttled requests may create this key together.
            if db.bind.dialect.name=='postgresql':
                from sqlalchemy.dialects.postgresql import insert
            else:
                from sqlalchemy.dialects.sqlite import insert
            db.execute(insert(Config).values(key=key,value=seal({'until':until})).on_conflict_do_nothing(index_elements=['key']))
            entry=db.scalar(select(Config).where(Config.key==key).with_for_update())
            entry.value=seal({'until':max(unseal(entry.value)['until'],until)})
        scheduler=db.get(User,scheduled_by) if scheduled_by else None
        method='pesel' if p.get('pesel') else 'address'
        criteria_keys=('imie','nazwisko','pesel') if method=='pesel' else (
            'imie','nazwisko','ulica','nr_budynku','nr_lokalu','kod_pocztowy','miejscowosc','kraj')
        audit(db,scheduled_by,'query.finished',jid,result['status'],details=seal({
            'username':scheduler.username if scheduler else None,
            'owner_id':j.owner_id,'search_id':sid,'environment':env,'attempt':attempt,
            'method':method,'criteria':{key:p.get(key,'') for key in criteria_keys},
            'request_id':result.get('request_id'),'error_code':result.get('error_code'),
        }))
        if result['status']=='unauthorized' and j.state in ['running','queued']:
            j.state='blocked';j.message='BAE odmówiło uprawnień. Administrator musi sprawdzić konfigurację.'
        finish_job(db,j)
    return True

def cleanup():
    with session() as db:
        cfg=configuration(db);t=now()
        old=list(db.scalars(select(Job.id).where(Job.created<t-cfg['retention_days']*86400,Job.state.not_in(['running','queued']))))
        for jid in old:
            db.execute(delete(Attempt).where(Attempt.job_id==jid));db.execute(delete(Row).where(Row.job_id==jid));db.execute(delete(Search).where(Search.job_id==jid));db.execute(delete(Job).where(Job.id==jid))
            audit(db,None,'retention.delete',jid)
        db.execute(delete(Audit).where(Audit.at<t-cfg['audit_days']*86400))
        db.execute(delete(LoginSession).where(LoginSession.expires<t))

class WorkerLane:
    """One in-flight query and one reusable HTTPS client per lane."""
    def __init__(self,adapter_factory=SEAdapter):
        self.factory=adapter_factory;self.client=None;self.cfg=None;self.future=None;self.idle_until=0
    def adapter(self,cfg):
        if self.client is None or self.cfg!=cfg:
            self.close();self.client=self.factory(cfg);self.cfg=dict(cfg)
        return self.client
    def run(self):return tick(self.adapter,close_adapter=False)
    def close(self):
        if self.client:self.client.close();self.client=None

class WorkerPool:
    def __init__(self,adapter_factory=SEAdapter):
        self.executor=ThreadPoolExecutor(max_workers=8,thread_name_prefix='bae-query')
        self.lanes=[WorkerLane(adapter_factory) for _ in range(8)]
    def step(self,concurrency):
        for lane in self.lanes:
            if lane.future and lane.future.done():
                try:
                    if not lane.future.result():lane.idle_until=now()+0.5
                except Exception:
                    log.error('worker_cycle_failed');lane.idle_until=now()+2
                lane.future=None
        active=sum(lane.future is not None for lane in self.lanes)
        for lane in self.lanes:
            if stop or active>=max(1,min(8,concurrency)):break
            if lane.future is None and now()>=lane.idle_until:
                lane.future=self.executor.submit(lane.run);active+=1
    def close(self):
        self.executor.shutdown(wait=True)
        for lane in self.lanes:lane.close()

def main():
    global stop
    def shutdown(*_):
        global stop;stop=True
    signal.signal(signal.SIGTERM,shutdown);signal.signal(signal.SIGINT,shutdown)
    last_clean=0;last_heartbeat=0;pool=WorkerPool()
    try:
        while not stop:
            try:
                if now()-last_heartbeat>=1:
                    cache.set('worker:heartbeat',str(now()),ex=90)
                    cache.set('worker:version',VERSION,ex=90);last_heartbeat=now()
                if now()-last_clean>3600:cleanup();last_clean=now()
                with session() as db:cfg=configuration(db)
                delay=float(cache.get('se-cooldown:'+cfg['environment']) or 0)-now()
                if delay>0:time.sleep(min(delay,0.5));continue
                pool.step(cfg.get('max_concurrency',1))
                time.sleep(0.1)
            except Exception:
                log.error('worker_cycle_failed');time.sleep(2)
    finally:pool.close()

if __name__=='__main__':main()
