from datetime import datetime, timezone
from tempfile import TemporaryFile
import asyncio, json, logging, math, re, secrets, time, traceback
from pathlib import Path
from typing import Literal
from contextlib import asynccontextmanager
import pyotp
from fastapi import FastAPI, Depends, HTTPException, Request, Response, UploadFile, File, Query
from fastapi.responses import StreamingResponse, JSONResponse
from starlette.background import BackgroundTask
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy import select, func, delete, update, or_, text
from .db import Attempt, session, User, LoginSession, Config, Job, Row, Search, Audit, AuditExportRows, audit, uid, now, engine
from .config import settings
from .security import current_user, operator, admin, authenticate, verify_otp, cache, seal, unseal, digest, csrf, password_hash, normalize, bulk_operator
from .adapter import configuration, readiness, DEFAULTS, SEAdapter, BaeError, HOSTS
from .importer import import_file, apply_mapping, attach_search, ImportError, fingerprint, repair_invalid_encoding
from .validation import FIELDS, person
from .exporter import DEFAULT_FIELDS, FILTERS, csv_stream, json_stream, xlsx_bytes, pdf_bytes, export_rows

from .version import VERSION

app=FastAPI(title='BAE Weryfikator',version=VERSION,docs_url=None,redoc_url=None,openapi_url=None)
log=logging.getLogger('bae.api')

@app.exception_handler(RequestValidationError)
async def invalid_request(request,exc):
    # Pydantic's default errors include the full submitted PESEL/password.
    return JSONResponse(status_code=422,content={'detail':'Nieprawidłowy format żądania','fields':[str(e['loc'][-1]) for e in exc.errors()]})

@app.exception_handler(Exception)
async def failure(request,exc):
    reference=secrets.token_hex(8)
    # Do not log exception messages, SQL parameters, request bodies or locals.
    frames=' > '.join(f'{Path(f.filename).name}:{f.lineno}:{f.name}' for f in traceback.extract_tb(exc.__traceback__)[-8:])
    log.error('api_failure reference=%s exception=%s frames=%s',reference,type(exc).__name__,frames)
    return JSONResponse(status_code=500,content={'detail':'Błąd techniczny. Operacja nie została zakończona.','reference':reference})

@app.middleware('http')
async def headers(request,call_next):
    if request.method not in ['GET','HEAD','OPTIONS']:
        origin=request.headers.get('origin')
        if origin and origin!=settings().origin:return JSONResponse(status_code=403,content={'detail':'Niedozwolone pochodzenie żądania'})
    declared=request.headers.get('content-length')
    try:
        if declared and int(declared)>settings().upload_mb*1024*1024:return JSONResponse(status_code=413,content={'detail':'Plik jest za duży'})
    except ValueError:return JSONResponse(status_code=400,content={'detail':'Nieprawidłowy rozmiar żądania'})
    response=await call_next(request)
    for k,v in {'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','X-Frame-Options':'DENY'}.items():response.headers[k]=v
    return response

class Strict(BaseModel):model_config=ConfigDict(extra='forbid')
class Login(Strict):
    username:str=Field(min_length=1,max_length=120)
    password:str=Field(min_length=1,max_length=256)
    code:str=Field(default='',max_length=8)

@app.post('/api/auth/login')
def login(body:Login,request:Request,response:Response):
    with session() as db:
        u=authenticate(db,body.username,body.password,request.client.host)
        verify_otp(u,body.code)
        token=secrets.token_urlsafe(48)
        db.add(LoginSession(id=digest(token),user_id=u.id,expires=now()+settings().session_seconds))
        audit(db,u.id,'login')
        response.set_cookie('bae_session',token,httponly=True,secure=settings().secure_cookie,samesite='strict',max_age=settings().session_seconds,path='/')
        return {'id':u.id,'username':u.username,'role':u.role,'bulk_allowed':u.role=='admin' or u.bulk_allowed,'csrf':csrf(token)}

@app.post('/api/auth/enroll')
def enroll(body:Login,request:Request):
    with session() as db:
        u=authenticate(db,body.username,body.password,request.client.host)
        if u.totp:raise HTTPException(409,'MFA jest już aktywne. Reset wymaga administratora.')
        key='enroll:'+u.id
        if not body.code:
            secret=pyotp.random_base32();cache.set(key,seal(secret),ex=600)
            return {'secret':secret,'uri':pyotp.TOTP(secret).provisioning_uri(u.username,issuer_name='BAE Weryfikator')}
        value=cache.get(key)
        if not value or not pyotp.TOTP(unseal(value)).verify(body.code,valid_window=1):raise HTTPException(401,'Nieprawidłowy kod aktywacji MFA')
        u.totp=seal(unseal(value));u.last_otp=int(time.time()//30)-1;cache.delete(key);audit(db,u.id,'mfa.enrolled')
        return {'ok':True}

@app.get('/api/auth/me')
def me(request:Request,u=Depends(current_user)):
    return {'id':u.id,'username':u.username,'role':u.role,'bulk_allowed':u.role=='admin' or u.bulk_allowed,'csrf':csrf(request.cookies['bae_session'])}

@app.post('/api/auth/logout')
def logout(request:Request,response:Response,u=Depends(current_user)):
    with session() as db:
        db.execute(delete(LoginSession).where(LoginSession.id==digest(request.cookies['bae_session'])));audit(db,u.id,'logout')
    response.delete_cookie('bae_session',path='/');return {'ok':True}

@app.get('/api/health/live')
def live():return {'status':'ok','version':VERSION}
@app.get('/api/health/ready')
def health():
    try:
        with session() as db:db.execute(text('SELECT 1'))
        cache.ping()
        if not cache.get('worker:heartbeat'):raise ValueError()
        return {'status':'ready'}
    except Exception:raise HTTPException(503,'Baza, Redis lub worker niedostępny')

@app.get('/api/connection')
def connection(u=Depends(current_user)):
    with session() as db:
        cfg=configuration(db);r=readiness(cfg)
        return {**r,'worker_online':bool(cache.get('worker:heartbeat')),'app_version':VERSION,'worker_version':cache.get('worker:version')}

def job_for(db,jid,u,write=False,lock=False):
    stmt=select(Job).where(Job.id==jid)
    if lock:stmt=stmt.with_for_update()
    j=db.scalar(stmt)
    if not j or (u.role not in ['admin','auditor'] and j.owner_id!=u.id):raise HTTPException(404,'Nie znaleziono zadania')
    if write and u.role=='auditor':raise HTTPException(403,'Audytor ma dostęp tylko do odczytu')
    if write and j.kind=='bulk' and u.role=='operator' and not u.bulk_allowed:raise HTTPException(403,'Weryfikacja masowa wymaga zgody administratora')
    return j

def job_data(db,j):
    counts=dict(db.execute(select(Search.state,func.count(Row.id)).join(Row,Row.search_id==Search.id).where(Row.job_id==j.id).group_by(Search.state)).all())
    complete=sum(counts.get(k,0) for k in ['found','not_found','ambiguous','invalid','technical_error','unauthorized'])
    recent=db.scalar(select(func.count(Row.id)).join(Search).where(Row.job_id==j.id,Search.checked>=now()-60))
    return {'id':j.id,'label':unseal(j.label),'state':j.state,'environment':j.environment,'created':j.created,'updated':j.updated,
            'kind':j.kind,'total':j.total,'duplicates':j.duplicates,'counts':counts,'checked':complete,'progress':round(100*complete/j.total,1) if j.total else 0,
            'pending':j.total-complete,'speed':round(recent/60,2),'message':j.message}

@app.get('/api/jobs')
def jobs(u=Depends(current_user),page:int=Query(1,ge=1),size:int=Query(20,ge=1,le=100)):
    with session() as db:
        stmt=select(Job)
        if u.role not in ['admin','auditor']:stmt=stmt.where(Job.owner_id==u.id)
        total=db.scalar(select(func.count()).select_from(stmt.subquery()))
        return {'total':total,'items':[job_data(db,j) for j in db.scalars(stmt.order_by(Job.created.desc()).offset((page-1)*size).limit(size))]}

@app.get('/api/jobs/{jid}')
def get_job(jid:str,u=Depends(current_user)):
    with session() as db:return job_data(db,job_for(db,jid,u))

class DeleteJob(Strict):
    confirm:Literal[True]

@app.delete('/api/jobs/{jid}')
def delete_job(jid:str,b:DeleteJob,u=Depends(admin)):
    with session() as db:
        j=job_for(db,jid,u,lock=True)
        if j.state in ['queued','running']:
            raise HTTPException(409,'Najpierw wstrzymaj zadanie, następnie usuń je')
        active=db.scalar(select(func.count()).select_from(Search).where(Search.job_id==jid,Search.state=='running',Search.lease_until>now()))
        if active:raise HTTPException(409,'Poczekaj na zakończenie wysłanego zapytania, następnie ponów usuwanie')
        db.execute(delete(Attempt).where(Attempt.job_id==jid))
        db.execute(delete(Row).where(Row.job_id==jid))
        db.execute(delete(Search).where(Search.job_id==jid))
        audit(db,u.id,'job.deleted',jid)
        db.delete(j)
    return {'ok':True}

@app.get('/api/jobs/{jid}/events')
async def events(jid:str,request:Request,u=Depends(current_user)):
    with session() as db:job_for(db,jid,u)
    async def stream():
        for _ in range(240):
            if await request.is_disconnected():break
            with session() as db:
                s=db.get(LoginSession,digest(request.cookies.get('bae_session','')));active=db.get(User,u.id)
                if not s or s.expires<now() or not active or not active.active:break
                j=db.get(Job,jid)
                if not j:break
                data=job_data(db,job_for(db,jid,active))
            yield 'data: '+json.dumps(data,ensure_ascii=False)+'\n\n'
            if data['state'] in ['completed','cancelled','blocked','draft','paused']:break
            await asyncio.sleep(2)
    return StreamingResponse(stream(),media_type='text/event-stream',headers={'X-Accel-Buffering':'no'})

@app.post('/api/import')
def upload(file:UploadFile=File(...),u=Depends(bulk_operator)):
    try:
        file.file.seek(0,2);length=file.file.tell();file.file.seek(0)
        if length>settings().upload_mb*1024*1024:raise HTTPException(413,'Limit pliku 128 MiB')
        extension=Path(file.filename or '').suffix.lower()
        with session() as db:
            cfg=configuration(db);j=Job(id=uid(),owner_id=u.id,label=seal((file.filename or 'Import')[:200]),environment=cfg['environment'])
            db.add(j);db.flush();r=import_file(db,j,file.file,extension,settings().max_rows);j.import_info=seal({'columns':r['columns'],'mapping':r['mapping']});audit(db,u.id,'import',j.id)
            return r
    except ImportError as e:raise HTTPException(422,str(e))
    finally:file.file.close()

class Mapping(Strict):mapping:dict[str,str]
@app.post('/api/jobs/{jid}/mapping')
def mapping(jid:str,b:Mapping,u=Depends(operator)):
    with session() as db:
        j=job_for(db,jid,u,True,True)
        try:
            r=apply_mapping(db,j,b.mapping)
            info=unseal(j.import_info) if j.import_info else {};info['mapping']=b.mapping;j.import_info=seal(info)
        except ImportError as e:raise HTTPException(422,str(e))
        audit(db,u.id,'import.mapped',jid);return r

class Person(Strict):
    id:str=Field(default='',max_length=200)
    imie:str=Field(default='',max_length=240)
    nazwisko:str=Field(default='',max_length=300)
    pesel:str=Field(default='',max_length=11)
    ulica:str=Field(default='',max_length=512)
    nr_budynku:str=Field(default='',max_length=128)
    nr_lokalu:str=Field(default='',max_length=128)
    kod_pocztowy:str=Field(default='',max_length=128)
    miejscowosc:str=Field(default='',max_length=512)
    kraj:str=Field(default='PL',max_length=2)

@app.post('/api/verify')
def verify(b:Person,u=Depends(operator)):
    p,errors=person(b.model_dump())
    if errors:raise HTTPException(422,'; '.join(errors))
    with session() as db:
        cfg=configuration(db)
        if not readiness(cfg)['ready']:raise HTTPException(503,'Skonfiguruj i włącz autoryzowany dostęp do BAE w Administracji')
        j=Job(id=uid(),owner_id=u.id,label=seal('Sprawdzenie osoby'),environment=cfg['environment'],state='queued',total=1)
        db.add(j);db.flush();sid=attach_search(db,j,p,[],{})
        # Row.search_id is a plain FK, without an ORM relationship. Flush the
        # Search first; otherwise SQLAlchemy can insert Row before its parent.
        db.flush()
        db.get(Search,sid).scheduled_by=u.id
        db.add(Row(job_id=j.id,position=1,raw=seal(b.model_dump()),person=seal(p),search_id=sid,
                   search_name=digest(p['imie']+' '+p['nazwisko']),search_source=digest(p['id']),search_pesel=digest(p['pesel'])))
        audit(db,u.id,'verify.queued',j.id);return {'job_id':j.id}

class Action(Strict):action:Literal['start','pause','resume','cancel','retry_errors','retry_review']
@app.post('/api/jobs/{jid}/action')
def action(jid:str,b:Action,u=Depends(operator)):
    with session() as db:
        j=job_for(db,jid,u,True,True);cfg=configuration(db)
        if b.action in ['start','resume','retry_errors','retry_review']:
            if not readiness(cfg)['ready'] or cfg['environment']!=j.environment:raise HTTPException(503,'Niekompletne połączenie BAE albo niezgodne środowisko zadania')
        if b.action=='start':
            if j.state!='draft':raise HTTPException(409,'Zadanie zostało już uruchomione')
            unmapped=db.scalar(select(func.count()).select_from(Row).where(Row.job_id==jid,Row.search_id.is_(None)))
            if unmapped:raise HTTPException(409,'Najpierw zatwierdź mapowanie kolumn')
            db.execute(update(Search).where(Search.job_id==jid,Search.state=='pending').values(scheduled_by=u.id))
            j.state='queued'
        elif b.action=='pause':
            if j.state not in ['queued','running']:raise HTTPException(409,'Nie można wstrzymać tego zadania')
            j.state='paused'
        elif b.action=='resume':
            if j.state not in ['paused','blocked']:raise HTTPException(409,'Nie można wznowić tego zadania')
            db.execute(update(Search).where(Search.job_id==jid,Search.state=='unauthorized').values(state='pending',scheduled=True,scheduled_by=u.id,attempts=0,next_at=0,result=None,checked=None))
            db.execute(update(Search).where(Search.job_id==jid).values(scheduled=True))
            db.execute(update(Search).where(Search.job_id==jid,Search.state=='pending').values(scheduled_by=u.id))
            j.state='queued';j.message=''
        elif b.action=='cancel':
            if j.state in ['completed','cancelled']:raise HTTPException(409,'Zadanie jest zakończone')
            j.state='cancelled'
        elif b.action=='retry_review':
            if j.state in ['running','queued','draft']:raise HTTPException(409,'Najpierw zakończ lub wstrzymaj przygotowane zadanie')
            if db.scalar(select(func.count()).select_from(Search).where(Search.job_id==jid,Search.state=='running',Search.lease_until>now())):
                raise HTTPException(409,'Poczekaj na zakończenie wysłanych zapytań przed ponowieniem kontroli')
            db.execute(update(Search).where(Search.job_id==jid).values(scheduled=False))
            targets=select(Row.search_id).join(Search,Row.search_id==Search.id).where(Row.job_id==jid,needs_review())
            db.execute(update(Search).where(Search.job_id==jid,Search.id.in_(targets)).values(scheduled=True))
            fixed=repair_invalid_encoding(db,j)
            if fixed:audit(db,u.id,'encoding.repaired',jid,str(fixed))
            requeued=db.execute(update(Search).where(Search.job_id==jid,Search.scheduled==True,Search.state.not_in(['invalid','superseded']))
                .values(state='pending',scheduled_by=u.id,attempts=0,next_at=0,result=None,checked=None,lease_token=None,lease_until=0)).rowcount
            j.state='queued';j.message='Ponowienie tylko wyników do kontroli i błędów. Ręczne oznaczenia do kontroli pozostają; nadal niepoprawne dane wymagają korekty.'
            j.updated=now();audit(db,u.id,'job.retry_review',jid,str(requeued))
            return {**job_data(db,j),'requeued':requeued}
        elif b.action=='retry_errors':
            if j.state in ['running','queued']:raise HTTPException(409,'Najpierw wstrzymaj zadanie')
            fixed=repair_invalid_encoding(db,j)
            if fixed:audit(db,u.id,'encoding.repaired',jid,str(fixed))
            db.execute(update(Search).where(Search.job_id==jid,Search.state.in_(['technical_error','unauthorized','pending'])).values(state='pending',scheduled=True,scheduled_by=u.id,attempts=0,next_at=0,result=None,checked=None))
            j.state='queued';j.message=''
        j.updated=now();audit(db,u.id,'job.'+b.action,jid);return job_data(db,j)

def rows_stmt(jid,status,search):
    stmt=select(Row,Search).outerjoin(Search,Row.search_id==Search.id)
    if jid is not None:stmt=stmt.where(Row.job_id==jid)
    if status=='needs_review':stmt=stmt.where(needs_review())
    elif status=='unmapped':stmt=stmt.where(Row.search_id==None)
    elif status=='review':stmt=stmt.where(or_(Row.review==True,Search.state.in_(['ambiguous','unauthorized'])))
    elif status:stmt=stmt.where(Search.state==status)
    if search:
        d=digest(search);stmt=stmt.where(or_(Row.search_name==d,Row.search_source==d,Row.search_pesel==d))
    return stmt

def needs_review():
    return or_(Row.review==True,Search.state.in_(['invalid','ambiguous','technical_error','unauthorized']))

def visible_jobs(u):
    stmt=select(Job.id)
    return stmt if u.role in ['admin','auditor'] else stmt.where(Job.owner_id==u.id)

@app.get('/api/records')
def records(u=Depends(current_user),page:int=Query(1,ge=1),size:int=Query(25,ge=1,le=100),
            status:Literal['','found','not_found','needs_review','invalid','ambiguous','technical_error','unauthorized','pending','running','unmapped']='',
            q:str=Query('',max_length=300)):
    with session() as db:
        stmt=rows_stmt(None,status,q).join(Job,Row.job_id==Job.id).where(Job.id.in_(visible_jobs(u)))
        total=db.scalar(select(func.count()).select_from(stmt.subquery()))
        items=[];labels={}
        for row,s in db.execute(stmt.order_by(Job.created.desc(),Job.id,Row.position).offset((page-1)*size).limit(size)):
            if row.job_id not in labels:
                job=db.get(Job,row.job_id);labels[row.job_id]=(unseal(job.label),job.environment)
            label,environment=labels[row.job_id]
            items.append({**row_data(row,s),'job_id':row.job_id,'job_label':label,'environment':environment})
        return {'total':total,'items':items}

def row_data(row,s,full=False):
    p=unseal(row.person) if row.person else {};result=unseal(s.result) if s and s.result else {}
    repairs=p.pop('_encoding_repairs',[])
    if p.get('pesel') and not full:p['pesel']='*******'+p['pesel'][-4:]
    return {'row_id':row.id,'position':row.position,**p,'encoding_repairs':repairs,'status':s.state if s else 'unmapped','review':row.review,
            'ade':result.get('ade'),'checked':s.checked if s else None,'note':result.get('note',''),
            'operator_note':unseal(row.note) if row.note else '', 'source':result.get('source',''),'request_id':result.get('request_id'),
            'review_reasons':result.get('review_reasons',[]),'error_code':result.get('error_code',''),'diagnostics':result.get('diagnostics',[]),'adapter_version':result.get('adapter_version','')}

@app.get('/api/jobs/{jid}/rows')
def rows(jid:str,u=Depends(current_user),page:int=Query(1,ge=1),size:int=Query(25,ge=1,le=100),status:str='',q:str=Query('',max_length=300),sort:Literal['position','status','checked']='position',desc:bool=False):
    with session() as db:
        job_for(db,jid,u);stmt=rows_stmt(jid,status,q)
        total=db.scalar(select(func.count()).select_from(stmt.subquery()))
        column={'position':Row.position,'status':Search.state,'checked':Search.checked}[sort]
        items=[row_data(r,s) for r,s in db.execute(stmt.order_by(column.desc() if desc else column.asc(),Row.position).offset((page-1)*size).limit(size))]
        return {'total':total,'items':items}

@app.get('/api/jobs/{jid}/rows/{rid}')
def row_detail(jid:str,rid:str,u=Depends(operator)):
    with session() as db:
        j=job_for(db,jid,u,True)
        row=db.get(Row,rid)
        if not row or row.job_id!=jid:raise HTTPException(404,'Nie znaleziono wiersza')
        audit(db,u.id,'row.reveal',jid)
        return row_data(row,db.get(Search,row.search_id) if row.search_id else None,True)

class Edit(Strict):
    person:Person
    note:str=Field(default='',max_length=1000)
    review:bool=False
@app.put('/api/jobs/{jid}/rows/{rid}')
def edit_row(jid:str,rid:str,b:Edit,u=Depends(operator)):
    with session() as db:
        j=job_for(db,jid,u,True,True)
        if j.state in ['running','queued']:raise HTTPException(409,'Wstrzymaj zadanie przed zmianą danych')
        row=db.get(Row,rid)
        if not row or row.job_id!=jid:raise HTTPException(404,'Nie znaleziono wiersza')
        p,errors=person(b.person.model_dump())
        previous=unseal(row.person) if row.person else {}
        if not p.get('_encoding_repairs') and previous.get('_encoding_repairs') and all(p[f]==previous.get(f) for f in ['imie','nazwisko']):
            p['_encoding_repairs']=previous['_encoding_repairs']
        existing=db.scalar(select(Search).where(Search.job_id==jid,Search.fingerprint==fingerprint(p,errors)))
        if existing and existing.state=='superseded':existing.state='invalid' if errors else 'pending';existing.checked=None;existing.result=None;existing.attempts=0;existing.next_at=0
        known={fingerprint(p,errors):existing.id} if existing else {}
        sid=attach_search(db,j,p,errors,known);db.flush()
        row.search_id=sid;row.person=seal(p);row.note=seal(b.note);row.review=b.review
        row.search_name=digest(p['imie']+' '+p['nazwisko']);row.search_source=digest(p['id']);row.search_pesel=digest(p['pesel'])
        db.flush()
        db.execute(update(Search).where(Search.job_id==jid,~Search.id.in_(select(Row.search_id).where(Row.job_id==jid,Row.search_id.is_not(None)))).values(state='superseded'))
        j.duplicates=j.total-db.scalar(select(func.count(func.distinct(Row.search_id))).where(Row.job_id==jid))
        audit(db,u.id,'row.edited',jid);return {'ok':True,'validation_errors':errors}

class Selection(Strict):
    ids:list[str]=Field(min_length=1,max_length=1000)
    action:Literal['retry','review']
@app.post('/api/jobs/{jid}/selection')
def selection(jid:str,b:Selection,u=Depends(operator)):
    with session() as db:
        j=job_for(db,jid,u,True,True)
        if j.state in ['running','queued']:raise HTTPException(409,'Wstrzymaj zadanie przed zmianą rekordów')
        selected=list(db.scalars(select(Row).where(Row.job_id==jid,Row.id.in_(b.ids))))
        if len(selected)!=len(set(b.ids)):raise HTTPException(404,'Nie znaleziono części wierszy')
        if b.action=='review':
            for r in selected:r.review=True
        else:
            if not readiness(configuration(db))['ready']:raise HTTPException(503,'Brak skonfigurowanego połączenia BAE')
            if db.scalar(select(func.count()).select_from(Search).where(Search.job_id==jid,Search.state=='running',Search.lease_until>now())):raise HTTPException(409,'Poczekaj na zakończenie wysłanego zapytania przed ponowieniem zaznaczonych')
            fixed=repair_invalid_encoding(db,j,b.ids)
            if fixed:audit(db,u.id,'encoding.repaired',jid,str(fixed))
            sids={r.search_id for r in selected if r.search_id}
            db.execute(update(Search).where(Search.job_id==jid).values(scheduled=False))
            # Shared duplicate results are rechecked together, preserving every original row.
            db.execute(update(Search).where(Search.id.in_(sids),Search.state!='invalid').values(state='pending',scheduled=True,scheduled_by=u.id,result=None,checked=None,attempts=0,next_at=0))
            j.state='queued'
        audit(db,u.id,'selection.'+b.action,jid);return {'ok':True}

class Export(Strict):
    format:Literal['csv','json','xlsx','pdf']='csv'
    variant:Literal['all','found','not_found','review','unverified']='all'
    ids:list[str]=Field(default_factory=list,max_length=1000)
    sensitive:bool=False
    fields:list[tuple[str,str]]=Field(default_factory=list,max_length=50)
@app.post('/api/jobs/{jid}/export')
def export(jid:str,b:Export,u=Depends(current_user)):
    if b.sensitive and u.role=='auditor':raise HTTPException(403,'Audytor nie może eksportować pełnych PESEL')
    fields=b.fields or [(f,f) for f in DEFAULT_FIELDS]
    if any(f not in DEFAULT_FIELDS+['kraj'] or not label or len(label)>100 for f,label in fields) or len({label for _,label in fields})!=len(fields):raise HTTPException(422,'Nieprawidłowy schemat eksportu')
    report = TemporaryFile()
    try:
        with session() as db:
            j = job_for(db, jid, u, lock=True)
            if j.state in ['queued','running']:raise HTTPException(409,'Wstrzymaj zadanie, aby eksport był spójny')
            if db.scalar(select(func.count()).select_from(Row).where(Row.job_id==jid,Row.search_id.is_(None))):raise HTTPException(409,'Zatwierdź mapowanie przed eksportem')
            if b.ids and db.scalar(select(func.count()).select_from(Row).where(Row.job_id==jid,Row.id.in_(b.ids)))!=len(set(b.ids)):raise HTTPException(404,'Nie znaleziono części wierszy')
            env = j.environment
            event = Audit(id=uid(), actor_id=u.id, action='export.'+b.format, job_id=jid,
                          outcome='summary' if b.format=='pdf' else ('sensitive' if b.sensitive else 'masked'))
            db.add(event)
            db.flush()
            count = 0
            batch = []
            counts = {}

            def write_batch():
                db.add(AuditExportRows(audit_id=event.id,batch=(count-1)//200,payload=seal(batch)))
                db.flush()
                batch.clear()

            def records():
                nonlocal count
                for row in export_rows(db,j,b.variant,b.ids,b.sensitive):
                    count += 1
                    if b.format=='pdf':
                        status=row['status']
                        counts[status]=counts.get(status,0)+1
                    else:
                        batch.append({
                            'source_row':row['wiersz_zrodlowy'],
                            'data':{label:row.get(key) for key,label in fields},
                        })
                        if len(batch)==200:write_batch()
                    yield row

            if b.format in ['csv','json']:
                chunks = csv_stream(records(),fields) if b.format=='csv' else json_stream(records(),fields)
                for chunk in chunks:
                    report.write(chunk.encode('utf-8'))
            elif b.format=='xlsx':
                report.write(xlsx_bytes(records(),fields))
            else:
                report.write(pdf_bytes(records(),j))
            if batch:write_batch()
            event.details=seal({
                'username':u.username,'environment':env,'variant':b.variant,'row_count':count,
                'fields':fields if b.format!='pdf' else [],
                'status_counts':counts if b.format=='pdf' else None,
            })
        report.seek(0)
    except BaseException:
        report.close()
        raise

    def output():
        with report:
            while chunk := report.read(65536):
                yield chunk

    media_types={
        'csv':'text/csv; charset=utf-8','json':'application/json',
        'xlsx':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','pdf':'application/pdf',
    }
    headers={'Content-Disposition':f'attachment; filename="BAE_{env}_{jid}.{b.format}"'}
    return StreamingResponse(output(),media_type=media_types[b.format],headers=headers,background=BackgroundTask(report.close))

@app.get('/api/admin/config')
def get_config(u=Depends(admin)):
    with session() as db:
        cfg=configuration(db);return {'config':cfg,'diagnostics':readiness(cfg),'secrets':{e:certificate_info_public(e) for e in HOSTS}}

def certificate_info_public(e):
    from .adapter import certificate_info
    return certificate_info(e)

class Connection(Strict):
    environment:Literal['INT','PROD']='INT'
    sender_eda:str=Field(default='',max_length=100)
    system_name:str=Field(default='',max_length=100)
    audience:str=Field(default='',max_length=300)
    login_hint:str=Field(default='',max_length=150)
    max_concurrency:int=Field(default=1,ge=1,le=8)
    requests_per_second:float=Field(default=0.5,ge=0.01,le=10,allow_inf_nan=False)
    limits_confirmed:bool=False
    enabled:bool=False
    retention_days:int=Field(default=30,ge=1,le=365)
    audit_days:int=Field(default=365,ge=30,le=3650)
@app.put('/api/admin/config')
def put_config(b:Connection,u=Depends(admin)):
    if b.sender_eda and not re.fullmatch(r'AE:PL-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[0-9]{2}',b.sender_eda):raise HTTPException(422,'Nieprawidłowy ADE nadawcy')
    if b.system_name and not re.fullmatch(r'[\w-]{1,100}',b.system_name):raise HTTPException(422,'Nieprawidłowa nazwa systemu')
    realm=HOSTS[b.environment]+'/auth/realms/EDOR'
    if b.audience and b.audience not in [realm,realm.replace('https:','http:')]:raise HTTPException(422,'Audience musi wskazywać realm EDOR wybranego środowiska')
    if b.login_hint and b.login_hint not in [b.sender_eda,'ADE.'+b.sender_eda]:raise HTTPException(422,'Login hint musi odpowiadać ADE nadawcy (opcjonalnie prefiks ADE.)')
    with session() as db:
        if db.scalar(select(func.count()).select_from(Job).where(Job.state.in_(['running','queued']))):raise HTTPException(409,'Wstrzymaj aktywne zadania przed zmianą konfiguracji')
        row=db.get(Config,'connection')
        if not row:row=Config(key='connection',value='');db.add(row)
        row.value=seal(b.model_dump());audit(db,u.id,'config.updated');return {'ok':True,'diagnostics':readiness(b.model_dump())}

@app.post('/api/admin/diagnostics')
def diagnostics(u=Depends(admin)):
    with session() as db:
        cfg=configuration(db);ready=readiness(cfg)
        auth_ready=readiness(cfg,authentication_only=True)
        common={'search':'not_tested','environment':cfg['environment'],
                'client_id':f"{cfg['sender_eda']}.SYSTEM.{cfg['system_name']}"}
        if not auth_ready['ready']:
            return {**ready,**common,'authentication':'incomplete','missing':auth_ready['missing'],
                    'message':'Nie można przetestować autoryzacji. Uzupełnij: '+' · '.join(auth_ready['missing'])}
        try:
            adapter=SEAdapter(cfg)
            try:adapter.token()
            finally:adapter.close()
            audit(db,u.id,'connection.token')
            return {**ready,**common,'authentication':'ok','message':'Autoryzacja poprawna: uzyskano ważny token. Test nie wyszukuje osób i nie potwierdza uprawnień do wyszukiwania w BAE.'}
        except BaeError as e:
            explanations={
                'http_401':'HTTP 401: serwer e-Doręczeń odrzucił uwierzytelnienie systemu. Porównaj nazwę po .SYSTEM. z identyfikatorem klienta (wielkość liter ma znaczenie), ADE, środowisko i zarejestrowany certyfikat.',
                'http_403':'HTTP 403: serwer e-Doręczeń odmówił dostępu. Sprawdź uprawnienia i aktywność zarejestrowanego systemu.',
                'http_400':'HTTP 400: serwer odrzucił żądanie tokenu. Sprawdź Audience JWT, login hint i dokładny identyfikator klienta.',
                'token_timeout':'Przekroczono czas oczekiwania na serwer autoryzacji e-Doręczeń.',
                'token_transport':'Nie udało się połączyć z serwerem autoryzacji e-Doręczeń. Sprawdź DNS, dostęp do Internetu, TLS i czas serwera.',
                'invalid_token_response':'Serwer autoryzacji zwrócił nieprawidłową odpowiedź tokenową.'}
            audit(db,u.id,'connection.token',outcome=e.code)
            return {**ready,**common,'authentication':e.code,
                    'message':explanations.get(e.code,'Test autoryzacji nie powiódł się: '+e.code)}

@app.get('/api/admin/users')
def users(u=Depends(admin)):
    with session() as db:return [{'id':x.id,'username':x.username,'role':x.role,'active':x.active,'auth_type':x.auth_type,'mfa':bool(x.totp),'bulk_allowed':x.bulk_allowed} for x in db.scalars(select(User).order_by(User.username))]
class UserCreate(Strict):
    username:str=Field(min_length=2,max_length=120)
    password:str=Field(default='',max_length=256)
    role:Literal['admin','operator','auditor']='operator'
    auth_type:Literal['local','ldap']='local'
    bulk_allowed:bool=False
@app.post('/api/admin/users')
def create_user(b:UserCreate,u=Depends(admin)):
    name=normalize(b.username)
    if not re.fullmatch(r'[a-z0-9._-]{2,120}',name):raise HTTPException(422,'Login: litery ASCII, cyfry, kropka, łącznik, podkreślenie')
    try:hashed=password_hash(b.password) if b.auth_type=='local' else ''
    except ValueError as e:raise HTTPException(422,str(e))
    with session() as db:
        if db.scalar(select(User).where(User.username==name)):raise HTTPException(409,'Login jest zajęty')
        db.add(User(username=name,password=hashed,role=b.role,auth_type=b.auth_type,bulk_allowed=b.bulk_allowed if b.role=='operator' else False));audit(db,u.id,'user.created');return {'ok':True}
class UserChange(Strict):
    active:bool
    role:Literal['admin','operator','auditor']
    bulk_allowed:bool|None=None
@app.put('/api/admin/users/{user_id}')
def change_user(user_id:str,b:UserChange,u=Depends(admin)):
    if user_id==u.id:raise HTTPException(409,'Własne konto zmienia inny administrator')
    with session() as db:
        target=db.get(User,user_id)
        if not target:raise HTTPException(404,'Nie znaleziono użytkownika')
        old_role=target.role
        target.active=b.active;target.role=b.role
        if target.role!='operator':target.bulk_allowed=False
        elif b.bulk_allowed is not None:target.bulk_allowed=b.bulk_allowed
        elif old_role!='operator':target.bulk_allowed=False
        if not target.active or target.role=='auditor' or (target.role=='operator' and not target.bulk_allowed):
            tasks=update(Job).where(Job.owner_id==user_id,Job.state.in_(['queued','running']))
            if target.active and target.role=='operator':tasks=tasks.where(Job.kind=='bulk')
            db.execute(tasks.values(state='paused',message='Dostęp do przetwarzania wyłączony przez administratora'))
        db.execute(delete(LoginSession).where(LoginSession.user_id==user_id));audit(db,u.id,'user.updated');return {'ok':True}

@app.get('/api/audit')
def history(u=Depends(current_user),page:int=Query(1,ge=1)):
    with session() as db:
        stmt=select(Audit)
        if u.role=='operator':stmt=stmt.where(Audit.actor_id==u.id)
        total=db.scalar(select(func.count()).select_from(stmt.subquery()))
        return {'total':total,'items':[{'id':a.id,'actor':a.actor_id,'at':a.at,'action':a.action,'job_id':a.job_id,'outcome':a.outcome} for a in db.scalars(stmt.order_by(Audit.at.desc()).offset((page-1)*50).limit(50))]}


class AuditPeriod(Strict):
    start:datetime
    end:datetime
    operation:Literal['all','search','export']='all'

    def bounds(self):
        if self.start.utcoffset() is not None and self.end.utcoffset() is not None and self.start<self.end:
            return self.start.timestamp(),self.end.timestamp()
        raise HTTPException(422,'Nieprawidłowy okres raportu. Wymagany jest czas ze strefą.')

    def statement(self):
        start,end=self.bounds()
        kinds={
            'all':or_(Audit.action=='query.finished',Audit.action.like('export.%')),
            'search':Audit.action=='query.finished',
            'export':Audit.action.like('export.%'),
        }
        return select(Audit,User.username).outerjoin(User,User.id==Audit.actor_id).where(
            Audit.at>=start,Audit.at<end,kinds[self.operation]).order_by(Audit.at.desc(),Audit.id.desc())

def audit_activity(event,username):
    details=unseal(event.details) if event.details else {}
    return {
        'id':event.id,'at':datetime.fromtimestamp(event.at,timezone.utc).isoformat(),
        'actor_id':event.actor_id,'username':details.get('username') or username,
        'job_id':event.job_id,'operation':event.action,'outcome':event.outcome,
        'details_available':bool(event.details),'row_count':details.get('row_count'),
    }

@app.post('/api/admin/audit/activity')
def audit_activity_page(period:AuditPeriod,page:int=Query(1,ge=1),u=Depends(admin)):
    with session() as db:
        stmt=period.statement()
        count=db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery()))
        return {'total':count,'items':[audit_activity(event,username)
            for event,username in db.execute(stmt.offset((page-1)*50).limit(50))]}

@app.post('/api/admin/audit/activity/{event_id}/details')
def audit_activity_details(event_id:str,batch:int=Query(0,ge=0),u=Depends(admin)):
    with session() as db:
        event=db.get(Audit,event_id)
        if not event or not (event.action=='query.finished' or event.action.startswith('export.')):
            raise HTTPException(404,'Nie znaleziono operacji')
        details=unseal(event.details) if event.details else None
        part=db.get(AuditExportRows,(event_id,batch))
        audit(db,u.id,'audit.details',event.job_id,details=seal({'event_id':event.id,'batch':batch}))
        return {'details':details,'rows':unseal(part.payload) if part else [],
                'batches':math.ceil(details['row_count']/200) if details and part else 0}

@app.post('/api/admin/audit/report')
def audit_activity_report(period:AuditPeriod,u=Depends(admin)):
    stmt=period.statement()
    with session() as db:
        audit(db,u.id,'audit.report',details=seal({
            'start':period.start.isoformat(),'end':period.end.isoformat(),'operation':period.operation,
        }))

    def records():
        with session() as db:
            for event,username in db.execute(stmt.execution_options(yield_per=200)):
                item=audit_activity(event,username)
                item['details']=json.dumps(unseal(event.details),ensure_ascii=False) if event.details else ''
                yield item
                if event.action not in ('export.csv','export.json','export.xlsx') or not item['row_count']:
                    continue
                for part in db.scalars(select(AuditExportRows).where(AuditExportRows.audit_id==event.id)
                                       .order_by(AuditExportRows.batch).execution_options(yield_per=10)):
                    for row in unseal(part.payload):
                        yield {**item,'details':json.dumps(row,ensure_ascii=False)}

    fields=[('id','ID operacji'),('at','Czas UTC'),('username','Login'),('actor_id','ID operatora'),
            ('job_id','ID zadania'),('operation','Operacja'),('outcome','Wynik'),('details','Szczegóły JSON')]
    return StreamingResponse(csv_stream(records(),fields),media_type='text/csv; charset=utf-8',
        headers={'Content-Disposition':'attachment; filename="BAE_raport_aktywnosci.csv"'})

@app.get('/api/stats')
def stats(u=Depends(current_user)):
    with session() as db:
        own=visible_jobs(u)
        counts=dict(db.execute(select(Search.state,func.count(Row.id)).join(Row,Row.search_id==Search.id).where(Row.job_id.in_(own)).group_by(Search.state)).all())
        total=db.scalar(select(func.coalesce(func.sum(Job.total),0)).where(Job.id.in_(own)))
        review=db.scalar(select(func.count(Row.id)).outerjoin(Search,Row.search_id==Search.id).where(Row.job_id.in_(own),needs_review()))
        return {'total':total,'counts':counts,'needs_review':review}

@app.get('/api/jobs/{jid}/preview')
def preview(jid:str,u=Depends(operator)):
    with session() as db:
        j=job_for(db,jid,u,True)
        if j.state!='draft':raise HTTPException(409,'Podgląd importu dostępny w zadaniu przed uruchomieniem')
        info=unseal(j.import_info) if j.import_info else {}
        rows=[unseal(r.raw) for r in db.scalars(select(Row).where(Row.job_id==jid).order_by(Row.position).limit(20))]
        return {**info,'preview':rows,'total':j.total}


@app.get('/api/jobs/{jid}/attempts')
def attempts(jid:str,u=Depends(current_user),page:int=Query(1,ge=1)):
    with session() as db:
        job_for(db,jid,u)
        stmt=select(Attempt).where(Attempt.job_id==jid)
        total=db.scalar(select(func.count()).select_from(stmt.subquery()))
        return {'total':total,'items':[{'id':a.id,'at':a.at,'number':a.number,'state':a.state,'search_id':a.search_id,
                'result':unseal(a.result)} for a in db.scalars(stmt.order_by(Attempt.at.desc()).offset((page-1)*50).limit(50))]}

#UMBedzin - RI - MCZU