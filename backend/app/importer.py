import csv, io, json
import ijson
from sqlalchemy import select, insert, delete, update, func
from .db import Job, Row, Search, uid, now
from .security import seal, unseal, digest
from .validation import flatten, mapping_for, person, FIELDS

class ImportError(ValueError):pass

def records(file,extension):
    if extension=='.csv':
        wrapper=io.TextIOWrapper(file,encoding='utf-8-sig',newline='')
        try:
            sample=wrapper.read(8192);wrapper.seek(0)
            try:dialect=csv.Sniffer().sniff(sample,delimiters=';,')
            except csv.Error:raise ImportError('Nie rozpoznano separatora ; lub ,')
            reader=csv.DictReader(wrapper,dialect=dialect)
            headers=reader.fieldnames
            if not headers or len(headers)>100 or len(headers)!=len(set(headers)) or any(not h or len(h)>256 for h in headers):raise ImportError('Nieprawidłowe lub powtórzone nagłówki CSV')
            for row in reader:
                if None in row or any(v is None for v in row.values()):raise ImportError('Niezgodna liczba kolumn w CSV')
                yield row
        except (UnicodeError,csv.Error):raise ImportError('CSV musi być poprawnym plikiem UTF-8')
        finally:wrapper.detach()
    elif extension=='.json':
        # A JSON object must not silently import as an empty array.
        prefix=file.read(4);file.seek(0)
        if prefix.startswith(b'\xef\xbb\xbf'):file.seek(3)
        start=file.tell()
        while True:
            c=file.read(1)
            if not c:raise ImportError('Pusty JSON')
            if not c.isspace():break
        if c!=b'[':raise ImportError('JSON musi zawierać tablicę obiektów')
        file.seek(start)
        try:
            for row in ijson.items(file,'item',use_float=True):
                if not isinstance(row,dict):raise ImportError('Każdy element JSON musi być obiektem')
                yield flatten(row)
        except (ijson.JSONError,UnicodeError):raise ImportError('Niepoprawny JSON lub kodowanie UTF-8')
    else:raise ImportError('Dozwolone są pliki CSV i JSON')

def import_file(db,job,file,extension,max_rows=100000):
    job.kind='bulk'
    columns=[];batch=[];total=0;preview=[]
    try:
        for position,raw in enumerate(records(file,extension),1):
            if position>max_rows:raise ImportError(f'Limit {max_rows} wierszy')
            if len(raw)>100 or any(len(str(v))>10000 for v in raw.values()) or len(json.dumps(raw))>32000:raise ImportError('Zbyt duży rekord lub zbyt wiele kolumn')
            for k in raw:
                if k not in columns:columns.append(k)
            if len(columns)>100:raise ImportError('Zbyt wiele różnych kolumn')
            if len(preview)<20:preview.append(raw)
            batch.append({'id':uid(),'job_id':job.id,'position':position,'raw':seal(raw),'review':False,'note':'','search_name':'','search_source':'','search_pesel':''})
            total=position
            if len(batch)==500:db.execute(insert(Row),batch);batch=[]
        if not total:raise ImportError('Plik nie zawiera rekordów')
        if batch:db.execute(insert(Row),batch)
        job.total=total;job.state='draft';job.updated=now()
        return {'job_id':job.id,'total':total,'columns':columns,'mapping':mapping_for(columns),'preview':preview}
    except Exception:
        db.rollback();raise

def fingerprint(p,errors=None):
    # Source IDs do not affect identity; keep all search criteria to avoid conflating stale addresses.
    fields=['imie','nazwisko','pesel'] if p['pesel'] else [f for f in FIELDS if f not in ['id','pesel']]
    return digest(json.dumps({'criteria':{f:p[f] for f in fields},'errors':errors or []},ensure_ascii=False,sort_keys=True))

def attach_search(db,job,p,errors,known):
    fp=fingerprint(p,errors)
    if fp not in known:
        s=Search(id=uid(),job_id=job.id,fingerprint=fp,payload=seal(p),state='invalid' if errors else 'pending',
                 result=seal({'status':'invalid','ade':None,'note':'; '.join(errors),'source':'Walidacja lokalna'}) if errors else None)
        db.add(s);known[fp]=s.id
    return known[fp]

def apply_mapping(db,job,mapping):
    if job.state!='draft':raise ImportError('Mapowanie jest dostępne tylko przed rozpoczęciem weryfikacji')
    if set(mapping)-set(FIELDS):raise ImportError('Nieznane pole mapowania')
    selected=[c for c in mapping.values() if c]
    if len(selected)!=len(set(selected)):raise ImportError('Jedna kolumna nie może zasilać dwóch pól')
    if not mapping.get('imie') or not mapping.get('nazwisko'):raise ImportError('Przypisz kolumny imienia i nazwiska')
    # Remapping a draft is atomic, including clearing all prior links.
    from sqlalchemy import update
    db.execute(update(Row).where(Row.job_id==job.id).values(search_id=None))
    db.execute(delete(Search).where(Search.job_id==job.id));db.flush()
    known={};invalid=0;encoding_fixed=0
    cursor=0
    while True:
        rows=db.scalars(select(Row).where(Row.job_id==job.id,Row.position>cursor).order_by(Row.position).limit(500)).all()
        if not rows:break
        prepared=[]
        for row in rows:
            p,errors=person(unseal(row.raw),mapping);s=attach_search(db,job,p,errors,known)
            encoding_fixed+=bool(p.get('_encoding_repairs'))
            prepared.append((row,p,s))
            invalid+=bool(errors)
        # Persist each batch of parent searches before assigning child FKs.
        # Keep batch flushing rather than issuing one INSERT roundtrip per row.
        db.flush()
        for row,p,s in prepared:
            row.person=seal(p);row.search_id=s;row.search_name=digest(p['imie']+' '+p['nazwisko']);row.search_source=digest(p['id']);row.search_pesel=digest(p['pesel'])
        cursor=rows[-1].position;db.flush()
        # Only keep fingerprints and IDs; expire ORM rows to keep memory bounded for 100k.
        db.expire_all()
    job.duplicates=job.total-len(known);job.updated=now()
    return {'total':job.total,'invalid':invalid,'duplicates':job.duplicates,'unique_queries':len(known),'encoding_fixed':encoding_fixed}

def repair_invalid_encoding(db,job,ids=None):
    """Repair only previously invalid names, preserving all valid results/raw data."""
    from .validation import repair_name_encoding
    fixed=0;cursor=0
    while True:
        stmt=select(Row).join(Search,Row.search_id==Search.id).where(Row.job_id==job.id,Row.position>cursor,Search.state=='invalid')
        if ids is not None:stmt=stmt.where(Row.id.in_(ids))
        rows=db.scalars(stmt.order_by(Row.position).limit(500)).all()
        if not rows:break
        known={};prepared=[]
        for row in rows:
            previous=unseal(row.person) if row.person else {}
            if not any(repair_name_encoding(previous.get(f,''))!=previous.get(f,'') for f in ['imie','nazwisko']):continue
            p,errors=person(previous)
            fp=fingerprint(p,errors)
            existing=db.scalar(select(Search).where(Search.job_id==job.id,Search.fingerprint==fp))
            if existing:
                known[fp]=existing.id
                if existing.state=='pending':existing.scheduled=True
                if existing.state=='superseded':existing.state='invalid' if errors else 'pending';existing.result=None;existing.checked=None;existing.attempts=0;existing.next_at=0
            sid=attach_search(db,job,p,errors,known);prepared.append((row,p,sid));fixed+=1
        db.flush()
        for row,p,sid in prepared:
            row.person=seal(p);row.search_id=sid;row.search_name=digest(p['imie']+' '+p['nazwisko'])
        db.flush();cursor=rows[-1].position
    if fixed:
        db.execute(update(Search).where(Search.job_id==job.id,~Search.id.in_(select(Row.search_id).where(Row.job_id==job.id,Row.search_id.is_not(None)))).values(state='superseded'))
        job.duplicates=job.total-db.scalar(select(func.count(func.distinct(Row.search_id))).where(Row.job_id==job.id))
    return fixed
