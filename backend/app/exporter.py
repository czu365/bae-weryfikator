import csv, io, json
from collections import Counter
from datetime import datetime, timezone
from sqlalchemy import select,or_
from .db import Row, Search
from .security import unseal
from .validation import FIELDS, encoding_note

EXTRA=['status','ade','sprawdzono','zrodlo','id_zapytania','uwagi','grupa_korespondencji','wiersz_zrodlowy']
DEFAULT_FIELDS=['id','imie','nazwisko','pesel','ulica','nr_budynku','nr_lokalu','kod_pocztowy','miejscowosc']+EXTRA
FILTERS={'all':None,'found':['found'],'not_found':['not_found'],'review':['ambiguous','invalid','technical_error','unauthorized'],'unverified':['pending','running']}

def safe_cell(v):
    v='' if v is None else str(v)
    return "'"+v if v.lstrip().startswith(('=','+','-','@','\t','\r','\n')) or (v and v[0] in '\t\r\n') else v

def export_rows(db,job,variant='all',ids=None,sensitive=False):
    stmt=select(Row,Search).join(Search,Row.search_id==Search.id).where(Row.job_id==job.id)
    statuses=FILTERS[variant]
    if statuses:stmt=stmt.where(or_(Search.state.in_(statuses),Row.review==True) if variant=='review' else Search.state.in_(statuses))
    if ids:stmt=stmt.where(Row.id.in_(ids))
    for row,s in db.execute(stmt.order_by(Row.position).execution_options(yield_per=500)):
        result=unseal(s.result) if s.result else {}
        p=unseal(row.person)
        value={**p,'status':'review' if row.review else s.state,'ade':result.get('ade'),
               'sprawdzono':datetime.fromtimestamp(s.checked,timezone.utc).isoformat() if s.checked else None,
               'zrodlo':result.get('source',''),'id_zapytania':result.get('request_id'),
               'uwagi':'; '.join(x for x in [result.get('note'),unseal(row.note) if row.note else '',encoding_note(p)] if x),
               'wiersz_zrodlowy':row.position,
               'grupa_korespondencji':'Weryfikacja wymagana' if row.review else ('Kandydat PURDE' if s.state=='found' else 'Ocena trybu doręczenia' if s.state=='not_found' else 'Weryfikacja wymagana')}
        if value['pesel'] and not sensitive:value['pesel']='*******'+value['pesel'][-4:]
        yield value

def csv_stream(rows,fields):
    buf=io.StringIO();w=csv.writer(buf,delimiter=';',lineterminator='\r\n')
    yield '\ufeff';w.writerow([safe_cell(label) for _,label in fields]);yield buf.getvalue();buf.seek(0);buf.truncate(0)
    for r in rows:
        w.writerow([safe_cell(r.get(f,'')) for f,_ in fields]);yield buf.getvalue();buf.seek(0);buf.truncate(0)

def json_stream(rows,fields):
    yield '[';first=True
    for r in rows:
        yield ('' if first else ',')+json.dumps({label:r.get(f) for f,label in fields},ensure_ascii=False)
        first=False
    yield ']'

def xlsx_bytes(rows,fields):
    from openpyxl import Workbook
    from openpyxl.cell import WriteOnlyCell
    wb=Workbook(write_only=True);ws=wb.create_sheet('Wyniki')
    def cells(values):
        out=[]
        for v in values:
            c=WriteOnlyCell(ws,value='' if v is None else str(v));c.data_type='s';c.number_format='@';out.append(c)
        return out
    ws.append(cells([label for _,label in fields]))
    for row in rows:ws.append(cells([row.get(f) for f,_ in fields]))
    b=io.BytesIO();wb.save(b);return b.getvalue()

def pdf_bytes(rows,job):
    from reportlab.pdfgen.canvas import Canvas
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.lib.pagesizes import A4
    font='/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'
    pdfmetrics.registerFont(TTFont('DejaVu',font))
    counts=Counter(r['status'] for r in rows);b=io.BytesIO();c=Canvas(b,pagesize=A4)
    c.setTitle('BAE Weryfikator – raport zbiorczy');c.setFont('DejaVu',19);c.drawString(48,785,'BAE Weryfikator')
    c.setFont('DejaVu',12);c.drawString(48,756,'Raport zbiorczy weryfikacji')
    c.setFont('DejaVu',9)
    texts=[f'Zadanie: {job.id}',f'Środowisko: {job.environment}',f'Wygenerowano (UTC): {datetime.now(timezone.utc).isoformat(timespec="seconds")}',f'Liczba wierszy w zestawieniu: {sum(counts.values())}','']
    labels={'found':'Odnaleziono ADE','not_found':'Brak dopasowania','ambiguous':'Niejednoznaczne','invalid':'Błędne dane','technical_error':'Błąd techniczny','unauthorized':'Brak uprawnień','pending':'Oczekujące','running':'W toku','review':'Kontrola operatora'}
    texts += [f'{labels.get(k,k)}: {v}' for k,v in sorted(counts.items())]
    texts+=['','Brak dopasowania nie jest dowodem braku adresu ADE.','Zestawienie nie stanowi automatycznej kwalifikacji do PUH.','Dobór kanału doręczenia wymaga oceny uprawnionego operatora.']
    y=725
    for text in texts:c.drawString(48,y,text);y-=22
    c.showPage();c.save();return b.getvalue()
