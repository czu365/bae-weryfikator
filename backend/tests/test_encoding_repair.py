import io,json,copy,pytest
from sqlalchemy import select
from app import api
from app.db import session,Job,Row,Search,uid
from app.validation import person,repair_name_encoding
from app.security import seal,unseal
from app.importer import import_file,apply_mapping,fingerprint

@pytest.mark.parametrize('bad,good', [('CIE\x8cLA','CIEŚLA'),('Cie\x9cla','Cieśla'),('\x8fRÓDŁO','ŹRÓDŁO'),('\x9fródło','źródło')])
def test_recognized_control_signatures(sample,bad,good):
    raw={**sample,'nazwisko':bad};before=copy.deepcopy(raw)
    p,errors=person(raw)
    assert not errors and p['nazwisko']==good and p['_encoding_repairs']
    assert raw==before and repair_name_encoding(good)==good

@pytest.mark.parametrize('name',['MICHAL','LUCJA','MICHALINA','ŁUCJA','MICHAŁ','MUÑOZ','ÆGIR','ŒUVRE','CIEŚLA'])
def test_valid_letters_and_names_are_not_rewritten(sample,name):
    p,errors=person({**sample,'nazwisko':name})
    assert not errors and p['nazwisko']==name and '_encoding_repairs' not in p

@pytest.mark.parametrize('name',['CIE.LA','CIE�LA','CIE?LA','CIE\x81LA','CIE\x00LA'])
def test_unknown_missing_characters_remain_invalid(sample,name):
    p,errors=person({**sample,'nazwisko':name})
    assert p['nazwisko']==name and errors

def test_identifiers_are_never_repaired(sample):
    p,errors=person({**sample,'id':'ID\x8c','pesel':'\x8c'+sample['pesel'][1:]})
    assert p['id']=='ID\x8c' and p['pesel'].startswith('\x8c') and errors

def test_import_repair_dedup_and_export(client,users,sample):
    raw=[{**sample,'id':'01','nazwisko':'CIE\x8cLA'},{**sample,'id':'02','nazwisko':'CIEŚLA'}]
    result=client.post('/api/import',files={'file':('synthetic.json',json.dumps(raw).encode(),'application/json')}).json();jid=result['job_id']
    mapped=client.post('/api/jobs/'+jid+'/mapping',json={'mapping':result['mapping']}).json()
    assert mapped['invalid']==0 and mapped['duplicates']==1 and mapped['encoding_fixed']==1
    rows=client.get('/api/jobs/'+jid+'/rows').json()['items']
    assert [r['nazwisko'] for r in rows]==['CIEŚLA']*2
    assert rows[0]['encoding_repairs'] and not rows[1]['encoding_repairs']
    with session() as db:
        first=db.scalar(select(Row).where(Row.job_id==jid,Row.position==1))
        assert unseal(first.raw)['nazwisko']=='CIE\x8cLA'
        s=db.get(Search,first.search_id);s.state='not_found';s.result=seal({'status':'not_found','ade':None});db.get(Job,jid).state='completed'
    exported=client.post('/api/jobs/'+jid+'/export',json={'format':'json','variant':'all'})
    assert exported.status_code==200 and 'Automatycznie naprawiono kodowanie' in exported.text
    assert 'CIEŚLA' in exported.text and '\\u008c' not in exported.text

def legacy(users,sample):
    with session() as db:
        j=Job(id=uid(),owner_id=users[0].id,label=seal('Legacy encoding QA'),state='completed',kind='bulk',total=3);db.add(j);db.flush();jid=j.id
        for i,(name,state) in enumerate([('CIE\x8cLA','invalid'),('CIE.LA','invalid'),('POPRAWNA','found')],1):
            p={**sample,'id':str(i),'nazwisko':name};s=Search(id=uid(),job_id=jid,fingerprint=fingerprint(p,['old invalid'] if state=='invalid' else []),payload=seal(p),state=state,result=seal({'status':state,'ade':None}));db.add(s);db.flush()
            db.add(Row(job_id=jid,position=i,raw=seal(p),person=seal(p),search_id=s.id))
        return jid

def test_retry_repairs_legacy_invalid_only(client,users,sample,monkeypatch):
    jid=legacy(users,sample);monkeypatch.setattr(api,'readiness',lambda cfg:{'ready':True})
    r=client.post('/api/jobs/'+jid+'/action',json={'action':'retry_errors'});assert r.status_code==200,r.text
    rows=client.get('/api/jobs/'+jid+'/rows').json()['items']
    assert [(r['nazwisko'],r['status']) for r in rows]==[('CIEŚLA','pending'),('CIE.LA','invalid'),('POPRAWNA','found')]
    assert rows[0]['encoding_repairs']

def test_manual_verify_and_edit_repair(client,users,sample,monkeypatch):
    monkeypatch.setattr(api,'readiness',lambda cfg:{'ready':True})
    r=client.post('/api/verify',json={**sample,'nazwisko':'CIE\x8cLA'});assert r.status_code==200,r.text
    jid=r.json()['job_id'];row=client.get('/api/jobs/'+jid+'/rows').json()['items'][0]
    assert row['nazwisko']=='CIEŚLA' and row['encoding_repairs']
    with session() as db:db.get(Job,jid).state='paused'
    r=client.put('/api/jobs/'+jid+'/rows/'+row['row_id'],json={'person':{**sample,'nazwisko':'CIEŚLA'},'note':'QA','review':False})
    assert r.status_code==200,r.text
    assert client.get('/api/jobs/'+jid+'/rows').json()['items'][0]['encoding_repairs']

def test_selected_retry_repairs_only_selected(client,users,sample,monkeypatch):
    jid=legacy(users,sample);monkeypatch.setattr(api,'readiness',lambda cfg:{'ready':True})
    rows=client.get('/api/jobs/'+jid+'/rows').json()['items']
    r=client.post('/api/jobs/'+jid+'/selection',json={'action':'retry','ids':[rows[0]['row_id']]});assert r.status_code==200,r.text
    changed=client.get('/api/jobs/'+jid+'/rows').json()['items']
    assert changed[0]['status']=='pending' and changed[0]['nazwisko']=='CIEŚLA'
    assert changed[1]['status']=='invalid' and changed[2]['status']=='found'
