import io,json,pyotp
from sqlalchemy import select
from openpyxl import load_workbook
from pypdf import PdfReader
from app import api,security
from app.db import session,Job,Search,Row,User
from app.security import seal,unseal
from app.exporter import safe_cell

def imported(client,sample):
    payload=[{**sample,'id':'0001'},{**sample,'id':'0002'}]
    r=client.post('/api/import',files={'file':('test.json',json.dumps(payload).encode(),'application/json')})
    assert r.status_code==200,r.text
    d=r.json();jid=d['job_id']
    r=client.post('/api/jobs/'+jid+'/mapping',json={'mapping':d['mapping']})
    assert r.status_code==200,r.text
    return jid

def test_full_local_flow_and_exports(client,sample):
    jid=imported(client,sample)
    assert client.post('/api/jobs/'+jid+'/action',json={'action':'start'}).status_code==503
    r=client.get('/api/jobs/'+jid+'/rows').json()
    assert r['total']==2 and r['items'][0]['pesel'].startswith('*******')
    assert r['items'][0]['id']=='0001' and r['items'][1]['id']=='0002'
    for fmt in ['csv','json','xlsx','pdf']:
        e=client.post('/api/jobs/'+jid+'/export',json={'format':fmt,'sensitive':True})
        assert e.status_code==200,e.text[:200]
        if fmt=='json':assert [r['id'] for r in e.json()]==['0001','0002']
        elif fmt=='csv':assert sample['pesel'] in e.text and '0002' in e.text
        elif fmt=='xlsx':
            wb=load_workbook(io.BytesIO(e.content));assert wb.active['A2'].value=='0001' and wb.active['A3'].value=='0002'
            assert wb.active['A2'].data_type=='s'
        else:
            text=PdfReader(io.BytesIO(e.content)).pages[0].extract_text();assert 'Liczba wierszy w zestawieniu: 2' in text
    with session() as db:
        j=db.get(Job,jid);s=db.scalar(select(Search).where(Search.job_id==jid))
        assert sample['pesel'] not in s.payload


def test_access_isolation_roles_and_csrf(client,users,sample):
    jid=imported(client,sample)
    api.app.dependency_overrides[security.current_user]=lambda:users[1]
    assert client.get('/api/jobs/'+jid).status_code==404
    assert client.post('/api/jobs/'+jid+'/export',json={'format':'json'}).status_code==404
    assert client.get('/api/admin/config').status_code==403
    api.app.dependency_overrides[security.current_user]=lambda:users[3]
    assert client.post('/api/verify',json=sample).status_code==403
    assert client.post('/api/jobs/'+jid+'/export',json={'format':'json','sensitive':True}).status_code==403
    api.app.dependency_overrides.clear()
    assert client.get('/api/jobs').status_code==401
    assert client.post('/api/auth/login',json={'username':'x','password':'x'},headers={'Origin':'https://evil.example'}).status_code==403


def test_mfa_enrollment_login_csrf_and_replay(client,users):
    api.app.dependency_overrides.clear()
    body={'username':users[0].username,'password':'Synthetic-test-pass-123','code':''}
    assert client.post('/api/auth/login',json=body).status_code==403
    r=client.post('/api/auth/enroll',json=body);assert r.status_code==200
    secret=r.json()['secret'];body['code']=pyotp.TOTP(secret).now()
    assert client.post('/api/auth/enroll',json=body).status_code==200
    login=client.post('/api/auth/login',json=body);assert login.status_code==200,login.text
    csrf=login.json()['csrf'];assert 'HttpOnly' in login.headers['set-cookie']
    assert client.get('/api/auth/me').status_code==200
    assert client.post('/api/auth/logout').status_code==403
    assert client.post('/api/auth/login',json=body).status_code==401 # OTP replay
    assert client.post('/api/auth/logout',headers={'X-CSRF-Token':csrf}).status_code==200
    assert client.get('/api/jobs').status_code==401


def test_validation_error_does_not_echo_secrets(client):
    r=client.post('/api/verify',json={'pesel':'synthetic-secret-input-too-long'})
    assert r.status_code==422 and 'synthetic-secret' not in r.text


def test_masked_export_and_spreadsheet_injection(client,sample):
    jid=imported(client,sample)
    e=client.post('/api/jobs/'+jid+'/export',json={'format':'json'});assert sample['pesel'] not in e.text
    assert safe_cell('=2+2')=="'=2+2"
    assert safe_cell('  @SUM(A1)')=="'  @SUM(A1)"
    assert safe_cell('000012')=='000012'
    e=client.post('/api/jobs/'+jid+'/export',json={'format':'csv','fields':[['id','=evil']]});assert "'=evil" in e.text


def test_manual_review_export_filter(client,sample):
    jid=imported(client,sample);r=client.get('/api/jobs/'+jid+'/rows').json()['items'][0]
    client.post('/api/jobs/'+jid+'/selection',json={'ids':[r['row_id']],'action':'review'})
    e=client.post('/api/jobs/'+jid+'/export',json={'format':'json','variant':'review'})
    assert len(e.json())==1 and e.json()[0]['status']=='review'
