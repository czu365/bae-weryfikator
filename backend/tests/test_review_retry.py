import copy,pytest
from sqlalchemy import select
from app import api,security,worker
from app.db import session,Job,Row,Search,User,now
from app.security import unseal
from app.adapter import interpret
from test_contract_adapter import response,ADE
from test_records import seed
from test_queue import TestAdapter,enable

@pytest.mark.parametrize('field,value,code',[
    ('edaStatus','STRUCK_OFF','ade_not_active'),('assignmentDegree','2','assignment_degree'),
    ('dateOfRemovalFromBAE','2026-01-01','removal_date'),('warning',{},'bae_warning'),
    ('designatedOperator',None,'operator_unknown')])
def test_exact_metadata_review_reason(sample,field,value,code):
    data=response(sample);data['baeSearchResponses'][0]['recipientEda'][field]=value;before=copy.deepcopy(data)
    result=interpret(data,sample)
    assert result['status']=='ambiguous' and result['ade']==ADE
    assert [r['code'] for r in result['review_reasons']]==[code] and data==before

def test_all_identity_reasons_and_no_values_in_diagnostics(sample):
    data=response(sample);p=data['baeSearchResponses'][0]['baeSearchData'][0]
    p.update(name='INNA',surname='INNE');p['officialIds'][0]['id']='11111111111'
    result=interpret(data,sample)
    assert {r['code'] for r in result['review_reasons']}=={'name_mismatch','surname_mismatch','pesel_mismatch'}
    assert not any(value in str(result['review_reasons']) for value in [sample['pesel'],'11111111111','INNA','INNE'])

def test_multiple_review_reasons_and_missing_current_identity(sample):
    data=response(sample);data['baeSearchResponses'][0]['baeSearchData'][0]['index']=2
    data['baeSearchResponses'][0]['recipientEda'].update(designatedOperator=None,assignmentDegree='2')
    result=interpret(data,sample)
    assert {r['code'] for r in result['review_reasons']}=={'current_identity','operator_unknown','assignment_degree'}

def test_retry_review_only_targets_review_and_errors(client,users,sample,monkeypatch):
    jid=seed(users[0],sample,['found','found','not_found','ambiguous','technical_error','unauthorized','invalid','pending'],[1])
    with session() as db:db.get(Job,jid).state='completed'
    monkeypatch.setattr(api,'readiness',lambda cfg:{'ready':True})
    r=client.post('/api/jobs/'+jid+'/action',json={'action':'retry_review'});assert r.status_code==200,r.text
    assert r.json()['requeued']==4
    with session() as db:
        pairs=db.execute(select(Row,Search).join(Search,Row.search_id==Search.id).where(Row.job_id==jid).order_by(Row.position)).all()
        assert [s.state for row,s in pairs]==['pending','found','not_found','pending','pending','pending','invalid','pending']
        assert [s.scheduled for row,s in pairs]==[True,False,False,True,True,True,True,False]
        assert pairs[0][0].review
    enable(monkeypatch)
    for _ in range(4):assert worker.tick(TestAdapter)
    assert not worker.tick(TestAdapter)
    assert client.get('/api/jobs/'+jid).json()['state']=='paused' # Other pending rows remain deferred.

def test_active_or_inflight_recheck_is_blocked(client,users,sample,monkeypatch):
    jid=seed(users[0],sample,['ambiguous']);monkeypatch.setattr(api,'readiness',lambda cfg:{'ready':True})
    for state in ['running','queued','draft']:
        with session() as db:db.get(Job,jid).state=state
        assert client.post('/api/jobs/'+jid+'/action',json={'action':'retry_review'}).status_code==409
    with session() as db:
        db.get(Job,jid).state='paused';s=db.scalar(select(Search).where(Search.job_id==jid));s.state='running';s.lease_until=now()+60
    assert client.post('/api/jobs/'+jid+'/action',json={'action':'retry_review'}).status_code==409

def test_retry_review_permission_enforced(client,users,sample,monkeypatch):
    jid=seed(users[0],sample,['ambiguous']);monkeypatch.setattr(api,'readiness',lambda cfg:{'ready':True})
    with session() as db:
        j=db.get(Job,jid);j.kind='bulk';j.state='completed';db.get(User,users[0].id).bulk_allowed=False
    api.app.dependency_overrides[security.current_user]=lambda:users[1]
    assert client.post('/api/jobs/'+jid+'/action',json={'action':'retry_review'}).status_code==404
    api.app.dependency_overrides[security.current_user]=lambda:users[3]
    assert client.post('/api/jobs/'+jid+'/action',json={'action':'retry_review'}).status_code==403
    with session() as db:u=db.get(User,users[0].id)
    api.app.dependency_overrides[security.current_user]=lambda:u
    assert client.post('/api/jobs/'+jid+'/action',json={'action':'retry_review'}).status_code==403

def test_completed_review_retry_finishes_without_loop(client,users,sample,monkeypatch):
    jid=seed(users[0],sample,['ambiguous','found'])
    with session() as db:db.get(Job,jid).state='completed'
    monkeypatch.setattr(api,'readiness',lambda cfg:{'ready':True})
    assert client.post('/api/jobs/'+jid+'/action',json={'action':'retry_review'}).json()['requeued']==1
    enable(monkeypatch);assert worker.tick(TestAdapter);assert not worker.tick(TestAdapter)
    assert client.get('/api/jobs/'+jid).json()['state']=='completed'

def test_review_retry_repairs_legacy_encoding_without_rechecking_good_rows(client,users,sample,monkeypatch):
    from test_encoding_repair import legacy
    jid=legacy(users,sample);monkeypatch.setattr(api,'readiness',lambda cfg:{'ready':True})
    r=client.post('/api/jobs/'+jid+'/action',json={'action':'retry_review'})
    assert r.status_code==200 and r.json()['requeued']==1,r.text
    rows=client.get('/api/jobs/'+jid+'/rows').json()['items']
    assert [(r['nazwisko'],r['status']) for r in rows]==[('CIEŚLA','pending'),('CIE.LA','invalid'),('POPRAWNA','found')]
