import copy,pytest
from app.adapter import interpret,BaeError
from test_contract_adapter import response,ADE

def test_null_provider_keeps_candidate_and_requires_review(sample):
    body=response(sample);body['baeSearchResponses'][0]['recipientEda']['designatedOperator']=None
    before=copy.deepcopy(body);result=interpret(body,sample)
    assert result['status']=='ambiguous' and result['ade']==ADE
    assert result['designated_operator'] is None and 'designatedOperator=null' in result['note']
    assert not result.get('error_code') and body==before

@pytest.mark.parametrize('value',['true','false',0,1,{},[]])
def test_bad_nonnull_provider_type_is_still_rejected(sample,value):
    body=response(sample);body['baeSearchResponses'][0]['recipientEda']['designatedOperator']=value
    with pytest.raises(BaeError):interpret(body,sample)

def test_missing_provider_is_still_rejected(sample):
    body=response(sample);del body['baeSearchResponses'][0]['recipientEda']['designatedOperator']
    with pytest.raises(BaeError):interpret(body,sample)

@pytest.mark.parametrize('value',[True,False])
def test_boolean_provider_is_unchanged(sample,value):
    body=response(sample);body['baeSearchResponses'][0]['recipientEda']['designatedOperator']=value
    assert interpret(body,sample)['status']=='found'

def test_unknown_provider_never_bypasses_essential_validation(sample):
    body=response(sample);body['baeSearchResponses'][0]['recipientEda'].update(designatedOperator=None,edaStatus=None)
    with pytest.raises(BaeError):interpret(body,sample)

def test_unknown_provider_worker_filters_and_export(client,users,sample,monkeypatch):
    from app import worker
    from test_queue import setup_job,enable,TestAdapter
    jid=setup_job(users,sample);enable(monkeypatch)
    body=response(sample);body['baeSearchResponses'][0]['recipientEda']['designatedOperator']=None
    class Adapter(TestAdapter):
        def search(self,p):return interpret(body,p)
    assert worker.tick(Adapter)
    job=client.get('/api/jobs/'+jid).json()
    assert job['state']=='completed' and job['counts']=={'ambiguous':1}
    records=client.get('/api/records?status=needs_review').json()
    assert records['total']==1 and records['items'][0]['ade']==ADE
    assert records['items'][0]['error_code']==''
    exported=client.post('/api/jobs/'+jid+'/export',json={'format':'json','variant':'review'})
    assert exported.status_code==200 and 'designatedOperator=null' in exported.text
