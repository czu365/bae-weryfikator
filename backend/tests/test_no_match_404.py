"""SE V4 documented no-match code vs generic HTTP/proxy/token failures."""
import json,httpx,pytest
from sqlalchemy import select
from app import worker,adapter,api
from app.adapter import SEAdapter,DEFAULTS,BaeError
from app.db import session,Search,Job,Attempt
from app.security import unseal
from test_contract_adapter import response
from test_queue import setup_job,enable

EVENT='12345678-1234-4234-8234-123456789abc'
def envelope(*codes,http_code='404'):
    return {'httpCode':http_code,'id':EVENT,'errorCodes':[{'errorCode':c,'language':'EN','message':'No results found. Please apply less strict criteria.'} for c in codes]}


def search_reply(sample,status=404,body=None,content=None,**kwargs):
    def reply(request):
        assert request.url.path=='/api/se/v4/search/bae_search'
        if content is not None:return httpx.Response(status,content=content,**kwargs)
        return httpx.Response(status,json=body,**kwargs)
    instance=SEAdapter(DEFAULTS,transport=httpx.MockTransport(reply));instance.token=lambda:'SYNTHETIC-TOKEN'
    try:return instance.search(sample)
    finally:instance.close()


def test_documented_404_means_no_match(sample):
    result=search_reply(sample,body=envelope('SEAPI-00010'))
    assert result['status']=='not_found' and result['ade'] is None
    assert result['request_id']==EVENT and result['response_code']=='SEAPI-00010'
    assert 'error_code' not in result and 'diagnostics' not in result
    assert result['source']=='SE API 4.0.5 / INT'


@pytest.mark.parametrize('code,status',[('SEAPI-00011','unauthorized'),('SEAPI-00014','invalid'),('SEAPI-00015','invalid'),('SEAPI-99999','technical_error')])
def test_other_se_404_codes_never_become_no_match(sample,code,status):
    with pytest.raises(BaeError) as caught:search_reply(sample,body=envelope(code))
    assert caught.value.status==status and caught.value.code==code


@pytest.mark.parametrize('body',[{},None,[],{'status':404,'error':'Not Found','path':'/wrong/path'},envelope('SEAPI-00010',http_code='200'),{'httpCode':'404','id':EVENT,'errorCodes':[]}, {'httpCode':'404','id':EVENT,'errorCodes':[{'errorCode':'SEAPI-00010'}]}])
def test_unrecognized_or_malformed_404_is_technical(sample,body):
    with pytest.raises(BaeError) as caught:search_reply(sample,body=body)
    assert caught.value.status=='technical_error' and caught.value.code=='http_404'
    assert caught.value.diagnostics


def test_html_proxy_404_is_technical_and_does_not_expose_content(sample):
    with pytest.raises(BaeError) as caught:search_reply(sample,content=b'<html>SYNTHETIC-SENSITIVE-MARKER</html>')
    assert caught.value.code=='http_404'
    assert 'SYNTHETIC-SENSITIVE-MARKER' not in str(caught.value)+json.dumps(caught.value.diagnostics)


@pytest.mark.parametrize('codes',[('SEAPI-00010','SEAPI-00011'),('SEAPI-00010','SEAPI-00014'),('SEAPI-00010','UNKNOWN-CODE')])
def test_mixed_no_match_and_other_error_never_becomes_no_match(sample,codes):
    with pytest.raises(BaeError):search_reply(sample,body=envelope(*codes))


def test_successful_200_found_and_empty_are_unchanged(sample):
    assert search_reply(sample,status=200,body=response(sample))['status']=='found'
    assert search_reply(sample,status=200,body={'totalResults':0,'baeSearchResponses':[]})['status']=='not_found'


def test_no_match_http_to_worker_results_and_exports(client,users,sample,monkeypatch):
    jid=setup_job(users,sample);enable(monkeypatch)
    class NoMatch(SEAdapter):
        def __init__(self,cfg):
            super().__init__(cfg,transport=httpx.MockTransport(lambda request:httpx.Response(404,json=envelope('SEAPI-00010'))))
            self.token=lambda:'SYNTHETIC-TOKEN'
    assert worker.tick(NoMatch)
    job=client.get('/api/jobs/'+jid).json();row=client.get('/api/jobs/'+jid+'/rows').json()['items'][0]
    assert job['state']=='completed' and job['counts']['not_found']==1 and not job['counts'].get('technical_error')
    assert row['status']=='not_found' and row['ade'] is None and row['error_code']=='' and row['diagnostics']==[]
    assert client.get('/api/stats').json()['counts']['not_found']==1
    exported=client.post('/api/jobs/'+jid+'/export',json={'format':'json','variant':'not_found'})
    assert exported.status_code==200 and len(exported.json())==1
    assert exported.json()[0]['status']=='not_found'
    with session() as db:
        attempt=db.scalar(select(Attempt).where(Attempt.job_id==jid))
        assert attempt.state=='not_found' and unseal(attempt.result)['response_code']=='SEAPI-00010'


def test_token_404_is_never_a_negative_search_result(sample):
    def unexpected(request):raise AssertionError('Token failure must prevent the search request')
    instance=SEAdapter(DEFAULTS,transport=httpx.MockTransport(unexpected))
    def missing_token():
        instance.check_http(httpx.Response(404,json=envelope('SEAPI-00010')))
    instance.token=missing_token
    try:
        with pytest.raises(BaeError) as caught:instance.search(sample)
        assert caught.value.status=='technical_error'
    finally:instance.close()
