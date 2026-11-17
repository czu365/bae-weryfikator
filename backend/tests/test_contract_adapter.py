import json,copy,httpx,pytest
from app.adapter import build_request,interpret,contract,BaeError,SEAdapter,retry_seconds,DEFAULTS

ADE='AE:PL-00000-00000-TESTA-00'
def response(p):return {'totalResults':1,'baeSearchResponses':[{'recipientEda':{'recipientEda':ADE,'assignmentDegree':'3','edaStatus':'ACTIVE','designatedOperator':True},'baeSearchData':[{'index':1,'isPublic':False,'name':p['imie'],'surname':p['nazwisko'],'officialIds':[{'referenceRegistry':'pesel','id':p['pesel']}]}]}]}

def test_official_contract_request_and_response(sample):
    cfg={**DEFAULTS,'sender_eda':ADE}
    body=build_request(sample,cfg)
    assert contract.doc['info']['version']=='4.0.5'
    assert body['officialIds']==[{'referenceRegistry':'pesel','id':sample['pesel']}]
    assert body['searchCategory']==['INDIVIDUAL']
    assert interpret(response(sample),sample)['status']=='found'
    assert interpret({'totalResults':0,'baeSearchResponses':[]},sample)['status']=='not_found'

def test_address_request(sample):
    p={**sample,'pesel':'','ulica':'Testowa','nr_budynku':'01','nr_lokalu':'02','kod_pocztowy':'00-000','miejscowosc':'Testowo','kraj':'PL'}
    body=build_request(p,{**DEFAULTS,'sender_eda':ADE})
    assert body['address'][0]['buildingNumber']=='01'
    assert 'officialIds' not in body

@pytest.mark.parametrize('change',[lambda r:r['baeSearchResponses'][0]['recipientEda'].update(edaStatus='STRUCK_OFF'),lambda r:r['baeSearchResponses'][0]['recipientEda'].update(assignmentDegree='2'),lambda r:r.update(totalResults=2),lambda r:r['baeSearchResponses'][0]['baeSearchData'][0].update(name='Inna'),lambda r:r['baeSearchResponses'][0]['recipientEda'].update(warning={'type':'BLOCK_WARNING'})])
def test_unsafe_matches_are_manual(sample,change):
    r=response(sample);change(r);assert interpret(r,sample)['status']=='ambiguous'

@pytest.mark.parametrize('r',[{}, {'totalResults':0}, {'totalResults':1,'baeSearchResponses':[]}, {'totalResults':0,'baeSearchResponses':[{}]}, {'totalResults':-1,'baeSearchResponses':[]}])
def test_malformed_never_not_found(sample,r):
    with pytest.raises(BaeError):interpret(r,sample)

@pytest.mark.parametrize('status,expected,retry',[(401,'unauthorized',False),(403,'unauthorized',False),(429,'technical_error',True),(503,'technical_error',True),(400,'invalid',False),(302,'technical_error',False)])
def test_http_semantics(sample,status,expected,retry):
    a=SEAdapter(DEFAULTS,transport=httpx.MockTransport(lambda r:httpx.Response(status,json={},headers={'Retry-After':'120'})))
    a.token=lambda:'synthetic-token'
    with pytest.raises(BaeError) as e:a.search(sample)
    assert e.value.status==expected and e.value.retry==retry
    if retry:assert e.value.retry_after==120
    a.close()

def test_transport_failure(sample):
    def fail(r):raise httpx.ConnectError('synthetic connection failure')
    a=SEAdapter(DEFAULTS,transport=httpx.MockTransport(fail));a.token=lambda:'test'
    with pytest.raises(BaeError) as e:a.search(sample)
    assert e.value.retry and e.value.status=='technical_error';a.close()

def test_success_does_not_invent_query_id(sample):
    a=SEAdapter(DEFAULTS,transport=httpx.MockTransport(lambda r:httpx.Response(200,json=response(sample))))
    a.token=lambda:'synthetic';result=a.search(sample);assert result['request_id'] is None and result['source'].endswith('INT');a.close()


@pytest.mark.parametrize('field',['isMainEda','dateOfEnteringToBAE','dateOfRemovalFromBAE','warning','additionalServiceOW'])
def test_prod_null_optional_recipient_metadata(sample,field):
    data=response(sample);data['baeSearchResponses'][0]['recipientEda'][field]=None
    before=copy.deepcopy(data)
    assert interpret(data,sample)['status']=='found'
    assert data==before # Original provider response is never modified.


def test_prod_all_optional_metadata_null_and_numeric_degree(sample):
    data=response(sample);recipient=data['baeSearchResponses'][0]['recipientEda']
    recipient.update(isMainEda=None,dateOfEnteringToBAE=None,dateOfRemovalFromBAE=None,warning=None,additionalServiceOW=None,assignmentDegree=3)
    assert interpret(data,sample)['status']=='found'


@pytest.mark.parametrize('field',['recipientEda','assignmentDegree','edaStatus'])
def test_required_recipient_null_is_still_rejected(sample,field):
    data=response(sample);data['baeSearchResponses'][0]['recipientEda'][field]=None
    with pytest.raises(BaeError):interpret(data,sample)


@pytest.mark.parametrize('value',['false','true',0,1,{},[]])
def test_nonboolean_is_main_eda_is_still_rejected(sample,value):
    data=response(sample);data['baeSearchResponses'][0]['recipientEda']['isMainEda']=value
    with pytest.raises(BaeError):interpret(data,sample)


@pytest.mark.parametrize('value',[False,True])
def test_real_boolean_is_main_eda_remains_valid(sample,value):
    data=response(sample);data['baeSearchResponses'][0]['recipientEda']['isMainEda']=value
    assert interpret(data,sample)['status']=='found'


@pytest.mark.parametrize('change',[
    lambda e:e.update(edaStatus='STRUCK_OFF'),
    lambda e:e.update(assignmentDegree=2),
    lambda e:e.update(dateOfRemovalFromBAE='2026-01-01'),
    lambda e:e.update(warning={'type':'BLOCK_WARNING'})])
def test_null_metadata_does_not_bypass_recipient_safety(sample,change):
    data=response(sample);recipient=data['baeSearchResponses'][0]['recipientEda'];recipient['isMainEda']=None;change(recipient)
    assert interpret(data,sample)['status']=='ambiguous'


@pytest.mark.parametrize('field',['professionalTitle','legalForm','entityName','nipStatus','address','officialIds'])
def test_nested_optional_person_nulls_are_absent(sample,field):
    data=response(sample);data['baeSearchResponses'][0]['baeSearchData'][0][field]=None
    assert interpret(data,sample)['status']=='found'


def test_optional_address_nulls_are_absent(sample):
    data=response(sample)
    data['baeSearchResponses'][0]['baeSearchData'][0]['address']=[{'addressType':['correspondence'],'countryCode':'PL','city':'Testowo','street':None,'flatNumber':None,'postalOffice':None}]
    assert interpret(data,sample)['status']=='found'


def test_required_nested_null_remains_error_and_diagnostics_contain_no_values(sample):
    data=response(sample);person=data['baeSearchResponses'][0]['baeSearchData'][0];person['isPublic']=None;person['name']='SYNTHETIC-PRIVATE-MARKER'
    with pytest.raises(BaeError) as caught:interpret(data,sample)
    assert caught.value.diagnostics[0]['path']=='baeSearchResponses/0/baeSearchData/0/isPublic'
    assert caught.value.diagnostics[0]['expected_type']=='boolean'
    assert 'SYNTHETIC-PRIVATE-MARKER' not in json.dumps(caught.value.diagnostics)


def test_warning_object_cannot_be_erased_into_false_success(sample):
    data=response(sample)
    data['baeSearchResponses'][0]['recipientEda']['warning']={'code':None,'type':None,'description':None}
    assert interpret(data,sample)['status']=='ambiguous'


def test_production_shaped_nulls_through_http_adapter(sample):
    data=response(sample)
    recipient=data['baeSearchResponses'][0]['recipientEda']
    recipient.update(isMainEda=None,assignmentDegree=3,dateOfEnteringToBAE='2026-01-01',dateOfRemovalFromBAE=None,additionalServiceOW=None,warning=None)
    person=data['baeSearchResponses'][0]['baeSearchData'][0]
    person.update(professionalTitle=None,legalForm=None,entityName=None,nipStatus=None)
    person['address']=[{'addressType':['correspondence'],'countryCode':'PL','city':'Testowo','street':None,'typeOfStreet':None,'postalCode':None,'buildingNumber':None,'flatNumber':None,'postalOffice':None,'postOfficeBox':None,'voivodeship':None,'district':None,'community':None}]
    a=SEAdapter(DEFAULTS,transport=httpx.MockTransport(lambda request:httpx.Response(200,json=data)))
    a.token=lambda:'SYNTHETIC-TEST-TOKEN'
    try:assert a.search(sample)['status']=='found'
    finally:a.close()
