"""SE API 4.0.5. No runtime mock, no success fallback."""
import datetime, hashlib, json, math, re, time, uuid, threading
from pathlib import Path
from email.utils import parsedate_to_datetime
import httpx, jwt, yaml
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from jsonschema import Draft4Validator, ValidationError
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT4
from .config import settings
from .security import cache, seal, unseal
from .db import Config

PATH='/search/bae_search'
HOSTS={'INT':'https://int-ow.edoreczenia.gov.pl','PROD':'https://ow.edoreczenia.gov.pl'}
DEFAULTS={'environment':'INT','sender_eda':'','system_name':'','audience':'','login_hint':'',
          'max_concurrency':1,'requests_per_second':0.5,'limits_confirmed':False,'enabled':False,'retention_days':30,'audit_days':365}

def configuration(db):
    row=db.get(Config,'connection')
    return {**DEFAULTS,**(unseal(row.value) if row else {})}

# Cache only the checked public certificate, never private-key bytes or objects.
# File identity is checked on every call; key-pair verification repeats at most
# every 30 seconds while unchanged. Date validity is always evaluated anew.
_certificate_cache={}
_certificate_lock=threading.Lock()
CERTIFICATE_CACHE_SECONDS=30

def _certificate_signature(paths):
    result=[]
    for path in paths:
        st=path.stat()
        result.append((str(path),st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns))
    return tuple(result)

def certificate_info(env):
    try:
        paths=(Path(settings().cert_files[env]),Path(settings().key_files[env]))
        with _certificate_lock:
            signature=_certificate_signature(paths)
            cached=_certificate_cache.get(env)
            if cached and cached[0]==signature and time.monotonic()-cached[1]<CERTIFICATE_CACHE_SECONDS:
                cert=cached[2]
            else:
                cert=x509.load_pem_x509_certificate(paths[0].read_bytes())
                key=serialization.load_pem_private_key(paths[1].read_bytes(),password=None)
                if not isinstance(key,RSAPrivateKey) or key.key_size<2048:return {'ready':False,'issue':'Wymagany klucz RSA o długości co najmniej 2048 bitów'}
                if key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)!=cert.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo):
                    return {'ready':False,'issue':'Certyfikat i klucz prywatny nie są parą'}
                if _certificate_signature(paths)!=signature:raise ValueError('certificate_changed_during_read')
                _certificate_cache[env]=(signature,time.monotonic(),cert)
        t=datetime.datetime.now(datetime.timezone.utc)
        valid=cert.not_valid_before_utc<=t<cert.not_valid_after_utc
        return {'ready':valid,'expires':cert.not_valid_after_utc.isoformat(),'issue':'' if valid else 'Certyfikat nieważny'}
    except Exception:
        return {'ready':False,'issue':'Brak lub nieprawidłowy certyfikat / klucz RSA w magazynie sekretów'}

def readiness(cfg,*,authentication_only=False):
    missing=[]
    for k in ['sender_eda','system_name','audience','login_hint']:
        if not cfg.get(k):missing.append(k)
    if not authentication_only:
        if not cfg['enabled']:missing.append('Połączenie wyłączone')
        if not cfg['limits_confirmed']:missing.append('Potwierdzenie limitu przez administratora')
    cert=certificate_info(cfg['environment'])
    if not cert['ready']:missing.append(cert['issue'])
    return {'ready':not missing,'missing':missing,'certificate':cert,'api_version':'4.0.5',
            'environment':cfg['environment'],'base_url':HOSTS[cfg['environment']]+'/api/se/v4'}

class BaeError(Exception):
    def __init__(self,status='technical_error',code='transport',retry=False,retry_after=0,request_id=None,diagnostics=None):
        self.status=status;self.code=code;self.retry=retry;self.retry_after=retry_after;self.request_id=request_id;self.diagnostics=diagnostics or []
        super().__init__(code)

def retry_seconds(value):
    try:return max(0,float(value))
    except (ValueError,TypeError):
        try:return max(0,parsedate_to_datetime(value).timestamp()-time.time())
        except (ValueError,TypeError):return 0

class Contract:
    def __init__(self,path=None):
        self.doc=yaml.safe_load(Path(path or settings().contract).read_text())
        if self.doc['info']['version']!='4.0.5' or PATH not in self.doc['paths']:raise RuntimeError('Nieobsługiwana wersja adaptera SE API')
    def validator(self,schema):
        # Published contract has type:string with numeric enum values for assignmentDegree.
        # Normalize a working copy of that enum only; preserve the official file byte-for-byte.
        doc=json.loads(json.dumps(self.doc))
        doc['components']['schemas']['AssignmentDegreeEnum']['enum']=['0','1','2','3']
        registry=Registry().with_resource('urn:bae:se4',Resource(contents=doc,specification=DRAFT4))
        return Draft4Validator({'$ref':'urn:bae:se4#/components/schemas/'+schema},registry=registry)

    def validate(self,value,schema):
        self.validator(schema).validate(value)

contract=Contract()

def build_request(p,cfg):
    body={'recipientEdasOnly':False,'senderEda':cfg['sender_eda'],'searchCategory':['INDIVIDUAL'],
          'name':p['imie'],'surname':p['nazwisko'],'offset':0,'limit':2}
    if p['pesel']:body['officialIds']=[{'referenceRegistry':'pesel','id':p['pesel']}]
    else:
        body['address']=[{k:p[f] for k,f in [('countryCode','kraj'),('city','miejscowosc'),('postalCode','kod_pocztowy'),('street','ulica'),('buildingNumber','nr_budynku'),('flatNumber','nr_lokalu')] if p[f]}]
    contract.validate(body,'BaeSearch')
    return body

def normalize_response(value):
    """Remove only known optional null fields, following the response schema.

    Required fields remain mandatory, including nested identity/status fields.
    Unknown properties and incorrect non-null values are never coerced.
    """
    def walk(item, schema):
        if '$ref' in schema:
            schema=contract.doc['components']['schemas'][schema['$ref'].rsplit('/',1)[-1]]
        if isinstance(item,dict):
            properties=schema.get('properties',{});required=set(schema.get('required',[]))
            result={}
            for key,child in item.items():
                if key in properties:
                    if child is None and key not in required:continue
                    if schema is contract.doc['components']['schemas']['RecipientEda'] and key=='assignmentDegree' and type(child) is int:
                        child=str(child)
                    result[key]=walk(child,properties[key])
                else:result[key]=child
            return result
        if isinstance(item,list) and 'items' in schema:
            return [walk(child,schema['items']) for child in item]
        return item
    return walk(value,contract.doc['components']['schemas']['SearchResponse'])


def response_diagnostics(value,schema='SearchResponse'):
    # Paths contain schema field names only. Never serialize instance/message.
    names={key for definition in contract.doc['components']['schemas'].values()
           for key in definition.get('properties',{})}
    issues=[]
    for error in contract.validator(schema).iter_errors(value):
        path='/'.join(str(part) if isinstance(part,int) or part in names else '*' for part in error.absolute_path) or '(odpowiedź)'
        expected=error.validator_value if error.validator=='type' else None
        missing=[key for key in error.validator_value if isinstance(error.instance,dict) and key not in error.instance] if error.validator=='required' else []
        issues.append({'path':path,'rule':error.validator,'actual_type':type(error.instance).__name__,'expected_type':expected,'missing_fields':missing})
        if len(issues)>=10:break
    return issues


def interpret(data,p):
    try:
        normalized=normalize_response(data)
        issues=response_diagnostics(normalized)
        # A confirmed production deviation: null provider metadata is unknown,
        # never coerced to true/false. It can only yield a manual-review result.
        issues=[issue for issue in issues if not (
            re.fullmatch(r'baeSearchResponses/[0-9]+/recipientEda/designatedOperator',issue['path'])
            and issue['rule']=='type' and issue['actual_type']=='NoneType'
            and issue.get('expected_type')=='boolean')]
        if issues:raise BaeError(code='invalid_response',diagnostics=issues)
        missing=[key for key in ['baeSearchResponses','totalResults'] if key not in normalized]
        if missing:raise BaeError(code='invalid_response',diagnostics=[{'path':'(odpowiedź)','rule':'required','actual_type':type(normalized).__name__,'missing_fields':missing}])
        rows=normalized['baeSearchResponses'];count=normalized['totalResults']
        if type(count) is not int or count<0 or (count==0 and rows) or (count>0 and not rows):
            raise BaeError(code='invalid_response',diagnostics=[{'path':'totalResults/baeSearchResponses','rule':'consistency','actual_type':type(count).__name__}])
    except BaeError:raise
    except Exception:
        raise BaeError(code='invalid_response',diagnostics=[{'path':'(odpowiedź)','rule':'structure','actual_type':type(data).__name__}]) from None
    for index,row in enumerate(rows):
        if 'recipientEda' not in row:
            raise BaeError(code='invalid_response',diagnostics=[{'path':f'baeSearchResponses/{index}','rule':'required','actual_type':'dict','missing_fields':['recipientEda']}])
    if count==0:return {'status':'not_found','ade':None,'note':'Brak dopasowania dla podanych danych. Nie przesądza o braku adresu ADE.'}
    def review(ade,reasons):
        return {'status':'ambiguous','ade':ade,'review_reasons':[{'code':code,'label':label} for code,label in reasons],
                'note':' '.join(label for code,label in reasons)}
    if count!=1 or len(rows)!=1:return review(None,[('multiple_matches','BAE zwróciło wiele dopasowań. Wymagana ocena operatora.')])
    item=rows[0];e=item['recipientEda'];ade=e['recipientEda']
    if not isinstance(ade,str) or not re.fullmatch(r'AE:PL-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[0-9]{2}',ade):raise BaeError(code='invalid_ade')
    current=[r for r in item.get('baeSearchData',[]) if r.get('index')==1]
    from .security import normalize
    reasons=[]
    if len(current)!=1:
        reasons.append(('current_identity','BAE nie zwróciło dokładnie jednego aktualnego zestawu danych osoby (index=1).'))
    else:
        if normalize(current[0].get('name',''))!=normalize(p['imie']):
            reasons.append(('name_mismatch','Imię podane w zapytaniu różni się od aktualnego imienia zwróconego przez BAE.'))
        if normalize(current[0].get('surname',''))!=normalize(p['nazwisko']):
            reasons.append(('surname_mismatch','Nazwisko podane w zapytaniu różni się od aktualnego nazwiska zwróconego przez BAE (także spacja i łącznik są porównywane ściśle).'))
        if p['pesel']:
            ids=[i['id'] for i in current[0].get('officialIds',[]) if i.get('referenceRegistry')=='pesel']
            if ids and p['pesel'] not in ids:reasons.append(('pesel_mismatch','PESEL zwrócony przez BAE jest sprzeczny z podanym w zapytaniu.'))
    if e['edaStatus']!='ACTIVE':reasons.append(('ade_not_active','BAE nie oznaczyło adresu ADE jako ACTIVE (aktywnego).'))
    if e['assignmentDegree']!='3':reasons.append(('assignment_degree','BAE nie zwróciło wymaganego stopnia przypisania ADE: 3.'))
    if e.get('dateOfRemovalFromBAE'):reasons.append(('removal_date','BAE zwróciło datę usunięcia adresu z bazy.'))
    if e.get('warning') is not None:reasons.append(('bae_warning','BAE zwróciło ostrzeżenie dotyczące adresu. Wymagana ocena operatora.'))
    if e['designatedOperator'] is None:reasons.append(('operator_unknown','Odnaleziono ADE, ale BAE nie określiło operatora (designatedOperator=null). Wymagana ręczna kontrola przed wyborem kanału doręczenia.'))
    if reasons:
        result=review(ade,reasons)
        if e['designatedOperator'] is None:result['designated_operator']=None
        return result
    return {'status':'found','ade':ade,'note':'Aktywny, ujawniony adres ADE. Kandydat do doręczenia elektronicznego; kanał ustala operator.'}

def interpret_search_404(response):
    """SE V4: only SEAPI-00010 is an explicit no-match result.

    Other documented 404s include denied access (00011), bad limits (00014)
    and invalid offset (00015). Generic router/proxy 404s stay technical errors.
    See COI Search Engine V4, section 4.2 error messages.
    """
    try:body=response.json()
    except ValueError:
        raise BaeError(code='http_404',diagnostics=[{'path':'(odpowiedź HTTP 404)','rule':'json','actual_type':'not_json'}]) from None
    issues=response_diagnostics(body,'SearchEngineError')
    if issues:
        raise BaeError(code='http_404',diagnostics=issues)
    if body['httpCode']!='404':
        raise BaeError(code='http_404',diagnostics=[{'path':'httpCode','rule':'http_status_mismatch','actual_type':type(body['httpCode']).__name__}])
    codes=[entry['errorCode'] for entry in body['errorCodes']]
    # Retain only an opaque UUID event identifier, never free-text error content.
    try:request_id=str(uuid.UUID(body['id']))
    except (ValueError,TypeError,AttributeError):request_id=None
    if all(code=='SEAPI-00010' for code in codes):
        return {'status':'not_found','ade':None,
                'note':'Nie znaleziono ADE spełniającego podane kryteria. Zweryfikuj dane osoby; wynik nie przesądza o braku adresu.',
                'response_code':'SEAPI-00010','request_id':request_id}
    # Never let an additional error (especially 00011) turn into a negative match.
    safe_codes=[code for code in codes if re.fullmatch(r'SEAPI-[0-9]{5}',code)]
    if 'SEAPI-00011' in codes:
        status='unauthorized'
    elif codes and all(code in ['SEAPI-00014','SEAPI-00015'] for code in codes):
        status='invalid'
    else:status='technical_error'
    code=','.join(dict.fromkeys(safe_codes))[:79] or 'http_404'
    raise BaeError(status,code,request_id=request_id,
                   diagnostics=[{'path':'(odpowiedź HTTP 404)','rule':'upstream_error','actual_type':'dict'}])


class SEAdapter:
    def __init__(self,cfg,transport=None):
        self.cfg=cfg;self.env=cfg['environment'];self.host=HOSTS[self.env]
        self.before_search=None
        self.http=httpx.Client(timeout=httpx.Timeout(25,connect=8),follow_redirects=False,transport=transport)
    def close(self):self.http.close()
    def token(self):
        key='se-token:'+hashlib.sha256(json.dumps(self.cfg,sort_keys=True).encode()).hexdigest()
        value=cache.get(key)
        if value:return unseal(value)
        with cache.lock(key+':lock',timeout=40,blocking_timeout=45):
            value=cache.get(key)
            if value:return unseal(value)
            now=int(time.time()); identity=f"{self.cfg['sender_eda']}.SYSTEM.{self.cfg['system_name']}"
            claims={'aud':self.cfg['audience'],'exp':now+300,'iat':now,'nbf':now,'iss':identity,'sub':identity,'jti':str(uuid.uuid4())}
            assertion=jwt.encode(claims,Path(settings().key_files[self.env]).read_bytes(),algorithm='RS256')
            try:
                response=self.http.post(self.host+'/auth/realms/EDOR/protocol/openid-connect/token',params={'login_hint':self.cfg['login_hint']},
                    data={'client_assertion_type':'urn:ietf:params:oauth:client-assertion-type:jwt-bearer','grant_type':'client_credentials','client_assertion':assertion})
            except httpx.TimeoutException:
                raise BaeError(code='token_timeout',retry=True) from None
            except httpx.RequestError:
                raise BaeError(code='token_transport',retry=True) from None
            self.check_http(response)
            try:
                body=response.json(); value=body['access_token']; ttl=int(body['expires_in'])
                if not isinstance(value,str) or not value or ttl<=0:raise ValueError()
                cache.set(key,seal(value),ex=ttl) # never request another token before its announced expiry
                return value
            except Exception:raise BaeError(code='invalid_token_response')
    def check_http(self,r):
        if r.status_code in [401,403]:raise BaeError('unauthorized','http_'+str(r.status_code))
        if r.status_code in [429,500,502,503,504]:raise BaeError(code='http_'+str(r.status_code),retry=True,retry_after=retry_seconds(r.headers.get('retry-after')))
        if r.status_code==400:
            try:
                b=r.json();codes=[str(x['errorCode'])[:50] for x in b['errorCodes']]
                code=','.join(c for c in codes if re.fullmatch('[A-Z0-9_-]+',c)) or 'http_400'
                rid=b.get('id')
            except Exception:code='http_400';rid=None
            raise BaeError('invalid',code,request_id=rid)
        if r.status_code!=200:raise BaeError(code='http_'+str(r.status_code))
    def search(self,p):
        try:
            token=self.token()
            # Pace the actual search after token refresh, so waiting callers
            # cannot burst together when a shared token becomes available.
            if self.before_search:self.before_search()
            response=self.http.post(self.host+'/api/se/v4'+PATH,json=build_request(p,self.cfg),headers={'Authorization':'Bearer '+token,'Accept':'application/json'})
            if len(response.content)>4*1024*1024:raise BaeError(code='response_too_large')
            if response.status_code==404:
                value=interpret_search_404(response)
            else:
                self.check_http(response)
                try:body=response.json()
                except ValueError:
                    raise BaeError(code='invalid_response',diagnostics=[{'path':'(odpowiedź)','rule':'json','actual_type':'not_json'}]) from None
                value=interpret(body,p)
            value.update(source='SE API 4.0.5 / '+self.env)
            # 200 success schema has no query ID; 404 SE envelopes may provide one.
            value.setdefault('request_id',None)
            return value
        except BaeError:raise
        except ValidationError:raise BaeError('invalid','contract_validation')
        except (httpx.TimeoutException,httpx.NetworkError):raise BaeError(code='network',retry=True)
        except Exception:raise BaeError(code='adapter_failure')
