import datetime,time,httpx,jwt
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.x509.oid import NameOID
from app.adapter import SEAdapter,DEFAULTS,certificate_info
from app.config import settings
from app import worker
from app.db import session,Job,Search,Attempt
from app.security import unseal
from test_queue import setup_job,TestAdapter,enable
from sqlalchemy import select


def test_signed_jwt_and_shared_token_cache(tmp_path,monkeypatch,database):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'SYNTHETIC TEST SYSTEM')]);t=datetime.datetime.now(datetime.timezone.utc)
    cert=x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(1).not_valid_before(t-datetime.timedelta(days=1)).not_valid_after(t+datetime.timedelta(days=1)).sign(key,hashes.SHA256())
    kp=tmp_path/'test.key';cp=tmp_path/'test.crt'
    kp.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    monkeypatch.setitem(settings().key_files,'INT',str(kp));monkeypatch.setitem(settings().cert_files,'INT',str(cp))
    cfg={**DEFAULTS,'sender_eda':'AE:PL-00000-00000-TESTA-00','system_name':'TEST','audience':'https://int-ow.edoreczenia.gov.pl/auth/realms/EDOR','login_hint':'ADE.AE:PL-00000-00000-TESTA-00'}
    requests=[]
    def handle(r):
        from urllib.parse import parse_qs
        form=parse_qs(r.content.decode());claims=jwt.decode(form['client_assertion'][0],key.public_key(),algorithms=['RS256'],audience=cfg['audience'])
        assert claims['iss']==claims['sub']==cfg['sender_eda']+'.SYSTEM.TEST'
        assert claims['jti'] and form['grant_type']==['client_credentials']
        requests.append(r);return httpx.Response(200,json={'access_token':'SYNTHETIC-TOKEN-NOT-FROM-BAE','expires_in':300})
    a=SEAdapter(cfg,transport=httpx.MockTransport(handle));b=SEAdapter(cfg,transport=httpx.MockTransport(handle))
    assert certificate_info('INT')['ready']
    assert a.token()==b.token() and len(requests)==1
    assert 'SYNTHETIC-TOKEN' not in ''.join(database.scan_iter('se-token:*'))
    values=[database.get(k) for k in database.scan_iter('se-token:*') if not k.endswith(':lock')]
    assert values and all('SYNTHETIC-TOKEN' not in value for value in values)
    a.close();b.close()


def test_durable_attempt_history_and_repeated_worker(users,sample,monkeypatch):
    jid=setup_job(users,sample);enable(monkeypatch)
    worker.tick(TestAdapter)
    with session() as db:
        s=db.scalar(select(Search).where(Search.job_id==jid));s.state='pending';s.checked=None;s.result=None;db.get(Job,jid).state='queued'
    worker.tick(TestAdapter)
    with session() as db:
        attempts=list(db.scalars(select(Attempt).where(Attempt.job_id==jid).order_by(Attempt.at)))
        assert len(attempts)==2 and all(unseal(a.result)['status']=='not_found' for a in attempts)
        assert db.get(Job,jid).state=='completed'
