import datetime,time
from concurrent.futures import ThreadPoolExecutor
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from app import adapter
from app.config import settings

@pytest.fixture
def pair(tmp_path,monkeypatch):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    start=datetime.datetime.now(datetime.timezone.utc);name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'SYNTHETIC CACHE TEST')])
    def cert(before,after):
        return x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(42).not_valid_before(before).not_valid_after(after).sign(key,hashes.SHA256())
    cp=tmp_path/'test.crt';kp=tmp_path/'test.key'
    cp.write_bytes(cert(start-datetime.timedelta(days=1),start+datetime.timedelta(days=1)).public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    monkeypatch.setitem(settings().cert_files,'INT',str(cp));monkeypatch.setitem(settings().key_files,'INT',str(kp))
    adapter._certificate_cache.clear()
    original=adapter.serialization.load_pem_private_key;calls=[]
    def load(*a,**kw):calls.append(1);return original(*a,**kw)
    monkeypatch.setattr(adapter.serialization,'load_pem_private_key',load)
    return cp,kp,start,cert,calls

def test_cached_pair_is_parsed_once_and_returns_fresh_result(pair):
    first=adapter.certificate_info('INT');first['ready']=False
    assert adapter.certificate_info('INT')['ready']
    assert len(pair[4])==1
    assert not any(isinstance(item,rsa.RSAPrivateKey) for entry in adapter._certificate_cache.values() for item in entry)

def test_threads_share_one_validation(pair):
    with ThreadPoolExecutor(max_workers=8) as pool:results=list(pool.map(lambda _:adapter.certificate_info('INT'),range(16)))
    assert all(r['ready'] for r in results) and len(pair[4])==1

def test_ttl_forces_revalidation(pair,monkeypatch):
    assert adapter.certificate_info('INT')['ready']
    then=time.monotonic();monkeypatch.setattr(adapter.time,'monotonic',lambda:then+31)
    assert adapter.certificate_info('INT')['ready'] and len(pair[4])==2

@pytest.mark.parametrize('target',[0,1])
def test_corrupted_or_removed_file_never_uses_cached_success(pair,target):
    assert adapter.certificate_info('INT')['ready']
    path=pair[target];path.write_bytes(b'INVALID SYNTHETIC FILE')
    assert not adapter.certificate_info('INT')['ready']
    path.unlink();assert not adapter.certificate_info('INT')['ready']

def test_replaced_key_is_checked(pair):
    assert adapter.certificate_info('INT')['ready']
    other=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    pair[1].write_bytes(other.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    result=adapter.certificate_info('INT');assert not result['ready'] and 'parą' in result['issue']

def test_date_expiry_and_not_before_checked_even_with_cache(pair,monkeypatch):
    assert adapter.certificate_info('INT')['ready']
    real=adapter.datetime.datetime
    class Clock(real):
        @classmethod
        def now(cls,tz=None):return pair[2]+datetime.timedelta(days=2)
    monkeypatch.setattr(adapter.datetime,'datetime',Clock)
    assert not adapter.certificate_info('INT')['ready'] and len(pair[4])==1

def test_atomic_certificate_replacement_invalidates_cache(pair):
    assert adapter.certificate_info('INT')['ready']
    cp,kp,start,cert,calls=pair
    alternate=cp.with_suffix('.new')
    alternate.write_bytes(cert(start-datetime.timedelta(days=3),start-datetime.timedelta(days=1)).public_bytes(serialization.Encoding.PEM));alternate.replace(cp)
    assert not adapter.certificate_info('INT')['ready'] and len(calls)==2
