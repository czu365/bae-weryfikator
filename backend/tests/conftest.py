import os,sys,tempfile
from pathlib import Path
from cryptography.fernet import Fernet
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
external=os.getenv('BAE_TEST_DATABASE_URL')
if external:
    from sqlalchemy.engine import make_url
    if not (make_url(external).database or '').startswith('bae_test'):raise RuntimeError('Testy wymagają osobnej bazy o nazwie zaczynającej się od bae_test')
os.environ['DATABASE_URL']=external or 'sqlite:///'+tempfile.mktemp(prefix='bae-tests-',suffix='.sqlite')
os.environ['DATA_KEY']=Fernet.generate_key().decode();os.environ['INDEX_KEY']='testing-only-key-not-for-deployment-'*2
os.environ.pop('DATA_KEY_FILE',None);os.environ.pop('INDEX_KEY_FILE',None)
os.environ['APP_ORIGIN']='https://testserver'
os.environ['SE_CONTRACT']=str(Path(__file__).resolve().parents[2]/'contracts/se-api_v.4.0.5.yaml')
import pytest,fakeredis
from app.db import Base,engine,session,User
from app.security import seal,password_hash
from app import security,adapter,worker,api
from fastapi.testclient import TestClient
from sqlalchemy import event

# Match PostgreSQL's FK enforcement even when local tests use SQLite.
if engine.dialect.name=='sqlite':
    @event.listens_for(engine,'connect')
    def sqlite_foreign_keys(connection,record):
        cursor=connection.cursor();cursor.execute('PRAGMA foreign_keys=ON');cursor.close()

@pytest.fixture(autouse=True)
def database(monkeypatch):
    Base.metadata.drop_all(engine);Base.metadata.create_all(engine)
    fake=fakeredis.FakeRedis(decode_responses=True)
    for m in [security,adapter,worker,api]:monkeypatch.setattr(m,'cache',fake)
    yield fake
    api.app.dependency_overrides.clear()

@pytest.fixture
def users():
    with session() as db:
        a=User(username='operator-test',password=password_hash('Synthetic-test-pass-123'),role='operator',bulk_allowed=True)
        b=User(username='other-test',password=password_hash('Synthetic-test-pass-456'),role='operator',bulk_allowed=True)
        admin=User(username='admin-test',password=password_hash('Synthetic-test-admin-123'),role='admin')
        auditor=User(username='auditor-test',password=password_hash('Synthetic-test-auditor-123'),role='auditor')
        db.add_all([a,b,admin,auditor]);db.flush();return a,b,admin,auditor

@pytest.fixture
def client(users):
    api.app.dependency_overrides[security.current_user]=lambda:users[0]
    return TestClient(api.app,base_url="https://testserver",raise_server_exceptions=True)

@pytest.fixture
def sample():
    # Generated test identifier, unrelated to a real person.
    prefix='0021010001';digit=(10-sum(int(a)*b for a,b in zip(prefix,[1,3,7,9,1,3,7,9,1,3]))%10)%10
    from app.validation import FIELDS
    p={f:'' for f in FIELDS};p.update(id='00001',imie='Testowa',nazwisko='Weryfikacyjna',pesel=prefix+str(digit),kraj='PL')
    return p
