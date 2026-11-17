import time, uuid
from contextlib import contextmanager
from sqlalchemy import create_engine, ForeignKey, UniqueConstraint, Index, String, Text, false
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from .config import settings

def uid(): return str(uuid.uuid4())
def now(): return time.time()

class Base(DeclarativeBase): pass

class User(Base):
    __tablename__='users'
    id: Mapped[str] = mapped_column(String(36),primary_key=True,default=uid)
    username: Mapped[str] = mapped_column(String(120),unique=True)
    password: Mapped[str] = mapped_column(Text,default='')
    role: Mapped[str] = mapped_column(String(20),default='operator')
    active: Mapped[bool] = mapped_column(default=True)
    auth_type: Mapped[str] = mapped_column(String(10),default='local')
    totp: Mapped[str | None] = mapped_column(Text,nullable=True)
    last_otp: Mapped[int] = mapped_column(default=-1)
    bulk_allowed: Mapped[bool] = mapped_column(default=False,server_default=false())

class LoginSession(Base):
    __tablename__='sessions'
    id: Mapped[str] = mapped_column(String(64),primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id',ondelete='CASCADE'),index=True)
    expires: Mapped[float] = mapped_column(index=True)

class Config(Base):
    __tablename__='config'
    key: Mapped[str] = mapped_column(String(30),primary_key=True)
    value: Mapped[str] = mapped_column(Text)

class Job(Base):
    __tablename__='jobs'
    id: Mapped[str] = mapped_column(String(36),primary_key=True,default=uid)
    owner_id: Mapped[str] = mapped_column(ForeignKey('users.id'),index=True)
    label: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(String(20),default='draft',index=True)
    environment: Mapped[str] = mapped_column(String(10),default='INT')
    kind: Mapped[str] = mapped_column(String(10),default='single',server_default='single')
    created: Mapped[float] = mapped_column(default=now,index=True)
    updated: Mapped[float] = mapped_column(default=now)
    total: Mapped[int] = mapped_column(default=0)
    import_info: Mapped[str] = mapped_column(Text,default='')
    duplicates: Mapped[int] = mapped_column(default=0)
    message: Mapped[str] = mapped_column(Text,default='')

class Search(Base):
    __tablename__='searches'
    id: Mapped[str] = mapped_column(String(36),primary_key=True,default=uid)
    job_id: Mapped[str] = mapped_column(ForeignKey('jobs.id',ondelete='CASCADE'),index=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    payload: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(String(24),default='pending',index=True)
    result: Mapped[str | None] = mapped_column(Text,nullable=True)
    scheduled_by: Mapped[str | None] = mapped_column(String(36),nullable=True)
    scheduled: Mapped[bool] = mapped_column(default=True)
    attempts: Mapped[int] = mapped_column(default=0)
    next_at: Mapped[float] = mapped_column(default=0.)
    lease_until: Mapped[float] = mapped_column(default=0.)
    lease_token: Mapped[str | None] = mapped_column(String(36),nullable=True)
    checked: Mapped[float | None] = mapped_column(nullable=True)
    __table_args__=(UniqueConstraint('job_id','fingerprint'), Index('ix_search_claim','state','next_at','lease_until'))

class Row(Base):
    __tablename__='rows'
    id: Mapped[str] = mapped_column(String(36),primary_key=True,default=uid)
    job_id: Mapped[str] = mapped_column(ForeignKey('jobs.id',ondelete='CASCADE'),index=True)
    position: Mapped[int]
    raw: Mapped[str] = mapped_column(Text)
    person: Mapped[str] = mapped_column(Text,default='')
    search_id: Mapped[str | None] = mapped_column(ForeignKey('searches.id'),nullable=True,index=True)
    search_name: Mapped[str] = mapped_column(String(64),default='',index=True)
    search_source: Mapped[str] = mapped_column(String(64),default='',index=True)
    search_pesel: Mapped[str] = mapped_column(String(64),default='',index=True)
    review: Mapped[bool] = mapped_column(default=False)
    note: Mapped[str] = mapped_column(Text,default='')
    __table_args__=(UniqueConstraint('job_id','position'),)

class Audit(Base):
    __tablename__='audit'
    id: Mapped[str] = mapped_column(String(36),primary_key=True,default=uid)
    actor_id: Mapped[str | None] = mapped_column(String(36),nullable=True,index=True)
    at: Mapped[float] = mapped_column(default=now,index=True)
    action: Mapped[str] = mapped_column(String(60))
    job_id: Mapped[str | None] = mapped_column(String(36),nullable=True)
    outcome: Mapped[str] = mapped_column(String(80))

    details: Mapped[str | None] = mapped_column(Text,nullable=True)

class AuditExportRows(Base):
    __tablename__='audit_export_rows'
    audit_id: Mapped[str] = mapped_column(ForeignKey('audit.id',ondelete='CASCADE'),primary_key=True)
    batch: Mapped[int] = mapped_column(primary_key=True)
    payload: Mapped[str] = mapped_column(Text)


engine = create_engine(settings().database,pool_pre_ping=True,**({'connect_args':{'check_same_thread':False}} if str(settings().database).startswith('sqlite') else {}))
Session = sessionmaker(engine,expire_on_commit=False)
@contextmanager
def session():
    with Session() as db:
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback(); raise

def audit(db,actor,action,job=None,outcome='ok',details=None):
    db.add(Audit(actor_id=actor,action=action,job_id=job,outcome=outcome,details=details))

class Attempt(Base):
    __tablename__='attempts'
    id: Mapped[str] = mapped_column(String(36),primary_key=True,default=uid)
    job_id: Mapped[str] = mapped_column(ForeignKey('jobs.id',ondelete='CASCADE'),index=True)
    search_id: Mapped[str] = mapped_column(String(36),index=True)
    at: Mapped[float] = mapped_column(default=now)
    number: Mapped[int]
    state: Mapped[str] = mapped_column(String(24))
    result: Mapped[str] = mapped_column(Text)
