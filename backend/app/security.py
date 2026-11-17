import base64, hashlib, hmac, json, os, secrets, ssl, time, unicodedata
import pyotp, redis
from cryptography.fernet import Fernet
from fastapi import Request, HTTPException, Depends
from sqlalchemy import select, delete
from .config import settings
from .db import session, User, LoginSession, audit

crypto = Fernet(settings().data_key.encode())
cache = redis.Redis.from_url(settings().redis,password=settings().redis_password,decode_responses=True,socket_timeout=5,socket_connect_timeout=5)

def seal(value): return crypto.encrypt(json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()).decode()
def unseal(value): return json.loads(crypto.decrypt(value.encode()))
def normalize(value): return unicodedata.normalize('NFC',str(value)).strip().casefold()
def digest(value): return hmac.new(settings().index_key,normalize(value).encode(),hashlib.sha256).hexdigest()
def csrf(token): return digest('csrf:'+token)
def password_hash(password):
    if len(password)<14 or len(password)>256: raise ValueError('Hasło musi mieć 14–256 znaków')
    salt=secrets.token_bytes(16)
    key=hashlib.scrypt(password.encode(),salt=salt,n=32768,r=8,p=1,maxmem=64*1024*1024)
    return base64.b64encode(salt+key).decode()
def password_ok(password,encoded):
    try:
        if len(password)>256:return False
        data=base64.b64decode(encoded)
        return hmac.compare_digest(data[16:],hashlib.scrypt(password.encode(),salt=data[:16],n=32768,r=8,p=1,maxmem=64*1024*1024))
    except (ValueError,TypeError): return False
DUMMY=password_hash(secrets.token_urlsafe(24))

def ldap_ok(username,password):
    if not settings().ldap_host or not password or not settings().ldap_domain: return False
    from ldap3 import Server,Connection,Tls
    tls=Tls(validate=ssl.CERT_REQUIRED,ca_certs_file=settings().ldap_ca or None)
    server=Server(settings().ldap_host,port=636,use_ssl=True,tls=tls,connect_timeout=5)
    try:
        with Connection(server,user=f'{username}@{settings().ldap_domain}',password=password,auto_bind=True,receive_timeout=5): return True
    except Exception: return False

def authenticate(db,username,password,ip):
    name=normalize(username)
    if not name or len(name)>120: raise HTTPException(401,'Nieprawidłowe dane logowania')
    key='login:'+digest(name+':'+ip)
    try:
        n=cache.incr(key)
        if n==1:cache.expire(key,900)
        # Also throttle each source and account across source addresses.
        for k,maximum in [('login-ip:'+digest(ip),100),('login-user:'+digest(name),30)]:
            v=cache.incr(k)
            if v==1:cache.expire(k,900)
            if v>maximum:raise HTTPException(429,'Zbyt wiele prób. Spróbuj za 15 minut.')
        if n>10:raise HTTPException(429,'Zbyt wiele prób. Spróbuj za 15 minut.')
    except redis.RedisError: raise HTTPException(503,'Usługa uwierzytelniania jest niedostępna')
    user=db.scalar(select(User).where(User.username==name).with_for_update())
    valid=ldap_ok(name,password) if user and user.auth_type=='ldap' else password_ok(password,user.password if user else DUMMY)
    if not user or not user.active or not valid:
        audit(db,user.id if user else None,'login','', 'denied')
        db.commit()
        raise HTTPException(401,'Nieprawidłowe dane logowania')
    return user

def verify_otp(user,code):
    if not user.totp: raise HTTPException(403,'Najpierw aktywuj MFA')
    otp=pyotp.TOTP(unseal(user.totp))
    step=int(time.time()//30)
    for k in [step-1,step,step+1]:
        if k>user.last_otp and hmac.compare_digest(otp.at(k*30),code):
            user.last_otp=k;return
    raise HTTPException(401,'Nieprawidłowy lub wykorzystany kod MFA')

def current_user(request:Request):
    token=request.cookies.get('bae_session','')
    with session() as db:
        s=db.get(LoginSession,digest(token)) if token else None
        u=db.get(User,s.user_id) if s and s.expires>time.time() else None
        if not u or not u.active:raise HTTPException(401,'Zaloguj się ponownie')
        if request.method not in ['GET','HEAD','OPTIONS'] and not hmac.compare_digest(request.headers.get('x-csrf-token',''),csrf(token)):
            raise HTTPException(403,'Nieprawidłowy token CSRF')
        return u

def operator(u=Depends(current_user)):
    if u.role not in ['admin','operator']:raise HTTPException(403,'Brak uprawnień operatora')
    return u

def admin(u=Depends(current_user)):
    if u.role!='admin':raise HTTPException(403,'Brak uprawnień administratora')
    return u


def bulk_operator(u=Depends(operator)):
    if u.role!='admin' and not u.bulk_allowed:
        raise HTTPException(403,'Weryfikacja masowa wymaga zgody administratora')
    return u
