import os
from pathlib import Path
from functools import lru_cache

def secret(name: str, required=True) -> str:
    path = os.getenv(name + '_FILE')
    value = Path(path).read_text().strip() if path else os.getenv(name, '')
    if required and not value:
        raise RuntimeError(f'Brak sekretu {name}_FILE')
    return value

class Settings:
    def __init__(self):
        self.database = os.getenv('DATABASE_URL', 'postgresql+psycopg://bae@db/bae')
        db_password = secret('DB_PASSWORD', False)
        if db_password:
            from sqlalchemy.engine import make_url
            self.database = make_url(self.database).set(password=db_password)
        self.redis = os.getenv('REDIS_URL', 'redis://redis:6379/0')
        self.redis_password = secret('REDIS_PASSWORD', False) or None
        self.data_key = secret('DATA_KEY')
        self.index_key = secret('INDEX_KEY').encode()
        if len(self.index_key) < 32:
            raise RuntimeError('INDEX_KEY musi mieć co najmniej 32 znaki')
        self.origin = os.getenv('APP_ORIGIN', 'https://localhost').rstrip('/')
        self.secure_cookie = os.getenv('COOKIE_SECURE', 'true').lower() == 'true'
        if not self.secure_cookie and not self.origin.startswith('http://localhost'):
            raise RuntimeError('Niezabezpieczone cookies dozwolone tylko na localhost')
        self.upload_mb = 128
        self.max_rows = 100_000
        self.session_seconds = 8 * 3600
        self.contract = Path(os.getenv('SE_CONTRACT', str(Path(__file__).resolve().parents[2] / 'contracts/se-api_v.4.0.5.yaml')))
        self.key_files = {e: os.getenv(f'BAE_{e}_KEY_FILE', f'/run/bae/{e.lower()}.key') for e in ['INT','PROD']}
        self.cert_files = {e: os.getenv(f'BAE_{e}_CERT_FILE', f'/run/bae/{e.lower()}.crt') for e in ['INT','PROD']}
        self.ldap_host = os.getenv('LDAP_HOST', '')
        self.ldap_domain = os.getenv('LDAP_DOMAIN', '')
        self.ldap_ca = os.getenv('LDAP_CA_FILE', '')

@lru_cache
def settings():
    return Settings()
