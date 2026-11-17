#!/usr/bin/env python3
"""One-time offline initialization. Does not create BAE credentials."""
import base64,os,secrets
from pathlib import Path
root=Path(__file__).resolve().parents[1];folder=root/'secrets';folder.mkdir(exist_ok=True);os.chmod(folder,0o750)
for name,value in {'data_key':base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),'index_key':secrets.token_hex(32),'db_password':secrets.token_urlsafe(32),'redis_password':secrets.token_urlsafe(32)}.items():
    target=folder/name
    if not target.exists():
        fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o640)
        with os.fdopen(fd,'w') as f:f.write(value+'\n')
    # Enforce group readability even when the caller uses umask 077.
    os.chmod(target,0o640)
env=root/'.env'
if not env.exists():
    env.write_text(f'APP_ORIGIN=https://localhost\nAPP_HOST=localhost\nBAE_SECRET_GID={os.getgid()}\n')
    os.chmod(env,0o600)
print('Wygenerowano brakujące sekrety. Zachowaj ich zaszyfrowaną kopię poza serwerem. Istniejące pliki pozostawiono bez zmian.')
