import argparse, getpass, re
from sqlalchemy import select, delete
from .db import session, User, LoginSession, audit
from .security import password_hash, normalize

def main():
    p=argparse.ArgumentParser();p.add_argument('action',choices=['create-admin','reset-password','reset-mfa']);p.add_argument('username');a=p.parse_args()
    name=normalize(a.username)
    if not re.fullmatch('[a-z0-9._-]{2,120}',name):p.error('Nieprawidłowy login')
    with session() as db:
        u=db.scalar(select(User).where(User.username==name).with_for_update())
        if a.action=='create-admin':
            if u:p.error('Konto już istnieje')
            password=getpass.getpass('Hasło (min. 14 znaków): ')
            if password!=getpass.getpass('Powtórz hasło: '):p.error('Hasła są różne')
            u=User(username=name,password=password_hash(password),role='admin');db.add(u);db.flush()
        else:
            if not u:p.error('Brak konta')
            if a.action=='reset-password':
                password=getpass.getpass('Nowe hasło (min. 14 znaków): ')
                if password!=getpass.getpass('Powtórz hasło: '):p.error('Hasła są różne')
                u.password=password_hash(password)
            else:u.totp=None;u.last_otp=-1
            db.execute(delete(LoginSession).where(LoginSession.user_id==u.id))
        audit(db,None,'cli.'+a.action)
    print('Gotowe. Pierwsza aktywacja MFA jest dostępna na stronie logowania.')
if __name__=='__main__':main()
