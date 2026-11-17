"""Upgrade a real old schema and retain its rows, without using live data."""
import os,sqlite3,subprocess,sys
from pathlib import Path


def test_existing_installation_upgrade_and_downgrade(tmp_path):
    backend=Path(__file__).resolve().parents[1]
    database=tmp_path/'old-installation.sqlite'
    env={**os.environ,'DATABASE_URL':'sqlite:///'+str(database)}
    def alembic(*args):
        result=subprocess.run([sys.executable,'-m','alembic',*args],cwd=backend,env=env,text=True,capture_output=True)
        assert result.returncode==0,result.stderr
    alembic('upgrade','7e981391de22')
    with sqlite3.connect(database) as db:
        for uid,role in [('op','operator'),('ad','admin')]:
            db.execute('INSERT INTO users (id,username,password,role,active,auth_type,last_otp) VALUES (?,?,?,?,?,?,?)',(uid,uid,'synthetic',role,1,'local',-1))
        for jid,owner,info,count in [('single','op','',1),('one-row-import','op','encrypted-import-info',1),('admin-import','ad','encrypted-import-info',2)]:
            db.execute('INSERT INTO jobs (id,owner_id,label,state,environment,created,updated,total,import_info,duplicates,message) VALUES (?,?,?,?,?,?,?,?,?,?,?)',(jid,owner,'encrypted-label','queued','INT',1,1,count,info,0,''))
    alembic('upgrade','head')
    with sqlite3.connect(database) as db:
        assert db.execute('SELECT bulk_allowed FROM users WHERE id="op"').fetchone()[0]==0
        jobs={r[0]:(r[1],r[2]) for r in db.execute('SELECT id,kind,state FROM jobs')}
        assert jobs['single']==('single','queued')
        assert jobs['one-row-import']==('bulk','paused')
        assert jobs['admin-import']==('bulk','queued')
    alembic('downgrade','7e981391de22')
    with sqlite3.connect(database) as db:
        assert db.execute('SELECT count(*) FROM users').fetchone()[0]==2
        assert db.execute('SELECT count(*) FROM jobs').fetchone()[0]==3
