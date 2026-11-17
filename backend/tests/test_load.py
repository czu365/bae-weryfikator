"""Opt-in real persistence load test; no external BAE calls."""
import io,os,time,resource,json
import pytest
from sqlalchemy import select,func
from app.db import session,Job,Row,Search,uid
from app.security import seal
from app.importer import import_file,apply_mapping
from app.exporter import export_rows,json_stream

@pytest.mark.skipif(os.getenv('BAE_LOAD_TEST')!='1',reason='Uruchom z BAE_LOAD_TEST=1')
def test_100000_import_map_export(users,tmp_path):
    # 100k rows with 100k different source IDs, 1000 unique synthetic identities.
    unique=int(os.getenv('BAE_LOAD_UNIQUE','1000'))
    names=['Test'+str(i).zfill(5).translate(str.maketrans('0123456789','ABCDEFGHIJ')) for i in range(unique)]
    file=tmp_path/'load.csv'
    with file.open('w') as f:
        f.write('id;imie;nazwisko;nr_budynku;kod_pocztowy;miejscowosc\n')
        for i in range(100000):f.write(f'{i:08d};{names[i%unique]};Weryfikacyjna;1;00-000;Testowo\n')
    t=time.perf_counter()
    with session() as db:
        j=Job(id=uid(),owner_id=users[0].id,label=seal('TEST OBCIĄŻENIOWY'));db.add(j);db.flush();jid=j.id
        with file.open('rb') as f:r=import_file(db,j,f,'.csv')
        summary=apply_mapping(db,j,r['mapping'])
        assert summary['total']==100000 and summary['duplicates']==100000-unique and summary['invalid']==0
    mapped=time.perf_counter()
    count=0;first=None;last=None
    with session() as db:
        j=db.get(Job,jid)
        for r in export_rows(db,j):
            count+=1;first=first or r['id'];last=r['id']
    assert count==100000 and first=='00000000' and last=='00099999'
    metrics={'rows':count,'unique_queries':summary['unique_queries'],'import_mapping_seconds':round(mapped-t,2),'export_seconds':round(time.perf_counter()-mapped,2),'peak_rss_mib':round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024,1),'external_bae_requests':0}
    print('\nLOAD_RESULT '+json.dumps(metrics))
