import io,json
import pytest
from sqlalchemy import select,func
from app.validation import person,pesel_valid,mapping_for,FIELDS
from app.importer import records,ImportError,import_file,apply_mapping
from app.db import session,Job,Row,Search,uid
from app.security import seal,unseal


def test_pesel_checksum_date_and_unicode(sample):
    assert pesel_valid(sample['pesel'])
    assert not pesel_valid('12345678901')
    assert not pesel_valid(sample['pesel'][:-1]+str((int(sample['pesel'][-1])+1)%10))
    p,e=person({**sample,'imie':'Łucja','nazwisko':'Zażółć-Gęślą'})
    assert not e and p['imie']=='Łucja'
    bad='0022310001';bad+=str((10-sum(int(a)*b for a,b in zip(bad,[1,3,7,9,1,3,7,9,1,3]))%10)%10)
    assert not pesel_valid(bad)

@pytest.mark.parametrize('data,ext',[(b'{}','.json'),(b'[] trailing','.json'),(b'[1]','.json'),(b'[{"a":[1]}]','.json'),(b'a;a\nx;y','.csv'),(b'a;b\nx','.csv'),(b'\xff;a\nx;y','.csv'),(b'a\nb','.exe')])
def test_reject_invalid_import(data,ext):
    with pytest.raises((ImportError,ValueError)):list(records(io.BytesIO(data),ext))

@pytest.mark.parametrize('sep',[';',','])
@pytest.mark.parametrize('bom',['','\ufeff'])
def test_csv_utf8_and_zeros(sep,bom):
    r=list(records(io.BytesIO((bom+sep.join(['ID','Imię','Nazwisko','Nr PESEL'])+'\n'+sep.join(['000001','Testowa','Weryfikacyjna','00123456789'])).encode()),'.csv'))
    assert r[0]['ID']=='000001'
    assert mapping_for(r[0])['imie']=='Imię'
    assert mapping_for(r[0])['pesel']=='Nr PESEL'

def test_nested_json():
    r=list(records(io.BytesIO(json.dumps([{'id':'0001','adres':{'ulica':'Testowa','miejscowosc':'Testowo'}}]).encode()),'.json'))
    assert r[0]['adres.ulica']=='Testowa'
    assert mapping_for(r[0])['ulica']=='adres.ulica'

def test_dedup_preserves_per_row_id_and_order(users,sample):
    with session() as db:
        j=Job(id=uid(),owner_id=users[0].id,label=seal('Test'));db.add(j);db.flush()
        data=[{**sample,'id':'0001'},{**sample,'id':'0002'}]
        result=import_file(db,j,io.BytesIO(json.dumps(data).encode()),'.json')
        summary=apply_mapping(db,j,result['mapping'])
        assert summary['duplicates']==1
        rows=db.scalars(select(Row).order_by(Row.position)).all()
        assert rows[0].search_id==rows[1].search_id
        assert [unseal(r.person)['id'] for r in rows]==['0001','0002']
        assert sample['pesel'] not in rows[0].raw
        assert apply_mapping(db,j,result['mapping'])['duplicates']==1

def test_numeric_identifier_is_invalid(sample):
    p,e=person({**sample,'pesel':int(sample['pesel'])})
    assert any('musi być tekstem' in error for error in e)

def test_import_atomic_rollback(users):
    with session() as db:
        j=Job(id=uid(),owner_id=users[0].id,label=seal('Test'));db.add(j);db.flush()
        with pytest.raises(ImportError):import_file(db,j,io.BytesIO(b'[{"id":"1"},null]'),'.json')
    with session() as db:assert db.scalar(select(func.count()).select_from(Row))==0
