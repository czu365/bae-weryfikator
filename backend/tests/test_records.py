from sqlalchemy import select
from app import api, security
from app.db import session, Job, Row, Search, uid
from app.security import seal


def seed(owner, sample, states, review_positions=()):
    with session() as db:
        j=Job(id=uid(),owner_id=owner.id,label=seal('Test zbiorczy'),total=len(states))
        db.add(j);db.flush()
        for position,state in enumerate(states,1):
            search=None
            if state!='unmapped':
                search=Search(id=uid(),job_id=j.id,fingerprint=str(position),payload=seal(sample),state=state)
                db.add(search);db.flush()
            db.add(Row(job_id=j.id,position=position,raw=seal(sample),person=seal(sample),search_id=search.id if search else None,review=position in review_positions))
        return j.id


def test_cards_match_global_records_and_manual_review(client,users,sample):
    first=seed(users[0],sample,['found','not_found','invalid','technical_error','ambiguous','unauthorized','pending','unmapped'],[1,3])
    second=seed(users[0],sample,['found','running'])
    seed(users[1],sample,['found','technical_error'])
    stats=client.get('/api/stats').json()
    assert stats['total']==10 and stats['needs_review']==5
    for status,expected in [('',10),('found',2),('not_found',1),('needs_review',5),('unmapped',1)]:
        response=client.get('/api/records',params={'status':status});assert response.status_code==200
        data=response.json();assert data['total']==len(data['items'])==expected
        assert all(r['job_id'] in [first,second] for r in data['items'])
        assert all(r['pesel']=='*******'+sample['pesel'][-4:] for r in data['items'])
        assert all('job_label' in r and 'raw' not in r and 'payload' not in r for r in data['items'])
    assert client.get('/api/jobs/'+first+'/rows?status=needs_review').json()['total']==5


def test_global_records_roles_pagination_and_filters(client,users,sample):
    seed(users[0],sample,['found']*27)
    seed(users[1],sample,['not_found']*4)
    for index,expected in [(0,27),(2,31),(3,31)]:
        api.app.dependency_overrides[security.current_user]=lambda i=index:users[i]
        first=client.get('/api/records').json();second=client.get('/api/records?page=2').json()
        assert first['total']==second['total']==expected
        assert len(first['items'])==25 and len(second['items'])==expected-25
        assert not set(r['row_id'] for r in first['items'])&set(r['row_id'] for r in second['items'])
    assert client.get('/api/records?status=arbitrary').status_code==422
    assert client.get('/api/records?page=0').status_code==422
    assert client.get('/api/records?size=101').status_code==422
    api.app.dependency_overrides.clear()
    assert client.get('/api/records').status_code==401
