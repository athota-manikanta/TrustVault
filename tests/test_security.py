from sqlalchemy import select
from .conftest import login, token, upload

def test_cross_user_denied_and_audited(env_app):
    m, client=env_app
    t=login(client,'owner');did=upload(client,t)
    client.post('/logout',data={'csrf':t})
    login(client,'stranger')
    assert client.get('/documents/'+did).status_code==404
    assert client.get('/documents/'+did+'/download').status_code==404
    assert did not in client.get('/').text
    with m.SessionLocal() as s:
        denied=s.scalars(select(m.Audit).where(m.Audit.document_id==did,m.Audit.outcome=='denied')).all()
        assert len(denied)>=2

def test_grant_and_revocation_immediate(env_app):
    m, client=env_app
    t=login(client,'owner');did=upload(client,t)
    r=client.post(f'/documents/{did}/grants',data={'csrf':t,'username':'reader','permission':'read'})
    assert r.status_code==200
    client.post('/logout',data={'csrf':t})
    rt=login(client,'reader')
    assert client.get(f'/documents/{did}/download').status_code==200
    client.post('/logout',data={'csrf':rt})
    ot=login(client,'owner')
    with m.SessionLocal() as s:
        rid=s.scalar(select(m.User).where(m.User.username=='reader')).id
    client.post(f'/documents/{did}/revoke/{rid}',data={'csrf':ot})
    client.post('/logout',data={'csrf':ot})
    login(client,'reader')
    assert client.get(f'/documents/{did}/download').status_code==404

def test_read_cannot_edit(env_app):
    _,client=env_app
    t=login(client,'owner');did=upload(client,t)
    client.post(f'/documents/{did}/grants',data={'csrf':t,'username':'reader','permission':'read'})
    client.post('/logout',data={'csrf':t})
    rt=login(client,'reader')
    assert client.post(f'/documents/{did}/edit',data={'csrf':rt,'title':'Hijacked','category':'X'}).status_code==404

def test_only_owner_may_grant(env_app):
    _,client=env_app
    t=login(client,'owner');did=upload(client,t)
    client.post('/logout',data={'csrf':t})
    at=login(client,'admin')
    assert client.post(f'/documents/{did}/grants',data={'csrf':at,'username':'stranger','permission':'read'}).status_code==404

def test_csrf_required(env_app):
    _,client=env_app
    login(client,'owner')
    assert client.post('/documents',data={'csrf':'wrong','title':'bad'},files={'file':('p.txt',b'hello','text/plain')}).status_code==403

def test_invalid_upload(env_app):
    _,client=env_app
    t=login(client,'owner')
    r=client.post('/documents',data={'csrf':t,'title':'bad'},files={'file':('bad.pdf',b'not a pdf','application/pdf')})
    assert r.status_code==400

def test_audit_tampering_detected(env_app):
    m,client=env_app
    login(client,'owner')
    with m.SessionLocal() as s:
        assert m.audit_integrity(s)
        row=s.scalar(select(m.Audit).order_by(m.Audit.id))
        row.detail='edited after event'
        s.commit()
        assert not m.audit_integrity(s)

def test_editor_can_edit_but_not_delete(env_app):
    _,client=env_app
    t=login(client,'owner');did=upload(client,t)
    client.post(f'/documents/{did}/grants',data={'csrf':t,'username':'reader','permission':'edit'})
    client.post('/logout',data={'csrf':t})
    rt=login(client,'reader')
    assert client.post(f'/documents/{did}/edit',data={'csrf':rt,'title':'Updated','category':'Business'}).status_code==200
    assert client.post(f'/documents/{did}/delete',data={'csrf':rt}).status_code==403
