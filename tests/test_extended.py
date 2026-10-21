"""Additional acceptance tests mapped to the challenge's ten requirements."""
from sqlalchemy import select
from .conftest import login, upload


def test_viewer_cannot_upload(env_app):
    _, c = env_app
    token = login(c, 'reader')
    response = c.post('/documents', data={'csrf':token,'title':'attempt'},files={'file':('a.txt',b'hello','text/plain')})
    assert response.status_code == 403


def test_nonowner_cannot_revoke_or_delete(env_app):
    _, c = env_app
    owner_token=login(c,'owner'); doc=upload(c,owner_token)
    c.post('/logout',data={'csrf':owner_token})
    viewer_token=login(c,'stranger')
    assert c.post(f'/documents/{doc}/revoke/1',data={'csrf':viewer_token}).status_code in (403,404)
    assert c.post(f'/documents/{doc}/delete',data={'csrf':viewer_token}).status_code in (403,404)


def test_admin_cannot_read_private_owner_document(env_app):
    _, c = env_app
    owner_token=login(c,'owner'); doc=upload(c,owner_token)
    c.post('/logout',data={'csrf':owner_token})
    login(c,'admin')
    assert c.get(f'/documents/{doc}/download').status_code == 404
    assert c.get('/admin').status_code == 200


def test_viewer_cannot_see_admin_dashboard(env_app):
    _,c=env_app
    login(c,'reader')
    assert c.get('/admin').status_code == 403


def test_filter_by_title_and_owner(env_app):
    _,c=env_app
    t=login(c,'owner'); doc=upload(c,t)
    result=c.get('/?q=roadmap&owner=owner')
    assert result.status_code==200
    assert doc in result.text
    assert doc not in c.get('/?q=not-a-document').text
    assert doc not in c.get('/?owner=somebody-else').text


def test_extension_signature_rejected(env_app):
    _,c=env_app
    t=login(c,'owner')
    for name, payload in [('fake.png',b'not really a png'),('fake.jpg',b'not jpeg data'),('fake.pdf',b'hello')]:
        result=c.post('/documents',data={'csrf':t,'title':'test'},files={'file':(name,payload,'application/octet-stream')})
        assert result.status_code==400


def test_revoke_stops_details_and_download(env_app):
    m,c=env_app
    t=login(c,'owner'); doc=upload(c,t)
    c.post(f'/documents/{doc}/grants',data={'csrf':t,'username':'reader','permission':'edit'})
    c.post('/logout',data={'csrf':t})
    rt=login(c,'reader')
    assert c.get(f'/documents/{doc}').status_code==200
    c.post('/logout',data={'csrf':rt})
    t=login(c,'owner')
    with m.SessionLocal() as db:
        uid=db.scalar(select(m.User).where(m.User.username=='reader')).id
    c.post(f'/documents/{doc}/revoke/{uid}',data={'csrf':t})
    c.post('/logout',data={'csrf':t})
    login(c,'reader')
    assert c.get(f'/documents/{doc}').status_code==404
    assert c.get(f'/documents/{doc}/download').status_code==404
    assert doc not in c.get('/').text
