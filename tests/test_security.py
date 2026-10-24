import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
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


def test_overlength_document_id_is_denied_and_audited_under_postgres_column_limit(env_app, monkeypatch):
    m, client = env_app
    owner_token = login(client, 'owner')
    invalid_id = 'x' * 37
    original_audit = m.audit

    def enforce_postgres_varchar_limit(session, actor, action, document_id=None, outcome='allowed', detail='', *, commit=True):
        if document_id is not None and len(document_id) > 36:
            raise ValueError('simulated PostgreSQL varchar(36) constraint failure')
        return original_audit(
            session, actor, action, document_id, outcome, detail, commit=commit,
        )

    monkeypatch.setattr(m, 'audit', enforce_postgres_varchar_limit)

    response = client.get(f'/documents/{invalid_id}')
    assert response.status_code == 404
    client.post('/logout', data={'csrf': owner_token})
    anonymous_response = client.get(f'/documents/{invalid_id}')
    assert anonymous_response.status_code == 401

    with m.SessionLocal() as session:
        denials = session.scalars(
            select(m.Audit).where(
                m.Audit.action == 'view',
                m.Audit.outcome == 'denied',
                m.Audit.detail.like('%invalid document identifier'),
            )
        ).all()
        assert len(denials) == 2
        assert all(denial.document_id is None for denial in denials)


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


def test_revoke_blocks_existing_session_and_completes_audited_workflow(env_app):
    m, client = env_app
    owner_token = login(client, 'owner')
    doc_id = upload(client, owner_token)
    grant_response = client.post(
        f'/documents/{doc_id}/grants',
        data={'csrf': owner_token, 'username': 'reader', 'permission': 'read'},
    )
    assert grant_response.status_code == 200
    assert grant_response.history[-1].status_code == 303

    client.post('/logout', data={'csrf': owner_token})
    reader_token = login(client, 'reader')
    reader_session = client.cookies.get('tv_session')
    download = client.get(f'/documents/{doc_id}/download')
    assert download.status_code == 200
    assert download.content == b'company private note'

    client.post('/logout', data={'csrf': reader_token})
    owner_token = login(client, 'owner')
    with m.SessionLocal() as session:
        reader_id = session.scalar(select(m.User.id).where(m.User.username == 'reader'))
    revoke_response = client.post(
        f'/documents/{doc_id}/revoke/{reader_id}',
        data={'csrf': owner_token},
    )
    assert revoke_response.status_code == 200
    assert revoke_response.history[-1].status_code == 303

    client.cookies.set('tv_session', reader_session)
    assert client.get(f'/documents/{doc_id}').status_code == 404
    assert client.get(f'/documents/{doc_id}/download').status_code == 404
    assert client.post(
        f'/documents/{doc_id}/edit',
        data={'csrf': reader_token, 'title': 'Unauthorized', 'category': 'Changed'},
    ).status_code == 404
    assert client.post(
        f'/documents/{doc_id}/delete',
        data={'csrf': reader_token},
    ).status_code == 404

    with m.SessionLocal() as session:
        events = session.scalars(
            select(m.Audit).where(m.Audit.document_id == doc_id)
        ).all()
        assert {event.action for event in events} >= {
            'upload', 'grant', 'download', 'revoke', 'view', 'edit', 'delete',
        }
        revoke_id = max(event.id for event in events if event.action == 'revoke')
        reader_denials = [
            event for event in events
            if event.actor_id == reader_id
            and event.action in {'view', 'download', 'edit', 'delete'}
            and event.id > revoke_id
        ]
        assert len(reader_denials) >= 4
        assert all(event.outcome == 'denied' for event in reader_denials)
        assert m.audit_integrity(session)


def test_revoked_grant_does_not_fetch_blob(env_app):
    m, client = env_app
    owner_token = login(client, 'owner')
    doc_id = upload(client, owner_token)
    client.post(
        f'/documents/{doc_id}/grants',
        data={'csrf': owner_token, 'username': 'reader', 'permission': 'read'},
    )
    client.post('/logout', data={'csrf': owner_token})

    reader_token = login(client, 'reader')
    reader_session = client.cookies.get('tv_session')
    delegate = m.blob_storage

    class StorageSpy:
        def __init__(self):
            self.get_calls = 0

        def put(self, key, content):
            delegate.put(key, content)

        def get(self, key):
            self.get_calls += 1
            return delegate.get(key)

        def delete(self, key):
            delegate.delete(key)

    storage_spy = StorageSpy()
    m.blob_storage = storage_spy
    assert client.get(f'/documents/{doc_id}/download').status_code == 200
    assert storage_spy.get_calls == 1

    client.post('/logout', data={'csrf': reader_token})
    owner_token = login(client, 'owner')
    with m.SessionLocal() as session:
        reader_id = session.scalar(select(m.User.id).where(m.User.username == 'reader'))
    client.post(f'/documents/{doc_id}/revoke/{reader_id}', data={'csrf': owner_token})

    client.cookies.set('tv_session', reader_session)
    assert client.get(f'/documents/{doc_id}/download').status_code == 404
    assert storage_spy.get_calls == 1


def test_document_edit_rolls_back_if_audit_cannot_be_written(env_app, monkeypatch):
    m, client = env_app
    owner_token = login(client, 'owner')
    doc_id = upload(client, owner_token)
    original_audit = m.audit

    def fail_edit_audit(session, actor, action, *args, **kwargs):
        if action == 'edit':
            raise RuntimeError('simulated audit write failure')
        return original_audit(session, actor, action, *args, **kwargs)

    monkeypatch.setattr(m, 'audit', fail_edit_audit)
    with pytest.raises(RuntimeError, match='simulated audit write failure'):
        client.post(
            f'/documents/{doc_id}/edit',
            data={'csrf': owner_token, 'title': 'Unlogged change', 'category': 'Changed'},
        )

    with m.SessionLocal() as session:
        assert session.get(m.Document, doc_id).title == 'Secret roadmap'
        assert session.scalar(
            select(m.Audit).where(m.Audit.document_id == doc_id, m.Audit.action == 'edit')
        ) is None


def test_upload_rolls_back_audit_failure_and_removes_blob(env_app, monkeypatch):
    m, client = env_app
    owner_token = login(client, 'owner')
    original_audit = m.audit

    def fail_upload_audit(session, actor, action, *args, **kwargs):
        if action == 'upload':
            raise RuntimeError('simulated audit write failure')
        return original_audit(session, actor, action, *args, **kwargs)

    monkeypatch.setattr(m, 'audit', fail_upload_audit)
    with pytest.raises(RuntimeError, match='simulated audit write failure'):
        upload(client, owner_token)

    with m.SessionLocal() as session:
        assert session.scalar(select(m.Document.id)) is None
    if m.STORAGE is not None:
        assert list(m.STORAGE.iterdir()) == []


def test_forwarded_ip_header_is_not_trusted_for_login_rate_limit(env_app):
    m, client = env_app
    csrf = token(client.get('/login'))
    client.post(
        '/login',
        headers={'X-Forwarded-For': '198.51.100.77'},
        data={'csrf': csrf, 'username': 'missing', 'password': 'invalid'},
    )
    with m.SessionLocal() as session:
        event = session.scalar(select(m.Audit).where(m.Audit.action == 'login'))
        assert event is not None
        assert 'ip=testclient' in event.detail
        assert '198.51.100.77' not in event.detail


def test_upload_limit_is_enforced(env_app):
    _, client = env_app
    owner_token = login(client, 'owner')
    response = client.post(
        '/documents',
        data={'csrf': owner_token, 'title': 'Too large'},
        files={'file': ('large.txt', b'x' * (8 * 1024 * 1024 + 1), 'text/plain')},
    )
    assert response.status_code == 413


def test_invalid_persisted_storage_key_cannot_escape_private_storage(env_app):
    m, client = env_app
    owner_token = login(client, 'owner')
    doc_id = upload(client, owner_token)
    with m.SessionLocal() as session:
        document = session.get(m.Document, doc_id)
        document.storage_key = '..\\outside.txt'
        session.commit()
    assert client.get(f'/documents/{doc_id}/download').status_code == 404


def test_audit_chain_cannot_detect_tail_truncation_without_external_checkpoint(env_app):
    m, client = env_app
    login(client, 'owner')
    with m.SessionLocal() as session:
        last = session.scalar(select(m.Audit).order_by(m.Audit.id.desc()))
        session.delete(last)
        session.commit()
        assert m.audit_integrity(session)


def test_session_cookie_has_secure_defaults(env_app):
    _, client = env_app
    response = client.get('/login')
    set_cookie = response.headers.get('set-cookie', '').lower()
    assert 'httponly' in set_cookie
    assert 'samesite=strict' in set_cookie


def test_https_mode_requires_a_stable_session_secret():
    project_root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as temp_dir:
        environment = os.environ.copy()
        environment.pop('TRUSTVAULT_SECRET', None)
        environment['TRUSTVAULT_HTTPS'] = '1'
        environment['TRUSTVAULT_STORAGE'] = str(Path(temp_dir) / 'storage')
        environment['DATABASE_URL'] = 'sqlite:///' + str(Path(temp_dir) / 'test.db')
        result = subprocess.run(
            [sys.executable, '-c', 'import app.main'],
            cwd=project_root,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
    assert result.returncode != 0
    assert 'TRUSTVAULT_SECRET must be set' in result.stderr


def test_https_mode_sets_secure_session_cookie():
    project_root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as temp_dir:
        environment = os.environ.copy()
        environment['TRUSTVAULT_SECRET'] = 'test-deployment-secret-at-least-32-characters'
        environment['TRUSTVAULT_HTTPS'] = '1'
        environment['TRUSTVAULT_STORAGE'] = str(Path(temp_dir) / 'storage')
        environment['DATABASE_URL'] = 'sqlite:///' + str(Path(temp_dir) / 'test.db')
        result = subprocess.run(
            [
                sys.executable,
                '-c',
                (
                    'from fastapi.testclient import TestClient; '
                    'from app.main import app; '
                    'response = TestClient(app).get("/login"); '
                    'assert "secure" in response.headers["set-cookie"].lower()'
                ),
            ],
            cwd=project_root,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
    assert result.returncode == 0, result.stderr


def test_login_and_upload_pages_keep_scripts_compatible_with_csp(env_app):
    _, client = env_app
    login_page = client.get('/login')
    assert "script-src 'self'" in login_page.headers['content-security-policy']
    assert "style-src-attr 'unsafe-inline'" in login_page.headers['content-security-policy']
    assert not re.search(r'<script(?![^>]*\bsrc=)', login_page.text, re.IGNORECASE)
    assert not re.search(r'\bon[a-z]+\s*=', login_page.text, re.IGNORECASE)

    login(client, 'owner')
    upload_page = client.get('/documents/new')
    assert '<label class="upload-zone" id="upload-zone" for="doc-file">' in upload_page.text
    assert 'class="visually-hidden"' in upload_page.text
    assert not re.search(r'<script(?![^>]*\bsrc=)', upload_page.text, re.IGNORECASE)
    assert not re.search(r'\bon[a-z]+\s*=', upload_page.text, re.IGNORECASE)
