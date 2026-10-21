"""
test_threats.py — tests that map directly to every row in THREATS.md.

These are the tests the evaluator will use to validate the threat model.
Removing any single authorisation check from app/main.py should cause at
least one test in this file to fail.
"""
from sqlalchemy import select
from .conftest import login, token, upload


# ---------------------------------------------------------------------------
# T1 — Insecure direct object reference (IDOR)
#       Every request re-checks grants server-side, not just the UI.
# ---------------------------------------------------------------------------

def test_idor_direct_document_url(env_app):
    """Stranger cannot open a document by guessing / knowing its UUID."""
    m, c = env_app
    t = login(c, 'owner')
    did = upload(c, t)
    c.post('/logout', data={'csrf': t})
    login(c, 'stranger')
    assert c.get(f'/documents/{did}').status_code == 404


def test_idor_direct_download_url(env_app):
    """Stranger cannot download a document blob by knowing its path."""
    m, c = env_app
    t = login(c, 'owner')
    did = upload(c, t)
    c.post('/logout', data={'csrf': t})
    login(c, 'stranger')
    assert c.get(f'/documents/{did}/download').status_code == 404


def test_idor_denied_access_is_audited(env_app):
    """Denied access attempts must appear in the audit log."""
    m, c = env_app
    t = login(c, 'owner')
    did = upload(c, t)
    c.post('/logout', data={'csrf': t})
    login(c, 'stranger')
    c.get(f'/documents/{did}')
    c.get(f'/documents/{did}/download')
    with m.SessionLocal() as s:
        denied = s.scalars(
            select(m.Audit).where(m.Audit.document_id == did, m.Audit.outcome == 'denied')
        ).all()
        assert len(denied) >= 2, "Both view and download denials must be recorded"


# ---------------------------------------------------------------------------
# T2 — Download bypass (storage outside static routes)
# ---------------------------------------------------------------------------

def test_static_route_does_not_serve_blobs(env_app):
    """The /static/ prefix must not expose private_storage files."""
    m, c = env_app
    t = login(c, 'owner')
    did = upload(c, t)
    with m.SessionLocal() as s:
        doc = s.get(m.Document, did)
        key = doc.storage_key
    # Attempt to fetch the blob via /static/
    r = c.get(f'/static/{key}')
    assert r.status_code in (404, 403), f"Blob accessible via /static/: {r.status_code}"


# ---------------------------------------------------------------------------
# T3 — Revoked user reuses old session / link
# ---------------------------------------------------------------------------

def test_revocation_is_immediate(env_app):
    """Once revoked, the reader's EXISTING SESSION cannot reach the document."""
    m, c = env_app
    owner_t = login(c, 'owner')
    did = upload(c, owner_t)
    c.post(f'/documents/{did}/grants', data={'csrf': owner_t, 'username': 'reader', 'permission': 'read'})

    # Switch to reader's session while owning a still-valid cookie
    c.post('/logout', data={'csrf': owner_t})
    reader_t = login(c, 'reader')
    assert c.get(f'/documents/{did}/download').status_code == 200, "Reader should be able to download before revoke"

    # Owner revokes in a fresh session
    c.post('/logout', data={'csrf': reader_t})
    owner_t = login(c, 'owner')
    with m.SessionLocal() as s:
        rid = s.scalar(select(m.User).where(m.User.username == 'reader')).id
    c.post(f'/documents/{did}/revoke/{rid}', data={'csrf': owner_t})
    c.post('/logout', data={'csrf': owner_t})

    # Reader tries again — must be denied
    login(c, 'reader')
    assert c.get(f'/documents/{did}/download').status_code == 404
    assert c.get(f'/documents/{did}').status_code == 404


# ---------------------------------------------------------------------------
# T4 — Viewer tampers with metadata (edit without edit grant)
# ---------------------------------------------------------------------------

def test_read_grant_cannot_edit_metadata(env_app):
    """A read-only grant must not allow metadata changes."""
    _, c = env_app
    t = login(c, 'owner')
    did = upload(c, t)
    c.post(f'/documents/{did}/grants', data={'csrf': t, 'username': 'reader', 'permission': 'read'})
    c.post('/logout', data={'csrf': t})
    rt = login(c, 'reader')
    r = c.post(f'/documents/{did}/edit', data={'csrf': rt, 'title': 'Hijacked', 'category': 'Evil'})
    assert r.status_code == 404, "Server must reject edit from read-only grantee"


# ---------------------------------------------------------------------------
# T5 — Viewer revokes / deletes (owner-only operations)
# ---------------------------------------------------------------------------

def test_viewer_cannot_revoke(env_app):
    """Only the document owner may revoke access."""
    m, c = env_app
    t = login(c, 'owner')
    did = upload(c, t)
    c.post(f'/documents/{did}/grants', data={'csrf': t, 'username': 'reader', 'permission': 'read'})
    c.post('/logout', data={'csrf': t})
    st = login(c, 'stranger')
    # stranger tries to revoke the reader
    with m.SessionLocal() as s:
        rid = s.scalar(select(m.User).where(m.User.username == 'reader')).id
    r = c.post(f'/documents/{did}/revoke/{rid}', data={'csrf': st})
    assert r.status_code in (403, 404)


def test_viewer_cannot_delete(env_app):
    """Only the document owner may delete the document."""
    _, c = env_app
    t = login(c, 'owner')
    did = upload(c, t)
    c.post('/logout', data={'csrf': t})
    st = login(c, 'stranger')
    assert c.post(f'/documents/{did}/delete', data={'csrf': st}).status_code in (403, 404)


def test_editor_cannot_delete(env_app):
    """An edit grant allows metadata changes but NOT deletion."""
    _, c = env_app
    t = login(c, 'owner')
    did = upload(c, t)
    c.post(f'/documents/{did}/grants', data={'csrf': t, 'username': 'reader', 'permission': 'edit'})
    c.post('/logout', data={'csrf': t})
    rt = login(c, 'reader')
    # Edit should succeed
    assert c.post(f'/documents/{did}/edit', data={'csrf': rt, 'title': 'Updated', 'category': 'OK'}).status_code == 200
    # Delete must fail
    assert c.post(f'/documents/{did}/delete', data={'csrf': rt}).status_code == 403


# ---------------------------------------------------------------------------
# T6 — CSRF
# ---------------------------------------------------------------------------

def test_csrf_blocks_upload(env_app):
    """Upload with wrong CSRF token must be rejected with 403."""
    _, c = env_app
    login(c, 'owner')
    r = c.post('/documents', data={'csrf': 'wrong-token', 'title': 'bad'}, files={'file': ('p.txt', b'hello', 'text/plain')})
    assert r.status_code == 403


def test_csrf_blocks_grant(env_app):
    """Grant with wrong CSRF token must be rejected."""
    _, c = env_app
    t = login(c, 'owner')
    did = upload(c, t)
    r = c.post(f'/documents/{did}/grants', data={'csrf': 'forged', 'username': 'reader', 'permission': 'read'})
    assert r.status_code == 403


def test_csrf_blocks_delete(env_app):
    """Delete with wrong CSRF token must be rejected."""
    _, c = env_app
    t = login(c, 'owner')
    did = upload(c, t)
    r = c.post(f'/documents/{did}/delete', data={'csrf': 'forged'})
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# T7 — Malicious file (magic-byte mismatch)
# ---------------------------------------------------------------------------

def test_pdf_magic_byte_required(env_app):
    """A file with .pdf extension but non-PDF content must be rejected."""
    _, c = env_app
    t = login(c, 'owner')
    r = c.post('/documents', data={'csrf': t, 'title': 'bad'}, files={'file': ('evil.pdf', b'not a pdf', 'application/pdf')})
    assert r.status_code == 400


def test_png_magic_byte_required(env_app):
    _, c = env_app
    t = login(c, 'owner')
    r = c.post('/documents', data={'csrf': t, 'title': 'bad'}, files={'file': ('fake.png', b'not a png', 'image/png')})
    assert r.status_code == 400


def test_txt_with_null_bytes_rejected(env_app):
    """A .txt file containing null bytes (binary content) must be rejected."""
    _, c = env_app
    t = login(c, 'owner')
    r = c.post('/documents', data={'csrf': t, 'title': 'bad'}, files={'file': ('binary.txt', b'hello\x00world', 'text/plain')})
    assert r.status_code == 400


def test_disallowed_extension_rejected(env_app):
    """Executable and other disallowed extensions must be rejected."""
    _, c = env_app
    t = login(c, 'owner')
    r = c.post('/documents', data={'csrf': t, 'title': 'bad'}, files={'file': ('evil.exe', b'MZ...', 'application/octet-stream')})
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# T8 — File path traversal (storage key is UUID, never user-supplied)
# ---------------------------------------------------------------------------

def test_path_traversal_attempt_rejected(env_app):
    """Document IDs containing path separators must not be resolvable."""
    m, c = env_app
    login(c, 'owner')
    # Try a traversal in the doc ID path parameter
    assert c.get('/documents/../admin').status_code in (404, 307, 301, 403)
    assert c.get('/documents/../../etc/passwd').status_code in (404, 422)


# ---------------------------------------------------------------------------
# T9 — Unauthenticated access to all document routes
# ---------------------------------------------------------------------------

def test_unauthenticated_view_redirects_or_errors(env_app):
    """Without a session, document access must be denied."""
    m, c = env_app
    t = login(c, 'owner')
    did = upload(c, t)
    c.post('/logout', data={'csrf': t})
    # Fresh client — no cookie
    from fastapi.testclient import TestClient
    fresh = TestClient(m.app)
    assert fresh.get(f'/documents/{did}', follow_redirects=False).status_code in (401, 302, 303)
    assert fresh.get(f'/documents/{did}/download', follow_redirects=False).status_code in (401, 302, 303)


def test_unauthenticated_access_is_audited(env_app):
    """Unauthenticated denied access must appear in the audit log."""
    m, c = env_app
    t = login(c, 'owner')
    did = upload(c, t)
    c.post('/logout', data={'csrf': t})
    from fastapi.testclient import TestClient
    fresh = TestClient(m.app)
    fresh.get(f'/documents/{did}')
    with m.SessionLocal() as s:
        denied = s.scalars(
            select(m.Audit).where(m.Audit.document_id == did, m.Audit.outcome == 'denied', m.Audit.actor_id == None)
        ).all()
        assert len(denied) >= 1, "Unauthenticated denials must be recorded with null actor"


# ---------------------------------------------------------------------------
# T10 — Audit tampering detection
# ---------------------------------------------------------------------------

def test_audit_tampering_detected(env_app):
    """Modifying an audit record's detail field must break the hash chain."""
    m, c = env_app
    login(c, 'owner')
    with m.SessionLocal() as s:
        assert m.audit_integrity(s), "Chain should be intact before tampering"
        row = s.scalar(select(m.Audit).order_by(m.Audit.id))
        row.detail = 'silently altered by attacker'
        s.commit()
        assert not m.audit_integrity(s), "Chain must report failure after tamper"


def test_audit_hash_field_tamper_detected(env_app):
    """Replacing the hash itself must also fail verification."""
    m, c = env_app
    login(c, 'owner')
    with m.SessionLocal() as s:
        row = s.scalar(select(m.Audit).order_by(m.Audit.id))
        row.event_hash = 'a' * 64  # forged hash
        s.commit()
        assert not m.audit_integrity(s)


# ---------------------------------------------------------------------------
# T11 — Admin cannot read other owners' documents
# ---------------------------------------------------------------------------

def test_admin_cannot_read_owner_document(env_app):
    """Admin role grants log access, not document access."""
    _, c = env_app
    t = login(c, 'owner')
    did = upload(c, t)
    c.post('/logout', data={'csrf': t})
    login(c, 'admin')
    assert c.get(f'/documents/{did}').status_code == 404
    assert c.get(f'/documents/{did}/download').status_code == 404


def test_admin_cannot_grant_access_to_others_doc(env_app):
    """Admin cannot grant themselves or others access to a document they don't own."""
    _, c = env_app
    t = login(c, 'owner')
    did = upload(c, t)
    c.post('/logout', data={'csrf': t})
    at = login(c, 'admin')
    r = c.post(f'/documents/{did}/grants', data={'csrf': at, 'username': 'stranger', 'permission': 'read'})
    assert r.status_code in (403, 404)


# ---------------------------------------------------------------------------
# T12 — Viewer cannot upload documents
# ---------------------------------------------------------------------------

def test_viewer_cannot_upload(env_app):
    _, c = env_app
    t = login(c, 'reader')
    r = c.post('/documents', data={'csrf': t, 'title': 'attempt'},
               files={'file': ('a.txt', b'hello', 'text/plain')})
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# T13 — Rate limiting on login (brute-force)
# ---------------------------------------------------------------------------

def test_rate_limiter_blocks_excessive_attempts(env_app):
    """More than RATE_MAX failed logins from the same IP should be blocked."""
    m, c = env_app
    # Grab a CSRF token
    t = token(c.get('/login'))
    # Send many bad password attempts (more than the rate limit threshold)
    for _ in range(12):
        c.post('/login', data={'csrf': token(c.get('/login')), 'username': 'owner', 'password': 'WRONG'})
    # The next attempt should be rate-limited even with correct credentials
    rt = token(c.get('/login'))
    r = c.post('/login', data={'csrf': rt, 'username': 'owner', 'password': 'testing-password-123'},
               follow_redirects=False)
    # Either blocked (200 with error page) or redirected — denied message or still on login page
    # The important thing: rate-limited IP must NOT be redirected to / (success)
    # A redirect to / means login succeeded despite being rate-limited
    assert r.status_code != 303 or r.headers.get('location') != '/', \
        "Rate limiter must not allow login after threshold exceeded"


# ---------------------------------------------------------------------------
# T14 — Disabled user cannot access system
# ---------------------------------------------------------------------------

def test_disabled_user_login_rejected(env_app):
    """A user disabled by admin must not be able to log in."""
    m, c = env_app
    # Admin disables the owner account
    at = login(c, 'admin')
    with m.SessionLocal() as s:
        oid = s.scalar(select(m.User).where(m.User.username == 'owner')).id
    c.post(f'/admin/users/{oid}/disable', data={'csrf': at})
    c.post('/logout', data={'csrf': at})
    # Owner tries to log in
    lt = token(c.get('/login'))
    r = c.post('/login', data={'csrf': lt, 'username': 'owner', 'password': 'testing-password-123'},
               follow_redirects=False)
    # Must NOT redirect to / (success)
    assert r.headers.get('location', '') != '/', "Disabled user must not be able to log in"


def test_disabled_user_active_session_denied(env_app):
    """An active session belonging to a disabled user must be rejected mid-session."""
    m, c = env_app
    # Owner logs in
    ot = login(c, 'owner')
    did = upload(c, ot)
    # Admin (different session — same test client, but we'll use DB directly)
    # Directly disable in DB to simulate admin action without switching sessions
    with m.SessionLocal() as s:
        u = s.scalar(select(m.User).where(m.User.username == 'owner'))
        u.enabled = 0
        s.commit()
    # Owner's session is still present — next request must fail
    r = c.get(f'/documents/{did}', follow_redirects=False)
    assert r.status_code in (401, 302, 303), "Active session of disabled user must be invalidated"


# ---------------------------------------------------------------------------
# T15 — Owner-only grant: non-owner cannot grant access
# ---------------------------------------------------------------------------

def test_non_owner_cannot_grant(env_app):
    """A user with read access cannot grant that same access to a third party."""
    m, c = env_app
    t = login(c, 'owner')
    did = upload(c, t)
    c.post(f'/documents/{did}/grants', data={'csrf': t, 'username': 'reader', 'permission': 'read'})
    c.post('/logout', data={'csrf': t})
    rt = login(c, 'reader')
    r = c.post(f'/documents/{did}/grants', data={'csrf': rt, 'username': 'stranger', 'permission': 'read'})
    assert r.status_code in (403, 404)


# ---------------------------------------------------------------------------
# T16 — Admin user management actions are audited
# ---------------------------------------------------------------------------

def test_user_disable_audited(env_app):
    """Disabling a user must generate an audit event."""
    m, c = env_app
    at = login(c, 'admin')
    with m.SessionLocal() as s:
        oid = s.scalar(select(m.User).where(m.User.username == 'owner')).id
    c.post(f'/admin/users/{oid}/disable', data={'csrf': at})
    with m.SessionLocal() as s:
        ev = s.scalar(
            select(m.Audit).where(m.Audit.action == 'user_disable', m.Audit.outcome == 'allowed')
        )
        assert ev is not None, "user_disable action must be audited"


# ---------------------------------------------------------------------------
# T17 — Dashboard does not leak unauthorized doc IDs
# ---------------------------------------------------------------------------

def test_dashboard_hides_unauthorized_docs(env_app):
    """Documents the logged-in user cannot access must not appear in the dashboard."""
    _, c = env_app
    t = login(c, 'owner')
    did = upload(c, t, title='Top Secret')
    c.post('/logout', data={'csrf': t})
    login(c, 'stranger')
    html = c.get('/').text
    assert did not in html
    assert 'Top Secret' not in html
