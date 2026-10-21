import os
import re
import tempfile
from pathlib import Path
import pytest


@pytest.fixture
def env_app(monkeypatch):
    """
    Isolated test fixture: fresh SQLite DB + temp blob storage per test.
    Rate-limit state is reset between tests to prevent cross-test pollution.
    """
    import sys
    # Force fresh import of app.main so DB / config is re-read each test.
    for key in list(sys.modules):
        if key == 'app.main':
            sys.modules.pop(key)

    with tempfile.TemporaryDirectory() as t:
        monkeypatch.setenv('DATABASE_URL', 'sqlite:///' + str(Path(t) / 'test.db'))
        monkeypatch.setenv('TRUSTVAULT_STORAGE', str(Path(t) / 'blobs'))
        monkeypatch.setenv('TRUSTVAULT_SECRET', 'test-secret-for-hmac-32chars-long!!')
        monkeypatch.setenv('TRUSTVAULT_HTTPS', '0')

        import app.main as m

        # Reset in-memory rate limiter between tests
        m._login_attempts.clear()
        m._blocked_until.clear()

        with m.SessionLocal() as s:
            for username, role in [
                ('owner',   'owner'),
                ('reader',  'viewer'),
                ('stranger','viewer'),
                ('admin',   'admin'),
            ]:
                s.add(m.User(
                    username=username,
                    role=role,
                    password_hash=m.PH.hash('testing-password-123'),
                ))
            s.commit()

        from fastapi.testclient import TestClient
        with TestClient(m.app) as client:
            yield m, client

        m.engine.dispose()


def token(resp):
    """Extract the CSRF token from an HTML response."""
    match = re.search(r'name="csrf" value="([^"]+)"', resp.text)
    assert match, f"No CSRF token in response (status {resp.status_code})"
    return match.group(1)


def login(client, name, password='testing-password-123'):
    """Log in as *name* and return the CSRF token from the resulting page."""
    t = token(client.get('/login'))
    r = client.post(
        '/login',
        data={'csrf': t, 'username': name, 'password': password},
        follow_redirects=True,
    )
    assert r.status_code == 200, f"Login failed for {name!r}: {r.status_code}"
    return token(r)


def upload(client, t, title='Secret roadmap'):
    """Upload a plain-text document and return its UUID."""
    r = client.post(
        '/documents',
        data={'csrf': t, 'title': title, 'category': 'Business'},
        files={'file': ('private.txt', b'company private note', 'text/plain')},
        follow_redirects=False,
    )
    assert r.status_code == 303, f"Upload failed: {r.status_code} — {r.text[:200]}"
    return r.headers['location'].split('/')[-1]
