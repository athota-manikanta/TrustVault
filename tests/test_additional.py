"""
test_additional.py — extra coverage for health endpoint, date filters,
admin user management and audit of admin actions.

These tests fill gaps identified during a post-development review. Each maps
to at least one entry in THREATS.md or the ten official requirements.
"""
from datetime import date, timedelta
from sqlalchemy import select
from .conftest import login, token, upload


# ---------------------------------------------------------------------------
# Health endpoint is public
# ---------------------------------------------------------------------------

def test_health_endpoint_public(env_app):
    """Health endpoint must respond 200 without authentication."""
    _, c = env_app
    r = c.get('/health')
    assert r.status_code == 200
    assert r.json()['status'] == 'ok'


# ---------------------------------------------------------------------------
# Dashboard date-range filter (requirement: search by date)
# ---------------------------------------------------------------------------

def test_dashboard_date_range_filter(env_app):
    """Date from/to query params must restrict the visible document list."""
    _, c = env_app
    t = login(c, 'owner')
    did = upload(c, t, title='Dated doc')
    today = date.today().isoformat()
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    tomorrow = (date.today() + timedelta(days=1)).isoformat()
    # Uploaded today — visible in [yesterday, tomorrow]
    assert did in c.get(f'/?from={yesterday}&to={tomorrow}').text
    # Future start date — must not appear
    assert did not in c.get(f'/?from={tomorrow}').text


# ---------------------------------------------------------------------------
# Admin user management — create, disable, role change (T16)
# ---------------------------------------------------------------------------

def test_admin_create_and_disable_user(env_app):
    """Admin can create a user; disabling them sets enabled=0 in the database."""
    m, c = env_app
    at = login(c, 'admin')
    r = c.post('/admin/users/create', data={
        'csrf': at,
        'username': 'newperson',
        'password': 'SecurePass123!',
        'role': 'viewer',
    })
    assert r.status_code in (200, 303)
    with m.SessionLocal() as s:
        new_user = s.scalar(select(m.User).where(m.User.username == 'newperson'))
        assert new_user is not None
        assert new_user.role == 'viewer'
        uid = new_user.id
    c.post(f'/admin/users/{uid}/disable', data={'csrf': at})
    with m.SessionLocal() as s:
        assert s.get(m.User, uid).enabled == 0


def test_admin_change_role_is_audited(env_app):
    """Changing a user role must write a role_change event to the audit log."""
    m, c = env_app
    at = login(c, 'admin')
    with m.SessionLocal() as s:
        oid = s.scalar(select(m.User).where(m.User.username == 'owner')).id
    c.post(f'/admin/users/{oid}/change-role', data={'csrf': at, 'role': 'viewer'})
    with m.SessionLocal() as s:
        ev = s.scalar(
            select(m.Audit).where(
                m.Audit.action == 'role_change',
                m.Audit.outcome == 'allowed',
            )
        )
        assert ev is not None, "role_change must write an audit event"


def test_admin_cannot_demote_own_account(env_app):
    """An admin cannot change their own role away from admin."""
    m, c = env_app
    at = login(c, 'admin')
    with m.SessionLocal() as s:
        aid = s.scalar(select(m.User).where(m.User.username == 'admin')).id
    r = c.post(f'/admin/users/{aid}/change-role', data={'csrf': at, 'role': 'viewer'})
    assert r.status_code == 400
    with m.SessionLocal() as s:
        assert s.get(m.User, aid).role == 'admin', "Self-demotion must be rejected"


def test_short_password_rejected_on_create(env_app):
    """Creating a user with a password shorter than 12 characters must return 400."""
    _, c = env_app
    at = login(c, 'admin')
    r = c.post('/admin/users/create', data={
        'csrf': at,
        'username': 'weakuser',
        'password': 'short',
        'role': 'viewer',
    })
    assert r.status_code == 400


def test_duplicate_username_rejected(env_app):
    """Creating a user with an existing username must be rejected gracefully."""
    _, c = env_app
    at = login(c, 'admin')
    r = c.post('/admin/users/create', data={
        'csrf': at,
        'username': 'owner',       # already exists in fixture
        'password': 'ValidPassword99!',
        'role': 'viewer',
    })
    # Should return 200 with an error message, not crash
    assert r.status_code == 200
    assert 'already exists' in r.text.lower() or 'exists' in r.text.lower()
