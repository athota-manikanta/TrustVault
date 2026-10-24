import pytest
from sqlalchemy import select

from scripts.initialize_cloud import (
    check_schema_permissions,
    validate_configuration,
    verify_audit_secret,
)
from scripts.seed import ACCOUNT_CONFIG, seed_demo_data, verify_demo_data


def credentials():
    return {
        env_name: f'Demo-{index}-Password-2026!'
        for index, (_, _, env_name) in enumerate(ACCOUNT_CONFIG, start=1)
    }


def test_cloud_configuration_requires_direct_neon_and_supabase_secret():
    passwords = credentials()
    url, storage = validate_configuration(
        'postgresql://neon_user:demo_password@ep-example.us-east-2.aws.neon.tech/trustvault'
        '?sslmode=require&channel_binding=require',
        'https://project.supabase.co',
        'sb_secret_example_key',
        'trustvault-documents',
        'application-secret-value-longer-than-thirty-two',
        passwords,
    )
    try:
        assert url.drivername == 'postgresql+psycopg'
        assert '-pooler.' not in url.host
    finally:
        storage.client.close()

    with pytest.raises(ValueError, match='direct connection'):
        validate_configuration(
            'postgresql://neon_user:demo_password@ep-example-pooler.us-east-2.aws.neon.tech/trustvault',
            'https://project.supabase.co',
            'sb_secret_example_key',
            'trustvault-documents',
            'application-secret-value-longer-than-thirty-two',
            passwords,
        )

    with pytest.raises(ValueError, match='sb_secret_'):
        validate_configuration(
            'postgresql://neon_user:demo_password@ep-example.us-east-2.aws.neon.tech/trustvault',
            'https://project.supabase.co',
            'not-a-secret-key',
            'trustvault-documents',
            'application-secret-value-longer-than-thirty-two',
            passwords,
        )


def test_seed_and_verify_are_idempotent(env_app):
    m, _ = env_app
    passwords = credentials()

    first = seed_demo_data(passwords)
    first_verified = verify_demo_data()
    second = seed_demo_data(passwords)
    second_verified = verify_demo_data()

    assert first == {'users_added': 4, 'document_added': 1, 'grant_added': 1}
    assert first_verified == {
        'users_verified': 4,
        'documents_verified': 1,
        'grants_verified': 1,
    }
    assert second == {'users_added': 0, 'document_added': 0, 'grant_added': 0}
    assert second_verified == first_verified

    with m.SessionLocal() as db:
        users = db.scalars(
            select(m.User).where(m.User.username.in_([name for name, _, _ in ACCOUNT_CONFIG]))
        ).all()
        documents = db.scalars(
            select(m.Document).where(m.Document.title == 'Welcome to TrustVault')
        ).all()
        grants = db.scalars(
            select(m.Grant).where(m.Grant.document_id == documents[0].id)
        ).all()
        assert len(users) == 4
        assert len(documents) == 1
        assert len(grants) == 1


def test_seed_requires_distinct_long_passwords_before_database_work():
    passwords = credentials()
    passwords['SEED_VIEWER_PASSWORD'] = passwords['SEED_OWNER_PASSWORD']
    with pytest.raises(ValueError, match='different password'):
        seed_demo_data(passwords)


def test_initializer_rejects_application_secret_that_breaks_audit_chain(env_app):
    m, _ = env_app
    with m.SessionLocal() as db:
        m.audit(db, None, 'initialization-test')

    original_secret = m.SECRET
    m.SECRET = 'different-application-secret'
    try:
        with pytest.raises(RuntimeError, match='does not match'):
            verify_audit_secret(m)
    finally:
        m.SECRET = original_secret


def test_schema_permission_check_is_read_only_and_disposes_engine(monkeypatch):
    observed = {}

    class Result:
        def scalar_one(self):
            return True

    class Transaction:
        def rollback(self):
            observed['rolled_back'] = True

    class Connection:
        def begin(self):
            return Transaction()

        def execute(self, statement):
            observed.setdefault('statements', []).append(str(statement))
            return Result()

    class ConnectionContext:
        def __enter__(self):
            return Connection()

        def __exit__(self, *args):
            return False

    class Engine:
        def connect(self):
            return ConnectionContext()

        def dispose(self):
            observed['disposed'] = True

    def create_engine(url, **kwargs):
        observed['url'] = url
        observed['options'] = kwargs
        return Engine()

    monkeypatch.setattr('scripts.initialize_cloud.create_engine', create_engine)
    from scripts.check_neon import normalize_database_url

    check_schema_permissions(
        normalize_database_url(
            'postgresql://user:password@example.neon.tech/db'
            '?sslmode=require&channel_binding=require'
        )
    )

    assert observed['rolled_back']
    assert observed['disposed']
    assert observed['statements'][0] == 'SET TRANSACTION READ ONLY'
    assert 'has_schema_privilege' in observed['statements'][1]
    assert observed['url'].query['connect_timeout'] == '10'
