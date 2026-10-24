"""Interactively initialize TrustVault on Neon and a private Supabase bucket."""
from getpass import getpass
import os
import sys

import httpx
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL

from app.storage import SupabaseBlobStorage
from scripts.check_neon import (
    CONNECT_TIMEOUT_SECONDS,
    ConnectionDiagnosticError,
    check_connection,
    check_host_connectivity,
    classify_connection_error,
    normalize_database_url,
)
from scripts.seed import ACCOUNT_CONFIG, seed_demo_data, validate_passwords, verify_demo_data


def validate_configuration(
    database_url: str,
    supabase_url: str,
    supabase_key: str,
    bucket: str,
    app_secret: str,
    passwords: dict[str, str],
) -> tuple[URL, SupabaseBlobStorage]:
    url = normalize_database_url(database_url)
    if '-pooler.' in (url.host or '').lower():
        raise ValueError(
            'Use the Neon direct connection URL for initialization, not the pooled URL.'
        )
    if not supabase_key.startswith('sb_secret_'):
        raise ValueError('Use a Supabase server-side secret key beginning with sb_secret_.')
    if len(app_secret) < 32:
        raise ValueError('Application secret must be at least 32 characters.')
    validate_passwords(passwords)
    storage = SupabaseBlobStorage(
        supabase_url,
        supabase_key,
        bucket,
        timeout=CONNECT_TIMEOUT_SECONDS,
    )
    return url, storage


def check_schema_permissions(url: URL) -> None:
    url = url.set(query={**url.query, 'connect_timeout': str(CONNECT_TIMEOUT_SECONDS)})
    engine = create_engine(url, echo=False, hide_parameters=True, pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            transaction = connection.begin()
            try:
                connection.execute(text('SET TRANSACTION READ ONLY'))
                can_create_public_schema = connection.execute(
                    text(
                        "SELECT has_schema_privilege(current_user, 'public', 'CREATE')"
                    )
                ).scalar_one()
                if not can_create_public_schema:
                    raise RuntimeError(
                        'Neon role needs CREATE permission on the public schema.'
                    )
            finally:
                transaction.rollback()
    finally:
        engine.dispose()


def verify_remote_prerequisites(url: URL, storage: SupabaseBlobStorage) -> None:
    check_host_connectivity(
        url.host,
        port=url.port or 5432,
        timeout=CONNECT_TIMEOUT_SECONDS,
    )
    check_connection(url)
    check_schema_permissions(url)
    storage.require_private_bucket()


def verify_audit_secret(app_module) -> None:
    with app_module.SessionLocal() as session:
        if not app_module.audit_integrity(session):
            raise RuntimeError(
                'TRUSTVAULT_SECRET does not match the existing audit chain; '
                'use the application secret already configured in Render.'
            )


def prompt_configuration() -> tuple[str, str, str, str, str, dict[str, str]]:
    print('TrustVault cloud initialization. Secret fields are hidden while typing.')
    database_url = getpass('Neon DIRECT PostgreSQL connection string: ')
    supabase_url = input('Supabase project URL: ').strip()
    bucket = input('Private Supabase Storage bucket [trustvault-documents]: ').strip()
    if not bucket:
        bucket = 'trustvault-documents'
    supabase_key = getpass('Supabase secret API key: ')
    app_secret = getpass('Existing Render TRUSTVAULT_SECRET (32+ characters): ')
    passwords = {
        env_name: getpass(f'{username} password (12+ unique characters): ')
        for username, _, env_name in ACCOUNT_CONFIG
    }
    return database_url, supabase_url, supabase_key, bucket, app_secret, passwords


def initialize(
    database_url: str,
    supabase_url: str,
    supabase_key: str,
    bucket: str,
    app_secret: str,
    passwords: dict[str, str],
) -> tuple[dict[str, int], dict[str, int]]:
    direct_url, preflight_storage = validate_configuration(
        database_url,
        supabase_url,
        supabase_key,
        bucket,
        app_secret,
        passwords,
    )
    try:
        verify_remote_prerequisites(direct_url, preflight_storage)
    finally:
        preflight_storage.client.close()

    process_env = {
        key: os.environ.get(key)
        for key in (
            'DATABASE_URL',
            'TRUSTVAULT_STORAGE_BACKEND',
            'SUPABASE_URL',
            'SUPABASE_SECRET_KEY',
            'SUPABASE_STORAGE_BUCKET',
            'TRUSTVAULT_SECRET',
            'TRUSTVAULT_HTTPS',
        )
    }
    configured = {
        'DATABASE_URL': direct_url.render_as_string(hide_password=False),
        'TRUSTVAULT_STORAGE_BACKEND': 'supabase',
        'SUPABASE_URL': supabase_url,
        'SUPABASE_SECRET_KEY': supabase_key,
        'SUPABASE_STORAGE_BUCKET': bucket,
        'TRUSTVAULT_SECRET': app_secret,
        'TRUSTVAULT_HTTPS': '1',
    }
    app_module = None
    try:
        os.environ.update(configured)

        # Importing the app initializes SQLAlchemy metadata on the validated direct Neon connection.
        import app.main as app_module

        verify_audit_secret(app_module)
        counts = seed_demo_data(passwords)
        verified = verify_demo_data()
        return counts, verified
    finally:
        if app_module is not None:
            app_module.blob_storage.client.close()
            app_module.engine.dispose()
            sys.modules.pop('app.main', None)
        for key, original in process_env.items():
            if original is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = original


def main() -> int:
    try:
        inputs = prompt_configuration()
        print('Validating configuration and checking Neon plus private bucket access...')
        counts, verified = initialize(*inputs)
    except EOFError:
        print('Initialization cancelled before database changes.')
        return 2
    except ValueError as error:
        print(f'Configuration invalid: {error}')
        return 2
    except ConnectionDiagnosticError as error:
        print(f'{error.category}: {error.guidance}')
        return 1
    except RuntimeError as error:
        print(f'Initialization stopped: {error}')
        return 1
    except httpx.HTTPError:
        print('Supabase Storage request failed. Check the project URL, secret key, bucket, and network.')
        return 1
    except Exception as error:
        category, guidance = classify_connection_error(error)
        print(f'Initialization failed ({category}). {guidance} No credentials or exception details are shown.')
        return 1

    print(
        'Initialization and verification succeeded: '
        f"{counts['users_added']} users added, "
        f"{counts['document_added']} sample documents added, "
        f"{counts['grant_added']} grants added; "
        f"{verified['users_verified']} accounts, "
        f"{verified['documents_verified']} document, and "
        f"{verified['grants_verified']} grant verified."
    )
    print('Existing demo account passwords are not changed when the script is rerun.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
