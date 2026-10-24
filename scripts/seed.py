"""Create demo accounts and their sample document in the configured database."""
import os
import uuid
from collections.abc import Mapping

from sqlalchemy import select


ACCOUNT_CONFIG = (
    ('admin_demo', 'admin', 'SEED_ADMIN_PASSWORD'),
    ('owner_demo', 'owner', 'SEED_OWNER_PASSWORD'),
    ('viewer_demo', 'viewer', 'SEED_VIEWER_PASSWORD'),
    ('other_demo', 'viewer', 'SEED_OTHER_PASSWORD'),
)
SAMPLE_TITLE = 'Welcome to TrustVault'
SAMPLE_CONTENT = b'TrustVault sample file\nThis is non-confidential demonstration content.\n'


def validate_passwords(passwords: Mapping[str, str]) -> None:
    values = []
    for _, _, env_name in ACCOUNT_CONFIG:
        password = passwords.get(env_name)
        if not isinstance(password, str) or len(password) < 12:
            raise ValueError(f'{env_name} must contain at least 12 characters.')
        values.append(password)
    if len(set(values)) != len(values):
        raise ValueError('Each demo account must have a different password.')


def seed_demo_data(passwords: Mapping[str, str]) -> dict[str, int]:
    validate_passwords(passwords)
    from app.main import (
        Document,
        Grant,
        PH,
        SessionLocal,
        User,
        audit,
        blob_storage,
    )

    added_users = 0
    added_document = 0
    added_grant = 0
    uploaded_blob_key = None
    committed = False

    try:
        with SessionLocal() as db:
            users = {}
            for username, role, env_name in ACCOUNT_CONFIG:
                user = db.scalar(select(User).where(User.username == username))
                if user is None:
                    user = User(
                        username=username,
                        role=role,
                        password_hash=PH.hash(passwords[env_name]),
                        enabled=1,
                    )
                    db.add(user)
                    added_users += 1
                elif user.role != role or not user.enabled:
                    raise RuntimeError(
                        f'Existing demo account {username} has a different role or is disabled; '
                        'review it manually before initialization.'
                    )
                users[username] = user

            db.flush()
            owner = users['owner_demo']
            viewer = users['viewer_demo']
            document = db.scalar(
                select(Document).where(
                    Document.title == SAMPLE_TITLE,
                    Document.owner_id == owner.id,
                )
            )

            if document is None:
                doc_id = str(uuid.uuid4())
                storage_key = str(uuid.uuid4())
                blob_storage.put(storage_key, SAMPLE_CONTENT)
                uploaded_blob_key = storage_key
                document = Document(
                    id=doc_id,
                    owner_id=owner.id,
                    title=SAMPLE_TITLE,
                    category='Getting Started',
                    original_name='welcome.txt',
                    media_type='text/plain',
                    storage_key=storage_key,
                    size=len(SAMPLE_CONTENT),
                )
                db.add(document)
                db.flush()
                audit(
                    db, owner.id, 'upload', doc_id, 'allowed',
                    'Seeded sample document', commit=False,
                )
                added_document = 1

            grant = db.scalar(
                select(Grant).where(
                    Grant.document_id == document.id,
                    Grant.user_id == viewer.id,
                )
            )
            if grant is None:
                db.add(Grant(
                    document_id=document.id,
                    user_id=viewer.id,
                    permission='read',
                ))
                audit(
                    db, owner.id, 'grant', document.id, 'allowed',
                    'viewer_demo:read (seed)', commit=False,
                )
                added_grant = 1

            if blob_storage.get(document.storage_key) is None:
                if uploaded_blob_key is None:
                    blob_storage.put(document.storage_key, SAMPLE_CONTENT)
                    uploaded_blob_key = document.storage_key

            db.commit()
            committed = True
    except Exception:
        if uploaded_blob_key is not None and not committed:
            blob_storage.delete(uploaded_blob_key)
        raise

    return {
        'users_added': added_users,
        'document_added': added_document,
        'grant_added': added_grant,
    }


def verify_demo_data() -> dict[str, int]:
    from app.main import Document, Grant, SessionLocal, User, blob_storage

    with SessionLocal() as db:
        users = {
            username: db.scalar(select(User).where(User.username == username))
            for username, _, _ in ACCOUNT_CONFIG
        }
        if any(user is None or not user.enabled for user in users.values()):
            raise RuntimeError('Demo account verification failed.')
        if any(user.role != role for user, (_, role, _) in zip(
            users.values(), ACCOUNT_CONFIG
        )):
            raise RuntimeError('Demo account role verification failed.')

        owner = users['owner_demo']
        viewer = users['viewer_demo']
        document = db.scalar(
            select(Document).where(
                Document.title == SAMPLE_TITLE,
                Document.owner_id == owner.id,
            )
        )
        if document is None:
            raise RuntimeError('Sample document verification failed.')
        grant = db.scalar(
            select(Grant).where(
                Grant.document_id == document.id,
                Grant.user_id == viewer.id,
                Grant.permission.in_(('read', 'edit')),
            )
        )
        if grant is None:
            raise RuntimeError('Sample document grant verification failed.')
        content = blob_storage.get(document.storage_key)
        if content != SAMPLE_CONTENT:
            raise RuntimeError('Sample document storage verification failed.')

        return {'users_verified': len(users), 'documents_verified': 1, 'grants_verified': 1}


def main() -> int:
    passwords = {env_name: os.environ.get(env_name, '') for _, _, env_name in ACCOUNT_CONFIG}
    try:
        counts = seed_demo_data(passwords)
        verify_demo_data()
    except (ValueError, RuntimeError) as error:
        raise SystemExit(str(error)) from None
    print(
        'Seed complete: '
        f"{counts['users_added']} accounts, "
        f"{counts['document_added']} document, "
        f"{counts['grant_added']} grant added; verification passed."
    )
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
