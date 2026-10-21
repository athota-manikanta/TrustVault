"""Create demo accounts (change passwords before exposing a public deployment)."""
import os
from sqlalchemy import select
from app.main import SessionLocal, User, PH, Document, Grant, STORAGE, audit
import uuid

accounts = [
    ('admin_demo', 'admin', 'SEED_ADMIN_PASSWORD'),
    ('owner_demo', 'owner', 'SEED_OWNER_PASSWORD'),
    ('viewer_demo', 'viewer', 'SEED_VIEWER_PASSWORD'),
    ('other_demo', 'viewer', 'SEED_OTHER_PASSWORD'),
]
with SessionLocal() as db:
    for name, role, env in accounts:
        password = os.getenv(env)
        if not password or len(password) < 12:
            raise SystemExit(f'Set {env} to a unique password with at least 12 characters before running seed.')
        if db.scalar(select(User).where(User.username == name)):
            print(f'Existing: {name} (not overwritten)')
            continue
        db.add(User(username=name, role=role, password_hash=PH.hash(password)))
        print(f'Added: {name} ({role})')
    db.commit()

# Seed a harmless document and a reader grant for the evaluation walkthrough.
with SessionLocal() as db:
    owner = db.scalar(select(User).where(User.username == 'owner_demo'))
    reader = db.scalar(select(User).where(User.username == 'viewer_demo'))
    existing = db.scalar(select(Document).where(Document.title == 'Welcome to TrustVault', Document.owner_id == owner.id))
    if not existing:
        doc_id, key = str(uuid.uuid4()), str(uuid.uuid4())
        content = b'TrustVault sample file\nThis is non-confidential demonstration content.\n'
        (STORAGE / key).write_bytes(content)
        db.add(Document(id=doc_id, owner_id=owner.id, title='Welcome to TrustVault',
            category='Getting Started', original_name='welcome.txt', media_type='text/plain',
            storage_key=key, size=len(content)))
        db.add(Grant(document_id=doc_id, user_id=reader.id, permission='read'))
        db.commit()
        audit(db, owner.id, 'upload', doc_id, 'allowed', 'Seeded sample document')
        audit(db, owner.id, 'grant', doc_id, 'allowed', 'viewer_demo:read (seed)')
        print('Added harmless welcome document shared with viewer_demo')
