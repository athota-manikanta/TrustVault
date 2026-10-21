"""TrustVault: server-side document ACLs, private blob storage and audited events."""
import hashlib
import hmac
import os
import secrets
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from fastapi import FastAPI, Request, Form, UploadFile, File, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine, String, Integer, DateTime, ForeignKey, Text, select, or_, event, Boolean
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker, Session
from starlette.middleware.sessions import SessionMiddleware
import io

BASE = Path(__file__).resolve().parent.parent
STORAGE = Path(os.environ.get('TRUSTVAULT_STORAGE', str(BASE / 'private_storage'))).resolve()
STORAGE.mkdir(parents=True, exist_ok=True)
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///' + str(BASE / 'trustvault.db'))
if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql+psycopg://', 1)
if DATABASE_URL.startswith('postgresql://'):
    DATABASE_URL = DATABASE_URL.replace('postgresql://', 'postgresql+psycopg://', 1)
SECRET = os.environ.get('TRUSTVAULT_SECRET', '')
if not SECRET:
    SECRET = secrets.token_urlsafe(48)
    print('WARNING: using ephemeral secret. Set TRUSTVAULT_SECRET in production.')
COOKIE_SECURE = os.environ.get('TRUSTVAULT_HTTPS', '0') == '1'
MAX_FILE = 8 * 1024 * 1024
ALLOWED = {
    '.pdf': {'application/pdf'},
    '.txt': {'text/plain'},
    '.png': {'image/png'},
    '.jpg': {'image/jpeg'},
    '.jpeg': {'image/jpeg'},
    '.docx': {'application/vnd.openxmlformats-officedocument.wordprocessingml.document'},
}
PH = PasswordHasher()

# ---------------------------------------------------------------------------
# Rate limiter – in-memory, per-IP, thread-safe
# ---------------------------------------------------------------------------
_rate_lock = Lock()
_login_attempts: dict[str, list[float]] = defaultdict(list)
_blocked_until: dict[str, float] = {}
RATE_WINDOW = 300      # seconds: rolling window
RATE_MAX = 10          # max attempts in window before block
BLOCK_SECONDS = 900    # 15-minute block on threshold breach


def _rate_check(ip: str) -> bool:
    """Return True if the request is allowed, False if blocked."""
    now = time.monotonic()
    with _rate_lock:
        # Clear expired block first
        if ip in _blocked_until and now >= _blocked_until[ip]:
            del _blocked_until[ip]
            _login_attempts[ip] = []
        if ip in _blocked_until:
            return False  # still blocked
        # Prune old timestamps
        _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < RATE_WINDOW]
        if len(_login_attempts[ip]) >= RATE_MAX:
            _blocked_until[ip] = now + BLOCK_SECONDS
            return False
        _login_attempts[ip].append(now)
        return True


def _rate_reset(ip: str):
    """Clear attempt history on successful login (optional – be conservative)."""
    with _rate_lock:
        _login_attempts[ip] = []
        _blocked_until.pop(ip, None)


# ---------------------------------------------------------------------------
# Database models
# ---------------------------------------------------------------------------

class BaseModel(DeclarativeBase):
    pass


class User(BaseModel):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(60), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default='viewer')
    enabled: Mapped[int] = mapped_column(Integer, default=1)


class Document(BaseModel):
    __tablename__ = 'documents'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    title: Mapped[str] = mapped_column(String(150))
    category: Mapped[str] = mapped_column(String(60), default='General')
    original_name: Mapped[str] = mapped_column(String(180))
    media_type: Mapped[str] = mapped_column(String(80))
    storage_key: Mapped[str] = mapped_column(String(36))
    size: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    owner: Mapped[User] = relationship()


class Grant(BaseModel):
    __tablename__ = 'grants'
    id: Mapped[int] = mapped_column(primary_key=True)
    document_id: Mapped[str] = mapped_column(ForeignKey('documents.id', ondelete='CASCADE'), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    permission: Mapped[str] = mapped_column(String(8))


class Audit(BaseModel):
    __tablename__ = 'audit_events'
    id: Mapped[int] = mapped_column(primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    actor_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    action: Mapped[str] = mapped_column(String(50))
    document_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    outcome: Mapped[str] = mapped_column(String(12))
    detail: Mapped[str] = mapped_column(String(200), default='')
    prev_hash: Mapped[str] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64))


engine = create_engine(
    DATABASE_URL,
    connect_args={'check_same_thread': False} if DATABASE_URL.startswith('sqlite') else {},
    pool_pre_ping=True,
)
if DATABASE_URL.startswith('sqlite'):
    @event.listens_for(engine, 'connect')
    def configure_sqlite(conn, _):
        cursor = conn.cursor()
        cursor.execute('PRAGMA foreign_keys=ON')
        cursor.execute('PRAGMA journal_mode=WAL')
        cursor.close()

SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
BaseModel.metadata.create_all(engine)

app = FastAPI(title='TrustVault', version='1.1.0', docs_url=None, redoc_url=None)
app.mount('/static', StaticFiles(directory=str(Path(__file__).parent / 'static')), name='static')
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET,
    https_only=COOKIE_SECURE,
    same_site='strict',
    session_cookie='tv_session',
    max_age=3600,
)
templates = Jinja2Templates(directory=str(Path(__file__).parent / 'templates'))


@app.middleware('http')
async def safe_headers(request, call_next):
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; style-src 'self' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; script-src 'self'; "
        "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    )
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=()'
    return response


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def db():
    with SessionLocal() as session:
        yield session


def current_user(request: Request, session: Session):
    uid = request.session.get('uid')
    if type(uid) is not int:
        return None
    user = session.get(User, uid)
    return user if user and user.enabled else None


def context(request, **kwargs):
    return {'request': request, 'csrf': request.session.get('csrf', ''), **kwargs}


def csrf_check(request, token):
    expected = request.session.get('csrf', '')
    if not expected or not hmac.compare_digest(expected, token):
        raise HTTPException(403, 'Invalid form security token')


def new_csrf(request):
    if not request.session.get('csrf'):
        request.session['csrf'] = secrets.token_urlsafe(32)


def redirect(path):
    return RedirectResponse(path, status_code=303)


def audit(session, actor, action, document_id=None, outcome='allowed', detail=''):
    """Append an HMAC-chained audit event. Transaction-serialised on SQLite."""
    last = session.scalar(select(Audit).order_by(Audit.id.desc()).limit(1))
    prev = last.event_hash if last else '0' * 64
    stamp = datetime.now(timezone.utc)
    encoded = '|'.join((prev, stamp.isoformat(), str(actor or ''), action, str(document_id or ''), outcome, detail[:200]))
    digest = hmac.new(SECRET.encode(), encoded.encode(), hashlib.sha256).hexdigest()
    session.add(Audit(
        occurred_at=stamp, actor_id=actor, action=action,
        document_id=document_id, outcome=outcome, detail=detail[:200],
        prev_hash=prev, event_hash=digest,
    ))
    session.commit()


def audit_integrity(session) -> bool:
    """Verify every link in the HMAC hash chain. Returns False on any tampering."""
    prev = '0' * 64
    for a in session.scalars(select(Audit).order_by(Audit.id)).all():
        timestamp = (
            a.occurred_at.replace(tzinfo=timezone.utc).isoformat()
            if a.occurred_at.tzinfo is None
            else a.occurred_at.isoformat()
        )
        payload = '|'.join((prev, timestamp, str(a.actor_id or ''), a.action, str(a.document_id or ''), a.outcome, a.detail))
        expected = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if a.prev_hash != prev or not hmac.compare_digest(a.event_hash, expected):
            return False
        prev = a.event_hash
    return True


def authorized(session, doc, user, level='read') -> bool:
    """Return True if *user* has at least *level* access to *doc*."""
    if doc.owner_id == user.id:
        return True
    grants = session.scalars(select(Grant).where(Grant.document_id == doc.id, Grant.user_id == user.id)).all()
    return any(g.permission == 'edit' or (level == 'read' and g.permission == 'read') for g in grants)


def access(request, session, doc_id, level='read', action='access'):
    """Authenticate, authorise and audit in one call. Raises HTTP 401/404."""
    user = current_user(request, session)
    if not user:
        audit(session, None, action, doc_id, 'denied', 'unauthenticated')
        raise HTTPException(401, 'Authentication required')
    doc = session.get(Document, doc_id)
    if not doc or not authorized(session, doc, user, level):
        audit(session, user.id, action, doc_id, 'denied', 'not found or no permission')
        raise HTTPException(404, 'Document not found')
    return user, doc


def owner_access(request, session, doc_id, action):
    """Require the caller to be the document owner."""
    user, doc = access(request, session, doc_id, 'read', action)
    if doc.owner_id != user.id:
        audit(session, user.id, action, doc_id, 'denied', 'owner required')
        raise HTTPException(403, 'Owner required')
    return user, doc


def page(request, session, name, **kwargs):
    new_csrf(request)
    user = current_user(request, session)
    return templates.TemplateResponse(request, name, context(request, user=user, **kwargs))


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.client.host if request.client else '0.0.0.0'


# ---------------------------------------------------------------------------
# Public / auth routes
# ---------------------------------------------------------------------------

@app.get('/health')
def health():
    return {'status': 'ok'}


@app.get('/', response_class=HTMLResponse)
def index(request: Request, session: Session = Depends(db)):
    user = current_user(request, session)
    if not user:
        return redirect('/login')
    q = request.query_params.get('q', '').strip()[:150]
    category = request.query_params.get('category', '').strip()[:60]
    owner = request.query_params.get('owner', '').strip()[:60]
    from_date = request.query_params.get('from', '').strip()[:10]
    to_date = request.query_params.get('to', '').strip()[:10]
    docs = session.scalars(select(Document).order_by(Document.created_at.desc())).all()
    allowed = []
    for d in docs:
        if not authorized(session, d, user):
            continue
        if q and q.lower() not in d.title.lower():
            continue
        if category and category.lower() not in d.category.lower():
            continue
        if owner and owner.lower() not in d.owner.username.lower():
            continue
        if from_date and d.created_at.date().isoformat() < from_date:
            continue
        if to_date and d.created_at.date().isoformat() > to_date:
            continue
        allowed.append({
            'doc': d,
            'can_edit': authorized(session, d, user, 'edit'),
            'is_owner': d.owner_id == user.id,
        })
    return page(
        request, session, 'dashboard.html',
        documents=allowed, q=q, category=category, owner=owner,
        from_date=from_date, to_date=to_date,
        owned_count=sum(x['is_owner'] for x in allowed),
        shared_count=sum(not x['is_owner'] for x in allowed),
    )


@app.get('/login', response_class=HTMLResponse)
def login_page(request: Request, session: Session = Depends(db)):
    return page(request, session, 'login.html')


@app.post('/login')
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf: str = Form(...),
    session: Session = Depends(db),
):
    csrf_check(request, csrf)
    ip = _client_ip(request)

    # Rate-limit check BEFORE any DB work (prevents enumeration timing too)
    if not _rate_check(ip):
        audit(session, None, 'login', None, 'denied', f'rate-limited ip={ip}')
        return page(request, session, 'login.html', error='Too many failed attempts. Please wait before trying again.')

    user = session.scalar(select(User).where(User.username == username.strip().lower()))
    try:
        valid = bool(user and user.enabled and PH.verify(user.password_hash, password))
    except (VerifyMismatchError, VerificationError):
        valid = False

    if not valid:
        audit(session, user.id if user else None, 'login', None, 'denied', f'invalid credentials ip={ip}')
        return page(request, session, 'login.html', error='Invalid username or password.')

    # Successful login — reset rate limiter for this IP
    _rate_reset(ip)
    request.session.clear()
    request.session['uid'] = user.id
    request.session['csrf'] = secrets.token_urlsafe(32)
    audit(session, user.id, 'login', None, 'allowed', f'ip={ip}')
    return redirect('/')


@app.post('/logout')
def logout(request: Request, csrf: str = Form(...), session: Session = Depends(db)):
    csrf_check(request, csrf)
    user = current_user(request, session)
    if user:
        audit(session, user.id, 'logout')
    request.session.clear()
    return redirect('/login')


# ---------------------------------------------------------------------------
# Document routes
# ---------------------------------------------------------------------------

@app.get('/documents/new', response_class=HTMLResponse)
def upload_page(request: Request, session: Session = Depends(db)):
    user = current_user(request, session)
    if not user:
        return redirect('/login')
    if user.role not in ('owner', 'admin'):
        raise HTTPException(403)
    return page(request, session, 'upload.html')


@app.post('/documents')
async def upload(
    request: Request,
    title: str = Form(...),
    category: str = Form('General'),
    csrf: str = Form(...),
    file: UploadFile = File(...),
    session: Session = Depends(db),
):
    csrf_check(request, csrf)
    user = current_user(request, session)
    if not user:
        raise HTTPException(401)
    if user.role not in ('owner', 'admin'):
        raise HTTPException(403)

    title = title.strip()
    category = category.strip() or 'General'
    filename = Path(file.filename or '').name
    suffix = Path(filename).suffix.lower()

    if not title or len(title) > 150 or len(category) > 60 or not filename or suffix not in ALLOWED:
        audit(session, user.id, 'upload', None, 'denied', 'invalid metadata/extension')
        raise HTTPException(400, 'Invalid title, category or file type')

    raw = await file.read(MAX_FILE + 1)
    if not raw or len(raw) > MAX_FILE:
        audit(session, user.id, 'upload', None, 'denied', 'file empty or too large')
        raise HTTPException(413, 'File must be between 1 byte and 8 MB')

    # Magic-byte validation
    signatures = {
        '.pdf': raw.startswith(b'%PDF-'),
        '.png': raw.startswith(b'\x89PNG\r\n\x1a\n'),
        '.jpg': raw.startswith(b'\xff\xd8\xff'),
        '.jpeg': raw.startswith(b'\xff\xd8\xff'),
        '.txt': b'\x00' not in raw,
        '.docx': raw.startswith(b'PK\x03\x04'),   # ZIP-based OOXML
    }
    if not signatures[suffix]:
        audit(session, user.id, 'upload', None, 'denied', 'file signature mismatch')
        raise HTTPException(400, 'File content does not match the extension')

    key = str(uuid.uuid4())
    doc_id = str(uuid.uuid4())
    path = STORAGE / key
    with open(path, 'xb') as fp:
        fp.write(raw)

    doc = Document(
        id=doc_id, owner_id=user.id, title=title, category=category,
        original_name=filename[:180],
        media_type=next(iter(ALLOWED[suffix])),
        storage_key=key, size=len(raw),
    )
    session.add(doc)
    session.commit()
    audit(session, user.id, 'upload', doc_id, 'allowed', filename[:100])
    return redirect('/documents/' + doc_id)


@app.get('/documents/{doc_id}', response_class=HTMLResponse)
def doc_detail(request: Request, doc_id: str, session: Session = Depends(db)):
    user, doc = access(request, session, doc_id, 'read', 'view')
    audit(session, user.id, 'view', doc_id)
    grants = (
        session.scalars(select(Grant).where(Grant.document_id == doc_id)).all()
        if doc.owner_id == user.id else []
    )
    users = (
        {u.id: u.username for u in session.scalars(select(User)).all()}
        if doc.owner_id == user.id else {}
    )
    return page(
        request, session, 'document.html',
        doc=doc,
        is_owner=doc.owner_id == user.id,
        can_edit=authorized(session, doc, user, 'edit'),
        grants=grants, users=users,
    )


@app.get('/documents/{doc_id}/download')
def download(request: Request, doc_id: str, session: Session = Depends(db)):
    user, doc = access(request, session, doc_id, 'read', 'download')
    path = STORAGE / doc.storage_key
    if not path.is_file():
        audit(session, user.id, 'download', doc_id, 'denied', 'blob missing')
        raise HTTPException(404, 'Stored file unavailable')
    audit(session, user.id, 'download', doc_id)
    return FileResponse(
        path,
        media_type='application/octet-stream',
        filename=doc.original_name,
        content_disposition_type='attachment',
        headers={'Cache-Control': 'no-store'},
    )


@app.post('/documents/{doc_id}/edit')
def edit_document(
    request: Request,
    doc_id: str,
    title: str = Form(...),
    category: str = Form('General'),
    csrf: str = Form(...),
    session: Session = Depends(db),
):
    csrf_check(request, csrf)
    user, doc = access(request, session, doc_id, 'edit', 'edit')
    if not title.strip() or len(title.strip()) > 150 or len(category) > 60:
        raise HTTPException(400)
    old_title = doc.title
    doc.title = title.strip()
    doc.category = category.strip() or 'General'
    doc.updated_at = datetime.now(timezone.utc)
    session.commit()
    audit(session, user.id, 'edit', doc_id, 'allowed', f'title: {old_title!r} → {doc.title!r}')
    return redirect('/documents/' + doc_id)


@app.post('/documents/{doc_id}/grants')
def grant(
    request: Request,
    doc_id: str,
    username: str = Form(...),
    permission: str = Form(...),
    csrf: str = Form(...),
    session: Session = Depends(db),
):
    csrf_check(request, csrf)
    user, doc = owner_access(request, session, doc_id, 'grant')
    target = session.scalar(select(User).where(User.username == username.strip().lower()))
    if not target or not target.enabled or target.id == user.id or permission not in ('read', 'edit'):
        audit(session, user.id, 'grant', doc_id, 'denied', 'invalid recipient/permission')
        raise HTTPException(400, 'Invalid recipient or permission')
    existing = session.scalar(select(Grant).where(Grant.document_id == doc_id, Grant.user_id == target.id))
    if existing:
        existing.permission = permission
    else:
        session.add(Grant(document_id=doc_id, user_id=target.id, permission=permission))
    session.commit()
    audit(session, user.id, 'grant', doc_id, 'allowed', f'{target.username}:{permission}')
    return redirect('/documents/' + doc_id)


@app.post('/documents/{doc_id}/revoke/{target_id}')
def revoke(
    request: Request,
    doc_id: str,
    target_id: int,
    csrf: str = Form(...),
    session: Session = Depends(db),
):
    csrf_check(request, csrf)
    user, doc = owner_access(request, session, doc_id, 'revoke')
    existing = session.scalar(select(Grant).where(Grant.document_id == doc_id, Grant.user_id == target_id))
    if existing:
        revoked_username = session.scalar(select(User.username).where(User.id == target_id)) or f'uid:{target_id}'
        session.delete(existing)
        session.commit()
        audit(session, user.id, 'revoke', doc_id, 'allowed', f'user:{revoked_username}')
    return redirect('/documents/' + doc_id)


@app.post('/documents/{doc_id}/delete')
def delete_document(request: Request, doc_id: str, csrf: str = Form(...), session: Session = Depends(db)):
    csrf_check(request, csrf)
    user, doc = owner_access(request, session, doc_id, 'delete')
    blob = STORAGE / doc.storage_key
    title = doc.title
    for grant_row in session.scalars(select(Grant).where(Grant.document_id == doc_id)).all():
        session.delete(grant_row)
    session.delete(doc)
    session.commit()
    audit(session, user.id, 'delete', doc_id, 'allowed', title)
    blob.unlink(missing_ok=True)
    return redirect('/')


# ---------------------------------------------------------------------------
# Admin routes
# ---------------------------------------------------------------------------

@app.get('/admin', response_class=HTMLResponse)
def admin_page(request: Request, session: Session = Depends(db)):
    user = current_user(request, session)
    if not user:
        raise HTTPException(401)
    if user.role != 'admin':
        audit(session, user.id, 'admin_view', None, 'denied')
        raise HTTPException(403)

    # Filters
    action_filter = request.query_params.get('action', '').strip()[:50]
    outcome_filter = request.query_params.get('outcome', '').strip()[:12]
    actor_filter = request.query_params.get('actor', '').strip()[:60]

    q = select(Audit).order_by(Audit.id.desc())
    if action_filter:
        q = q.where(Audit.action == action_filter)
    if outcome_filter:
        q = q.where(Audit.outcome == outcome_filter)
    events = session.scalars(q.limit(200)).all()

    actor_names = {u.id: u.username for u in session.scalars(select(User)).all()}

    # Filter by actor name if given
    if actor_filter:
        target_ids = {uid for uid, uname in actor_names.items() if actor_filter.lower() in uname.lower()}
        events = [e for e in events if e.actor_id in target_ids]

    denied_count = session.query(Audit).filter(Audit.outcome == 'denied').count()
    total_events = session.query(Audit).count()

    return page(
        request, session, 'admin.html',
        events=events,
        integrity=audit_integrity(session),
        docs_count=session.query(Document).count(),
        users_count=session.query(User).count(),
        actor_names=actor_names,
        denied_count=denied_count,
        total_events=total_events,
        action_filter=action_filter,
        outcome_filter=outcome_filter,
        actor_filter=actor_filter,
    )


@app.get('/admin/audit-export')
def export_audit(request: Request, session: Session = Depends(db)):
    """Download the full audit log as CSV for offline analysis."""
    user = current_user(request, session)
    if not user:
        raise HTTPException(401)
    if user.role != 'admin':
        audit(session, user.id, 'audit_export', None, 'denied', 'non-admin')
        raise HTTPException(403)

    actor_names = {u.id: u.username for u in session.scalars(select(User)).all()}
    events = session.scalars(select(Audit).order_by(Audit.id)).all()

    lines = ['id,occurred_at,actor,action,document_id,outcome,detail,event_hash\n']
    for e in events:
        actor_name = actor_names.get(e.actor_id, '') if e.actor_id else 'anonymous'
        row = ','.join([
            str(e.id),
            e.occurred_at.isoformat(),
            actor_name,
            e.action,
            e.document_id or '',
            e.outcome,
            '"' + e.detail.replace('"', '""') + '"',
            e.event_hash,
        ])
        lines.append(row + '\n')

    audit(session, user.id, 'audit_export', None, 'allowed', f'{len(events)} rows')
    content = ''.join(lines)
    return StreamingResponse(
        io.BytesIO(content.encode()),
        media_type='text/csv',
        headers={'Content-Disposition': 'attachment; filename="trustvault-audit.csv"', 'Cache-Control': 'no-store'},
    )


@app.get('/admin/users', response_class=HTMLResponse)
def admin_users(request: Request, session: Session = Depends(db)):
    user = current_user(request, session)
    if not user:
        raise HTTPException(401)
    if user.role != 'admin':
        audit(session, user.id, 'admin_users_view', None, 'denied')
        raise HTTPException(403)
    users = session.scalars(select(User).order_by(User.id)).all()
    return page(request, session, 'users.html', users=users)


@app.post('/admin/users/{target_id}/disable')
def disable_user(request: Request, target_id: int, csrf: str = Form(...), session: Session = Depends(db)):
    csrf_check(request, csrf)
    user = current_user(request, session)
    if not user:
        raise HTTPException(401)
    if user.role != 'admin':
        raise HTTPException(403)
    target = session.get(User, target_id)
    if not target:
        raise HTTPException(404)
    if target.id == user.id:
        raise HTTPException(400, 'Cannot disable your own account')
    target.enabled = 0
    session.commit()
    audit(session, user.id, 'user_disable', None, 'allowed', f'user:{target.username}')
    return redirect('/admin/users')


@app.post('/admin/users/{target_id}/enable')
def enable_user(request: Request, target_id: int, csrf: str = Form(...), session: Session = Depends(db)):
    csrf_check(request, csrf)
    user = current_user(request, session)
    if not user:
        raise HTTPException(401)
    if user.role != 'admin':
        raise HTTPException(403)
    target = session.get(User, target_id)
    if not target:
        raise HTTPException(404)
    target.enabled = 1
    session.commit()
    audit(session, user.id, 'user_enable', None, 'allowed', f'user:{target.username}')
    return redirect('/admin/users')


@app.post('/admin/users/create')
def create_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    csrf: str = Form(...),
    session: Session = Depends(db),
):
    csrf_check(request, csrf)
    user = current_user(request, session)
    if not user:
        raise HTTPException(401)
    if user.role != 'admin':
        raise HTTPException(403)

    username = username.strip().lower()
    role = role.strip()

    if not username or len(username) > 60 or role not in ('admin', 'owner', 'viewer'):
        raise HTTPException(400, 'Invalid username or role')
    if len(password) < 12:
        raise HTTPException(400, 'Password must be at least 12 characters')

    existing = session.scalar(select(User).where(User.username == username))
    if existing:
        users_list = session.scalars(select(User).order_by(User.id)).all()
        return page(request, session, 'users.html', users=users_list, error=f'Username "{username}" already exists')

    new_user = User(username=username, role=role, password_hash=PH.hash(password))
    session.add(new_user)
    session.commit()
    audit(session, user.id, 'user_create', None, 'allowed', f'user:{username} role:{role}')
    return redirect('/admin/users')


@app.post('/admin/users/{target_id}/change-role')
def change_role(
    request: Request,
    target_id: int,
    role: str = Form(...),
    csrf: str = Form(...),
    session: Session = Depends(db),
):
    csrf_check(request, csrf)
    user = current_user(request, session)
    if not user:
        raise HTTPException(401)
    if user.role != 'admin':
        raise HTTPException(403)
    if role not in ('admin', 'owner', 'viewer'):
        raise HTTPException(400, 'Invalid role')
    target = session.get(User, target_id)
    if not target:
        raise HTTPException(404)
    if target.id == user.id and role != 'admin':
        raise HTTPException(400, 'Cannot demote your own admin account')
    old_role = target.role
    target.role = role
    session.commit()
    audit(session, user.id, 'role_change', None, 'allowed', f'user:{target.username} {old_role}→{role}')
    return redirect('/admin/users')
