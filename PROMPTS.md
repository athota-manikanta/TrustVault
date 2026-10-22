# PROMPTS.md — AI assistance journal

This file documents every significant interaction with AI tools during the development of TrustVault. Each entry records: what was asked, what the AI produced, what was wrong or needed fixing, and how it was corrected.

---

## Entry 1 — 2026-10-21 — Initial scaffold

**What I asked:** "Build a secure document-sharing platform in FastAPI. It needs: three roles (admin, owner, viewer), per-document read/edit grants, audit logs, CSRF protection, and server-side access checks on every route."

**What the AI produced:** A working FastAPI application with SQLAlchemy models, Argon2 password hashing, a hash-chain audit log, CSRF middleware, and server-rendered Jinja2 templates. The structure was sound.

**What was wrong:**
1. The audit `hmac.new()` call was missing — it was written as `hmac.new(SECRET.encode(), ...)` but `hmac.new` is not the correct Python API. The correct call is `hmac.new(SECRET.encode(), msg.encode(), hashlib.sha256)`.
2. The `Content-Security-Policy` header allowed `'unsafe-inline'` scripts, which would defeat XSS protection.
3. The rate limiter was completely absent despite "brute-force login" being in THREATS.md as an unmitigated risk.

**What I did instead:**
- Corrected the HMAC call and verified it with the `test_audit_tampering_detected` test.
- Removed `'unsafe-inline'` from CSP; the app uses no inline scripts (drag-and-drop logic was moved to an external `app.js` file).
- Implemented an in-memory sliding-window rate limiter (`_rate_check`, `_rate_reset`) with a 10-attempt/5-minute window and a 15-minute block.

**Commit:** `0cf2af0` (Initialize TrustVault application) — HMAC correction, CSP fix, and rate limiter are all present in the initial commit because these were caught and fixed during code review before the first push. The rate limiter placement specifically (`_rate_check` before any DB access) can be verified at `app/main.py` in `login()`.

---

## Entry 2 — 2026-10-21 — Access control: the `authorized()` function

**What I asked:** "Write a Python function that checks whether a user has at least `read` or `edit` access to a document. The owner always has full access. Others need a matching row in the `grants` table."

**What the AI produced:**
```python
def authorized(session, doc, user, level='read'):
    if doc.owner_id == user.id: return True
    grants = session.query(Grant).filter_by(document_id=doc.id, user_id=user.id).all()
    if level == 'read':
        return any(g.permission in ('read', 'edit') for g in grants)
    return any(g.permission == 'edit' for g in grants)
```

**What was wrong:**
The logic has a subtle semantic error: it checks `g.permission in ('read', 'edit')` for read, but it also returns `True` for an edit-level check only when `g.permission == 'edit'`. This is correct in isolation, but the AI used `session.query()` (legacy SQLAlchemy 1.x style) rather than `select()` (2.x style), which is inconsistent with the rest of the codebase and will eventually emit deprecation warnings.

More importantly, I verified that the function is called with the correct `level` argument at every route. The AI did not check this — it only wrote the function. I manually traced every call site:
- `download()` → `access(..., 'read', 'download')` ✓
- `edit_document()` → `access(..., 'edit', 'edit')` ✓  
- `doc_detail()` → `access(..., 'read', 'view')` ✓

**What I did instead:** Rewrote using SQLAlchemy 2.x `select()`, simplified the read-check expression, and added the trace above to confirm all call sites pass the correct level. The test `test_read_grant_cannot_edit_metadata` verifies this at runtime.

**Commit:** `0cf2af0` — `authorized()` at line 252 of `app/main.py` uses `select()` throughout. The call-site trace is documented above; the test `test_read_grant_cannot_edit_metadata` in `tests/test_threats.py` provides runtime verification.

---

## Entry 3 — 2026-10-21 — Audit log integrity: hash chain design

**What I asked:** "I need an append-only audit log where tampering can be detected. Each event should include a hash of the previous event so the chain can be verified. Use HMAC-SHA256 with the application secret."

**What the AI produced:** A hash-chain implementation that was structurally correct. However, it had two issues:

1. **Timezone handling:** The `occurred_at` field was stored in SQLite as a naive datetime (no timezone). When replaying the chain, the verification function compared it using `.isoformat()`, but SQLite returns naive datetimes, so the stored ISO string (without `+00:00`) didn't match what the verifier computed (which assumed UTC and appended `+00:00`). This caused `audit_integrity()` to return `False` on a chain with no actual tampering.

2. **Concurrent write race:** The AI's version fetched the last event's hash with `SELECT ... ORDER BY id DESC LIMIT 1` and then inserted a new event. On PostgreSQL with multiple workers, two events could read the same `prev_hash` before either commits, breaking the chain. The AI did not mention this risk at all.

**What was wrong, specifically (about access control / audit):**
The AI was confident the chain was correct. It was not. The timezone bug would cause legitimate integrity checks to fail, and on a deployed system this would make the "ALERT" banner appear constantly, training administrators to ignore it — exactly the wrong behaviour for a tamper-evidence system.

**What I did instead:**
- Added timezone normalization in `audit_integrity()`: `a.occurred_at.replace(tzinfo=timezone.utc) if a.occurred_at.tzinfo is None else a.occurred_at`.
- Documented the multi-worker race in THREATS.md (T25) as a known accepted risk for the current SQLite single-worker deployment, with a note that an advisory lock or outbox pattern is needed for PostgreSQL.
- Enabled SQLite WAL mode (`PRAGMA journal_mode=WAL`) to reduce write contention in single-worker scenarios.

**Commit:** `0cf2af0` — timezone fix at `audit_integrity()` (line 235 of `app/main.py`); WAL mode at the SQLite `connect` event listener (line 143). T25 in `THREATS.md` documents the accepted race risk.

---

## Entry 4 — 2026-10-21 — Rate limiting implementation

**What I asked:** "Implement a login rate limiter that blocks an IP after 10 failed attempts in 5 minutes, with a 15-minute lockout. It should be thread-safe."

**What the AI produced:** A working sliding-window rate limiter using a `defaultdict(list)` of timestamps and a `Lock`. Structurally correct.

**What was wrong:**
1. The AI placed the rate check **after** the database query to look up the user. This means that even when rate-limited, we still hit the database and execute Argon2 verification. An attacker doing a credential stuffing attack would still cause significant CPU load even when "blocked". The check must happen **before** any DB work.
2. The AI did not reset the attempt counter on successful login. This means a legitimate user who made 9 failed attempts (e.g. wrong caps lock) and then succeeded would still be locked out 1 attempt later. I chose to reset on success (`_rate_reset`) which is the standard UX approach.
3. The rate limiter was per-process in-memory. The AI did not mention this limitation. Documented in THREATS.md (T12).

**What I did instead:** Moved `_rate_check(ip)` to be the first thing called in the `login()` route handler, before any DB access. Added `_rate_reset(ip)` on successful login.

**Commit:** `0cf2af0` — `_rate_check` is the first call inside `login()` (before the `session.scalar` user lookup). `_rate_reset` is called on the success path. Test: `test_rate_limiter_blocks_excessive_attempts` in `tests/test_threats.py`.

---

## Entry 5 — 2026-10-21 — Access control: admin role boundaries

**What I asked:** "Make sure the admin role cannot read documents owned by other users. Admin should only see the audit log and manage users."

**What the AI produced:** The AI suggested adding `if user.role == 'admin': return True` inside the `authorized()` function. This would give admins automatic access to all documents.

**What was wrong — specifically about access control:**
This is the most dangerous suggestion in the entire session. The problem statement explicitly says: *"An administrator ... is not automatically granted access to documents belonging to others."* An AI confident wrong answer here would create a critical vulnerability. If the evaluator logged in as admin and tried to fetch any document UUID directly, they would succeed — violating requirement #1 of the problem statement.

The test `test_admin_cannot_read_owner_document` and `test_admin_cannot_grant_access_to_others_doc` exist precisely to catch this. I rejected the AI's suggestion entirely.

**What I did instead:** Left `authorized()` unchanged — it only checks ownership or named grants. The admin role is checked only in the `/admin` and `/admin/users*` route handlers. I manually verified that no document route has an `if admin` bypass. The test suite confirms this.

**Commit:** `0cf2af0` — `authorized()` at line 252 of `app/main.py` has no role-based shortcut. The admin panel routes check `user.role != 'admin'` in isolation. Tests `test_admin_cannot_read_owner_document` and `test_admin_cannot_grant_access_to_others_doc` in `tests/test_threats.py` verify this.

---

## Entry 6 — 2026-10-21 — User management endpoints

**What I asked:** "Add admin endpoints to create users, disable/enable accounts, and change roles. Disabled users should be blocked on every request, not just at login."

**What the AI produced:** Endpoints that checked `user.role == 'admin'` in each handler, which is correct. However, it also suggested storing `user.enabled` in the session cookie so the server didn't need to check the DB each time — "for performance".

**What was wrong:**
Caching the `enabled` flag in the session cookie defeats the requirement that *"taking access away works immediately"*. If the flag is cached in the cookie, a disabled user whose cookie hasn't expired can continue to access the system for up to one hour. This directly contradicts requirement #3 of the problem statement.

**What I did instead:** `current_user()` fetches the user from the database on every request and checks `user.enabled`. The DB query is fast (primary key lookup). Session cookies store only the user ID. The test `test_disabled_user_active_session_denied` verifies that disabling a user mid-session takes effect on the very next request.

**Commit:** `0cf2af0` — `current_user()` at line 193 of `app/main.py` returns `None` if `user.enabled` is falsy, checked on every request. Session stores only `uid` (an integer). Test: `test_disabled_user_active_session_denied` in `tests/test_threats.py`.

---

## Prompts and context reused across the session

The following system prompt was prepended to all AI sessions for this project:

> "You are helping build a security-critical document-sharing platform. Before suggesting any change to authorisation, access control, or audit logging, reason explicitly about: (1) what an attacker could do if this code is wrong, (2) whether the change widens access without an explicit grant, and (3) whether the change could silence the audit log. Never suggest caching security state in client-controlled storage."

This prompt was helpful in reducing confident-but-wrong suggestions on access control. It did not prevent the admin-bypass suggestion in Entry 5, which shows that even a well-prompted AI will suggest security holes. The correction had to come from understanding the requirements.
