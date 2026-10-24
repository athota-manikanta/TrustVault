# TrustVault — Project Write-up

## What I built

TrustVault is a server-rendered FastAPI application for sharing documents with individually-named access grants and a tamper-evident audit trail. Document access is enforced server-side on every request. Allowed and denied activity is recorded in an HMAC-keyed hash chain; edited fields and broken links can be detected, but the database is not an immutable audit archive.

The stack: **Python / FastAPI**, **SQLAlchemy 2.x**, **SQLite** with WAL mode for local development and tests, **Jinja2 templates**, **Argon2** password hashing, and **Starlette** sessions. PostgreSQL is supported for the hosted architecture. No JavaScript frameworks or client-side routing are used; authorization decisions remain server-side.

---

## Permission model

There are three roles:

| Role | What they can do |
|---|---|
| **Owner** | Upload documents, set metadata, grant named read or edit access to any user, revoke that access, delete their own documents |
| **Viewer** | View and download documents they have been explicitly granted |
| **Admin** | View the audit log and activity dashboard, manage user accounts (create, disable, change role). **Cannot read, download, or modify documents belonging to others unless explicitly granted access like any other user.** |

Every document endpoint calls `access()` or `owner_access()` as the first substantive step. These helpers:

1. Call `current_user()`, which fetches the user row from the database on every request and checks the `enabled` flag — no caching of security state in the session cookie.
2. Check whether the document exists and whether the user is authorized (owner, or has a matching row in the `grants` table).
3. Write an audit event with `outcome='denied'` before raising any HTTP exception.

Successful document and user mutations append their success audit event in the same database transaction. A database/audit failure rolls the mutation back. PostgreSQL uses a transaction-scoped advisory lock to serialize audit-chain appends.

Unauthorized document requests return **404**, not 403, so an attacker cannot confirm a document's existence from the response code.

---

## What I deliberately did not build

| Feature | Why omitted |
|---|---|
| MFA / TOTP | Out of scope; a username+password system is the stated requirement |
| Password reset / email | No email transport in scope; admins reset access by creating new accounts |
| File versioning | Not required; noted in README and THREATS.md |
| Antivirus scanning | Magic bytes + extension allowlist is the stated validation check; full AV would need a sidecar service and is explicitly flagged as a residual risk in T7 |
| Provider-backed object storage | A Supabase Storage adapter and private-bucket preflight are implemented; real provider access and persistence were not exercised by the automated tests or independently verified in this audit |
| Share links with expiry | Bearer links are a known risk for document systems; the problem statement does not require them and omitting them eliminates T3-class attacks |
| Groups / folder inheritance | Per-document named-user grants are simpler to reason about and audit. Groups add complexity and confusion about who has access. |
| JWT / bearer tokens | Eliminated persistent tokens that could be replayed after revocation |

---

## How I used AI

I used an AI assistant throughout the build. My workflow:

1. Prepend a security-focused system prompt to every session that required the AI to reason about attacker goals before suggesting any authorisation change.
2. Ask for a feature or component.
3. Read the output, trace every call site, and check it against the requirements.
4. Correct anything wrong before committing.

This approach produced working code quickly, but it did not eliminate errors — particularly in security-sensitive areas. Detailed examples of what went wrong and how I corrected it are in `PROMPTS.md`. The most significant failure was Entry 5: the AI suggested adding `if user.role == 'admin': return True` inside the `authorized()` function, which would have given admins automatic access to all documents — directly violating the core requirement. I rejected it entirely.

The AI also produced a correct-looking but subtly broken audit chain (Entry 3: timezone naive vs aware datetime mismatch causing the integrity check to always return `False`), placed the rate-limiter check after the database query instead of before it (Entry 4), and used the deprecated `session.query()` API (Entry 2). In each case the fix required understanding the requirement, not just reading the code.

---

## What is unfinished

- **No MFA.** A password-only system is the stated scope but is insufficient for truly sensitive data.
- **In-memory rate limiter.** It resets on process restart and does not work across multiple workers. Production needs Redis or a WAF-level solution. Documented as T12.
- **Audit chain is not immutable.** Removing the last records cannot be detected without an externally stored checkpoint. An attacker with both the database and application secret can recompute valid hashes. An external append-only sink and independently stored checkpoints are needed in production. Documented as T11.
- **No file versioning.** Metadata edits are supported; replacing file content is not.
- **SQLite for local use.** PostgreSQL is supported via `DATABASE_URL`; appends use a transaction advisory lock, but production multi-worker PostgreSQL behavior has not been integration-tested (T25).
- **No antivirus.** Magic bytes + extension allowlist is the implemented check. Documented as T7.

---

## If I had another week

1. Deploy earlier and test the live system as an attacker.
2. Add a Redis-backed rate limiter and session store.
3. Implement an external audit sink (write events to an append-only log service alongside the database chain).
4. Add group-based grants as an optional extension to per-document named grants.
5. Run live multi-worker PostgreSQL tests and configure an independently stored audit checkpoint.
