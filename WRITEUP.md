# TrustVault — Project Write-up

## What I built

TrustVault is a server-rendered FastAPI application for sharing documents with individually-named access grants and a tamper-evident audit trail. Document access is enforced server-side on every request. Allowed and denied activity is recorded in an HMAC-keyed hash chain; edited fields and broken links can be detected, but the database is not an immutable audit archive.

The stack: **Python / FastAPI**, **SQLAlchemy 2.x**, **SQLite** with WAL mode for local development and tests, **Jinja2 templates**, **Argon2** password hashing, and **Starlette** sessions. PostgreSQL is configured for the hosted architecture, and a Supabase Storage adapter is implemented for private document objects. Provider integration, PostgreSQL behavior, and persistence have not been independently verified end to end. No JavaScript frameworks or client-side routing are used; authorization decisions remain server-side.

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
| Provider-backed object storage | Not omitted: a Supabase Storage adapter and private-bucket preflight are implemented. Real provider access and persistence were not exercised by the automated tests or independently verified in this audit. |
| Share links with expiry | Bearer links are a known risk for document systems; the problem statement does not require them and omitting them eliminates T3-class attacks |
| Groups / folder inheritance | Per-document named-user grants are simpler to reason about and audit. Groups add complexity and confusion about who has access. |
| JWT / bearer tokens | Eliminated persistent tokens that could be replayed after revocation |

---

## AI-assisted development and evidence

AI tools were used during development, but original prompt transcripts are not preserved in this repository. `PROMPTS.md` distinguishes implementation details that can be checked against code, tests, and commits from recollections of AI interactions that lack independent records. In particular, the historical claims in Entries 1, 4, 5, and 6 and the original interaction dates for Entries 2 and 3 remain unverified and require the author's confirmation. The journal does not claim that all entries have independently verified evidence or that it satisfies a required number of documented AI interactions.

The repository does support specific implementation facts, including the current owner/grant authorization checks, read-versus-edit tests, audit-chain timezone handling, and PostgreSQL advisory-lock commit attribution. These facts do not prove what an AI suggested or when. Any account of AI mistakes or corrections should be treated as personal recollection unless supported by authentic records.

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
