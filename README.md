# TrustVault — Secure Document Sharing & Audit System

A responsive FastAPI application for individually authorized document access, immediate grant revocation and audited activity. Built as an AI-assisted starting implementation for the Snovasys Fresher Hiring Challenge. **You must personally review, test, document, and deploy your own submission.**

## Functionality
- Four seed accounts covering administrator, owner and viewers, with hashed passwords, plus a harmless sample document shared with the demonstration viewer.
- Upload/search/organize by title, category, owner, and starting date.
- Owner-managed named-user **read** or **edit** grants; revoke access immediately on the next server request.
- Private opaque file storage, without static-file routes; download checks authorization on each request.
- Owner deletes, audit of allowed and denied document operations, admin activity dashboard and keyed hash-chain integrity indicator.
- CSRF tokens for write forms, session cookies, restrictive security headers, file extension/signature and size checks.
- Mutations and their success audit events share one database transaction; PostgreSQL audit appends are serialized with a transaction-scoped advisory lock.
- The **administrator does not automatically read other owners' documents**. Admins monitor activity and may own their own files.

## Clean-clone setup (Windows)

From the repository root, either use the local launcher:
```
start_windows.bat
```

It creates `.venv`, installs `requirements.txt`, seeds local-only demo accounts, and starts Uvicorn. The launcher prints locally generated passwords and stores them in `.local-demo-credentials.json`, which is ignored by Git. Do not use these local passwords in the hosted application. If the local database already exists but the ignored credential file does not, the launcher stops rather than changing existing accounts.

For a manual setup, use PowerShell:
```
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```
Set `TRUSTVAULT_SECRET` and four different `SEED_*_PASSWORD` values in the current shell, then run:
```
.\.venv\Scripts\python.exe -m scripts.seed
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```
Open http://127.0.0.1:8000. The seed accounts are `admin_demo` (administrator), `owner_demo` (owner), `viewer_demo` (viewer), and `other_demo` (viewer). Their passwords are the values you assign; use unique passwords of at least 12 characters. Never commit or publish them. `.env.example` is a placeholder reference; the application reads environment variables and does not automatically load that file.

## Run tests
```
python -m pytest -q
```
Tests are isolated in a temporary SQLite DB and private file directory. They do not operate on your local project data.

## Deployment

The public application is hosted at [https://trustvault-ohg9.onrender.com/](https://trustvault-ohg9.onrender.com/). The deployment architecture for this project is Render for FastAPI and its Jinja2 pages, Neon PostgreSQL for relational data, and Supabase Storage for private document objects. `render.yaml`, `app/main.py`, and `app/storage.py` describe the application-side configuration. Render's local filesystem is ephemeral; database and document persistence must come from the external providers.

**Render Free startup:** Free web services may spin down after inactivity. The first request can take longer while the service starts; wait for it to become available and retry if the initial page shows a startup screen.

**Limited live check (2026-10-24):** unauthenticated `GET /` returned 303, `GET /health` returned 200, and `GET /login` returned 200 with the TrustVault login form. No login or state-changing workflow was performed for this audit. These responses do not independently verify Render environment settings, Neon connectivity or persistence, Supabase bucket privacy, document sharing/revocation, or restart persistence.

To connect or initialize the deployment:

1. In Render, use the repository's Blueprint (`render.yaml`) and configure the external values as secret environment variables. Keep `TRUSTVAULT_HTTPS=1` and use a stable, random `TRUSTVAULT_SECRET`.
2. Set Render's `DATABASE_URL` to the Neon **pooled** PostgreSQL connection string. Keep the TLS parameters (`sslmode=require` and, if supplied, `channel_binding=require`).
3. Create a Supabase Storage bucket named `trustvault-documents` with public access disabled. Configure `SUPABASE_URL`, `SUPABASE_STORAGE_BUCKET`, and the server-side `SUPABASE_SECRET_KEY` in Render. Never expose this key to browser code or commit it.
4. Configure distinct passwords of at least 12 characters for the four demo identities, then deploy and wait for Render's `/health` check.
5. From a trusted local Windows computer with this clone and dependencies installed, run `.\.venv\Scripts\python.exe .\scripts\initialize_cloud.py` in PowerShell. This is a local command; no paid Render shell is needed. It securely prompts for the **direct** Neon connection string, Supabase URL/key, the existing Render application secret, and the four demo passwords. It checks database connectivity/schema permission and that the configured bucket is private before initializing the schema and idempotently creating missing demo accounts, the sample document, and its viewer grant. It does not change Render settings or overwrite existing demo-account passwords.
6. For a complete live acceptance check, separately verify the owner → viewer grant → download → revoke → denied next request and corresponding audit event. Also verify the object cannot be fetched from a public URL and data survives a service restart. These stateful checks were not completed in this audit.

The demo identities are `admin_demo` (administrator), `owner_demo` (owner), `viewer_demo` (viewer), and `other_demo` (viewer). No passwords are included in this repository. Provide evaluator credentials only through the submission channel permitted by the challenge, and rotate them after judging.

## Verification record

- **Local tests:** `python -m pytest -q` — **98 passed, 1 warning** on 2026-10-24. Tests use isolated SQLite databases and temporary local blob directories; no PostgreSQL integration test was run. The warning is Starlette's deprecation notice about using `httpx` with `starlette.testclient`.
- **Automated workflow evidence:** tests exercise owner upload, named read/edit grants, viewer download, immediate revocation against an existing session, denial and audit records, and storage access ordering using isolated SQLite/filesystem fixtures. They do not constitute a live provider integration test.
- **Live checks:** only the three unauthenticated GET requests listed above are verified. Authentication, permissions, private storage, persistence, and live audit integrity remain unverified.
- **Other verification gaps:** a fresh clone was not used to test setup; no migration framework is present; and no demo video is present in tracked files or was verified.
- **Runtime:** Render starts the service with `uvicorn app.main:app --host 0.0.0.0 --port $PORT`; local development can use `python -m uvicorn app.main:app --reload`.
- **Operations:** the login limiter is in-memory and per-process. The audit chain is tamper-evident, not immutable; production incident retention should use an independent append-only sink and external checkpoints.

## Permission model
Owner: CRUD on their own documents; grant/revoke access. Editor: view, download, edit metadata of a named document. Viewer: view and download an explicitly granted document. Administrator: admin log/dashboard and ability to own their own documents; **not** automatic access to documents belonging to others. Every data route independently calls a server authorization helper, including downloads.

## Architectural limits / known gaps
- Metadata edits supported; replacing file content / versioning not implemented.
- Date filtering is a *starting date* filter. No PDF text search.
- JWT/share links deliberately omitted. This eliminates persistent bearer download URLs; existing sessions still require fresh permission checks.
- Database auditing is keyed tamper-evident **only**, not immutable. Someone able to alter the database can remove the tail of the chain without detection; someone with the database and application secret can rewrite valid hashes. Prefer remote append-only logging with external checkpoints in production.
- PostgreSQL audit appends use a transaction-scoped advisory lock, but a live PostgreSQL multi-worker integration test has not been run. SQLite WAL is intended for local/single-process use, not concurrent multi-process production.
- There is no formal schema migration framework. SQLAlchemy `metadata.create_all()` initializes missing tables during application import; planned production schema changes need a separately reviewed migration process.
- Deletion spans PostgreSQL and object storage: the document and audit event commit before the stored object is deleted. A storage error can leave an orphaned object; no retry/outbox mechanism is implemented.
- No user self-registration, password reset, virus scanning, or quotas. Supabase Storage is implemented, but hosted provider configuration and persistence have not been independently verified in this audit. The login limiter is in-memory/per-process; use a shared service or edge control for multi-worker production.
- Minimal format checks do not certify uploaded files as malware-free. Only use harmless test documents.

## API and role authorization
| Endpoint | Method | Allowed |
|---|---|---|
| `/`, `/login`, `/health` | GET | Dashboard: authenticated only; login & health public |
| `/login`, `/logout` | POST | Login public with CSRF; logout active session |
| `/documents/new` | GET | owner/admin |
| `/documents` | POST | owner/admin; CSRF; file validation |
| `/documents/{id}` | GET | owner, named read/editor grant |
| `/documents/{id}/download` | GET | owner, named read/editor grant |
| `/documents/{id}/edit` | POST | owner or named editor; CSRF |
| `/documents/{id}/grants` | POST | owner only; CSRF |
| `/documents/{id}/revoke/{user_id}` | POST | owner only; CSRF |
| `/documents/{id}/delete` | POST | owner only; CSRF |
| `/admin` | GET | administrator only |

## Schema
`users(id, username, password_hash, role, enabled)`; `documents(id, owner_id, title, category, original_name, media_type, storage_key, size, created_at, updated_at)`; `grants(id, document_id, user_id, permission)`; `audit_events(id, occurred_at, actor_id, action, document_id, outcome, detail, prev_hash, event_hash)`.

## Five-minute demo outline
0:00 architecture and role model; 0:45 owner uploads; 1:30 grant viewer read; 2:15 viewer downloads; 2:40 unauthorized user denied by direct URL; 3:15 owner revokes and the existing viewer session is denied; 3:45 admin reviews the activity and denial log; 4:20 run the security tests and discuss residual risks; 4:50 summarize what was and was not verified.

## Simplest Windows local start (recommended for beginners)
Unzip the project, open the inner `trustvault_project` folder, and double-click `start_windows.bat`. It creates a virtual environment, installs dependencies, creates random local-only passwords, prints the four usernames/passwords, and starts the web app at `http://127.0.0.1:8000`. Keep the black window open while using the site. On later starts the same local passwords will be reused. The local credentials file (`.local-demo-credentials.json`) is excluded from Git; never upload it or use these demo credentials in a public deployment. If a database already exists but the credential file does not, the launcher stops to prevent an accidental mismatch. An internet connection is needed on first installation.


## Additional documentation

- `REQUIREMENTS_CHECKLIST.md` — crosswalk to the ten official requirements.
- `API_ACCESS.md` — endpoint-by-endpoint permissions.
- `THREATS.md` — full threat model with mitigations and residual risks.
- `PROMPTS.md` — existing AI-assistance journal; its historical entries have not been independently verified during this change.
- `tests/test_extended.py` — extra authorization, admin, search and upload-validation cases.
- Workspace search includes a date-to filter, and the activity center shows actor names and denied-attempt counts.

**Assessment caution:** This project is a functioning local reference implementation, not a guarantee of passing a security assessment. Before presenting, you must run it yourself, validate the live deployment, understand and own any modifications, and make only truthful claims about your work and AI usage. The Windows launcher is for LOCAL practice, not production hosting.
