# TrustVault — Secure Document Sharing & Audit System

A responsive FastAPI application for individually authorized document access, immediate grant revocation and audited activity. Built as an AI-assisted starting implementation for the Snovasys Fresher Hiring Challenge. **You must personally review, test, document, and deploy your own submission.**

## Functionality
- Four seed accounts covering administrator, owner and viewers, with hashed passwords, plus a harmless sample document shared with the demonstration viewer.
- Upload/search/organize by title, category, owner, and starting date.
- Owner-managed named-user **read** or **edit** grants; revoke access immediately on the next server request.
- Private opaque file storage, without static-file routes; download checks authorization on each request.
- Owner deletes, audit of allowed and denied document operations, admin activity dashboard and keyed hash-chain integrity indicator.
- CSRF tokens for write forms, session cookies, restrictive security headers, file extension/signature and size checks.
- The **administrator does not automatically read other owners' documents**. Admins monitor activity and may own their own files.

## Setup (Windows Command Prompt)
```
py -m venv .venv
.venv\Scripts\activate.bat
python -m pip install -r requirements.txt
```
Set a persistent application secret and four distinct demo account passwords. For Windows CMD, for example:
```
set TRUSTVAULT_SECRET=replace-with-a-long-random-unique-value
set SEED_ADMIN_PASSWORD=use-a-different-long-password-here
set SEED_OWNER_PASSWORD=use-a-different-long-password-here
set SEED_VIEWER_PASSWORD=use-a-different-long-password-here
set SEED_OTHER_PASSWORD=use-a-different-long-password-here
python -m scripts.seed
python -m uvicorn app.main:app --reload
```
Open http://127.0.0.1:8000. Log in with `admin_demo`, `owner_demo`, `viewer_demo`, or `other_demo` using the password YOU assigned to each. **Never publish real passwords in code**. For the required judging demo, use isolated, non-sensitive sample passwords shared securely as prescribed in your submission instructions; rotate after judging.

## Run tests
```
python -m pytest -q
```
Tests are isolated in a temporary SQLite DB and private file directory. They do not operate on your local project data.

## Deployment
- Use a Python host with persistent PostgreSQL and **persistent private storage** (a non-public persistent volume or properly permissioned object storage adapter). Many free application filesystems are ephemeral; this project needs persistent blobs for dependable deployment.
- Configure `DATABASE_URL`, `TRUSTVAULT_SECRET`, `TRUSTVAULT_STORAGE` and `TRUSTVAULT_HTTPS=1`. Ensure the reverse proxy enforces TLS. Do not expose `TRUSTVAULT_STORAGE` as static content.
- Install dependencies: `pip install -r requirements.txt`.
- Seed accounts exactly once using `python -m scripts.seed` with the four passwords configured as private environment variables.
- Start: `uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}` (Unix shell). On Windows: `python -m uvicorn app.main:app`.
- On production, route all public requests through HTTPS and consider an external immutable audit sink; see THREATS.md.
- Open the live site using an incognito window; test a non-authorized ID and revoked access on the public deployment itself.

## Permission model
Owner: CRUD on their own documents; grant/revoke access. Editor: view, download, edit metadata of a named document. Viewer: view and download an explicitly granted document. Administrator: admin log/dashboard and ability to own their own documents; **not** automatic access to documents belonging to others. Every data route independently calls a server authorization helper, including downloads.

## Architectural limits / known gaps
- Metadata edits supported; replacing file content / versioning not implemented.
- Date filtering is a *starting date* filter. No PDF text search.
- JWT/share links deliberately omitted. This eliminates persistent bearer download URLs; existing sessions still require fresh permission checks.
- Database auditing is keyed tamper-evident **only**, not immutable against an administrator with database and secret access. Prefer remote append-only logging in production.
- Concurrent transactions on multi-worker PostgreSQL need stronger chain serialization (advisory locking/outbox) to ensure strict hash-chain order.
- No user self-registration, password reset, account disabling UI, rate limiting, virus scanning, quotas, or object storage integration. Add these before use with real confidential data.
- Minimal format checks do not certify uploaded files as malware-free. Only use harmless test documents.
- No hosted live link or genuine multi-day commits are included in a ZIP. These must be produced by the candidate.

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
0:00 architecture and role model; 0:45 owner uploads; 1:30 grant viewer read; 2:15 viewer downloads; 2:40 unauthorized user denied by direct URL; 3:15 owner revokes and viewer denied again; 3:45 admin activity and denial log; 4:20 run security tests and discuss threats.

## Simplest Windows local start (recommended for beginners)
Unzip the project, open the inner `trustvault_project` folder, and double-click `start_windows.bat`. It creates a virtual environment, installs dependencies, creates random local-only passwords, prints the four usernames/passwords, and starts the web app at `http://127.0.0.1:8000`. Keep the black window open while using the site. On later starts the same local passwords will be reused. The local credentials file (`.local-demo-credentials.json`) is excluded from Git; never upload it or use these demo credentials in a public deployment. If a database already exists but the credential file does not, the launcher stops to prevent an accidental mismatch. An internet connection is needed on first installation.


## Additional documentation

- `REQUIREMENTS_CHECKLIST.md` — crosswalk to the ten official requirements.
- `API_ACCESS.md` — endpoint-by-endpoint permissions.
- `THREATS.md` — full threat model with mitigations and residual risks.
- `PROMPTS.md` — AI-assistance journal documenting corrections made to AI-generated code.
- `tests/test_extended.py` — extra authorization, admin, search and upload-validation cases.
- Workspace search includes a date-to filter, and the activity center shows actor names and denied-attempt counts.

**Assessment caution:** This project is a functioning local reference implementation, not a guarantee of passing a security assessment. Before presenting, you must run it yourself, validate the live deployment, understand and own any modifications, and make only truthful claims about your work and AI usage. The Windows launcher is for LOCAL practice, not production hosting.
