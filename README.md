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
- Netlify static hosting does not run this FastAPI application or provide its persistent database/blob requirements. The supplied Netlify URL was protected by Netlify Team access, described below.
- `render.yaml` describes a Render Free FastAPI web service. The same application serves the Jinja2 pages and API. The Render filesystem is ephemeral, so production database and document bytes are external: Neon PostgreSQL and a private Supabase Storage bucket.
- The Blueprint intentionally has no Render-managed database. Create a Neon project and copy its **pooled** PostgreSQL connection string into Render's `DATABASE_URL`; retain the supplied `sslmode=require` parameter. The pooled connection string is suitable for the app's synchronous SQLAlchemy/psycopg driver.
- Create a Supabase Storage bucket named `trustvault-documents` (or set the chosen name in `SUPABASE_STORAGE_BUCKET`) and keep it **private**. Configure `SUPABASE_URL`, `SUPABASE_STORAGE_BUCKET`, and the server-only Supabase `sb_secret_...` key as `SUPABASE_SECRET_KEY` in Render's secret environment settings. This key is sent only in the `apikey` header (not as a JWT bearer token). Do not put it in frontend variables or source control.
- Supabase objects are read/written/deleted only by FastAPI using authenticated server-side Storage API requests. The application never generates public or signed URLs. Every download first re-checks the active user and current document grant, then retrieves bytes through the server; revoked grants are denied on the next request.
- **Step-by-step setup:**
  1. Review the repository and push it to a GitHub repository you control only when you are ready to authorize Render to deploy it.
  2. In Neon, create a project/database. In the Console choose **Connect**, select the database and role, enable pooling, and copy the connection string. Keep `sslmode=require`; store the value as `DATABASE_URL` only in Render.
  3. In Supabase, create a project and a Storage bucket with public access disabled. Copy the project URL and create/copy a server-only secret API key (`sb_secret_...`) from **Settings → API Keys**. Never use this privileged key in browser code.
  4. In Render, choose **New → Blueprint**, connect the repository, and select `render.yaml`. Set the prompted `DATABASE_URL`, `SUPABASE_URL`, `SUPABASE_SECRET_KEY`, and `SUPABASE_STORAGE_BUCKET` values. Set four distinct `SEED_*_PASSWORD` values (at least 12 characters) for the demo accounts. Render generates `TRUSTVAULT_SECRET`; retain `TRUSTVAULT_HTTPS=1`.
  5. Deploy the Blueprint and wait for the `/health` check to pass. The free web service may sleep when idle and its local filesystem is temporary; Neon and Supabase own persistent state. Review current provider quotas, suspension/retention policies, and free-tier limits before relying on the services.
  6. From the Render service shell, run `python -m scripts.seed` once. It creates demo users and a harmless sample document in the configured database and private bucket. Do not rerun with different passwords expecting existing passwords to change; reset users explicitly if needed.
  7. Test the public HTTPS URL in a private browser session: log in as owner, upload a harmless document, grant viewer read access, download as viewer, revoke access, then confirm the same viewer session receives 404 on the next detail/download request. Confirm the object is not publicly downloadable, and confirm data remains after a service restart.
- The deployment instructions and Blueprint are configuration only: no service, bucket, DNS record, or credential was created during this work. The live application is not verified until those steps and the acceptance checks have actually been performed.
- **Observed deployment status:** On 2026-10-22, `GET /`, `GET /health`, and `GET /login` at `https://trustvaultz.netlify.app/` returned HTTP 401 from Netlify Team protection. The live application and backend could not be inspected or authenticated, so no claim is made that the complete backend is deployed or working there.
- Configure the Blueprint's `sync: false` Neon, Supabase, and seed-password values in the Render dashboard before starting the service. `TRUSTVAULT_SECRET` is generated by Render. HTTPS mode fails startup without a secret. Never make the bucket public.
- Install dependencies: `pip install -r requirements.txt`.
- Start: `uvicorn app.main:app --host 0.0.0.0 --port $PORT` (Render supplies `PORT`). On Windows local development: `python -m uvicorn app.main:app`.
- On production, route all public requests through HTTPS and send audit events to an external append-only sink. The login limiter uses the direct peer address and deliberately ignores `X-Forwarded-For`; only configure trusted proxy handling when the proxy source IPs are explicitly restricted.
- Verify the deployed backend with an incognito session, role-specific credentials, persistence across restart, and a non-authorized ID and revoked grant. Deployment was not performed as part of this work.

## Permission model
Owner: CRUD on their own documents; grant/revoke access. Editor: view, download, edit metadata of a named document. Viewer: view and download an explicitly granted document. Administrator: admin log/dashboard and ability to own their own documents; **not** automatic access to documents belonging to others. Every data route independently calls a server authorization helper, including downloads.

## Architectural limits / known gaps
- Metadata edits supported; replacing file content / versioning not implemented.
- Date filtering is a *starting date* filter. No PDF text search.
- JWT/share links deliberately omitted. This eliminates persistent bearer download URLs; existing sessions still require fresh permission checks.
- Database auditing is keyed tamper-evident **only**, not immutable. Someone able to alter the database can remove the tail of the chain without detection; someone with the database and application secret can rewrite valid hashes. Prefer remote append-only logging with external checkpoints in production.
- PostgreSQL audit appends use a transaction-scoped advisory lock, but a live PostgreSQL multi-worker integration test has not been run. SQLite WAL is intended for local/single-process use, not concurrent multi-process production.
- No user self-registration, password reset, virus scanning, or quotas. Supabase Storage is implemented, but no live provider/bucket integration has been configured or tested. The login limiter is in-memory/per-process; use a shared service or edge control for multi-worker production.
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
- `PROMPTS.md` — existing AI-assistance journal; its historical entries have not been independently verified during this change.
- `tests/test_extended.py` — extra authorization, admin, search and upload-validation cases.
- Workspace search includes a date-to filter, and the activity center shows actor names and denied-attempt counts.

**Assessment caution:** This project is a functioning local reference implementation, not a guarantee of passing a security assessment. Before presenting, you must run it yourself, validate the live deployment, understand and own any modifications, and make only truthful claims about your work and AI usage. The Windows launcher is for LOCAL practice, not production hosting.
