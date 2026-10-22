# API permission reference

| Method | Path | Authentication / permission |
|---|---|---|
| GET | `/health` | Public |
| GET | `/login` | Public |
| POST | `/login` | CSRF token and correct credentials; rate-limited by direct peer address (untrusted forwarding headers ignored) |
| POST | `/logout` | Valid CSRF token |
| GET | `/` | Logged-in; only documents the caller is authorized to see |
| GET | `/documents/new` | Owner or admin role |
| POST | `/documents` | Owner or admin role + CSRF; extension/magic-byte/size validation |
| GET | `/documents/{id}` | Owner or explicit read/edit grant; 404 if missing or unauthorized |
| GET | `/documents/{id}/download` | Owner or explicit read/edit grant; streams from private storage |
| POST | `/documents/{id}/edit` | Owner or explicit edit grant + CSRF |
| POST | `/documents/{id}/grants` | Document owner only + CSRF |
| POST | `/documents/{id}/revoke/{user_id}` | Document owner only + CSRF; takes effect on the next request |
| POST | `/documents/{id}/delete` | Document owner only + CSRF |
| GET | `/admin` | Administrator role only; shows audit log and user summary |
| GET | `/admin/users` | Administrator role only; lists all users |
| POST | `/admin/users/create` | Administrator role only + CSRF; validates username, role, password length |
| POST | `/admin/users/{id}/disable` | Administrator role only + CSRF; blocks all future requests for that user |
| POST | `/admin/users/{id}/enable` | Administrator role only + CSRF |
| POST | `/admin/users/{id}/change-role` | Administrator role only + CSRF; cannot demote own account |

## Permission design notes

- **No implicit access by role.** The administrator role grants access to `/admin` and user-management endpoints only. Admins have no automatic access to documents owned by others; they must be granted access explicitly like any other user.
- **Server-side enforcement on every request.** There are no client-controlled permission flags. `current_user()` queries the database on every request and checks the `enabled` flag; a disabled user's session stops working on the very next request without any server-side invalidation step.
- **Denied access is audited.** Every 401 and 404 raised by `access()` or `owner_access()` writes an audit event with `outcome='denied'` before raising the exception.
- **404 over 403 for documents.** Unauthorized requests to document endpoints return 404, not 403, so an attacker cannot confirm a document's existence from the response code.
- **Mutation/audit atomicity.** Upload, edit, grant, revoke, delete and admin user changes write their success audit row in the same database transaction as the corresponding mutation. An audit write or commit failure rolls the mutation back.
- **Audit limitations.** The HMAC chain detects edited fields and broken links, not removal of its final events; the database and application secret are not an immutable external archive. PostgreSQL appends are serialized with a transaction-scoped advisory lock. SQLite is intended for local/single-process use.
- **Cookie and proxy behavior.** Session cookies are HTTP-only and SameSite=Strict. Set `TRUSTVAULT_HTTPS=1` behind correctly configured TLS to enable Secure cookies; arbitrary `X-Forwarded-For` values are not trusted.
