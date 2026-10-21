# API permission reference

| Method | Path | Authentication / permission |
|---|---|---|
| GET | `/health` | Public |
| GET | `/login` | Public |
| POST | `/login` | CSRF token and correct credentials |
| POST | `/logout` | Valid CSRF token |
| GET | `/` | Logged-in; only visible authorized documents |
| GET | `/documents/new` | Owner or admin role |
| POST | `/documents` | Owner or admin role + CSRF; validate upload |
| GET | `/documents/{id}` | Owner or explicit read/edit grant |
| GET | `/documents/{id}/download` | Owner or explicit read/edit grant |
| POST | `/documents/{id}/edit` | Owner or explicit edit grant + CSRF |
| POST | `/documents/{id}/grants` | Document owner + CSRF |
| POST | `/documents/{id}/revoke/{user_id}` | Document owner + CSRF |
| POST | `/documents/{id}/delete` | Document owner + CSRF |
| GET | `/admin` | Administrator role only (does not grant file access) |

All document permissions are evaluated at request time from the database. Unauthorized/missing documents deliberately share a 404 response. Form actions are protected by CSRF tokens. No anonymous sharing links are issued.
