# TrustVault — Interview Walkthrough (practice, do not memorize blindly)

## 60-second introduction
TrustVault is a secure document-sharing application built with FastAPI, SQLAlchemy, server-rendered HTML and private file storage. Its key rule is that access is checked on the server for each document request, rather than trusting hidden buttons or guessable URLs. Owners grant named users read or edit access, revoke it at any time, and all important actions and rejected accesses are audited. The administrator sees activity but cannot automatically read another owner’s confidential documents.

## Five-minute demo plan
1. **0:00–0:45** Sign in as owner; explain roles and the searchable document library.
2. **0:45–1:30** Upload a small valid PDF/TXT; show file metadata and download.
3. **1:30–2:20** Share with `viewer_demo` as read-only; demonstrate download works but metadata edit is denied.
4. **2:20–3:05** Return as owner and revoke viewer permission; sign in as viewer and demonstrate the old URL returns 404.
5. **3:05–4:00** Sign in as `other_demo`, attempt direct document URL; show failure; sign in as admin and find the denied audit event.
6. **4:00–5:00** Show `test_security.py`, `test_extended.py`, `THREATS.md`, the verification command, and what remains unfinished.

## Likely interview questions and accurate answers

**Where exactly is authorization decided?** `authorized()` in `app/main.py`. `access()` invokes it on every document detail and download request; write operations check edit permission or ownership.

**What if someone guesses a UUID?** It does not grant access. Missing and unauthorized documents both return 404; denials appear in the audit trail.

**Can admins read all files?** No, not by role alone. The admin activity page is a separate privilege; document content requires ownership or an explicit grant.

**What happens after revocation?** The corresponding `Grant` row is removed. The next request queries current grants again, so a previously known URL stops working. Files already downloaded cannot be remotely erased.

**Where are the actual uploaded bytes?** In a private storage directory with random blob keys, not exposed by a static route. The authenticated download endpoint checks access before sending file contents.

**How does logging resist edits?** Each audit event has an HMAC-SHA256 over its contents and prior event hash. `audit_integrity()` verifies the chain. This detects modifications if the signing secret is kept independently safe, but does not stop a privileged attacker with control over both database and signing key. Concurrent multi-worker writes are not fully hardened.

**Why FastAPI?** Python is accessible to me, FastAPI has straightforward routes and request validation, and SQLAlchemy keeps persistence readable and testable.

**How do you prove permissions work?** Pytest exercises two different logged-in users, exact document URLs, downloads, edits, share revocation, denied audit records, CSRF and invalid file content.

**What remains unfinished?** Enterprise identity federation, malware scanning, external immutable logging, object storage with lifecycle, rate limiting and multi-worker audit serialization. Describe these honestly.

## Live-change practice
Try adding a **category-only** filter or another audit event field, explain what routes use the value, write a test and run `python -m pytest -q`. Do this yourself before the interview.

## Important
Never claim you personally designed, tested, deployed or reviewed a part unless you did. The challenge asks for truthful AI assistance records and a live code walkthrough.
