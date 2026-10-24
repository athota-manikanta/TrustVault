# PROMPTS.md — AI assistance journal

This journal distinguishes repository-verifiable implementation details from recollections of AI interactions. The repository does not contain the original prompt transcripts. Unless an entry says otherwise, its account of what an AI suggested is author-reported and has not been independently corroborated. This document does not establish that the project satisfies any required count of genuine AI-development entries.

---

## Entry 1 — Initial scaffold account

**Evidence status:** The prior draft described an initial AI scaffold and subsequent HMAC, Content Security Policy (CSP), and login rate-limiter corrections. The code and tests can show the current implementation, but do not establish that an AI produced the scaffold or made those specific mistakes. The original interaction and its date require the author's confirmation. This is not presented as verified AI-development evidence.

---

## Entry 2 — Authorization helper and SQLAlchemy API

**Evidence status:** The code supports the implementation facts below. The original AI interaction and its date are not independently documented in this repository.

The earlier draft incorrectly characterized the read/edit permission logic as a semantic security bug, then acknowledged that the logic was correct. That characterization is withdrawn. The supported improvement is modernization from the legacy `session.query()` pattern to SQLAlchemy's `select()` API, together with review of the authorization helper's route call sites.

The current helper checks ownership or a named grant. Read access accepts a read or edit grant; edit access requires an edit grant. The document detail, download, and edit routes request their corresponding access levels. Tests including `test_read_grant_cannot_edit_metadata` cover the read-versus-edit boundary. These code and test facts do not independently verify the claimed original AI suggestion.

---

## Entry 3 — Audit chain and database concurrency

**Evidence status:** The implementation and commit attribution below are repository-verifiable. The original AI interaction and its date are not independently documented.

The earlier draft combined separate concerns and incorrectly attributed the PostgreSQL advisory lock to commit `0cf2af0`. The timezone-normalization and SQLite WAL changes are present in the initial implementation commit `0cf2af0`. PostgreSQL advisory locking was introduced later in commit `0654a2b`. These are distinct implementation changes; the earlier SQLite-only deployment description is obsolete. The current deployment is configured for Render, Neon PostgreSQL, and Supabase Storage, but live provider behavior and PostgreSQL integration remain unverified.

The audit chain is tamper-evident, not immutable. Tests cover detection of changes and known limitations; they do not establish that the production audit log is independently protected.

---

## Entry 4 — Login rate-limiter account

**Evidence status:** The prior draft attributed specific rate-limiter suggestions and corrections to an AI interaction. The current code, tests, and threat documentation can verify implementation characteristics, but not that interaction or its date. The original interaction requires the author's confirmation. This is not presented as verified AI-development evidence.

---

## Entry 5 — Administrator access-boundary account

**Evidence status:** The prior draft attributed a proposed administrator document-access bypass to an AI interaction. Repository tests and implementation can verify the current access boundary, but do not establish that the suggestion was made or rejected in an actual AI exchange. The original interaction requires the author's confirmation. This is not presented as verified AI-development evidence.

---

## Entry 6 — User-management and session account

**Evidence status:** The prior draft attributed a suggestion to cache enabled-user state in the session to an AI interaction. The current implementation and tests can verify that enabled status is checked on requests, but do not establish that this suggestion was made or corrected in an actual AI exchange. The original interaction requires the author's confirmation. This is not presented as verified AI-development evidence.

---

## Reusable security prompt template

The following is a reusable prompt template, not evidence that this exact text was used in an earlier session:

> You are helping build a security-critical document-sharing platform. Before suggesting any change to authorisation, access control, or audit logging, reason explicitly about: (1) what an attacker could do if this code is wrong, (2) whether the change widens access without an explicit grant, and (3) whether the change could silence the audit log. Never suggest caching security state in client-controlled storage.

---

## Evidence still needed

The author should confirm or correct the historical accounts in Entries 1, 4, 5, and 6, and whether the reusable prompt template reflects an actual prompt. Original prompt records or other contemporaneous evidence would support those claims. Until then, they must not be counted as verified AI-development entries. The original interaction date for Entry 2 and Entry 3 also remains unverified.
