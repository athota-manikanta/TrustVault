# Verified challenge requirements — implementation map

Official: https://hackathon.snovasys.com/project/1 and https://hackathon.snovasys.com/event/1/instruction

| Requirement | Location | Evidence / limitation |
|---|---|---|
| Authentication and 3 roles | `User`, `/login`, `/logout` | Role restrictions, Argon2 password hashes, signed HTTP-only cookies |
| Upload, organize, manage | `/documents`, detail and edit/delete endpoints | Metadata update, category, delete; no version history |
| Per-document read / edit grants | `Grant`, `authorized()` | Named accounts; no groups |
| Owner grants / revokes | `/grants`, `/revoke/{id}` | Owner-only, current DB permissions |
| No unauthorized read/change/delete | `access()` and `owner_access()` | Test unauthorized URL, download, edit, delete |
| Audit uploads/downloads/edits/deletes/grants | `audit()` | Includes denied accesses; HMAC chain is tamper-evident with caveats |
| Search name/owner/category/date | `/` dashboard query | Date from/to filters are upload dates |
| Validate uploads | `upload()` | Extension/signature/size; not antivirus |
| Admin activity view | `/admin` | Counts, named actors, hash validation |
| Automated isolation tests | `tests/` | `python -m pytest -q` |

## Submission items that must be personally completed
- [ ] Ensure your own genuine Git commit history, without backdating
- [ ] Deploy with persistence for files and database, HTTPS and a fixed secret
- [ ] Verify live URL in an incognito browser
- [ ] Provide live demo credentials for one account of each role (not local-only generated secrets)
- [ ] Add five or more **genuine**, dated `PROMPTS.md` entries, two focused on access control or audit, with links to real corrective commits
- [ ] Record your own five-minute demo video
- [ ] Complete official submission form and answer its six questions
- [ ] Follow the event's repository publication instructions and clarify timing with placement cell if needed

**Never substitute this checklist for your personal testing or claim all requirements are production-secure.**
