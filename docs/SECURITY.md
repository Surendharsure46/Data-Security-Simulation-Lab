# Security controls and threat model

Threatready is treated as a security-sensitive application: it stores learner work, grades it, and runs learner-supplied SQL and cryptographic operations in REAL_LAB exercises.

## Assets and threats

| Asset | Threat | Controls |
|---|---|---|
| Accounts | Credential stuffing, brute force | PBKDF2-SHA256 (600k iterations default, per-user salt); sliding-window rate limit per IP and per username (in-memory, single process); generic error messages; dummy hash on unknown users to reduce timing differences; password complexity on registration. |
| Sessions/tokens | Theft, replay | 256-bit random opaque tokens; only SHA-256 stored; expiry (12 h default); logout revokes; sent in `Authorization` header (never URLs or cookies), so CSRF does not apply to the API. Browser keeps the token in `sessionStorage` (cleared when the tab closes). |
| Learner sessions | Cross-user / cross-org access | Every session-scoped route loads the session through `load_session`: wrong org or non-owner learner → **404** (no enumeration); staff (instructor/admin, same org) read-only; writes require owner + ACTIVE status. Tested in `tests/test_api_security.py`. |
| Assessment integrity | Learner reads answers or probes scores | Ground truth, timeline, variant parameters and `step_key` never serialized; no score preview before submission; server-side scoring only; assessment mode disables hints; knowledge-check answers never sent. Tested. |
| Scenario content | Code injection via content | Pydantic `extra=forbid` schemas; checks resolved from fixed registries; referential validation; policies are structured conditions (no expressions/eval); nesting depth ≤3. |
| REAL_LAB SQL | Escape to other files, DoS | Per-user database file; SQLite authorizer denies ATTACH/DETACH/PRAGMA and internal `_lab_*` tables, read-only for non-DBA roles; one statement per call; 2 s progress-handler budget; 200-row display cap; backup ids validated by regex (no path traversal). |
| REAL_LAB files | Path traversal, cross-user leakage | Paths built only from server-side ids (`user-<id>-<hash>/<lab>`); no user-supplied filenames; atomic database creation. |
| Output rendering | XSS, CSV formula injection | React escapes by default (no `dangerouslySetInnerHTML`); HTML reports fully escaped and served with `Content-Security-Policy: default-src 'none'`; CSV cells starting with `= + - @` are prefixed. |
| Transport/headers | Clickjacking, sniffing | `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, COOP; API CSP `default-src 'none'`; UI CSP restricts to self. Use a TLS-terminating reverse proxy for any non-local deployment. |
| Errors | Information disclosure | Domain errors return safe messages; unhandled errors return a generic 500 and are logged server-side; OpenAPI docs disabled when `THREATREADY_ENV=production`. |
| Secrets | Committed credentials | No secrets in the repository; `.env.example` has placeholders; bootstrap admin password only from environment; synthetic “secrets” in content are clearly marked `krsim-SYNTHETIC-…`. |
| Data | Real personal data | Synthetic data only, reserved `.example` domains, 555-01xx phone numbers, randomly generated card numbers (never issued); no external calls. |

## Audit

`AuditRecord` captures logins (success/failure), registration, session start/reset, timeline runs, submissions, user role/status changes and integration toggles; visible to instructors/admins of the same organisation. Within scenarios, every learner action is logged in `ScenarioAction`.

## Retention and deletion

- `python -m app.cli reset-data --yes` deletes the local database and all lab files (development).
- Per-session reset discards simulated state; submitted attempts are kept until the database is deleted.
- Lab pages each offer a reset of that lab's state.

## Known gaps

- Rate limiting is per process; use a shared store (e.g. Redis) or proxy-level limits for multi-process deployments.
- No MFA, password reset or OAuth/SSO (no fake login buttons are shown).
- Dependency review (2026-10-13): `pip-audit -r backend/requirements.txt` reports **no known vulnerabilities** after upgrading FastAPI/Starlette, uvicorn, SQLAlchemy, Pydantic and cryptography. `npm audit` reports one remaining **moderate** advisory in `react-router` 6.x (open redirect via backslash paths in `<Link>`/`useNavigate`), fixed only in the v7 major release. Threatready never navigates to user- or server-supplied paths (all routes are static), which limits exposure; migrating to React Router 7 is a recommended follow-up. CI runs `pip-audit` and `npm audit` on every push.
