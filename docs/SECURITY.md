# Security controls and threat model

Threatready is treated as a security-sensitive application: it stores learner work, grades it, and runs learner-supplied SQL and cryptographic operations in REAL_LAB exercises.

## Assets and threats

| Asset | Threat | Controls |
|---|---|---|
| Accounts | Credential stuffing, brute force | Better Auth email + password with scrypt hashes; password complexity (contracts); sliding-window limits per IP and per email on login/registration plus a global per-IP throttler; Better Auth's own limiter in production; generic "Invalid email or password"; failed logins audited. Optional TOTP two-factor; **required for staff permissions** when `THREATREADY_REQUIRE_STAFF_MFA` is on (default in production). Email verification required in production. |
| Sessions | Theft, replay, CSRF | Opaque session tokens in an **httpOnly** cookie (`Secure` in production, `SameSite=Lax`), 12 h lifetime; logout and deactivation revoke sessions server-side. JavaScript never sees a credential and nothing is kept in browser storage. Every state-changing `/api` request with an `Origin` header must come from the same host or `THREATREADY_TRUSTED_ORIGINS`. |
| Authorization | Missing or wrong checks | Fail-closed guard: every route declares `@Permission` or `@Public` (a CI test lists all routes); static role→permission map; resource ownership in domain code returns **404** for anything outside the caller's scope; a CI test calls every session route as another learner. **PostgreSQL row-level security** is the backstop: API transactions run as the NOLOGIN role `threatready_app` with the caller's id, organization and staff flag, so a missing `WHERE` clause returns no foreign rows and writes to other users' rows are rejected. |
| Assessment integrity | Learner reads answers or probes scores | Ground truth, timeline, variant parameters and `step_key` never serialized; no score preview before submission; server-side scoring only; hints disabled in assessment mode; knowledge-check answers never sent. Tested. |
| Scenario and policy content | Code injection | Zod schemas (strict objects); checks resolved from fixed registries; referential validation; policies are structured conditions (no expressions or eval), nesting depth ≤ 3; user-controlled keys are looked up with `Object.hasOwn` (no prototype keys). |
| REAL_LAB SQL | Escape, denial of service | Per-user database file; SQLite authorizer denies ATTACH/DETACH/PRAGMA, recursive CTEs and internal `_lab_*` tables, read-only for non-DBA roles; one statement per call; each statement runs in a **child process that is killed after 2 s** (SQLite cannot be interrupted from JavaScript mid-step), at most 4 concurrent per process, 64 MB heap; 200-row display cap; backup ids validated by regex. |
| REAL_LAB files | Path traversal, cross-user leakage | Paths built only from server-side ids (`user-<random Better Auth id>/<lab>`, validated); no user-supplied filenames; atomic database creation. On AWS the lab files are on encrypted EFS through an access point. |
| Output rendering | XSS, CSV formula injection | React escapes by default; HTML reports fully escaped and served with `Content-Security-Policy: default-src 'none'`; CSV cells starting with `= + - @` are prefixed. |
| Transport and headers | Clickjacking, sniffing, downgrade | `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, COOP, HSTS in production; API CSP `default-src 'none'`, UI CSP self-only; `Cache-Control: no-store` on the API; no `X-Powered-By`. TLS at Cloudflare (strict) and the ALB (TLS 1.3 policy); the ALB accepts only Cloudflare ranges. |
| Errors | Information disclosure | Uniform `{"detail": …}` errors; unhandled errors return a generic 500 and are logged (Sentry when configured, without default PII); OpenAPI only outside production. |
| Secrets | Committed or leaked credentials | No secrets in the repository; `.env.example` placeholders; production secrets in Secrets Manager injected into ECS tasks; GitHub deploys through OIDC (no stored AWS keys); the CLI never takes passwords as arguments. |
| Data | Real personal data | Synthetic data only, reserved `.example` domains, 555-01xx numbers, generated card numbers; no data sent to external services (LlmPort is a no-op). |

## Audit

`audit_records` captures registrations, logins (success and failure), logouts, session start/reset, timeline runs, submissions, mission starts/submissions, level unlocks, role choice, user role/status changes and integration toggles; visible to instructors and admins of the same organization. Within scenarios every learner action is logged in `scenario_actions`.

## Retention and deletion

- Per-session reset discards simulated state; submitted attempts are kept.
- Lab pages each offer a reset; the worker deletes lab folders of deleted users daily.
- RDS keeps automated backups for 14 days.

## Known gaps

- Password reset and email delivery: the SES MailPort adapter is a stub (console mail only), so production email verification needs it implemented before self-registration is opened.
- The per-email/IP login limiter is per process; with several API tasks the effective limit multiplies by the task count (Cloudflare rate limiting is recommended in front).
- `npm audit` (2026-10-14): 6 moderate, 0 high. react-router 6.x open-redirect advisory (fix only in v7; the app navigates only to static routes) and esbuild's dev-server advisory pulled in by drizzle-kit (development tooling, never deployed). CI fails on high-severity advisories.
