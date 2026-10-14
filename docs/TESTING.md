# Testing

## Suites

| Suite | Location | Command | What it covers |
|---|---|---|---|
| Backend unit + API + lab + migration | `backend/tests` | `.\.venv\Scripts\python.exe -m pytest` (from `backend/`) | Policy language and evaluator (exact/partial/no match, missing and malformed input, multiple matches, exceptions, conflicts, disabled, versions, regression); detectors and validators; synthetic content; scenario-definition validation and answer-free public view; auth, rate limiting, cross-user isolation, staff read-only, hidden answers, hints, input validation, safe rendering (HTML/CSV); scenario lifecycle, reproducibility, reset/replay, variant B, correlation, event schema, remediation verification, business-disruption trade-offs, evidence-dependent grading, deterministic scoring, policy versioning/rollback/draft preview, engineering metrics, all report types/formats, export; REAL_LAB crypto and SQLite exercises including denied dangerous statements, injection and path traversal; simulated labs; knowledge checks; pathways; integration honesty; Alembic migrations == models; learning journey (`test_career.py`): public content without login and without answers, stable shuffled answer positions, role choice → Level 0, step sequencing (check locked until lessons read, labs locked until the check passes, labs in order, locked levels), demo lab fail → remedial lesson → retry → pass, Level 0 completion → level unlock + celebration + title, simulation lab pass with skills and locked sessions, fail → practice / new variant (variant really changes), Level 1 completion → Level 2, practice not counting for independent labs, attempt privacy. |
| Frontend type check | `frontend` | `npm run typecheck` | Strict TypeScript across the app. |
| Frontend unit/component | `frontend/src/**/*.test.tsx` | `npm test` | Structured policy editor (conditions, nested groups, exceptions, list parsing, DETECTION → MONITOR), evaluation trace rendering, text-labelled status badges, error formatting. |
| End-to-end (browser) | `frontend/e2e` | `npx playwright test` | Builds the UI, starts a throw-away backend (fresh SQLite + migrations, port 8099) and `vite preview` (port 5199), then drives the full learner journey: welcome page → Let’s Get Started → choose a role and create the account → My Journey (title, six levels, guided tour) → Level 0 lesson reader → start guided scenario in the practice sandbox → scan and inspect the export → classify with owner → create a BLOCK policy → test prohibited and legitimate transfers → run the business day → triage every alert (adapting to the random variant) → open a case, link evidence, record observation/inference/unknown → scope and severity → preserve evidence, disable account, escalate → revoke the excessive grant → control-validation replay → report sections → submit (asserts PASS ≥ 70) → open the generated case report and assert it contains the executed actions → reset → replay. |

Browser for e2e: the Playwright-managed Chromium (`npx playwright install chromium`), or any installed channel via `PW_CHANNEL`, e.g. `$env:PW_CHANNEL="msedge"`.

Everything at once: `powershell -ExecutionPolicy Bypass -File scripts\test.ps1 -E2E`.

## Results recorded for the Level 0–5 journey (2026-10-14)

| Check | Result |
|---|---|
| Backend `pytest` | **96 passed**, 0 failed |
| Frontend `npm run typecheck` | Passed |
| Frontend `npm test` | **6 passed** |
| Playwright end-to-end journey (`PW_CHANNEL=msedge`) | **Passed** |
| Manual browser walk-through: welcome → get started → role → account → My Journey + tour → Level 0 lessons → knowledge check → demo lab (live instructor checklist) → hashing lab (embedded, filtered) → congratulations popup → Level 1 page → simulation lab view | Passed |

## Results recorded for the career-workflow update (2026-10-14)

| Check | Result |
|---|---|
| Backend `pytest` | **94 passed** (86 existing + 8 career workflow), 0 failed |
| Frontend `npm run typecheck` | Passed |
| Frontend `npm test` | **6 passed** |
| Playwright end-to-end journey incl. onboarding (`PW_CHANNEL=msedge`) | **Passed** (1 run) |
| Manual browser walk-through (dev server): onboarding → Organization Home → MSN-101 pass branch (skills recorded, next mission) → MSN-102 fail branch (skill gaps, remedial lessons, retry) | Passed |

## Results recorded for release 0.1.0 (2026-10-13, Windows 11, Python 3.11, Node 26)

| Check | Result |
|---|---|
| Backend `pytest` (after dependency upgrades) | **85 passed**, 0 failed (≈62 s) |
| Frontend `npm run typecheck` | Passed |
| Frontend `npm test` (Vitest 5.0.4) | **6 passed**, 0 failed |
| Playwright end-to-end journey (production build via `vite preview`, Microsoft Edge channel) | **Passed 3 of 3 consecutive runs** (≈1.2–1.3 min each) |
| Clean-environment setup: new venv from `requirements-dev.txt` → `validate-content` → `init-db` on an empty database → server start → `/api/health` | **Passed** |
| `pip-audit -r backend/requirements.txt` | No known vulnerabilities |
| `npm audit` | 1 moderate advisory (react-router 6.x; fix requires v7 — see SECURITY.md) |

### Not verified

- The Playwright-managed Chromium download did not complete on the build machine; e2e runs used installed Microsoft Edge (`PW_CHANNEL=msedge`). The default (bundled Chromium) path is expected to work after `npx playwright install chromium`.
- The browser e2e test exercises whichever variant is randomly assigned; variant B is covered end to end by the API test `test_variant_b_full_flow`.
- Docker/Compose files (Docker not installed).
- PostgreSQL (SQLite only).
- A deprecation warning from Starlette's test client about `httpx` is expected and harmless for this release.

### Defects found and fixed during verification

See CHANGELOG.md, “Fixed during verification”.
