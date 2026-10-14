# Testing

## Suites

| Suite | Location | Command | What it covers |
|---|---|---|---|
| API (unit, HTTP, labs, journey, migrations, worker) | `apps/api/test` | `npm test -w @threatready/api` (builds first) | Policy language and evaluator; detectors and validators; synthetic content; scenario-definition validation and answer-free public view; registration, login, logout, throttling, closed Better Auth sign-up, deactivation; **every route declares an access policy**; **another learner gets 404 on every session route**; staff read-only; **row-level security** with no `WHERE` clause; hidden answers; hints; validation and domain errors; CSRF Origin check; headers; CSV/HTML safety; OpenAPI; scenario lifecycle, reproducibility, reset/replay, variants A and B, correlation, event schema, remediation verification, business-disruption trade-offs, evidence-dependent grading, deterministic scoring, policy versioning/rollback/draft preview, engineering metrics, all report types and formats, export; REAL_LAB crypto and SQLite exercises including denied dangerous statements, multi-statement and recursive SQL, **runaway query killed within the budget**, injection, path traversal, per-user isolation; simulated labs; knowledge checks; pathways; integration honesty; full learning journey; migrations (RLS on every owned table, idempotent); pg-boss job and lab cleanup. |
| Web type check | `apps/web` | `npm run typecheck -w threatready-web` | Strict TypeScript. |
| Web component tests | `apps/web/src/**/*.test.tsx` | `npm test -w threatready-web` | Policy editor, trace rendering, badges, error formatting. |
| End-to-end (browser) | `apps/web/e2e` | `npm run e2e` | Builds the API and web app, starts a throw-away API (in-memory PGlite, port 8099) and `vite preview` (port 5199), then drives the whole journey: welcome → Get Started → role + account (email) → My Journey → Level 0 lesson → tool gating → bootstrap admin → guided reference scenario from discovery to submission (PASS) → report → reset → replay. |
| Boundaries | `scripts/check-boundaries.mjs` | `npm run check:boundaries` | Domain/labs/content framework-free; contracts and web independent of the API. |

The API tests run against the `tsc` build in `apps/api/dist` (tsc emits the decorator metadata NestJS needs; this avoids a native SWC binding). Each test file migrates one PGlite template database and clones it for every test, so tests are isolated and need no external PostgreSQL. CI additionally applies the migrations to a real PostgreSQL 17 service.

Everything at once: `powershell -ExecutionPolicy Bypass -File scripts\test.ps1 -E2E`.

## Results recorded for the NestJS / PostgreSQL migration (0.4.0, 2026-10-14, Windows 11, Node 26.10)

| Check | Result |
|---|---|
| `npm run check:boundaries` | Passed |
| API + web type check | Passed |
| API Vitest suite | **108 passed** in 8 files (7 ported from the Python suite, plus migrations/worker) |
| Web component tests | **6 passed** |
| Playwright end-to-end journey (`PW_CHANNEL=msedge`) | **Passed** |
| Manual browser check (dev servers): Get Started → role → account creation → My Journey; session cookie not readable from JavaScript, nothing in browser storage | Passed |
| `npm audit --omit=dev` | 6 moderate, 0 high: react-router 6 (fix needs v7, see SECURITY.md) and esbuild inside drizzle-kit (development tooling only) |

### Not verified

- Docker image and compose file (Docker not installed; CI builds the image).
- OpenTofu plan/apply (no AWS account; CI runs `tofu validate`).
- The PostgreSQL CI job has not run yet (no CI run happened during the migration); locally all tests use PGlite.
- Python-to-TypeScript ports keep behaviour, not random values: the synthetic RNG changed, so generated names and numbers differ from 0.3.x, while every property the tests rely on holds.
