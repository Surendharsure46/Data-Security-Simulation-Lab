# Architecture

Threatready is a **modular monolith in TypeScript**: one NestJS application (`apps/api`) with clear internal boundaries, PostgreSQL through Drizzle ORM, Better Auth for identity, and a React single-page application (`apps/web`). Request schemas live in a shared package (`packages/contracts`) used by both. In production the API also serves the built web app, so one container image is the whole application. The same image runs as two ECS services: `api` and `worker`.

```
Browser (React SPA, apps/web)
   │  JSON over HTTPS, httpOnly session cookie (SameSite=Lax), same origin
   ▼
NestJS API (apps/api, THREATREADY_ROLE=api)
   ├── server.ts            security headers + CSP, Origin check for state-changing requests, Better Auth handler at /api/identity,
   │                        JSON body limit, OpenAPI at /api/openapi.json (non-production), static web app + SPA fallback
   ├── platform/            cross-cutting HTTP layer
   │     auth.ts            Better Auth (Drizzle adapter, email + password, scrypt, sessions, TOTP two-factor), principal resolution
   │     http.ts            guard chain, @Permission/@Public, Zod request validation, request transaction, error filter
   │     openapi.ts         OpenAPI 3.1 generated from route metadata and the Zod schemas
   ├── modules/             controllers only (HTTP shape, no business rules)
   │     auth · journey (career + curriculum) · sessions · environment · policies (+engineering) · investigations · labs · admin · health
   ├── domain/              business logic, framework-free (enforced by scripts/check-boundaries.mjs)
   │     career, curriculum, session-lifecycle, detection, policy-engine, scenario-defs, simulation, discovery, policies,
   │     investigation, assessment, reports
   ├── labs/                encryption (REAL_LAB, node:crypto), dblab (REAL_LAB, node:sqlite in a killable child process), simlabs
   ├── content/             synthetic enterprise (company.ts), career/curriculum JSON, scenario JSON
   ├── db/                  schema.ts (Drizzle), client.ts (pg or PGlite), uow.ts (unit of work), context.ts (request context + RLS)
   ├── ports/               LlmPort, StoragePort, MailPort, PaymentPort with development adapters and production stubs
   └── worker/              pg-boss jobs on the same database (THREATREADY_ROLE=worker)
```

## Request lifecycle and authorization chain

Every request passes, in order:

1. **Throttler** (`@nestjs/throttler`, per IP) and, for `/api/auth/login|register`, a per-IP and per-email sliding window.
2. **Identity**: `AuthGuard` resolves the Better Auth session cookie to a `Principal` (user id, organization, role, staff flag, MFA). Deactivated users resolve to nobody.
3. **Route policy**: every route declares `@Permission(...)` or `@Public()`. A route with neither is refused at runtime (fail closed) and fails the route-coverage test.
4. **Role → permission** (static map in `platform/http.ts`): `learner` → `self`; `instructor` → `self`, `staff.read`; `admin` → plus `admin.manage`. Staff permissions require a verified second factor when `THREATREADY_REQUIRE_STAFF_MFA=true`.
5. **Entitlement** (stub hook for the PaymentPort; everyone is entitled today).
6. **Validation**: `@ZBody` / `@ZQuery` parse with the Zod schemas from `@threatready/contracts`; failures are `422 {"detail":"Invalid input","errors":[{field,message}]}`.
7. **Request transaction**: the handler runs inside one database transaction as the restricted role `threatready_app` with `app.user_id`, `app.org_id` and `app.staff` set, so PostgreSQL row-level security applies (`db/context.ts`, migration `0001_rls.sql`).
8. **Resource ownership** in domain code: objects outside the caller's scope are **404**, never 403, so ids cannot be enumerated. Staff may read sessions and attempts in their own organization; only owners write.

Errors use one shape: `{"detail": message}`. Domain rules throw `DomainError(message, status)`.

## Data access

Domain services were written against a unit of work (`db/uow.ts`): rows loaded through it are tracked, field assignments are flushed automatically before the next query and at the end of the request. JSON columns are replaced, never mutated in place. Inserts and deletes are immediate. All queries go through the request's transaction (`uow()` / `tx()`), which keeps the embedded database (single connection) deadlock-free.

Databases: `postgres://…` uses node-postgres (RDS in production); `pglite://<dir>` or `pglite://memory` runs PostgreSQL compiled to WebAssembly in-process for local development and the test suite. The same migrations run on both.

## Identity

Better Auth runs in-process; users, accounts (scrypt password hashes), sessions and TOTP secrets are tables in our database. Its own endpoints are mounted at `/api/identity` (session, sign-out, two-factor, password change). Public sign-up through Better Auth is closed; registration and login go through `/api/auth/register` and `/api/auth/login`, which apply the contracts validation, the self-registration policy, throttling and the audit trail, then forward Better Auth's `Set-Cookie`. The browser never sees a credential: the session cookie is httpOnly.

## Background work

The `worker` role starts pg-boss on the same PostgreSQL database (schema `pgboss`; no extra infrastructure). Current job: `maintenance.lab-cleanup` (daily) removes lab folders of deleted users. The API never runs jobs; it only enqueues.

## Learner workflow layer

The journey (`domain/career.ts`, `domain/curriculum.ts`, `modules/journey.controller.ts`, `content/data/career.json`) sits on top of the scenario engine, labs and assessment engine without changing how they grade: public welcome/get-started pages with role choice, Levels 0–5 with fundamentals and knowledge checks, sequential labs, a comprehension gate, explanation with cited evidence, required criteria on the stored assessment attempt, skill gaps with remedial lessons, retries (practice or new variant), skill records and automatic level unlocks. Node-by-node mapping: [WORKFLOW.md](WORKFLOW.md).

## Key design decisions

1. **Per-session environments.** Starting a scenario provisions a private copy of the synthetic company keyed by `session_id`: isolation, trivial reset and deterministic replay. Submitted assessment attempts survive resets.
2. **Content is data, logic is code.** Scenario JSON is validated with Zod and cross-checked against the environment. Task checks, rubric checks and critical conditions are names resolved from fixed server-side registries; content never executes code.
3. **One policy engine everywhere.** Live activity, dry runs, the labelled test suite, the assessment's defence-in-depth check, the demo lab and the AI prompt gateway all use `evaluatePolicy` / `decide`.
4. **Hidden answers stay on the server.** `publicView()` is the only scenario representation sent to clients; `step_key` is never serialized; no score preview before submission; knowledge-check answers never leave the server.
5. **Honest provenance.** Scenario events are `SIMULATED` with `kr-sim-*` sources; labs state `REAL_LAB` or `SIMULATED`.
6. **No AI in decisions.** Explanations are deterministic templates. The LlmPort exists with a no-op adapter only.

## Data flow of one simulated activity

`executeActivity` (`domain/simulation.ts`): identity check → access path (direct grant, group grant, data owner, quarantine exemptions) → egress blocklist → live content scan and context → evaluation of every enabled policy (trace stored) → DLP decision event → transfer event → detection events → correlation links within the transaction and to earlier activity on the same resource → one alert per matched alerting policy.

## Timeline runs

`runTimeline(mode)` replays the scripted business day on sim-day *n* for run *n*. `validation` substitutes the subject with a **validation clone** that has the subject's original role and groups, so a replay proves the control gap is closed rather than that one account was disabled. Each run records the action sequence number so the engine can tell whether a replay came after the latest control change.

## Frontend

React 18 + TypeScript + Vite in `apps/web`. `src/api.ts` is a same-origin `fetch` wrapper (cookies are sent automatically; errors surface the server's `detail`). `state.tsx` holds the auth context (probes `/api/auth/me` on load; login supports the TOTP step), the career profile and the active scenario session. `components/AuthForm.tsx` is the shared sign-in / registration form. In development Vite proxies `/api` to the API.

## Boundaries and non-goals

- `scripts/check-boundaries.mjs` (CI) keeps `domain/`, `labs/` and `content/` free of NestJS/Express and the HTTP layer, keeps `packages/contracts` independent of the apps and stops the web app importing API code.
- No microservices, no Kubernetes, no message broker: pg-boss on PostgreSQL is enough at this scale.
- Vendor connectors are not implemented; see [INTEGRATIONS.md](INTEGRATIONS.md).
