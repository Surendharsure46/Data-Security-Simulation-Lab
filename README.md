# Threatready

**A practical Data Security training and validation platform that connects enterprise simulations, policy engineering, security investigations and verified real-tool practice in one progressive learning environment.**

The journey starts on a public **Welcome to Data Security** page. **Let’s Get Started** (top right) leads to a page that explains the platform, shows what you will do and lets you **choose a role**. You then climb **six levels, Level 0 (Foundation) to Level 5 (Mastery)**. Each level has short fundamentals, a server-graded knowledge check and hands-on labs with a step-by-step instructor panel. When a level is complete a **congratulations popup** appears and the next level unlocks automatically. See [docs/WORKFLOW.md](docs/WORKFLOW.md).

Inside simulation labs, learners work in a private copy of the company. They discover and classify data, write and test executable DLP policies, run a simulated business day, then investigate the alerts. After that they contain the incident, fix the root cause, prove the fix by replaying the day, and receive a server-calculated, explainable assessment and an incident report generated from what they actually did.

> All companies, people, records and events are synthetic. Every event, lab result and report states its execution mode: **SIMULATED**, **REAL_LAB** (a real operation in your isolated local lab) or **INTEGRATED** (no integrated connectors exist in this release).

---

## What works today (verified by automated tests)

| Area | Status | Mode |
|---|---|---|
| Learning journey: public welcome + get-started pages, role choice, Levels 0–5 (fundamentals reader, knowledge checks, 15 guided labs), lab sessions with step-by-step instructions, required criteria, skill gaps + remedial lessons, retries, skill records, automatic level unlock with congratulations popup, guided tour | Implemented, API-tested (10 tests) and browser-tested | server-side |
| Reference scenario *Unauthorized Customer-Data Export* (2 variants), full loop from discovery to report | Implemented, API- and browser-tested | SIMULATED |
| Scenario engine: start, pause, resume, reset (new attempt / new variant), deterministic replay, control-validation replay | Implemented | SIMULATED |
| Data Discovery: 10 detectors with validators (Luhn, IBAN mod-97, SSN rules), masked evidence, confidence | Implemented | SIMULATED |
| Classification Studio: configurable labels, register with history, owner/handling/exception, editable recommendation rules, access review with real revocation | Implemented | SIMULATED |
| DLP Policy Studio: validated structured rule language, versioning, diff, rollback, enable/disable, draft preview, full evaluation trace | Implemented | SIMULATED |
| Security Event Explorer: common event schema, filters, related events, JSON Lines export | Implemented | SIMULATED |
| Incident Investigation: alert triage, explainable correlation, cases, evidence, typed notes, risk model, remediation with verification probes | Implemented | SIMULATED |
| Data Security Engineering: labelled test suite, precision/recall, regression comparison, change records | Implemented | SIMULATED |
| Assessment engine: 5 weighted categories, 17 criteria, critical failures, deterministic digest, targeted learning | Implemented | server-side |
| Reports: inventory, classification register, policy tests, incident timeline, case report (14 sections), remediation verification, assessment — MD/HTML/JSON/CSV | Implemented | derived |
| Encryption Lab: SHA-256/HMAC, AES-256-GCM + scrypt, wrong-key and tamper rejection, envelope encryption + KEK rotation | Implemented | **REAL_LAB** |
| Encryption Lab: TLS metadata exercise, configuration review/validator | Implemented | SIMULATED |
| Database Security Lab (SQLite): authorizer-enforced roles, SQL injection vs parameterised, masking views, audit log, backup/restore/verify | Implemented | **REAL_LAB** |
| Privacy & Governance lab: minimisation, retention + verified deletion of disposable records, legal hold, findings report | Implemented | SIMULATED |
| Cloud DSPM lab: exposure model, synthetic audit events, remediation, re-assessment | Implemented | SIMULATED |
| AI Data Security lab: prompt-gateway DLP, permission-aware retrieval (RAG) tests, AI log retention | Implemented | SIMULATED |
| Learning paths: L0–L5, 10 modules, 40 lessons, 4 specialist pathways, server-graded knowledge checks | Implemented | — |
| Auth: Better Auth email accounts (scrypt), httpOnly cookie sessions, optional TOTP two-factor (required for staff in production), email verification, throttled login, roles (learner/instructor/admin), fail-closed route policies, PostgreSQL row-level security, audit log | Implemented | — |
| Enterprise Capstone (Module 10) | **Planned — not implemented** | — |
| PostgreSQL lab, Microsoft Purview, Sentinel, AWS connectors, external AI | **Not implemented** (see docs/INTEGRATIONS.md) | — |
| Ports for LLM, storage (S3), mail (SES) and payments | Interfaces + development adapters; production adapters are stubs | — |
| AWS infrastructure (OpenTofu), Docker image, CI/CD with OIDC deploy | Files only — not provisioned | — |

See [docs/PRODUCT_REQUIREMENTS.md](docs/PRODUCT_REQUIREMENTS.md) for the feature-by-feature status and [CHANGELOG.md](CHANGELOG.md) for history.

## Tech stack

TypeScript end to end, as set out in the architecture decision document: a **NestJS** modular monolith (`apps/api`, roles `api` and `worker`), **PostgreSQL** with **Drizzle ORM** and SQL migrations (row-level security as a backstop), **Better Auth** in-process, **Zod** contracts shared with the **React** app (`packages/contracts`), **pg-boss** background jobs, **Vitest** + supertest and **Playwright** tests, and one container image for **ECS Fargate (ARM64)** behind an ALB and **Cloudflare**, provisioned with **OpenTofu** and deployed by **GitHub Actions** over OIDC. Locally the API uses embedded PostgreSQL (**PGlite**), so no database server or Docker is needed. Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Quick start (Windows, PowerShell)

Prerequisite: **Node.js 26.10+** (npm 11). Nothing else.

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
```

```powershell
powershell -ExecutionPolicy Bypass -File scripts\dev.ps1
```

Open http://localhost:5173, read the welcome page, click **Let’s Get Started**, choose a role and create your account with your email address. **My Journey** then shows a **Continue** button for your next step.

Manual equivalent (two terminals):

```powershell
npm ci
npm run dev        # API on :8000 with the embedded database in apps/api/var/pgdata
npm run dev:web    # web app on :5173 (proxies /api to :8000)
```

To create an administrator, set `THREATREADY_BOOTSTRAP_ADMIN_EMAIL` and `THREATREADY_BOOTSTRAP_ADMIN_PASSWORD` (12+ characters) in `.env` before starting the API, or run `node apps/api/dist/cli.js create-user EMAIL admin NAME` with the password in `THREATREADY_NEW_USER_PASSWORD`. Accounts from 0.3.x are not carried over (usernames became email addresses).

## Running the tests

```powershell
powershell -ExecutionPolicy Bypass -File scripts\test.ps1 -E2E
```

Or individually: `npm run check:boundaries` · `npm run typecheck` · `npm test` (API + web) · `npm run e2e` (first run `npx playwright install chromium`; set `$env:PW_CHANNEL="msedge"` to use the installed Edge instead). Details and the latest results: [docs/TESTING.md](docs/TESTING.md).

## A first exercise

0. On **My Journey** click **Continue**: read the Level 0 lessons, pass the knowledge check and complete the two Level 0 labs to unlock Level 1. Level 1's first lab is the simulation below; its lab view groups these steps into phases and links to each tool.
1. **Simulation Workspace** (opened from the lab). Read the briefing; the right-hand checklist tracks 15 tasks (hints available in guided mode).
2. **Data Discovery** → *Run discovery scan*; open `customer_master_export_2026Q1.csv` and inspect masked evidence and who can read it.
3. **Classification Studio** → classify the export and assign an owner; review the grants in *Ownership & access review*.
4. **DLP Policy Studio** → create a policy, test a prohibited and a legitimate transfer, read the trace.
5. **Simulation Workspace** → *Run business day*. **Incident Investigation** → triage alerts, open a case, link evidence, record observations/inferences/unknowns, set scope with the risk calculator, contain.
6. Fix the root cause, then *Run control-validation replay*. Write the report sections, then in the lab's **Submit Evidence and Explanation** phase write your explanation, cite case evidence and submit. Pass, and your skills are recorded and the next lab opens. Fail, and you see your skill gaps and a remedial lesson, and can retry.

## Repository layout

```
packages/contracts   Zod request schemas and the policy language, shared by API and web
apps/api             NestJS API + worker: domain/, labs/, content/, modules/ (controllers), platform/ (auth, guards), db/ (Drizzle), migrations/, test/
apps/web             React + TypeScript (Vite), Vitest component tests, Playwright e2e (e2e/)
infra/tofu           OpenTofu for AWS (network, RDS, S3, ECS Fargate, ALB, EFS, Cloudflare, GitHub OIDC)
.github/workflows    CI (verify, e2e, PostgreSQL, image, infra) and deploy
docs/                Workflow, requirements, architecture, data model, scenarios, assessment, integrations, security, testing, deployment
scripts/             Windows setup/dev/test/build scripts and the module-boundary check
```

## Known limitations

- Single reference scenario (two variants); the multi-stage capstone is not implemented.
- Production adapters for S3 storage, SES mail, payments and an LLM are stubs; mail is logged to the console, so production email verification needs the SES adapter first.
- The Docker image, compose file and OpenTofu code have not been run on this machine (no Docker, no AWS account); CI builds the image and validates the infrastructure.
- Login throttling is per process; put Cloudflare rate limiting in front of several API tasks.
- Detection metrics describe the labelled synthetic test set only — not production performance.
- Assessment results are platform outcomes for the tasks assessed, **not professional certification**.

Security notes: [docs/SECURITY.md](docs/SECURITY.md).
