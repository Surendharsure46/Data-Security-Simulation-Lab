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
| Auth: local accounts, PBKDF2, hashed bearer tokens, rate-limited login, roles (learner/instructor/admin), audit log | Implemented | — |
| Enterprise Capstone (Module 10) | **Planned — not implemented** | — |
| PostgreSQL lab, Microsoft Purview, Sentinel, AWS, external AI | **Not implemented** (see docs/INTEGRATIONS.md) | — |

See [docs/PRODUCT_REQUIREMENTS.md](docs/PRODUCT_REQUIREMENTS.md) for the feature-by-feature status and [CHANGELOG.md](CHANGELOG.md) for history.

## Quick start (Windows, PowerShell)

Prerequisites: **Python 3.11+** (with the `py` launcher) and **Node.js 20+** (tested with Node 26 / npm 11). Docker is optional and not required.

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
```

```powershell
powershell -ExecutionPolicy Bypass -File scripts\dev.ps1
```

Open http://localhost:5173, read the welcome page, click **Let’s Get Started**, choose a role and create your account. **My Journey** then shows a **Continue** button for your next step.

Manual equivalent:

```powershell
cd backend
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m app.cli init-db
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

```powershell
cd frontend
npm ci
npm run dev
```

To create an administrator, set `THREATREADY_BOOTSTRAP_ADMIN_PASSWORD` (12+ characters) in `.env` before `init-db`, or run `python -m app.cli create-user NAME --role admin`.

## Running the tests

```powershell
powershell -ExecutionPolicy Bypass -File scripts\test.ps1 -E2E
```

Or individually: `backend> .\.venv\Scripts\python.exe -m pytest` · `frontend> npm run typecheck` · `frontend> npm test` · `frontend> npx playwright test` (first run `npx playwright install chromium`; set `$env:PW_CHANNEL="msedge"` to use the installed Edge instead). Details and the latest results: [docs/TESTING.md](docs/TESTING.md).

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
backend/   FastAPI app (app/), Alembic migrations, pytest suite, scenario content (app/content)
frontend/  React + TypeScript (Vite), Vitest unit tests, Playwright e2e (e2e/)
docs/      Workflow, requirements, architecture, data model, scenarios, assessment, integrations, security, testing, deployment
scripts/   Windows setup/dev/test/build scripts
```

## Known limitations

- Single reference scenario (two variants); the multi-stage capstone is not implemented.
- SQLite only. The configuration accepts other SQLAlchemy URLs but PostgreSQL has not been tested.
- No vendor integrations; the Docker/Compose files are provided but were **not tested** (Docker was unavailable on the build machine).
- In-memory login rate limiting assumes a single server process.
- Detection metrics describe the labelled synthetic test set only — not production performance.
- Assessment results are platform outcomes for the tasks assessed, **not professional certification**.

Security notes: [docs/SECURITY.md](docs/SECURITY.md).
