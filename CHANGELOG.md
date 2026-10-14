# Changelog

## 0.3.1 — 2026-10-14 (level-gated tools and new palette)

### Changed
- The sidebar's tool group ("Tools · n/13 unlocked") now unlocks tools with the level that first uses them (Encryption Lab at L0; simulation tools and Database Lab at L1; Engineering at L3; Privacy, Cloud, AI and Real-Tool Practice at L4; Administrator for staff). Locked tools show 🔒 and their level; opening one directly shows a "Unlocks at Level n" page. Staff see every tool. Lab sessions are unaffected.
- New palette: white, purple and neon accents (cyan, pink, green). Sidebar sections are colour-coded (Learn purple, Progress cyan, Tools pink), with an icon on every item and neon highlights on the active item.
- The e2e journey checks the Level 0 tool lock, then runs the practice sandbox as the bootstrap administrator of the throwaway e2e backend.

## 0.3.0 — 2026-10-14 (guided Level 0–5 learning journey)

### Added
- Public **Welcome to Data Security** page (detailed introduction, motivation, level outline) with **Let’s Get Started** in the fixed top-right corner.
- Public **Get started** page: how the platform works, what you do in every level, the Level 0–5 path, four role cards, and account creation or sign-in that applies the chosen role.
- Six progressive levels (Level 0 Foundation → Level 5 Mastery). Each has fundamentals (one lesson per screen, progress dots, Level 0 organisation briefing), a five-question server-graded knowledge check (stable shuffled options) and hands-on labs taken in order.
- 15 labs, including the interactive demo lab (real detectors and policy engine) and lab missions for hashing, file encryption, database least privilege/injection/audit/masking/restore, key rotation and config review, privacy, cloud, AI and TLS, plus four simulation labs.
- Guided lab sessions: the lab runs embedded and filtered to the exercises being practised; a sticky instructor panel gives numbered step-by-step instructions, a live checklist and the explanation form.
- Automatic level unlock (cascading if earlier work already completes a level), rank titles per level (Trainee → Principal), and a congratulations popup with new responsibilities and challenges; journey-complete celebration after Level 5.
- My Journey home with a Continue card, level path, skills and recent results; Level page with "Before you start" and numbered steps; a first-visit guided tour (restart from the top bar).
- Navigation regrouped (Learn · Progress), with every previous tool kept under a collapsed **Lab toolkit (advanced)** group; teal accent matching ThreatReady.
- API: `GET /api/career/public` (no auth), `PUT /role`, `GET /journey`, `GET /levels/{n}`, `POST /levels/{n}/read/{key}`, `POST /levels/{n}/check`. Migration `0003_levels_and_roles` adds `learner_profiles.desired_role`.
- Tests: `test_career.py` rewritten (10 tests); Playwright journey covers welcome → get started → role → account → My Journey → lesson reader.

### Changed
- Replaced the onboarding wizard, Organization Home and promotion page with the public pages, My Journey, Level pages and the popup. Mission ids were renumbered by level. Migration 0003 returns existing learners to *choose a role* at Level 0 and keeps passed labs.
- Comprehension and knowledge-check options are served in a stable, shuffled order so the correct answer is not always in the same position.

## 0.2.0 — 2026-10-14 (career and mission workflow)

### Added
- Learner workflow aligned with the ThreatReady simulation diagram (docs/WORKFLOW.md): onboarding (Welcome to Data Security → Organization Briefing → Interactive Demo → Join as Junior Data Protection Analyst), Organization Home, View Assigned Mission, six mission phases, Submit Evidence and Explanation, server-side competency assessment with mission required criteria, skill gaps with remedial lessons, retry with practice or a new variant, skill records, “more missions in level?” decision, level unlock and promotion screen.
- `content/career.py`: organisation briefing, interactive-demo content, 4 levels / 11 missions (scenario and lab missions), 14 skills with criterion/exercise mappings, `validate_career_content()` (run at start-up, in `validate-content` and in tests).
- `services/career.py`, `routers/career.py` (`/api/career/*`), `services/session_lifecycle.py` (shared session start/submit).
- Models `LearnerProfile`, `MissionAttempt`, `SkillRecord`; Alembic migration `0002_career_and_missions`.
- Scenario tasks carry a validated `phase`; task progress and the public scenario view expose it.
- Frontend: `Onboarding`, `OrgHome` (now `/`), `Mission` (`/mission`, `/missions/:attemptId`), `Promotion`; career context gates the app behind onboarding; navigation regrouped into *Organization* and *Mission toolkit*; the previous dashboard moved to `/progress` (“Skills & Progress”).
- Tests: `backend/tests/test_career.py` (8 tests); the Playwright journey now covers onboarding.

### Changed
- Sessions linked to a mission refuse `POST /sessions/{id}/submit` and `/reset` (409). Submit and retry from the mission view instead. The workspace and the Assessment page link back to the mission.
- The Simulation Workspace launcher is presented as a practice sandbox. Its sessions are graded but do not complete missions.

## 0.1.0 — 2026-10-13 (initial release)

### Added
- FastAPI backend (modular monolith) with SQLAlchemy 2 models, Alembic migration `0001`, CLI (`init-db`, `create-user`, `validate-content`, `reset-data`).
- Synthetic enterprise *Kestrel Ridge Financial* with deterministic content samples.
- Sensitive-data detectors with validators, keyword-proximity confidence and masked evidence.
- Validated structured policy language and deterministic evaluator with documented precedence, exceptions and traces.
- Scenario engine with per-session environments, ten-step business-day timeline, two variants, control-validation replay, pause/resume/reset.
- Reference scenario *Unauthorized Customer-Data Export* with 15 progress tasks, hints, remediation catalogue, labelled policy test suite and 17-criterion rubric with two critical conditions.
- Investigation: explainable correlation, cases, evidence references, typed notes, risk model, remediation with verification probes.
- Assessment engine with inputs digest; seven report types in Markdown/HTML/JSON/CSV.
- REAL_LAB Encryption Lab and SQLite Database Security Lab; simulated Privacy, Cloud DSPM and AI Data Security labs.
- Curriculum: six levels, ten modules, 40 lessons, four pathways, server-graded knowledge checks.
- React/TypeScript UI covering all 16 navigation areas, shared policy editor and trace viewer, light/dark themes.
- Tests: pytest (unit, API, labs, migrations), Vitest component tests, Playwright end-to-end journey.
- Windows scripts, `.env.example`, optional Dockerfile/compose (untested), CI workflow.

### Security
- Upgraded backend dependencies after `pip-audit` flagged cryptography 44.0.3 and starlette 0.46.2 (now cryptography 50.0.2, FastAPI 0.143.0 / Starlette 1.8.0, uvicorn 0.54.0, SQLAlchemy 2.1.4, Alembic 1.20.0, Pydantic 2.14.1).
- Upgraded react-router-dom to 6.30.6, Vite 6.4.4, Vitest 5.0.4 and Playwright 1.64.0 after `npm audit`; one moderate react-router advisory remains (fix requires v7; see docs/SECURITY.md).

### Fixed during verification
- Payment-card regex matched across tokens with mixed separators (false positive).
- Secret detector missed prefixed names such as `CRM_CLIENT_SECRET=`.
- CSV header detection ignored files starting with a comment line.
- Events export route shadowed by `/events/{event_id}`.
- Off-by-one in truncated SQL lab row counts.
- Lab files keyed only by user id could be inherited after a database recreation.
- Concurrent first requests could observe a half-built lab database or race on lab-state creation.
- Case-note form could lose typed text through stale state updates; pages no longer unmount forms while refreshing.
- Reports and the case view no longer use ground truth to choose or describe cases.
- Checkboxes could shrink to zero width in narrow grid cells (invisible to users).
- Quiz lessons' “Go to practice” link pointed to the wrong page.
- `AssessmentAttempt.total_score` pinned to `Float` so SQLAlchemy 2.1 matches migration 0001.
