# Changelog

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
