# Architecture

Threatready is a **modular monolith**: one FastAPI process with clear internal module boundaries, a SQLite database (via SQLAlchemy + Alembic) and a React single-page application. In production mode the backend also serves the built UI, so a single process on port 8000 is the whole application.

```
Browser (React SPA)
   │  JSON over HTTP, Authorization: Bearer <token>
   ▼
FastAPI app (app/main.py) ── security headers, safe error handlers
   ├── routers/            HTTP layer: validation (Pydantic), authorization, serialization
   │     auth · sessions · environment · policies(+engineering) · investigations · curriculum · labs · admin
   ├── services/           domain logic, no HTTP
   │     detection        sensitive-data detectors + validators + masking
   │     policy_engine    rule language (Pydantic), evaluator, precedence, explanations, diff
   │     scenario_defs    scenario schema, referential validation, public (answer-free) view
   │     simulation       environment provisioning, access control, activity execution, events, alerts, timeline runs
   │     discovery        scans, classification register, rules, access review
   │     policies         versioning, dry runs, labelled test suite, metrics, change records
   │     investigation    correlation, risk model, remediation + verification
   │     assessment       task progress checks, rubric checks, critical conditions, scoring, digest
   │     reports          report builders + Markdown/HTML/JSON/CSV renderers
   ├── labs/               encryption (REAL_LAB), dblab (REAL_LAB), simlabs (cloud, privacy, AI)
   ├── content/            company.py (synthetic enterprise), curriculum.py, scenarios/*.json
   └── models.py / db.py   SQLAlchemy 2 models, engine/session
```

## Key design decisions

1. **Per-session environments.** Starting a scenario provisions a private copy of the synthetic company (identities, groups, assets, grants, destinations, labels, classification rules and baseline policies) keyed by `session_id`. This gives isolation between learners, trivial reset and deterministic replay. A reset deletes the session-scoped rows and re-provisions; submitted `AssessmentAttempt`s are retained.
2. **Content is data, logic is code.** Scenario JSON is validated by `ScenarioDefinition` (Pydantic, `extra=forbid`) and cross-checked against the environment (every actor, asset, destination, grant and step must exist). Task checks, rubric checks and critical conditions are **names** resolved from fixed server-side registries — scenario content can never execute code.
3. **One policy engine everywhere.** Live activity, dry-run tests, the labelled test suite, the assessment's defence-in-depth check and the AI prompt gateway all use `policy_engine.evaluate_policy`/`decide`.
4. **Hidden answers stay on the server.** `public_view()` is the only scenario representation sent to clients. Events and alerts carry an internal `step_key` that is never serialized. There is no score preview before submission.
5. **Honest provenance.** Every event has `provenance` (`SIMULATED` for all scenario events) and a `kr-sim-*` source system. Lab responses state `REAL_LAB` or `SIMULATED`.
6. **AI is not used for any decision.** Explanations are deterministic templates (`explain_entry`). No external AI provider is implemented.

## Data flow of one simulated activity

`execute_activity` (services/simulation.py):

1. **Identity**: sign-in or account-disabled check → `IDENTITY` event.
2. **Access control**: `access_path()` resolves direct grant → group grant → data owner; quarantined assets allow only owner/Security → `FILE_ACCESS`/`DATABASE`/`CLOUD_STORAGE` event (ALLOWED/DENIED, with the grant that allowed it).
3. **Egress blocklist**: blocked external destinations stop the transfer → `PROXY` event BLOCKED.
4. **Policy evaluation**: content of the asset is scanned live (DLP inspects content at egress, independent of labels); context is built (actor, content, resource, destination, business context, after-hours) → all enabled policies evaluated → `PolicyEvaluation` row with the full trace.
5. **DLP decision** → `DLP` event (decisive policy and version), then the transfer event (`EMAIL_GATEWAY`/`PROXY`/`ENDPOINT`/`FILE_ACCESS`).
6. **Detections** → `DETECTION` events for matched detection policies.
7. **Correlation links**: all events of the transaction relate to each other; earlier events by the same actor on the same resource in the same run are linked explicitly.
8. **Alerts**: one per matched policy with `alert=true`, referencing the triggering event, all transaction events and the policy version.

## Timeline runs

`run_timeline(mode)` replays the scenario's scripted business day on sim-day *n* for run *n*. `standard` uses the original identities. `validation` substitutes the subject's steps with a **validation clone** that has the subject's *original* role and group memberships, so a replay proves that the control gap is fixed rather than merely that one account was disabled. Each run records the `ScenarioAction` sequence number at which it happened so that the engine can tell whether a replay came after the latest control change.

## Time

All timestamps are stored in UTC (SQLite drops tzinfo; `as_utc` restores it) and rendered as `YYYY-MM-DDTHH:MM:SSZ`. The UI labels every time as UTC. The simulation clock is per session and advances one minute per learner action.

## Frontend

React 18 + TypeScript + Vite; react-router; no UI framework — a small design system in `src/styles.css` and `src/components/ui.tsx` (tokens, light/dark themes, text-labelled badges, accessible focus, responsive grid). `state.tsx` holds the auth context, the active-session context and a `useLoad` hook (keeps data on screen while refreshing). The structured policy editor (`components/PolicyEditor.tsx`) is shared by the DLP Policy Studio and the AI lab; `components/Trace.tsx` renders evaluation traces.

## Boundaries and non-goals

- No distributed infrastructure, queues or Kubernetes — unnecessary at this scale and on an 8 GB machine.
- No vendor connectors are implemented; see docs/INTEGRATIONS.md.
- PostgreSQL is a future option; migrations are generated with `render_as_batch` for SQLite compatibility.
