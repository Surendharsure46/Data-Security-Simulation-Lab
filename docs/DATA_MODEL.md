# Data model

Defined in `backend/app/models.py`; schema created by Alembic migrations `0001_initial_schema`, `0002_career_and_missions` and `0003_levels_and_roles`. A test (`tests/test_migrations.py`) asserts that the migrations produce exactly the ORM schema.

## Platform entities

| Entity | Purpose |
|---|---|
| `Organization` | Training tenant. Users and sessions belong to one organisation; staff can only see their own organisation. |
| `User` | Platform account (`learner`, `instructor`, `admin`). PBKDF2-SHA256 password hash. |
| `AuthToken` | SHA-256 hash of an opaque bearer token, expiry, revocation flag. |
| `AuditRecord` | Platform audit trail (logins, session starts/resets, submissions, role changes, integration toggles). |
| `IntegrationConfig` / `IntegrationRun` | Per-organisation connector switches (no secrets stored) and provenance of connector runs. |

## Scenario session entities (all carry `session_id`)

| Entity | Purpose |
|---|---|
| `ScenarioSession` | Scenario id + version, variant, mode (GUIDED/ASSESSMENT), status (ACTIVE/PAUSED/SUBMITTED), attempt number, sim clock, run count, event sequence, hints used, flags (viewed assets, run log). |
| `ScenarioAction` | Ordered log of every learner action (`seq`, type, params, result, provenance, sim time). Source for “after the last fix” checks and reports. |
| `SimIdentity`, `SimGroup` | Synthetic people and service identities (department, role, employment type, status, attributes) and group membership. |
| `DataAsset` | Synthetic file/table/object: system, location, owner, current label, record count, stored content sample, handling notes, exception, quarantine flag. |
| `AccessGrant` | Asset permission for an identity or group; status ACTIVE/REVOKED; access-review decision and note. |
| `Destination` | Egress destination: kind, domain, category, sanctioned/internal, blocklist flag. |
| `ClassificationLabel` | Configurable label scheme (key, name, rank, handling). |
| `ClassificationRule` | Detector → recommended label rules (thresholds, confidence, enabled, version). |
| `DiscoveryScan`, `ClassificationFinding` | Scan runs (with rule snapshot) and per-asset detector findings with masked evidence. |
| `ClassificationAssignment` | Append-only classification register history (previous/new label, owner, justification). |
| `Policy`, `PolicyVersion` | Policy header (key, kind, status, current version) and immutable versioned definitions. |
| `PolicyEvaluation` | Full trace of every live or dry-run evaluation. |
| `PolicyTestRun`, `ChangeRecord` | Labelled test-suite runs (policy snapshot, per-case results, metrics) and change records. |
| `SecurityEvent` | Common event schema (below). |
| `Alert` | Alert with policy id/version, triggering event, linked event ids, disposition. |
| `InvestigationCase`, `CaseNote`, `EvidenceReference` | Case fields (hypothesis, determination, severity, subjects, affected assets, exposure, root causes, report sections), typed notes citing evidence, evidence references validated against session state. |
| `RemediationAction` | Applied action with before/after state, verification result and status (VERIFIED, VERIFICATION_FAILED, RECORDED). |
| `AssessmentAttempt` | Submitted score, category scores, per-criterion explanations, critical failures, missing tasks, recommendations, input digest, report snapshot. |

## Learning-journey entities (migrations 0002, 0003)

| Entity | Purpose |
|---|---|
| `LearnerProfile` | One per user: onboarding step (ROLE → DONE), chosen role (`desired_role`), highest unlocked level 0–5 (`career_level`), title, fundamentals read and demo-lab progress (`onboarding` JSON), pending celebration (`pending_promotion`: unlocked level, or 6 = journey complete). Knowledge checks are stored as `LabExerciseResult(lab="knowledge", exercise="LEVEL-Ln")`. |
| `MissionAttempt` | One attempt at a mission: strategy (ASSIGNED / PRACTICE / NEW_VARIANT), whether it counts toward the mission, status (IN_PROGRESS, PASSED, NOT_PASSED, PRACTICE_PASSED, ABANDONED), linked scenario session and assessment attempt, comprehension result, explanation, cited evidence snapshot, score and the full outcome (required criteria, skills, skill gaps, remedial lessons, next step). |
| `SkillRecord` | Append-only skill evidence from passed missions: skill key, proficiency %, mission, attempt and the criteria/exercises it rests on. |

## User-level lab entities

| Entity | Purpose |
|---|---|
| `LabState` | Per-user, per-lab JSON state (cloud estate, privacy dataset, AI configuration, encryption progress, learner profile/pathway). |
| `LabExerciseResult` | Passed exercises with provenance (REAL_LAB / SIMULATED) and evidence detail. Drives lesson completion. |

REAL_LAB files (encrypted files, lab keyring, lab SQLite database and backups) live under `THREATREADY_LAB_DATA_DIR/user-<id>-<tag>/` and are never shared between users.

## Common security-event schema

| Field | Notes |
|---|---|
| `event_id` | `evt-<session>-<seq>`, deterministic within a session |
| `timestamp` | UTC |
| `organization_id`, `scenario_id`, `scenario_session_id` | context |
| `run_number` | 0 = ad-hoc learner activity or verification probe; n = timeline run n |
| `actor_id`, `resource_id`, `destination` | synthetic keys |
| `action`, `result` | e.g. DOWNLOAD/EMAIL/UPLOAD/SIGN_IN/ANOMALY; ALLOWED, ALLOWED_WITH_WARNING, BLOCKED, DENIED, SUCCESS, FAILURE, DETECTED |
| `data_classification` | label at the time of the event (null = unlabeled) |
| `source_type`, `source_system` | IDENTITY, FILE_ACCESS, DATABASE, CLOUD_STORAGE, DLP, DETECTION, EMAIL_GATEWAY, PROXY, ENDPOINT; systems are `kr-sim-*` |
| `provenance` | SIMULATED, REAL_LAB or INTEGRATED — stored, never inferred from names |
| `policy_id`, `policy_version` | decisive or detecting policy |
| `transaction_id`, `related_event_ids` | explicit relationships |
| `evidence_refs` | cases citing the event |
| `extension` | source-specific fields preserved as-is (device, IP, access path, grant, record count, decision trace, detector types …) |

The internal column `step_key` maps timeline events to scenario steps for grading and is never serialized.
