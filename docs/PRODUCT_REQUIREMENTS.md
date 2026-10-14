# Product requirements and implementation status

**Positioning**: “A practical Data Security training and validation platform that connects enterprise simulations, policy engineering, security investigations and verified real-tool practice in one progressive learning environment.” No claims of uniqueness, certification or production equivalence are made.

**Learning cycle**: Understand → Discover → Classify → Configure → Execute → Detect → Investigate → Remediate → Verify → Document.

## Users and stories

| Persona | Story | Status |
|---|---|---|
| Fresher | As a beginner I complete knowledge checks and guided classification with hints so I learn the vocabulary by doing. | Implemented (L0 quizzes, guided mode) |
| DLP engineer | I write a policy, test it against prohibited and legitimate transfers, measure precision/recall on a labelled set and record a change. | Implemented |
| SOC analyst | I triage alerts, correlate events with explained relationships, scope the exposure and write an evidence-based report. | Implemented |
| Data protection engineer | I encrypt files, rotate keys, harden a database role model and verify restores in real local labs. | Implemented (REAL_LAB) |
| New hire (career workflow) | I am onboarded into the organisation, receive missions from the business, prove my work with an explanation and cited evidence, see my skill gaps and a remedial lesson when I fail, retry with practice or a new variant, and am promoted to a role with harder challenges when a level is complete. | Implemented (docs/WORKFLOW.md) |
| Learner (assessment) | I take an unfamiliar variant without hints and get an explainable score with critical-failure rules. | Implemented |
| Instructor | I review learners' sessions read-only and see the audit trail. | Implemented |
| Administrator | I manage users/roles and connector switches. | Implemented |

## Feature-by-feature status

| Spec section | Requirement | Status |
|---|---|---|
| §3.1 | Real behaviour: persistence, policy effect on later evaluations, events, alerts, remediation state, reproducibility, server-side scoring | Implemented & tested |
| §3.2 | Execution modes visible everywhere | Implemented (badges, event `provenance`, lab responses) |
| §6 | 16 navigation areas | Implemented; Capstone is honestly marked PLANNED inside Learning Paths |
| §7 M01 | Inventory, search/filter, detectors with evidence/confidence, labels, register, exceptions/ownership, rule versions, export | Implemented. Policy-version comparison of classification outcomes: via re-scan + rule versions (no side-by-side diff view) |
| §7 M02 | Policy engine, create/edit/enable/disable/test/version/compare, event generator, explanations | Implemented |
| §7 M03 | Real file encryption, key verification, envelope/KEK rotation, TLS metadata, config remediation | Implemented (TLS capture simulated; no live capture) |
| §7 M04 | SQLite lab: queries, permissions, least privilege, parameterised queries, audit, bulk detection, masking, backup/restore | Implemented. PostgreSQL/MySQL lab: not implemented |
| §7 M05 | Minimisation, retention rules, deletion of disposable data, legal hold, findings report | Implemented (simulated). DSAR/consent workflows: not implemented |
| §7 M06 | Simulated storage, exposure model, synthetic audit events, remediation, verification | Implemented. Real-cloud exercise: not implemented |
| §7 M07 | Alert queue, filters, cases, evidence, timeline, observation/inference/unknown, scope, containment, verification, report | Implemented |
| §7 M08 | Rule editing/testing, labelled metrics with scope note, regression comparison, change records | Implemented |
| §7 M09 | Prompt DLP, RAG permission leakage, document permissions, retention config, tunable policy | Implemented (simulated, no model calls) |
| §7 M10 | Multi-stage capstone | **Not implemented** |
| §8 | L0–L5 with prerequisites, objectives, tasks, evidence, rubric, critical failures, remediation, unlock; specialist pathways | Implemented |
| §10 | Vertical slice steps 1–15 | Implemented, API-tested (both variants) and browser-tested |
| §11 | Scenario engine (validated definitions, state, replay, variants, hints, provenance) | Implemented; one scenario definition |
| §12 | Normalised entities and event schema | Implemented |
| §13 | Policy engine incl. precedence, exceptions, test workspace, diffs, embedded test cases | Implemented |
| §14 | Explainable correlation (no time-only links) | Implemented |
| §15 | Weighted rubric, critical failures, explanations, deterministic digest, guided vs independent | Implemented |
| §16 | AI optional, never source of truth | No AI implemented; deterministic explanations |
| §17 | Integration registry with honest status | Implemented; no vendor connectors |
| §19 | Reports MD/HTML/CSV/JSON, 14-section incident report | Implemented; PDF not implemented |
| §20 | Platform security controls | Implemented (see SECURITY.md); no OAuth/MFA |
| §21 | Unit, API, e2e tests | Implemented (see TESTING.md) |
| §22 | Windows-friendly setup, scripts, Docker optional | Implemented; Docker untested |

## Out of scope for this release

Capstone, PostgreSQL lab, real cloud/vendor connectors, external AI, PDF export, OAuth/SSO, MFA, multi-process rate limiting.
