# Scenarios

## Reference scenario: Unauthorized Customer-Data Export (`customer-data-export` v1.0.0)

**Level** L1 Practitioner · **Modules** M01, M02, M07, M08 · **~75 min** · **Mode** SIMULATED · Definition: `apps/api/src/content/scenarios/customer-data-export.json`

### Environment (Kestrel Ridge Financial, fictional)

- 14 identities across Customer Operations, Finance, HR, IT, Security, Legal, Marketing, Internal Audit — including a vendor contractor, a departing employee and a service identity.
- 10 groups, 15 data assets (CSV extracts, CRM/HR tables, documents, a cloud object, a secrets file), 20 access grants, 10 destinations (internal, sanctioned partners, personal webmail/cloud, USB, approved/unapproved AI).
- Default 4-level label scheme (Public, Internal, Confidential, Restricted), configurable per scenario.
- Baseline controls: a bulk-download **detection** (≥10,000 records), an external-email DLP rule (monitor), and a cloud-upload rule for Confidential+ data in **monitor-only pilot mode**.
- Built-in coverage gaps: the nightly customer export is unlabeled and has no owner; the CRM table and ticket report are under-classified; a secrets file is readable by all staff; the export folder ACL lets all support agents (including contractors) read bulk extracts.

### Business day timeline (hidden from learners until executed)

Ten scripted activities, including legitimate work (scheduled export by the service identity, payroll submission to the payroll provider, partner hand-off, brochure upload, internal email), an **ambiguous** after-hours bulk download with a ticket reference that cannot be verified, and the subject's bulk download followed by a transfer to a personal destination.

**Variants**: A — the vendor contractor uploads the export to personal cloud storage (no DLP alert under baseline controls; only correlation reveals it). B — a departing employee emails it to personal webmail (DLP monitor alert). Assessment-mode sessions receive a random variant; reset rotates the variant.

### State model

`ScenarioSession.status`: ACTIVE ⇄ PAUSED → SUBMITTED; *reset* returns to ACTIVE with a new attempt number and a fresh environment. All write endpoints refuse non-ACTIVE sessions (409). Progress is 15 tasks evaluated from state (not clicks):

| Stage | Task | Completed when |
|---|---|---|
| Discover | discover | ≥1 discovery scan |
| Discover | inspect | export asset detail opened |
| Classify | classify | export has a label and an owner |
| Classify | access_review | a review decision is recorded on an export grant |
| Configure | policy | ≥1 learner-authored policy version |
| Configure | policy_test | ≥2 dry runs with different outcomes |
| Execute | run_day | ≥1 timeline run |
| Detect | triage | every run-1 alert has a disposition |
| Investigate | case | primary case has ≥3 evidence items |
| Investigate | analysis | OBSERVATION, INFERENCE and UNKNOWN notes |
| Investigate | scope | affected assets, exposure, records and severity recorded |
| Remediate | contain | a CONTAINMENT action applied |
| Remediate | fix | a control change after run 1 |
| Verify | verify | a validation replay after the latest control change |
| Document | report | summary, root cause, residual risk, lessons learned written |

### Expected outcomes and evidence-dependent ground truth

Ground truth is **partly computed from what actually happened**: if the learner's controls blocked the transfer in run 1, “confirmed exfiltration” is no longer supported and the expected determination becomes *attempted exfiltration prevented* with zero records exposed. The expected severity is recalculated with the documented risk model accordingly.

Legitimate activity must keep working in the validation replay (e.g. blocking the personal-cloud domain stops the marketing brochure upload and is penalised as business disruption). Revoking sessions alone does not stop a user signing in again. Reimaging a device before preserving evidence destroys evidence (critical failure).

### Remediation catalogue

PRESERVE_EVIDENCE, DISABLE_ACCOUNT, REVOKE_SESSIONS, BLOCK_DESTINATION, QUARANTINE_ASSET, REVOKE_GRANT, REIMAGE_DEVICE (destructive, needs explicit confirmation), REQUEST_EXTERNAL_TAKEDOWN (recorded; outcome explicitly unverifiable), ESCALATE (Privacy Office, Legal, HR, data owner, management, CISO), ENABLE_ACCOUNT. Each action records before/after state and is verified against the environment (sign-in probes, egress probes, effective-access recomputation).

### Labelled policy test suite

14 cases (8 should be prevented, 6 legitimate) used by Data Security Engineering to compute TP/FP/TN/FN, precision and recall with an explicit scope note.

### Mission phases

Every task also carries a `phase` used by the mission workflow (`UNDERSTAND`, `INSPECT`, `ACT`, `OBSERVE`, `VALIDATE`, `SUBMIT`). The reference scenario maps discover/inspect/case/analysis/scope → INSPECT; classify/access_review/policy/policy_test/contain/fix → ACT; run_day/triage → OBSERVE; verify → VALIDATE; report → SUBMIT. Phases group work for display. They do not force an order, and completion is still computed from state.

## Adding a scenario

Create `app/content/scenarios/<id>.json` matching `ScenarioDefinition`; run `python -m app.cli validate-content`. Unknown checks, identities, assets, destinations, grants or steps are rejected; category weights must total 100.

## Stand-alone labs

Encryption, Database, Privacy, Cloud DSPM and AI labs are per-user (not scenario sessions), resettable, and record exercise results with provenance. See README for their modes.
