/**
 * Scenario-session access, creation, submission and reset, shared by the scenario API and the mission workflow.
 * Serializers deliberately omit internal fields (`step_key`) that would reveal which timeline step - and therefore which
 * ground-truth role - an event or alert belongs to.
 */
import { randomInt } from "node:crypto";
import { desc, eq, inArray } from "drizzle-orm";
import { audit } from "../common/audit.js";
import { DomainError, iso, pyRepr } from "../common/util.js";
import { type Principal, uow } from "../db/context.js";
import {
  access_grants, alerts, assessment_attempts, case_notes, change_records, classification_assignments, classification_findings, classification_labels,
  classification_rules, data_assets, destinations, discovery_scans, evidence_references, investigation_cases, mission_attempts, policies,
  policy_evaluations, policy_test_runs, policy_versions, remediation_actions, scenario_actions, scenario_sessions, security_events,
  sim_groups, sim_identities,
} from "../db/schema.js";
import * as assessment from "./assessment.js";
import * as reports from "./reports.js";
import { getDefinition, type ScenarioDefinition } from "./scenario-defs.js";
import { provisionEnvironment, recordAction, type AlertRow, type EventRow, type SessionRow } from "./simulation.js";

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
export type AttemptRow = typeof assessment_attempts.$inferSelect;

export function startTime(d: ScenarioDefinition): Date {
  return new Date(d.sim_start);
}

/**
 * Load a session the caller may see. 404 (not 403) for sessions outside the caller's scope, so ids cannot be enumerated;
 * staff may read sessions in their own organization; only the owner may write, and only while the session is ACTIVE.
 */
export async function loadSession(id: number, p: Principal, opts: { write: boolean }): Promise<SessionRow> {
  const s = await uow().get(scenario_sessions, id);
  if (!s || s.org_id !== p.orgId) throw new DomainError("Session not found", 404);
  const isOwner = s.user_id === p.userId;
  if (!isOwner && !p.staff) throw new DomainError("Session not found", 404);
  if (opts.write) {
    if (!isOwner) throw new DomainError("Only the session owner can change a session", 403);
    if (s.status !== "ACTIVE") throw new DomainError(`Session is ${s.status}; resume it (or reset after submission) to make changes`, 409);
  }
  return s;
}

export async function ownerSession(id: number, p: Principal): Promise<SessionRow> {
  const s = await loadSession(id, p, { write: false });
  if (s.user_id !== p.userId) throw new DomainError("Only the session owner can change a session", 403);
  return s;
}

/**
 * Provision a new session. Independent assessments always get an unpredictable variant unless the caller asks for one
 * *different* from a previous attempt (`excludeVariant`).
 */
export async function startScenarioSession(p: Principal, scenarioId: string, mode: string, variant?: string | null,
  opts: { excludeVariant?: string | null } = {}): Promise<SessionRow> {
  const d = getDefinition(scenarioId);
  if (!d) throw new DomainError("Scenario not found", 404);
  const keys = d.variants.map((v) => v.key);
  let chosen: string;
  if (opts.excludeVariant !== undefined && opts.excludeVariant !== null) {
    const choices = keys.filter((k) => k !== opts.excludeVariant);
    const pool = choices.length ? choices : keys;
    chosen = pool[randomInt(pool.length)];
  } else if (mode === "ASSESSMENT" || !variant) {
    chosen = keys[randomInt(keys.length)];
  } else if (!keys.includes(variant)) {
    throw new DomainError(`Unknown variant; available: ${pyRepr(keys)}`, 422);
  } else {
    chosen = variant;
  }
  const s = await uow().insert(scenario_sessions, {
    user_id: p.userId, org_id: p.orgId, scenario_id: d.id, scenario_version: d.version, variant: chosen, mode, status: "ACTIVE",
    sim_clock: startTime(d), flags: {}, hints_used: {},
  });
  await provisionEnvironment(s);
  await recordAction(s, "SESSION_START", { mode });
  await audit({ user_id: p.userId, org_id: p.orgId, action: "session.start", target_type: "session", target_id: s.id, detail: { scenario: d.id, mode } });
  return s;
}

/** Grade the session on the server, store the attempt with a report snapshot and lock the session. */
export async function submitScenarioSession(s: SessionRow, p: Principal) {
  const snapshot = reports.toMarkdown(await reports.build(s, "case-report"));
  const attempt = await assessment.submit(s, p.userId, snapshot);
  s.status = "SUBMITTED";
  s.updated_at = new Date();
  await recordAction(s, "SUBMIT", {}, { attempt_id: attempt.id, score: attempt.total_score });
  await audit({ user_id: p.userId, org_id: p.orgId, action: "assessment.submit", target_type: "session", target_id: s.id,
    detail: { score: attempt.total_score, passed: attempt.passed } });
  return attempt;
}

export async function missionAttemptForSession(sessionId: number) {
  return uow().one(mission_attempts, eq(mission_attempts.session_id, sessionId), [desc(mission_attempts.id)]);
}

/** Delete all simulated state of a session (assessment attempts are kept). */
export async function wipeSession(sid: number): Promise<void> {
  const u = uow();
  const caseIds = (await u.all(investigation_cases, eq(investigation_cases.session_id, sid))).map((c) => c.id);
  if (caseIds.length) {
    await u.delete(case_notes, inArray(case_notes.case_id, caseIds));
    await u.delete(evidence_references, inArray(evidence_references.case_id, caseIds));
  }
  await u.delete(remediation_actions, eq(remediation_actions.session_id, sid));
  await u.delete(investigation_cases, eq(investigation_cases.session_id, sid));
  await u.delete(change_records, eq(change_records.session_id, sid));
  const polIds = (await u.all(policies, eq(policies.session_id, sid))).map((x) => x.id);
  if (polIds.length) await u.delete(policy_versions, inArray(policy_versions.policy_id, polIds));
  for (const t of [policy_test_runs, policies, policy_evaluations, alerts, security_events, classification_findings, discovery_scans,
    classification_assignments, classification_rules, classification_labels, access_grants, destinations, data_assets, sim_groups,
    sim_identities, scenario_actions] as const) {
    await u.delete(t, eq(t.session_id, sid));
  }
}

// --------------------------------------------------------------------------- serializers

export function eventOut(e: EventRow): Json {
  return {
    event_id: e.event_id, timestamp: iso(e.timestamp), organization_id: e.organization_id, scenario_id: e.scenario_id,
    scenario_session_id: e.session_id, run_number: e.run_number, actor_id: e.actor_id, resource_id: e.resource_id, action: e.action,
    result: e.result, data_classification: e.data_classification, source_type: e.source_type, source_system: e.source_system,
    provenance: e.provenance, policy_id: e.policy_id, policy_version: e.policy_version, destination: e.destination,
    transaction_id: e.transaction_id, related_event_ids: e.related_event_ids ?? [], evidence_refs: e.evidence_refs ?? [], summary: e.summary,
    extension: e.extension ?? {},
  };
}

export function alertOut(a: AlertRow): Json {
  return {
    alert_id: a.alert_id, run_number: a.run_number, title: a.title, severity: a.severity, status: a.status, disposition: a.disposition,
    disposition_note: a.disposition_note, policy_id: a.policy_id, policy_version: a.policy_version, triggering_event_id: a.triggering_event_id,
    event_ids: a.event_ids ?? [], actor_id: a.actor_id, resource_id: a.resource_id, explanation: a.explanation, timestamp: iso(a.timestamp),
    provenance: "SIMULATED",
  };
}

export function attemptOut(a: AttemptRow): Json {
  return {
    id: a.id, session_id: a.session_id, scenario_id: a.scenario_id, attempt_number: a.attempt_number, mode: a.mode, rubric_version: a.rubric_version,
    total_score: a.total_score, passed: a.passed, category_scores: a.category_scores, criteria: a.criteria, critical_failures: a.critical_failures,
    missing_tasks: a.missing_tasks, recommendations: a.recommendations, inputs_digest: a.inputs_digest, submitted_at: iso(a.submitted_at),
    label: a.mode === "GUIDED" ? "Guided practice result" : "Independent assessment result",
    disclaimer: "Platform assessment outcome for the tasks in this scenario only. Not a professional certification.",
  };
}
