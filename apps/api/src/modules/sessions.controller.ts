/** Scenario catalogue, session lifecycle, timeline execution, assessment and reports. */
import { Controller, Get, Param } from "@nestjs/common";
import { ActivityIn, ConfirmIn, ReportQuery, ResetIn, RunIn, StartSessionIn } from "@threatready/contracts";
import { and, asc, desc, eq, isNull } from "drizzle-orm";
import { z } from "zod";
import { audit } from "../common/audit.js";
import { DomainError, iso } from "../common/util.js";
import { type Principal, uow } from "../db/context.js";
import {
  alerts, assessment_attempts, data_assets, investigation_cases, policies, remediation_actions, scenario_actions, scenario_sessions, security_events,
} from "../db/schema.js";
import { taskProgress } from "../domain/assessment.js";
import { rememberCompletedTasks } from "../domain/curriculum.js";
import * as reports from "../domain/reports.js";
import { allDefinitions, getDefinition, publicView } from "../domain/scenario-defs.js";
import {
  alertOut, attemptOut, eventOut, loadSession, missionAttemptForSession, ownerSession, startScenarioSession, startTime, submitScenarioSession, wipeSession,
} from "../domain/session-lifecycle.js";
import { advanceClock, executeActivity, provisionEnvironment, recordAction, runTimeline, type SessionRow } from "../domain/simulation.js";
import { CurrentPrincipal, IdParam, Permission, PERMISSIONS, PostCreated, PostOk, RawResponse, ZBody, ZQuery } from "../platform/http.js";

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const ListQuery = z.object({ all_users: z.enum(["true", "false"]).optional() });

export async function sessionSummary(s: SessionRow, detail = false): Promise<Json> {
  const d = getDefinition(s.scenario_id);
  const out: Json = {
    id: s.id, scenario_id: s.scenario_id, scenario_title: d ? d.title : s.scenario_id, scenario_version: s.scenario_version, mode: s.mode,
    status: s.status, attempt_number: s.attempt_number, sim_clock: iso(s.sim_clock), run_count: s.run_count, created_at: iso(s.created_at),
    updated_at: iso(s.updated_at), user_id: s.user_id, execution_mode: "SIMULATED",
  };
  const m = await missionAttemptForSession(s.id);
  out.mission = m ? { attempt_id: m.id, mission_id: m.mission_id, status: m.status } : null;
  if (detail) {
    const u = uow();
    const progress = await taskProgress(s);
    out.progress = progress;
    out.progress_percent = Math.round(100 * progress.filter((t) => t.done).length / Math.max(1, progress.length));
    out.scenario = d ? publicView(d) : null;
    out.runs = (s.flags ?? {}).runs ?? [];
    out.counts = {
      events: await u.count(security_events, eq(security_events.session_id, s.id)),
      alerts: await u.count(alerts, eq(alerts.session_id, s.id)),
      open_alerts: await u.count(alerts, eq(alerts.session_id, s.id), isNull(alerts.disposition)),
      cases: await u.count(investigation_cases, eq(investigation_cases.session_id, s.id)),
      policies: await u.count(policies, eq(policies.session_id, s.id)),
      unlabeled_assets: await u.count(data_assets, eq(data_assets.session_id, s.id), isNull(data_assets.label_key)),
      remediations: await u.count(remediation_actions, eq(remediation_actions.session_id, s.id)),
    };
    out.hints_enabled = s.mode === "GUIDED";
    out.hints_used = s.hints_used ?? {};
    const latest = await u.one(assessment_attempts, eq(assessment_attempts.session_id, s.id), [desc(assessment_attempts.id)]);
    out.latest_attempt = latest ? attemptOut(latest) : null;
  }
  return out;
}

const touch = (s: SessionRow) => { s.updated_at = new Date(); };

@Controller("api")
@Permission(PERMISSIONS.SELF)
export class SessionsController {
  @Get("scenarios")
  scenarios() {
    return [...allDefinitions().values()].map(publicView);
  }

  @Get("scenarios/:scenarioId")
  scenario(@Param("scenarioId") scenarioId: string) {
    const d = getDefinition(scenarioId);
    if (!d) throw new DomainError("Scenario not found", 404);
    return publicView(d);
  }

  @PostCreated("sessions")
  async start(@CurrentPrincipal() p: Principal, @ZBody(StartSessionIn) body: z.infer<typeof StartSessionIn>) {
    return sessionSummary(await startScenarioSession(p, body.scenario_id, body.mode, body.variant ?? null), true);
  }

  @Get("sessions")
  async list(@CurrentPrincipal() p: Principal, @ZQuery(ListQuery) q: z.infer<typeof ListQuery>) {
    const where = q.all_users === "true" && p.staff
      ? eq(scenario_sessions.org_id, p.orgId)
      : and(eq(scenario_sessions.org_id, p.orgId), eq(scenario_sessions.user_id, p.userId))!;
    const out: Json[] = [];
    for (const s of await uow().all(scenario_sessions, where, [desc(scenario_sessions.updated_at)])) out.push(await sessionSummary(s));
    return out;
  }

  @Get("sessions/:sessionId")
  async get(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal) {
    return sessionSummary(await loadSession(id, p, { write: false }), true);
  }

  @PostOk("sessions/:sessionId/pause")
  async pause(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal) {
    const s = await ownerSession(id, p);
    if (s.status !== "ACTIVE") throw new DomainError(`Cannot pause a ${s.status} session`, 409);
    s.status = "PAUSED";
    touch(s);
    await recordAction(s, "SESSION_PAUSE", {});
    return sessionSummary(s);
  }

  @PostOk("sessions/:sessionId/resume")
  async resume(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal) {
    const s = await ownerSession(id, p);
    if (s.status !== "PAUSED") throw new DomainError(`Cannot resume a ${s.status} session`, 409);
    s.status = "ACTIVE";
    touch(s);
    await recordAction(s, "SESSION_RESUME", {});
    return sessionSummary(s);
  }

  /** Discard all simulated state and start a new attempt. Submitted assessment attempts are kept. */
  @PostOk("sessions/:sessionId/reset")
  async reset(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal, @ZBody(ResetIn) body: z.infer<typeof ResetIn>) {
    const s = await ownerSession(id, p);
    if (!body.confirm) throw new DomainError("Reset discards all work in this session (submitted attempts are kept). Resubmit with confirm=true.", 409);
    if (await missionAttemptForSession(s.id)) {
      throw new DomainError("This session belongs to a mission. Use 'Retry with practice or new variant' in the mission view.", 409);
    }
    const d = getDefinition(s.scenario_id);
    if (!d) throw new DomainError(`Scenario ${s.scenario_id} is not available`, 404);
    await rememberCompletedTasks(p.userId);
    await wipeSession(s.id);
    if (body.new_variant && d.variants.length > 1) {
      const keys = d.variants.map((v) => v.key);
      s.variant = keys.includes(s.variant) ? keys[(keys.indexOf(s.variant) + 1) % keys.length] : keys[0];
    }
    s.attempt_number += 1;
    s.status = "ACTIVE";
    s.run_count = 0;
    s.event_seq = 0;
    s.flags = {};
    s.hints_used = {};
    s.sim_clock = startTime(d);
    s.scenario_version = d.version;
    touch(s);
    await provisionEnvironment(s);
    await recordAction(s, "SESSION_RESET", { attempt: s.attempt_number });
    await audit({ user_id: p.userId, org_id: p.orgId, action: "session.reset", target_type: "session", target_id: s.id });
    return sessionSummary(s, true);
  }

  @PostOk("sessions/:sessionId/hints/:taskKey")
  async revealHint(@IdParam("sessionId") id: number, @Param("taskKey") taskKey: string, @CurrentPrincipal() p: Principal) {
    const s = await loadSession(id, p, { write: true });
    if (s.mode !== "GUIDED") throw new DomainError("Hints are disabled in independent assessment mode", 403);
    const allHints = getDefinition(s.scenario_id)?.hints ?? {};
    const hints = Object.hasOwn(allHints, taskKey) ? allHints[taskKey] : undefined;
    if (!hints) throw new DomainError("No hints for this task", 404);
    const used: Record<string, number[]> = { ...(s.hints_used ?? {}) };
    const revealed = [...(used[taskKey] ?? [])];
    if (revealed.length < hints.length) {
      revealed.push(revealed.length);
      used[taskKey] = revealed;
      s.hints_used = used;
      await recordAction(s, "HINT", { task: taskKey, index: revealed[revealed.length - 1] });
    }
    return { task: taskKey, hints: revealed.map((i) => hints[i]), remaining: hints.length - revealed.length };
  }

  @Get("sessions/:sessionId/hints")
  async revealedHints(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal) {
    const s = await loadSession(id, p, { write: false });
    const d = getDefinition(s.scenario_id);
    return Object.fromEntries(Object.entries((s.hints_used ?? {}) as Record<string, number[]>).filter(([k]) => d && Object.hasOwn(d.hints, k))
      .map(([k, v]) => [k, v.map((i) => d!.hints[k][i])]));
  }

  @PostOk("sessions/:sessionId/timeline/run")
  async run(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal, @ZBody(RunIn) body: z.infer<typeof RunIn>) {
    const s = await loadSession(id, p, { write: true });
    const result = await runTimeline(s, body.mode);
    touch(s);
    await audit({ user_id: p.userId, org_id: p.orgId, action: "session.run_timeline", target_type: "session", target_id: s.id, detail: result });
    return result;
  }

  /** Controlled synthetic event generator: run one activity through all live controls. */
  @PostOk("sessions/:sessionId/activities")
  async activity(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal, @ZBody(ActivityIn) body: z.infer<typeof ActivityIn>) {
    const s = await loadSession(id, p, { write: true });
    const ts = advanceClock(s);
    const spec: Json = { actor: body.actor, action: body.action, resource: body.resource ?? null, destination: body.destination ?? null,
      record_count: body.record_count ?? null,
      context: { business_justification: body.business_justification ?? null, ticket_id: body.ticket_id ?? null, device_managed: true } };
    const res = await executeActivity(s, spec, { timestamp: ts, runNumber: 0, learnerInitiated: true });
    await recordAction(s, "ACTIVITY", Object.fromEntries(Object.entries(spec).filter(([, v]) => v !== null)), { outcome: res.outcome });
    touch(s);
    return { outcome: res.outcome, reason: res.reason, transaction_id: res.transaction_id, decision: res.decision ?? null, policy_trace: res.entries ?? [],
      events: res.events.map(eventOut), alerts: res.alerts.map(alertOut) };
  }

  @Get("sessions/:sessionId/actions")
  async actions(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal) {
    const s = await loadSession(id, p, { write: false });
    return (await uow().all(scenario_actions, eq(scenario_actions.session_id, s.id), [asc(scenario_actions.seq)])).map((a) => ({ seq: a.seq,
      action_type: a.action_type, params: a.params, result: a.result, provenance: a.provenance, sim_time: iso(a.sim_time), created_at: iso(a.created_at) }));
  }

  // ------------------------------------------------------------------------- assessment

  @PostOk("sessions/:sessionId/submit")
  async submit(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal, @ZBody(ConfirmIn) body: z.infer<typeof ConfirmIn>) {
    const s = await loadSession(id, p, { write: true });
    if (!body.confirm) throw new DomainError("Submission locks the session for grading. Resubmit with confirm=true.", 409);
    if (await missionAttemptForSession(s.id)) {
      throw new DomainError("This session belongs to a mission. Submit your evidence and explanation from the mission view.", 409);
    }
    return attemptOut(await submitScenarioSession(s, p));
  }

  @Get("sessions/:sessionId/attempts")
  async attempts(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal) {
    const s = await loadSession(id, p, { write: false });
    return (await uow().all(assessment_attempts, eq(assessment_attempts.session_id, s.id), [asc(assessment_attempts.id)])).map(attemptOut);
  }

  @Get("attempts")
  async myAttempts(@CurrentPrincipal() p: Principal) {
    return (await uow().all(assessment_attempts, eq(assessment_attempts.user_id, p.userId), [desc(assessment_attempts.id)])).map(attemptOut);
  }

  @Get("attempts/:attemptId/report")
  async attemptReport(@IdParam("attemptId") attemptId: number, @CurrentPrincipal() p: Principal) {
    const a = await uow().get(assessment_attempts, attemptId);
    if (!a) throw new DomainError("Attempt not found", 404);
    await loadSession(a.session_id, p, { write: false });
    return new RawResponse(a.report_snapshot, "text/markdown; charset=utf-8");
  }

  // ------------------------------------------------------------------------- reports

  @Get("sessions/:sessionId/reports")
  async reportTypes(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal) {
    await loadSession(id, p, { write: false });
    return Object.entries(reports.REPORT_TYPES).map(([k, v]) => ({ type: k, title: v,
      formats: ["md", "html", "json", ...(["inventory", "classification-register", "policy-tests", "incident-timeline", "remediation-verification"].includes(k) ? ["csv"] : [])] }));
  }

  @Get("sessions/:sessionId/reports/:reportType")
  async report(@IdParam("sessionId") id: number, @Param("reportType") reportType: string, @CurrentPrincipal() p: Principal,
    @ZQuery(ReportQuery) q: z.infer<typeof ReportQuery>) {
    const s = await loadSession(id, p, { write: false });
    const rep = await reports.build(s, reportType);
    const fname = `threatready-${reportType}-session${s.id}.${q.format}`;
    const headers: Record<string, string> = q.download === "true" ? { "Content-Disposition": `attachment; filename="${fname}"` } : {};
    if (q.format === "json") return new RawResponse(JSON.stringify(rep), "application/json", headers);
    if (q.format === "csv") return new RawResponse(reports.toCsv(rep), "text/csv; charset=utf-8", headers);
    if (q.format === "html") {
      return new RawResponse(reports.toHtml(rep), "text/html; charset=utf-8", { ...headers, "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'" });
    }
    return new RawResponse(reports.toMarkdown(rep), "text/markdown; charset=utf-8", headers);
  }
}
