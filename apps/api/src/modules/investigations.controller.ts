/** Security Event Explorer, alert triage, investigation cases, remediation and risk model. */
import { Controller, Delete, Get, Param, Patch } from "@nestjs/common";
import {
  AlertsQuery, CaseIn, CasePatch, DispositionIn, EventsQuery, EVIDENCE_TYPES, EvidenceIn, NOTE_KINDS, NoteIn, RemediationIn, RiskIn,
} from "@threatready/contracts";
import { and, asc, eq, ilike, inArray, isNull, or, type SQL } from "drizzle-orm";
import { z } from "zod";
import { DomainError, iso, pyRepr, sorted, uniqueSorted } from "../common/util.js";
import { type Principal, uow } from "../db/context.js";
import {
  access_grants, alerts, case_notes, classification_findings, data_assets, evidence_references, investigation_cases, remediation_actions,
  security_events, sim_identities,
} from "../db/schema.js";
import {
  applyRemediation, type CaseRow, correlate, DETERMINATIONS, DISPOSITIONS, EXPOSURE_STATUSES, PARTIES, type RemediationRow, riskScore,
  ROOT_CAUSES, SEVERITIES, verifyState,
} from "../domain/investigation.js";
import { getPolicy } from "../domain/policies.js";
import { alertOut, eventOut, loadSession } from "../domain/session-lifecycle.js";
import { advanceClock, labelRanks, policyVersions, recordAction, type SessionRow } from "../domain/simulation.js";
import { CurrentPrincipal, IdParam, Permission, PERMISSIONS, PostCreated, PostOk, ZBody, ZQuery } from "../platform/http.js";

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
const read = (id: number, p: Principal) => loadSession(id, p, { write: false });
const write = (id: number, p: Principal) => loadSession(id, p, { write: true });

async function getAlert(s: SessionRow, alertId: string) {
  const a = await uow().one(alerts, and(eq(alerts.session_id, s.id), eq(alerts.alert_id, alertId))!);
  if (!a) throw new DomainError("Alert not found", 404);
  return a;
}

async function getCase(s: SessionRow, caseId: number): Promise<CaseRow> {
  const c = await uow().one(investigation_cases, and(eq(investigation_cases.session_id, s.id), eq(investigation_cases.id, caseId))!);
  if (!c) throw new DomainError("Case not found", 404);
  return c;
}

export function remOut(r: RemediationRow): Json {
  return { id: r.id, seq: r.seq, case_id: r.case_id, action_type: r.action_type, target_key: r.target_key, justification: r.justification,
    status: r.status, before_state: r.before_state, after_state: r.after_state, verification: r.verification, provenance: r.provenance,
    sim_time: iso(r.sim_time) };
}

async function caseOut(c: CaseRow, detail = false): Promise<Json> {
  const out: Json = {
    id: c.id, title: c.title, status: c.status, alert_ids: c.alert_ids, hypothesis: c.hypothesis, severity: c.severity, determination: c.determination,
    subject_identities: c.subject_identities, affected_asset_keys: c.affected_asset_keys, exposure_status: c.exposure_status,
    records_potentially_exposed: c.records_potentially_exposed, root_causes: c.root_causes, summary: c.summary,
    root_cause_narrative: c.root_cause_narrative, residual_risk: c.residual_risk, lessons_learned: c.lessons_learned,
    created_at: iso(c.created_at), updated_at: iso(c.updated_at),
  };
  if (detail) {
    const u = uow();
    out.evidence = (await u.all(evidence_references, eq(evidence_references.case_id, c.id), [asc(evidence_references.id)]))
      .map((e) => ({ id: e.id, ref_type: e.ref_type, ref_id: e.ref_id, label: e.label, note: e.note, created_at: iso(e.created_at) }));
    out.notes = (await u.all(case_notes, eq(case_notes.case_id, c.id), [asc(case_notes.id)]))
      .map((n) => ({ id: n.id, kind: n.kind, text: n.text, evidence_ids: n.evidence_ids, created_at: iso(n.created_at) }));
    out.remediations = (await u.all(remediation_actions, eq(remediation_actions.case_id, c.id), [asc(remediation_actions.seq)])).map(remOut);
  }
  return out;
}

/** Resolve an evidence reference against session state; reject anything that does not exist. */
async function evidenceLabel(s: SessionRow, refType: string, refId: string): Promise<string> {
  const u = uow();
  if (refType === "EVENT") {
    const e = await u.one(security_events, and(eq(security_events.session_id, s.id), eq(security_events.event_id, refId))!);
    if (e) return `${e.event_id} ${iso(e.timestamp)} ${e.summary}`.slice(0, 300);
  } else if (refType === "ALERT") {
    const a = await u.one(alerts, and(eq(alerts.session_id, s.id), eq(alerts.alert_id, refId))!);
    if (a) return `${a.alert_id} ${a.title}`.slice(0, 300);
  } else if (refType === "ASSET") {
    const a = await u.one(data_assets, and(eq(data_assets.session_id, s.id), eq(data_assets.key, refId))!);
    if (a) return `Asset ${a.name} (${a.location})`.slice(0, 300);
  } else if (refType === "IDENTITY") {
    const i = await u.one(sim_identities, and(eq(sim_identities.session_id, s.id), eq(sim_identities.key, refId))!);
    if (i) return `Identity ${i.display_name} — ${i.title} (${i.employment_type})`;
  } else if (refType === "GRANT") {
    const g = await u.one(access_grants, and(eq(access_grants.session_id, s.id), eq(access_grants.key, refId))!);
    if (g) return `Grant ${g.key}: ${g.principal_type} ${g.principal_key} ${g.permission} on ${g.asset_key} (${g.status})`;
  } else if (refType === "POLICY_VERSION") {
    const idx = refId.indexOf("@v");
    const key = idx >= 0 ? refId.slice(0, idx) : refId;
    const ver = idx >= 0 ? refId.slice(idx + 2) : "";
    try {
      const pol = await getPolicy(s, key);
      if (ver && /^\d+$/.test(ver) && (await policyVersions(pol.id)).some((v) => v.version === Number(ver))) return `Policy ${key} version ${ver}`;
    } catch (e) {
      if (!(e instanceof DomainError)) throw e;
    }
  } else if (refType === "FINDING") {
    if (/^\d+$/.test(refId) && Number(refId) <= 2_147_483_647) {
      const f = await u.one(classification_findings, and(eq(classification_findings.session_id, s.id), eq(classification_findings.id, Number(refId)))!);
      if (f) return `Finding ${f.detector}×${f.match_count} (${f.confidence}) on ${f.asset_key}`;
    }
  }
  throw new DomainError(`${refType} '${refId}' does not exist in this session`, 404);
}

const escapeLike = (v: string) => v.replace(/[\\%_]/g, (c) => `\\${c}`);

@Controller("api/sessions/:sessionId")
@Permission(PERMISSIONS.SELF)
export class InvestigationsController {
  @Get("investigation/vocabulary")
  async vocabulary(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal) {
    await read(id, p);
    return { dispositions: DISPOSITIONS, determinations: DETERMINATIONS, exposure_statuses: EXPOSURE_STATUSES, root_causes: ROOT_CAUSES,
      severities: SEVERITIES, escalation_parties: PARTIES, note_kinds: NOTE_KINDS, evidence_types: EVIDENCE_TYPES };
  }

  // ------------------------------------------------------------------------- events

  @Get("events")
  async events(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal, @ZQuery(EventsQuery) q: z.infer<typeof EventsQuery>) {
    const s = await read(id, p);
    const where: SQL[] = [eq(security_events.session_id, s.id)];
    if (q.actor) where.push(eq(security_events.actor_id, q.actor));
    if (q.resource) where.push(eq(security_events.resource_id, q.resource));
    if (q.source_type) where.push(eq(security_events.source_type, q.source_type));
    if (q.result) where.push(eq(security_events.result, q.result));
    if (q.run !== undefined) where.push(eq(security_events.run_number, q.run));
    if (q.transaction) where.push(eq(security_events.transaction_id, q.transaction));
    if (q.q) {
      const like = `%${escapeLike(q.q)}%`;
      where.push(or(ilike(security_events.summary, like), ilike(security_events.event_id, like), ilike(security_events.actor_id, like),
        ilike(security_events.resource_id, like))!);
    }
    const rows = await uow().all(security_events, and(...where), [asc(security_events.timestamp), asc(security_events.seq)]);
    return rows.slice(0, q.limit).map(eventOut);
  }

  @Get("events/:eventId")
  async event(@IdParam("sessionId") id: number, @Param("eventId") eventId: string, @CurrentPrincipal() p: Principal) {
    const s = await read(id, p);
    const u = uow();
    const e = await u.one(security_events, and(eq(security_events.session_id, s.id), eq(security_events.event_id, eventId))!);
    if (!e) throw new DomainError("Event not found", 404);
    const related = e.related_event_ids?.length
      ? await u.all(security_events, and(eq(security_events.session_id, s.id), inArray(security_events.event_id, e.related_event_ids))) : [];
    const al = (await u.all(alerts, eq(alerts.session_id, s.id))).filter((a) => (a.event_ids ?? []).includes(e.event_id));
    return { ...eventOut(e), related: related.map(eventOut), alerts: al.map(alertOut) };
  }

  // ------------------------------------------------------------------------- alerts

  @Get("alerts")
  async alerts(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal, @ZQuery(AlertsQuery) q: z.infer<typeof AlertsQuery>) {
    const s = await read(id, p);
    const where: SQL[] = [eq(alerts.session_id, s.id)];
    if (q.status) where.push(eq(alerts.status, q.status));
    if (q.run !== undefined) where.push(eq(alerts.run_number, q.run));
    if (q.undispositioned === "true") where.push(isNull(alerts.disposition));
    return (await uow().all(alerts, and(...where), [asc(alerts.timestamp), asc(alerts.id)])).map(alertOut);
  }

  @Get("alerts/:alertId")
  async alert(@IdParam("sessionId") id: number, @Param("alertId") alertId: string, @CurrentPrincipal() p: Principal) {
    const s = await read(id, p);
    const a = await getAlert(s, alertId);
    const corr = await correlate(s, a);
    const u = uow();
    const ev = new Map((corr.length ? await u.all(security_events, and(eq(security_events.session_id, s.id),
      inArray(security_events.event_id, corr.map((c) => c.event_id)))) : []).map((e) => [e.event_id, e]));
    const caseIds = (await u.all(investigation_cases, eq(investigation_cases.session_id, s.id))).filter((c) => (c.alert_ids ?? []).includes(a.alert_id))
      .map((c) => c.id);
    return { ...alertOut(a), correlated: corr.map((c) => ({ ...c, event: eventOut(ev.get(c.event_id)!) })), case_ids: caseIds,
      correlation_method: "Events share an explicit attribute with the alert (transaction, recorded relation, actor or resource) "
        + "within 24 hours. Time proximity alone never links events." };
  }

  @PostOk("alerts/:alertId/disposition")
  async disposition(@IdParam("sessionId") id: number, @Param("alertId") alertId: string, @CurrentPrincipal() p: Principal,
    @ZBody(DispositionIn) body: z.infer<typeof DispositionIn>) {
    const s = await write(id, p);
    const a = await getAlert(s, alertId);
    a.disposition = body.disposition;
    a.disposition_note = body.note;
    a.status = body.disposition === "BENIGN_POSITIVE" || body.disposition === "FALSE_POSITIVE" ? "CLOSED" : "IN_PROGRESS";
    advanceClock(s);
    await recordAction(s, "ALERT_DISPOSITION", { alert: alertId, disposition: body.disposition });
    return alertOut(a);
  }

  // ------------------------------------------------------------------------- cases

  @Get("cases")
  async cases(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal) {
    const s = await read(id, p);
    const out: Json[] = [];
    for (const c of await uow().all(investigation_cases, eq(investigation_cases.session_id, s.id), [asc(investigation_cases.id)])) out.push(await caseOut(c));
    return out;
  }

  @PostCreated("cases")
  async createCase(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal, @ZBody(CaseIn) body: z.infer<typeof CaseIn>) {
    const s = await write(id, p);
    for (const aid of body.alert_ids) {
      const al = await getAlert(s, aid);
      if (al.status === "NEW") al.status = "IN_PROGRESS";
    }
    const u = uow();
    const c = await u.insert(investigation_cases, { session_id: s.id, title: body.title, alert_ids: uniqueSorted(body.alert_ids), hypothesis: body.hypothesis });
    for (const aid of c.alert_ids) await u.insert(evidence_references, { case_id: c.id, ref_type: "ALERT", ref_id: aid, label: `Alert ${aid}` });
    advanceClock(s);
    await recordAction(s, "CASE_CREATE", { case_id: c.id, alerts: c.alert_ids });
    return caseOut(c, true);
  }

  @Get("cases/:caseId")
  async getCase(@IdParam("sessionId") id: number, @IdParam("caseId") caseId: number, @CurrentPrincipal() p: Principal) {
    return caseOut(await getCase(await read(id, p), caseId), true);
  }

  @Patch("cases/:caseId")
  async patchCase(@IdParam("sessionId") id: number, @IdParam("caseId") caseId: number, @CurrentPrincipal() p: Principal,
    @ZBody(CasePatch) data: z.infer<typeof CasePatch>) {
    const s = await write(id, p);
    const c = await getCase(s, caseId);
    const u = uow();
    if ("determination" in data && data.determination !== null && !DETERMINATIONS.includes(data.determination!)) {
      throw new DomainError(`determination must be one of ${pyRepr(DETERMINATIONS)}`);
    }
    if ("exposure_status" in data && data.exposure_status !== null && !EXPOSURE_STATUSES.includes(data.exposure_status!)) {
      throw new DomainError(`exposure_status must be one of ${pyRepr(EXPOSURE_STATUSES)}`);
    }
    if (data.root_causes && !data.root_causes.every((r) => ROOT_CAUSES.includes(r))) throw new DomainError(`root_causes must be from ${pyRepr(ROOT_CAUSES)}`);
    if (data.subject_identities) {
      const known = new Set((await u.all(sim_identities, eq(sim_identities.session_id, s.id))).map((i) => i.key));
      if (!data.subject_identities.every((k) => known.has(k))) throw new DomainError("Unknown subject identity");
    }
    if (data.affected_asset_keys) {
      const known = new Set((await u.all(data_assets, eq(data_assets.session_id, s.id))).map((a) => a.key));
      if (!data.affected_asset_keys.every((k) => known.has(k))) throw new DomainError("Unknown asset key");
    }
    if (data.alert_ids) for (const aid of data.alert_ids) await getAlert(s, aid);
    const row = c as unknown as Json;
    for (const [k, v] of Object.entries(data)) row[k] = v ?? null;
    c.updated_at = new Date();
    await recordAction(s, "CASE_UPDATE", { case_id: c.id, fields: sorted(Object.keys(data)) });
    return caseOut(c, true);
  }

  @PostCreated("cases/:caseId/notes")
  async addNote(@IdParam("sessionId") id: number, @IdParam("caseId") caseId: number, @CurrentPrincipal() p: Principal,
    @ZBody(NoteIn) body: z.infer<typeof NoteIn>) {
    const s = await write(id, p);
    const c = await getCase(s, caseId);
    const valid = new Set((await uow().all(evidence_references, eq(evidence_references.case_id, c.id))).map((e) => e.id));
    if (!body.evidence_ids.every((e) => valid.has(e))) throw new DomainError("Notes may only cite evidence already linked to this case");
    if (body.kind === "OBSERVATION" && !body.evidence_ids.length) {
      throw new DomainError("An observation must cite at least one linked evidence item; use INFERENCE or HYPOTHESIS otherwise");
    }
    const n = await uow().insert(case_notes, { case_id: c.id, kind: body.kind, text: body.text, evidence_ids: body.evidence_ids });
    await recordAction(s, "CASE_NOTE", { case_id: c.id, kind: body.kind });
    return { id: n.id, kind: n.kind, text: n.text, evidence_ids: n.evidence_ids };
  }

  @Delete("cases/:caseId/notes/:noteId")
  async deleteNote(@IdParam("sessionId") id: number, @IdParam("caseId") caseId: number, @IdParam("noteId") noteId: number,
    @CurrentPrincipal() p: Principal) {
    const s = await write(id, p);
    const c = await getCase(s, caseId);
    const n = await uow().one(case_notes, and(eq(case_notes.case_id, c.id), eq(case_notes.id, noteId))!);
    if (!n) throw new DomainError("Note not found", 404);
    await uow().delete(case_notes, eq(case_notes.id, n.id));
    await recordAction(s, "CASE_NOTE_DELETE", { case_id: c.id, note_id: noteId });
    return { ok: true };
  }

  @PostCreated("cases/:caseId/evidence")
  async addEvidence(@IdParam("sessionId") id: number, @IdParam("caseId") caseId: number, @CurrentPrincipal() p: Principal,
    @ZBody(EvidenceIn) body: z.infer<typeof EvidenceIn>) {
    const s = await write(id, p);
    const c = await getCase(s, caseId);
    const label = await evidenceLabel(s, body.ref_type, body.ref_id);
    const u = uow();
    if (await u.one(evidence_references, and(eq(evidence_references.case_id, c.id), eq(evidence_references.ref_type, body.ref_type),
      eq(evidence_references.ref_id, body.ref_id))!)) throw new DomainError("Evidence already linked", 409);
    const e = await u.insert(evidence_references, { case_id: c.id, ref_type: body.ref_type, ref_id: body.ref_id, label, note: body.note });
    if (body.ref_type === "EVENT") {
      const ev = (await u.one(security_events, and(eq(security_events.session_id, s.id), eq(security_events.event_id, body.ref_id))!))!;
      ev.evidence_refs = uniqueSorted([...(ev.evidence_refs ?? []), `case:${c.id}`]);
    }
    await recordAction(s, "CASE_EVIDENCE", { case_id: c.id, ref_type: body.ref_type, ref_id: body.ref_id });
    return { id: e.id, ref_type: e.ref_type, ref_id: e.ref_id, label: e.label, note: e.note };
  }

  @Delete("cases/:caseId/evidence/:evidenceId")
  async removeEvidence(@IdParam("sessionId") id: number, @IdParam("caseId") caseId: number, @IdParam("evidenceId") evidenceId: number,
    @CurrentPrincipal() p: Principal) {
    const s = await write(id, p);
    const c = await getCase(s, caseId);
    const u = uow();
    const e = await u.one(evidence_references, and(eq(evidence_references.case_id, c.id), eq(evidence_references.id, evidenceId))!);
    if (!e) throw new DomainError("Evidence not found", 404);
    if ((await u.all(case_notes, eq(case_notes.case_id, c.id))).some((n) => (n.evidence_ids ?? []).includes(evidenceId))) {
      throw new DomainError("Evidence is cited by case notes; remove or edit those notes first", 409);
    }
    await u.delete(evidence_references, eq(evidence_references.id, e.id));
    await recordAction(s, "CASE_EVIDENCE_REMOVE", { case_id: c.id, evidence_id: evidenceId });
    return { ok: true };
  }

  @Get("cases/:caseId/timeline")
  async caseTimeline(@IdParam("sessionId") id: number, @IdParam("caseId") caseId: number, @CurrentPrincipal() p: Principal) {
    const s = await read(id, p);
    const c = await getCase(s, caseId);
    const u = uow();
    const linked = new Set((await u.all(evidence_references, and(eq(evidence_references.case_id, c.id), eq(evidence_references.ref_type, "EVENT"))!))
      .map((e) => e.ref_id));
    const ids = new Set(linked);
    if (c.alert_ids?.length) {
      for (const a of await u.all(alerts, and(eq(alerts.session_id, s.id), inArray(alerts.alert_id, c.alert_ids)))) for (const x of a.event_ids ?? []) ids.add(x);
    }
    if (!ids.size) return [];
    const evs = await u.all(security_events, and(eq(security_events.session_id, s.id), inArray(security_events.event_id, [...ids])),
      [asc(security_events.timestamp), asc(security_events.seq)]);
    return evs.map((e) => ({ ...eventOut(e), linked_as_evidence: linked.has(e.event_id) }));
  }

  // ------------------------------------------------------------------------- remediation & risk

  @PostCreated("remediation")
  async remediate(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal, @ZBody(RemediationIn) body: z.infer<typeof RemediationIn>) {
    const s = await write(id, p);
    return remOut(await applyRemediation(s, { ...body, case_id: body.case_id ?? null }));
  }

  @Get("remediation")
  async remediations(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal) {
    const s = await read(id, p);
    return (await uow().all(remediation_actions, eq(remediation_actions.session_id, s.id), [asc(remediation_actions.seq)])).map(remOut);
  }

  @PostOk("remediation/:remId/verify")
  async reverify(@IdParam("sessionId") id: number, @IdParam("remId") remId: number, @CurrentPrincipal() p: Principal) {
    const s = await write(id, p);
    const r = await uow().one(remediation_actions, and(eq(remediation_actions.session_id, s.id), eq(remediation_actions.id, remId))!);
    if (!r) throw new DomainError("Remediation action not found", 404);
    advanceClock(s);
    r.verification = await verifyState(s, r);
    if (r.status !== "RECORDED") r.status = r.verification.verified ? "VERIFIED" : "VERIFICATION_FAILED";
    await recordAction(s, "REMEDIATION_VERIFY", { remediation_id: r.id }, { status: r.status });
    return remOut(r);
  }

  @PostOk("risk-score")
  async risk(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal, @ZBody(RiskIn) body: z.infer<typeof RiskIn>) {
    const s = await read(id, p);
    const ranks = await labelRanks(s);
    if (body.label !== null && body.label !== undefined && !Object.hasOwn(ranks, body.label)) throw new DomainError("Unknown label");
    return { ...riskScore({ label_rank: body.label ? ranks[body.label] : null, records: body.records, destination_external: body.destination_external,
      data_left_org: body.data_left_org }),
    model: "severity = sensitivity(0-3) + volume(0-2) + external destination(0/2) + data left org(0/1/2); >=8 CRITICAL, 6-7 HIGH, 3-5 MEDIUM, <=2 LOW" };
  }
}
