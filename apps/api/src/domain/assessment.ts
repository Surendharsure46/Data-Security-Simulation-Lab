/**
 * Task progress checks and the assessment (competency) engine.
 *
 * Every check is a pure function of persisted session state. Scenario JSON selects checks by name from the registries
 * below; no scenario content is executed. Identical state produces an identical score and `inputs_digest`.
 */
import { createHash } from "node:crypto";
import { and, asc, eq, inArray, ne } from "drizzle-orm";
import { round, sorted, stableStringify } from "../common/util.js";
import { uow } from "../db/context.js";
import {
  access_grants, alerts, assessment_attempts, case_notes, data_assets, discovery_scans, evidence_references, investigation_cases, policies,
  policy_evaluations, policy_versions, remediation_actions, scenario_actions, security_events, sim_identities,
} from "../db/schema.js";
import { primaryCase, riskScore, type CaseRow } from "./investigation.js";
import { resolveStep, type ScenarioDefinition } from "./scenario-defs.js";
import {
  buildContext, CONTROL_CHANGE_ACTIONS, definitionFor, evaluate, getAsset, getDestination, getIdentity, labelRanks, lastActionSeq,
  loadPolicies, variantParams, type SessionRow,
} from "./simulation.js";

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
const PREVENTED = new Set(["BLOCKED", "DENIED", "FAILURE"]);

// --------------------------------------------------------------------------- shared state helpers

/** Lazy accessor bundle passed to every check. */
class Ctx {
  readonly d: ScenarioDefinition;
  readonly gt: Json;
  readonly params: Record<string, string>;
  private caseCache: { v: CaseRow | undefined } | null = null;

  constructor(readonly s: SessionRow) {
    this.d = definitionFor(s);
    this.gt = this.d.ground_truth;
    this.params = variantParams(s);
  }

  get culprit(): string {
    return this.params.culprit;
  }

  runs(): Json[] {
    return [...((this.s.flags ?? {}).runs ?? [])];
  }

  firstStandardRun(): number | null {
    return this.runs().find((r) => r.mode === "standard")?.run_number ?? null;
  }

  latestValidationRun(): Json | null {
    const vals = this.runs().filter((r) => r.mode === "validation");
    return vals.length ? vals[vals.length - 1] : null;
  }

  async stepOutcome(runNumber: number, step: string): Promise<string | null> {
    const evs = await uow().all(security_events, and(eq(security_events.session_id, this.s.id), eq(security_events.run_number, runNumber),
      eq(security_events.step_key, step)));
    if (!evs.length) return null;
    return evs.some((e) => PREVENTED.has(e.result)) ? "PREVENTED" : "ALLOWED";
  }

  async exfilSucceededInFirstRun(): Promise<boolean | null> {
    const r = this.firstStandardRun();
    if (r === null) return null;
    return (await this.stepOutcome(r, this.gt.exfil_step)) === "ALLOWED";
  }

  async primaryCase(): Promise<CaseRow | undefined> {
    if (!this.caseCache) this.caseCache = { v: await primaryCase(this.s) };
    return this.caseCache.v;
  }

  evidence(c: CaseRow) {
    return uow().all(evidence_references, eq(evidence_references.case_id, c.id));
  }

  notes(c: CaseRow) {
    return uow().all(case_notes, eq(case_notes.case_id, c.id));
  }

  remediations() {
    return uow().all(remediation_actions, eq(remediation_actions.session_id, this.s.id), [asc(remediation_actions.seq)]);
  }

  async expectedOutcome(): Promise<Json> {
    if ((await this.exfilSucceededInFirstRun()) === false) {
      return { exposure_status: ["ATTEMPT_PREVENTED", "NO_EVIDENCE_OF_EXFILTRATION"], determinations: ["ATTEMPTED_EXFILTRATION_PREVENTED"],
        data_left_org: "NO", records: 0 };
    }
    return { exposure_status: this.gt.exposure_status, determinations: this.gt.determinations, data_left_org: "YES", records: this.gt.records_exposed };
  }
}

const strip = (x: string | null | undefined) => (x ?? "").trim();

// --------------------------------------------------------------------------- task progress checks

type TaskCheck = (c: Ctx, p: Json) => Promise<boolean>;

const TASK_CHECKS: Record<string, TaskCheck> = {
  scan_count_at_least: async (c, p) => (await uow().count(discovery_scans, eq(discovery_scans.session_id, c.s.id))) >= p.count,
  assets_viewed: async (c, p) => {
    const viewed = new Set<string>((c.s.flags ?? {}).viewed_assets ?? []);
    return (p.assets as string[]).every((a) => viewed.has(a));
  },
  asset_labeled_with_owner: async (c, p) => {
    for (const k of p.assets as string[]) {
      const a = await getAsset(c.s, k);
      if (!(a.label_key && a.owner_key)) return false;
    }
    return true;
  },
  grants_reviewed: async (c, p) => (await uow().all(access_grants, and(eq(access_grants.session_id, c.s.id), eq(access_grants.asset_key, p.asset))))
    .some((g) => g.review_decision),
  learner_policy_versions_at_least: async (c, p) => {
    const rows = await uow().db.select({ id: policy_versions.id }).from(policy_versions).innerJoin(policies, eq(policy_versions.policy_id, policies.id))
      .where(and(eq(policies.session_id, c.s.id), ne(policy_versions.author, "scenario-baseline")));
    return rows.length >= p.count;
  },
  dry_runs_with_distinct_outcomes: async (c, p) => {
    const evals = await uow().all(policy_evaluations, and(eq(policy_evaluations.session_id, c.s.id), eq(policy_evaluations.dry_run, true)));
    return evals.length >= p.count && new Set(evals.map((e) => e.final_outcome)).size >= 2;
  },
  run_count_at_least: async (c, p) => c.s.run_count >= p.count,
  run_alerts_dispositioned: async (c) => {
    const run = c.firstStandardRun();
    if (run === null) return false;
    const al = await uow().all(alerts, and(eq(alerts.session_id, c.s.id), eq(alerts.run_number, run)));
    return al.length > 0 && al.every((a) => a.disposition);
  },
  case_evidence_at_least: async (c, p) => {
    const cs = await c.primaryCase();
    return cs !== undefined && (await c.evidence(cs)).length >= p.count;
  },
  case_note_kinds: async (c, p) => {
    const cs = await c.primaryCase();
    if (!cs) return false;
    const kinds = new Set((await c.notes(cs)).map((n) => n.kind));
    return (p.kinds as string[]).every((k) => kinds.has(k));
  },
  case_scope_recorded: async (c) => {
    const cs = await c.primaryCase();
    return Boolean(cs && cs.affected_asset_keys?.length && cs.exposure_status && cs.severity && cs.records_potentially_exposed !== null);
  },
  remediation_category_applied: async (c, p) => {
    const cat = new Map(c.d.remediation_catalog.map((r) => [r.type, r.category]));
    return (await c.remediations()).some((r) => cat.get(r.action_type) === p.category);
  },
  control_fix_after_run: async (c) => {
    const runs = c.runs();
    if (!runs.length) return false;
    return (await lastActionSeq(c.s, CONTROL_CHANGE_ACTIONS)) > runs[0].action_seq;
  },
  validation_run_after_last_fix: async (c) => {
    const v = c.latestValidationRun();
    return v !== null && v.action_seq > (await lastActionSeq(c.s, CONTROL_CHANGE_ACTIONS));
  },
  case_report_fields: async (c) => {
    const cs = await c.primaryCase();
    return Boolean(cs && [cs.summary, cs.root_cause_narrative, cs.residual_risk, cs.lessons_learned].every((x) => strip(x)));
  },
};

export async function taskProgress(s: SessionRow): Promise<Json[]> {
  const c = new Ctx(s);
  const out: Json[] = [];
  for (const t of c.d.tasks) {
    out.push({ key: t.key, stage: t.stage, phase: t.phase, title: t.title, description: t.description,
      done: Boolean(await TASK_CHECKS[t.check.type](c, t.check.params)),
      hints_available: (c.d.hints[t.key] ?? []).length,
      hints_revealed: ((s.hints_used ?? {})[t.key] ?? []).length });
  }
  return out;
}

// --------------------------------------------------------------------------- rubric checks (fraction 0..1, explanation)

type RubricCheck = (c: Ctx, p: Json) => Promise<[number, string]>;

async function validationInfo(c: Ctx): Promise<[Json | null, boolean]> {
  const v = c.latestValidationRun();
  if (v === null) return [null, false];
  return [v, v.action_seq > (await lastActionSeq(c.s, CONTROL_CHANGE_ACTIONS))];
}

const RUBRIC_CHECKS: Record<string, RubricCheck> = {
  label_matches: async (c, p) => {
    const truth = c.gt.labels as Record<string, string[]>;
    let ok = 0;
    const wrong: string[] = [];
    for (const k of p.assets as string[]) {
      const a = await getAsset(c.s, k);
      if (a.label_key && truth[k].includes(a.label_key)) ok += 1;
      else wrong.push(`${a.name} (${a.label_key || "unlabeled"})`);
    }
    return [ok / p.assets.length, `${ok}/${p.assets.length} assets correctly classified.` + (wrong.length ? ` Review: ${wrong.join(", ")}.` : "")];
  },
  grants_revoked: async (c) => {
    const keys = c.gt.excessive_grants as string[];
    const grants = new Map((await uow().all(access_grants, eq(access_grants.session_id, c.s.id))).map((g) => [g.key, g]));
    const frac = keys.filter((k) => grants.get(k)?.status === "REVOKED").length / keys.length;
    return [frac, frac === 1 ? "Excessive permission removed."
      : "An excessive permission on the customer export is still active. Review which groups can read it and why."];
  },
  alert_dispositions: async (c, p) => {
    const group = c.gt.alert_groups[p.group];
    const run = c.firstStandardRun();
    if (run === null) return [0, "The business day was never run, so no alerts exist to triage."];
    const al = (await uow().all(alerts, and(eq(alerts.session_id, c.s.id), eq(alerts.run_number, run))))
      .filter((a) => a.step_key && group.steps.includes(a.step_key));
    if (!al.length) {
      if (p.group === "malicious") return [0, "No alert was raised for the malicious activity in run 1 (detection gap)."];
      return [1, "No alerts of this kind were generated (controls were tuned before the run)."];
    }
    const ok = al.filter((a) => a.disposition && group.accepted.includes(a.disposition));
    const frac = ok.length / al.length;
    let msg = `${ok.length}/${al.length} alerts in this group dispositioned appropriately.`;
    if (p.group === "ambiguous" && frac < 1) msg += " Evidence did not establish malicious intent; a supported conclusion was expected.";
    if (p.group === "benign" && frac < 1) msg += " Some legitimate business activity was treated as malicious or left untriaged.";
    return [frac, msg];
  },
  case_determination: async (c) => {
    const cs = await c.primaryCase();
    if (!cs) return [0, "No investigation case opened."];
    const exp = await c.expectedOutcome();
    const detOk = exp.determinations.includes(cs.determination);
    const subjects = new Set(cs.subject_identities ?? []);
    const nonSubject = new Set<string>([...c.gt.legitimate_steps, ...c.gt.ambiguous_steps]);
    const innocent = new Set(c.d.timeline.filter((st) => nonSubject.has(st.key)).map((st) => resolveStep(st, c.params).actor as string));
    innocent.delete(c.culprit);
    const subjOk = subjects.has(c.culprit) && ![...subjects].some((x) => innocent.has(x));
    const frac = 0.6 * Number(detOk) + 0.4 * Number(subjOk);
    return [frac, [
      detOk ? "Determination supported by the run-1 evidence." : `Determination '${cs.determination}' is not supported by what the run-1 events show.`,
      subjOk ? "Subject identity correct." : "Subject identities incomplete or include someone the evidence does not implicate.",
    ].join(" ")];
  },
  case_severity: async (c) => {
    const cs = await c.primaryCase();
    if (!cs || !cs.severity) return [0, "No severity recorded."];
    const exp = await c.expectedOutcome();
    const ri = c.gt.risk_inputs;
    const expected = riskScore({ label_rank: (await labelRanks(c.s))[ri.label] ?? null, records: ri.records,
      destination_external: ri.destination_external, data_left_org: exp.data_left_org }).severity;
    const order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
    const diff = Math.abs(order.indexOf(cs.severity) - order.indexOf(expected));
    return [diff === 0 ? 1 : diff === 1 ? 0.5 : 0,
      diff === 0 ? "Severity matches the risk model." : `Severity ${cs.severity} differs from the risk-model result by ${diff} level(s).`];
  },
  case_evidence_coverage: async (c) => {
    const cs = await c.primaryCase();
    if (!cs) return [0, "No case."];
    const ev = await c.evidence(cs);
    const eventIds = ev.filter((e) => e.ref_type === "EVENT").map((e) => e.ref_id);
    const run = c.firstStandardRun();
    const stepsLinked = new Set<string | null>();
    if (eventIds.length) {
      for (const e of await uow().all(security_events, inArray(security_events.event_id, eventIds))) if (e.run_number === run) stepsLinked.add(e.step_key);
    }
    const alertIds = ev.filter((e) => e.ref_type === "ALERT").map((e) => e.ref_id);
    const alertSteps = new Set<string | null>();
    if (alertIds.length) for (const a of await uow().all(alerts, inArray(alerts.alert_id, alertIds))) alertSteps.add(a.step_key);
    const hasDownload = stepsLinked.has(c.gt.download_step);
    const hasTransfer = stepsLinked.has(c.gt.exfil_step);
    const hasPath = ev.some((e) => (e.ref_type === "GRANT" && c.gt.excessive_grants.includes(e.ref_id))
      || (e.ref_type === "ASSET" && c.gt.affected_assets_required.includes(e.ref_id)));
    const frac = (Number(hasDownload) + Number(hasTransfer) + Number(hasPath)) / 3;
    const missing = ([["the bulk download event", hasDownload], ["the outbound transfer/DLP event", hasTransfer],
      ["the access path (grant or asset record)", hasPath]] as [string, boolean][]).filter(([, ok]) => !ok).map(([n]) => n);
    if (missing.length && (alertSteps.has(c.gt.download_step) || alertSteps.has(c.gt.exfil_step))) {
      missing.push("(linking an alert is not the same as linking the underlying event)");
    }
    return [frac, missing.length ? `Missing evidence: ${missing.join(", ")}.` : "Evidence covers download, transfer and access path."];
  },
  case_notes_quality: async (c) => {
    const cs = await c.primaryCase();
    if (!cs) return [0, "No case."];
    const notes = await c.notes(cs);
    const obs = notes.some((n) => n.kind === "OBSERVATION" && n.evidence_ids?.length);
    const inf = notes.some((n) => n.kind === "INFERENCE");
    const unk = notes.some((n) => n.kind === "UNKNOWN");
    const gaps = ([["an observation citing evidence", obs], ["an inference", inf], ["an unknown", unk]] as [string, boolean][])
      .filter(([, ok]) => !ok).map(([g]) => g);
    return [(Number(obs) + Number(inf) + Number(unk)) / 3,
      gaps.length ? `Missing: ${gaps.join(", ")}.` : "Notes separate observations, inferences and unknowns."];
  },
  case_scope: async (c) => {
    const cs = await c.primaryCase();
    if (!cs) return [0, "No case."];
    const exp = await c.expectedOutcome();
    const assets = new Set(cs.affected_asset_keys ?? []);
    const acceptable = new Set<string>(c.gt.affected_assets_acceptable);
    const assetsOk = (c.gt.affected_assets_required as string[]).every((a) => assets.has(a)) && [...assets].every((a) => acceptable.has(a));
    const statusOk = exp.exposure_status.includes(cs.exposure_status);
    const rec = cs.records_potentially_exposed;
    const recOk = exp.records === 0 ? rec === 0 : rec !== null && Math.abs(rec - exp.records) <= 0.05 * exp.records;
    const frac = 0.5 * Number(assetsOk) + 0.25 * Number(statusOk) + 0.25 * Number(recOk);
    const notes: string[] = [];
    if (!assetsOk) notes.push("affected assets do not match what the events show");
    if (!statusOk) notes.push("exposure status not supported by the transfer events");
    if (!recOk) notes.push("record estimate inconsistent with the event record counts");
    return [frac, notes.length ? "Scope issues: " + notes.join("; ") + "." : "Scope supported by evidence."];
  },
  validation_exfil_prevented: async (c) => {
    const [v, afterFix] = await validationInfo(c);
    if (!v) return [0, "No control-validation replay was run."];
    if ((await c.stepOutcome(v.run_number, c.gt.exfil_step)) !== "PREVENTED") return [0, `In validation run ${v.run_number} the exfiltration step still succeeded.`];
    if (!afterFix) return [0.5, "The path was closed in the last replay, but controls changed afterwards and were not re-verified."];
    return [1, `Validation run ${v.run_number} shows the exfiltration path closed.`];
  },
  validation_legitimate_allowed: async (c) => {
    const [v] = await validationInfo(c);
    if (!v) return [0, "No control-validation replay was run."];
    const steps = c.gt.legitimate_steps as string[];
    const disrupted: string[] = [];
    for (const st of steps) if ((await c.stepOutcome(v.run_number, st)) === "PREVENTED") disrupted.push(st);
    return [(steps.length - disrupted.length) / steps.length, disrupted.length
      ? `${disrupted.length} legitimate business activities were blocked or denied in the replay (business disruption).`
      : "All legitimate activities still succeed."];
  },
  dlp_blocks_canonical_exfil: async (c) => {
    const asset = await getAsset(c.s, c.gt.affected_assets_required[0]);
    const culprit = await getIdentity(c.s, c.culprit);
    const cases: [string, string][] = [["UPLOAD", "dst-personal-cloud"], ["EMAIL", "dst-personal-webmail"]];
    const pols = await loadPolicies(c.s);
    let blocked = 0;
    for (const [action, destKey] of cases) {
      const ctx = await buildContext(c.s, { actor: culprit, asset, action, destination: await getDestination(c.s, destKey), record_count: null,
        context: { device_managed: true }, timestamp: new Date(Date.UTC(2026, 2, 9, 12, 0)) });
      const res = await evaluate(c.s, ctx, { dryRun: true, transactionId: "assessment", policies: pols, persist: false });
      if (res.decision.outcome === "BLOCK") blocked += 1;
    }
    return [blocked / cases.length, `DLP blocks ${blocked}/${cases.length} canonical exfiltration paths independent of access control.`];
  },
  subject_contained: async (c) => {
    const ident = await getIdentity(c.s, c.culprit);
    const rems = (await c.remediations()).filter((r) => r.target_key === c.culprit);
    if (ident.status === "DISABLED" && rems.some((r) => r.action_type === "DISABLE_ACCOUNT" && r.status === "VERIFIED")) {
      return [1, "Subject account disabled and verified by sign-in probe."];
    }
    if (ident.sessions_revoked_at !== null) return [0.5, "Sessions revoked, but the account can still sign in."];
    return [0, "The subject identity was not contained."];
  },
  escalated_to: async (c, p) => {
    const targets = new Set((await c.remediations()).filter((r) => r.action_type === "ESCALATE").map((r) => r.target_key));
    const hit = sorted((p.any_of as string[]).filter((x) => targets.has(x)));
    return [hit.length ? 1 : 0, hit.length ? `Escalated to ${hit.join(", ")}.` : "A personal-data incident was not escalated to Privacy Office or Legal."];
  },
  report_completeness: async (c) => {
    const cs = await c.primaryCase();
    if (!cs) return [0, "No case."];
    const filled = [cs.summary, cs.root_cause_narrative, cs.residual_risk, cs.lessons_learned].filter((f) => strip(f).length >= 20).length;
    const truth = new Set<string>(c.gt.root_causes);
    const chosen = new Set(cs.root_causes ?? []);
    const hit = [...chosen].filter((x) => truth.has(x));
    const unsupported = sorted([...chosen].filter((x) => !truth.has(x) && x !== "MISSING_DATA_OWNER"));
    const rc = Math.max(0, hit.length / truth.size - 0.25 * unsupported.length);
    let msg = `${filled}/4 report sections substantive (20+ characters). Root causes: ${hit.length}/${truth.size} identified`;
    if (unsupported.length) msg += `; unsupported by evidence: ${unsupported.join(", ")}`;
    return [0.5 * filled / 4 + 0.5 * rc, msg + "."];
  },
};

const CRITICAL_CHECKS: Record<string, (c: Ctx) => Promise<[boolean, string]>> = {
  evidence_destroyed: async (c) => {
    const hit = Boolean((await getIdentity(c.s, c.culprit)).attributes?.evidence_destroyed);
    return [hit, hit ? "Device reimaged before evidence preservation; endpoint evidence lost." : ""];
  },
  exfil_not_verified_closed: async (c) => {
    const v = c.latestValidationRun();
    if (!v) return [true, "No control-validation replay was performed."];
    if ((await c.stepOutcome(v.run_number, c.gt.exfil_step)) !== "PREVENTED") {
      return [true, "The latest control-validation replay shows the exfiltration path still open."];
    }
    return [false, ""];
  },
};

// --------------------------------------------------------------------------- scoring

/** Hash of every learner-controlled input the score depends on. */
async function digest(s: SessionRow): Promise<string> {
  const u = uow();
  const sid = s.id;
  const payload: Json = {
    assets: (await u.all(data_assets, eq(data_assets.session_id, sid), [asc(data_assets.key)])).map((a) => [a.key, a.label_key, a.owner_key, a.quarantined]),
    grants: (await u.all(access_grants, eq(access_grants.session_id, sid), [asc(access_grants.key)])).map((g) => [g.key, g.status, g.review_decision]),
    alerts: (await u.all(alerts, eq(alerts.session_id, sid), [asc(alerts.alert_id)])).map((a) => [a.alert_id, a.disposition]),
    identities: (await u.all(sim_identities, eq(sim_identities.session_id, sid), [asc(sim_identities.key)]))
      .map((i) => [i.key, i.status, stableStringify(i.attributes)]),
    remediations: (await u.all(remediation_actions, eq(remediation_actions.session_id, sid), [asc(remediation_actions.seq)]))
      .map((r) => [r.seq, r.action_type, r.target_key, r.status]),
    actions: (await u.all(scenario_actions, eq(scenario_actions.session_id, sid), [asc(scenario_actions.seq)])).map((a) => [a.seq, a.action_type]),
    events: (await u.all(security_events, eq(security_events.session_id, sid), [asc(security_events.seq)])).map((e) => [e.event_id, e.step_key, e.result]),
    policies: (await loadPolicies(s)).map(({ p, pv }) => [p.key, p.status, p.current_version, stableStringify(pv.definition)]),
    cases: [] as Json[],
    flags: stableStringify(s.flags ?? {}),
  };
  for (const cs of await u.all(investigation_cases, eq(investigation_cases.session_id, sid), [asc(investigation_cases.id)])) {
    const ev = await u.all(evidence_references, eq(evidence_references.case_id, cs.id));
    const notes = await u.all(case_notes, eq(case_notes.case_id, cs.id));
    payload.cases.push({
      fields: [cs.determination, cs.severity, cs.exposure_status, cs.records_potentially_exposed, sorted(cs.affected_asset_keys ?? []),
        sorted(cs.subject_identities ?? []), sorted(cs.root_causes ?? []), cs.summary, cs.root_cause_narrative, cs.residual_risk,
        cs.lessons_learned, sorted(cs.alert_ids ?? [])],
      evidence: sorted(ev.map((e) => JSON.stringify([e.ref_type, e.ref_id]))),
      notes: sorted(notes.map((n) => JSON.stringify([n.kind, n.text, n.evidence_ids ?? []]))),
    });
  }
  return createHash("sha256").update(stableStringify(payload)).digest("hex");
}

export async function scoreSession(s: SessionRow): Promise<Json> {
  const c = new Ctx(s);
  const rubric = c.d.rubric;
  const criteriaOut: Json[] = [];
  const catPoints: Record<string, number> = Object.fromEntries(Object.keys(rubric.categories).map((k) => [k, 0]));
  const catMax: Record<string, number> = { ...catPoints };
  for (const crit of rubric.criteria) {
    let [frac, why] = await RUBRIC_CHECKS[crit.check](c, crit.params);
    frac = Math.max(0, Math.min(1, frac));
    const earned = round(crit.points * frac, 2);
    catPoints[crit.category] += earned;
    catMax[crit.category] += crit.points;
    criteriaOut.push({ key: crit.key, category: crit.category, description: crit.description, points: crit.points, earned, explanation: why,
      lessons: crit.lessons });
  }
  const categoryScores: Json = {};
  let total = 0;
  for (const [k, cat] of Object.entries(rubric.categories)) {
    const pct = catMax[k] ? catPoints[k] / catMax[k] : 0;
    const weighted = round(pct * cat.weight, 2);
    total += weighted;
    categoryScores[k] = { name: cat.name, weight: cat.weight, percent: round(pct * 100, 1), weighted };
  }
  const criticals: Json[] = [];
  for (const cc of rubric.critical_conditions) {
    const [hit, why] = await CRITICAL_CHECKS[cc.check](c);
    if (hit) criticals.push({ key: cc.key, description: cc.description, detail: why });
  }
  total = round(total, 2);
  const progress = await taskProgress(s);
  const recs = new Map<string, Json>();
  for (const cr of criteriaOut) {
    if (cr.earned < 0.7 * cr.points) {
      for (const lesson of cr.lessons) {
        if (!recs.has(lesson)) recs.set(lesson, { lesson_id: lesson, because: [] });
        recs.get(lesson)!.because.push(cr.description);
      }
    }
  }
  return {
    scenario_id: s.scenario_id, rubric_version: rubric.version, mode: s.mode, total_score: total, pass_threshold: rubric.pass_threshold,
    passed: total >= rubric.pass_threshold && !criticals.length, category_scores: categoryScores, criteria: criteriaOut,
    critical_failures: criticals, missing_tasks: progress.filter((t) => !t.done).map((t) => t.title), recommendations: [...recs.values()],
    inputs_digest: await digest(s),
  };
}

export async function submit(s: SessionRow, userId: string, reportSnapshot: string) {
  const r = await scoreSession(s);
  return uow().insert(assessment_attempts, {
    session_id: s.id, user_id: userId, scenario_id: s.scenario_id, rubric_version: r.rubric_version, mode: s.mode, total_score: r.total_score,
    passed: r.passed, category_scores: r.category_scores, criteria: r.criteria, critical_failures: r.critical_failures,
    missing_tasks: r.missing_tasks, recommendations: r.recommendations, inputs_digest: r.inputs_digest, attempt_number: s.attempt_number,
    variant: s.variant, report_snapshot: reportSnapshot,
  });
}
