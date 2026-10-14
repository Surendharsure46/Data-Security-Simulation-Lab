/**
 * Simulation engine: environment provisioning, access control, activity execution, policy evaluation, event and
 * alert generation, and timeline runs. All events produced here have provenance SIMULATED; source systems are
 * prefixed `kr-sim-` so they can never be mistaken for vendor telemetry.
 */
import { randomUUID } from "node:crypto";
import type { PolicyDefinition } from "@threatready/contracts";
import { and, asc, eq, inArray, max, ne } from "drizzle-orm";
import { addDays, addMinutes, addSeconds, dateOnly, DomainError, fmtInt, pad, sorted, uniqueSorted } from "../common/util.js";
import { environmentTemplate } from "../content/company.js";
import { uow } from "../db/context.js";
import {
  access_grants, alerts, classification_labels, classification_rules, data_assets, destinations, policies, policy_evaluations,
  policy_versions, scenario_actions, scenario_sessions, security_events, sim_groups, sim_identities,
} from "../db/schema.js";
import { maxConfidence, scanText } from "./detection.js";
import { decide, evaluatePolicy, explainEntry, parsePolicy } from "./policy-engine.js";
import { getDefinition, resolveStep, TRANSFER_ACTIONS, type ScenarioDefinition } from "./scenario-defs.js";

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
export type SessionRow = typeof scenario_sessions.$inferSelect;
export type IdentityRow = typeof sim_identities.$inferSelect;
export type AssetRow = typeof data_assets.$inferSelect;
export type DestinationRow = typeof destinations.$inferSelect;
export type PolicyRow = typeof policies.$inferSelect;
export type PolicyVersionRow = typeof policy_versions.$inferSelect;
export type EventRow = typeof security_events.$inferSelect;
export type AlertRow = typeof alerts.$inferSelect;
export interface LoadedPolicy { p: PolicyRow; pv: PolicyVersionRow; d: PolicyDefinition }

export const SOURCE_SYSTEMS: Record<string, string> = {
  IDENTITY: "kr-sim-idp", FILE_ACCESS: "kr-sim-file-audit", DATABASE: "kr-sim-db-audit", CLOUD_STORAGE: "kr-sim-object-store-audit",
  DLP: "kr-sim-dlp", DETECTION: "kr-sim-analytics", EMAIL_GATEWAY: "kr-sim-mail-gateway", PROXY: "kr-sim-web-proxy",
  ENDPOINT: "kr-sim-endpoint-agent",
};
const SECURITY_GROUP = "grp-security";

// ScenarioAction types that change a control: used to decide whether a replay happened after the most recent fix.
export const CONTROL_CHANGE_ACTIONS = [
  "CLASSIFY", "POLICY_CREATE", "POLICY_UPDATE", "POLICY_STATUS", "GRANT_REVIEW_REVOKE", "REMEDIATION:REVOKE_GRANT",
  "REMEDIATION:BLOCK_DESTINATION", "REMEDIATION:QUARANTINE_ASSET", "CLASSIFICATION_RULE_UPDATE",
];

// --------------------------------------------------------------------------- provisioning

export async function provisionEnvironment(s: SessionRow): Promise<void> {
  const env = environmentTemplate();
  const u = uow();
  const session_id = s.id;
  await u.insertMany(classification_labels, env.labels.map((l: Json) => ({ session_id, ...l })));
  await u.insertMany(sim_identities, env.identities.map((i: Json) => ({ session_id, ...i })));
  await u.insertMany(sim_groups, env.groups.map((g: Json) => ({ session_id, ...structuredClone(g) })));
  await u.insertMany(data_assets, env.assets.map((a: Json) => ({ session_id, ...a })));
  await u.insertMany(access_grants, env.grants.map((g: Json) => ({ session_id, ...g })));
  await u.insertMany(destinations, env.destinations.map((d: Json) => ({ session_id, ...d })));
  await u.insertMany(classification_rules, env.classification_rules.map((r: Json) => ({ session_id, ...r })));
  for (const p of env.policies) {
    const definition = parsePolicy(p.definition);
    const pol = await u.insert(policies, { session_id, key: p.key, kind: definition.kind, status: "ENABLED", current_version: 1, baseline: true });
    await u.insert(policy_versions, {
      policy_id: pol.id, version: 1, definition, change_note: "Baseline policy provided by the scenario", author: "scenario-baseline",
    });
  }
}

export function definitionFor(s: SessionRow): ScenarioDefinition {
  const d = getDefinition(s.scenario_id);
  if (!d) throw new DomainError(`Scenario ${s.scenario_id} is not available`, 404);
  return d;
}

export function variantParams(s: SessionRow): Record<string, string> {
  const v = definitionFor(s).variants.find((x) => x.key === s.variant);
  if (!v) throw new DomainError("Session variant not found in scenario definition", 500);
  return v.params;
}

// --------------------------------------------------------------------------- lookups

export async function getIdentity(s: SessionRow, key: string): Promise<IdentityRow> {
  const i = await uow().one(sim_identities, and(eq(sim_identities.session_id, s.id), eq(sim_identities.key, key))!);
  if (!i) throw new DomainError(`Unknown identity '${key}'`, 404);
  return i;
}

export async function getAsset(s: SessionRow, key: string): Promise<AssetRow> {
  const a = await uow().one(data_assets, and(eq(data_assets.session_id, s.id), eq(data_assets.key, key))!);
  if (!a) throw new DomainError(`Unknown asset '${key}'`, 404);
  return a;
}

export async function getDestination(s: SessionRow, key: string): Promise<DestinationRow> {
  const d = await uow().one(destinations, and(eq(destinations.session_id, s.id), eq(destinations.key, key))!);
  if (!d) throw new DomainError(`Unknown destination '${key}'`, 404);
  return d;
}

export async function labelRanks(s: SessionRow): Promise<Record<string, number>> {
  const rows = await uow().all(classification_labels, eq(classification_labels.session_id, s.id));
  return Object.fromEntries(rows.map((l) => [l.key, l.rank]));
}

export async function groupsOf(s: SessionRow, identityKey: string): Promise<string[]> {
  const rows = await uow().all(sim_groups, eq(sim_groups.session_id, s.id));
  return sorted(rows.filter((g) => (g.members ?? []).includes(identityKey)).map((g) => g.key));
}

/** Explain whether `identity` can read `asset` and through which grant. */
export async function accessPath(s: SessionRow, identity: IdentityRow, asset: AssetRow): Promise<Json> {
  const groups = await groupsOf(s, identity.key);
  if (asset.quarantined) {
    if (identity.key === asset.owner_key || groups.includes(SECURITY_GROUP)) {
      return { allowed: true, via: "quarantine exemption (owner/security)", grant_key: null, permission: "READ" };
    }
    return { allowed: false, via: null, grant_key: null, reason: "Asset is quarantined" };
  }
  const grants = await uow().all(access_grants,
    and(eq(access_grants.session_id, s.id), eq(access_grants.asset_key, asset.key), eq(access_grants.status, "ACTIVE")), [asc(access_grants.key)]);
  for (const g of grants) {
    if (g.principal_type === "IDENTITY" && g.principal_key === identity.key) {
      return { allowed: true, via: `direct grant ${g.key}`, grant_key: g.key, permission: g.permission };
    }
  }
  for (const g of grants) {
    if (g.principal_type === "GROUP" && groups.includes(g.principal_key)) {
      return { allowed: true, via: `group ${g.principal_key} via grant ${g.key}`, grant_key: g.key, permission: g.permission };
    }
  }
  if (identity.key === asset.owner_key) return { allowed: true, via: "data owner", grant_key: null, permission: "OWNER" };
  return { allowed: false, via: null, grant_key: null, reason: "No active grant for identity or its groups" };
}

// --------------------------------------------------------------------------- policy evaluation

export async function loadPolicies(s: SessionRow): Promise<LoadedPolicy[]> {
  const u = uow();
  const pols = await u.all(policies, eq(policies.session_id, s.id), [asc(policies.key)]);
  if (!pols.length) return [];
  const versions = await u.all(policy_versions, inArray(policy_versions.policy_id, pols.map((p) => p.id)));
  return pols.map((p) => {
    const pv = versions.find((v) => v.policy_id === p.id && v.version === p.current_version)!;
    return { p, pv, d: parsePolicy(pv.definition) };
  });
}

export async function policyVersions(policyId: number): Promise<PolicyVersionRow[]> {
  return uow().all(policy_versions, eq(policy_versions.policy_id, policyId), [asc(policy_versions.version)]);
}

export async function buildContext(s: SessionRow, args: {
  actor: IdentityRow; asset: AssetRow; action: string; destination: DestinationRow | null; record_count: number | null | undefined;
  context: Json; timestamp: Date;
}): Promise<Json> {
  const { actor, asset, action, destination, record_count, context, timestamp } = args;
  const scan = scanText(asset.content_sample);
  const ranks = await labelRanks(s);
  const hour = timestamp.getUTCHours();
  const ctx: Json = {
    action: { type: action },
    actor: { id: actor.key, department: actor.department, role: actor.enterprise_role, employment_type: actor.employment_type,
      groups: await groupsOf(s, actor.key) },
    content: {
      label: asset.label_key,
      label_rank: asset.label_key ? (ranks[asset.label_key] ?? null) : null,
      detected_types: sorted(Object.keys(scan)),
      max_confidence: maxConfidence(scan),
      match_count: Object.values(scan).reduce((n, r) => n + r.match_count, 0),
      record_count: record_count ?? asset.record_count,
    },
    resource: { id: asset.key, system: asset.system, department: asset.department, owner_assigned: asset.owner_key !== null },
    context: {
      business_justification: context.business_justification ?? null,
      ticket_id: context.ticket_id ?? null,
      after_hours: !(hour >= 7 && hour < 19),
      device_managed: context.device_managed ?? true,
    },
    _label_ranks: ranks,
  };
  if (destination) {
    ctx.destination = { id: destination.key, kind: destination.kind, category: destination.category, sanctioned: destination.sanctioned,
      internal: destination.internal, domain: destination.domain };
  }
  return ctx;
}

export function publicContext(ctx: Json): Json {
  return Object.fromEntries(Object.entries(ctx).filter(([k]) => !k.startsWith("_")));
}

export async function evaluate(s: SessionRow, ctx: Json, opts: { dryRun: boolean; transactionId: string; policies?: LoadedPolicy[]; persist?: boolean }) {
  const pols = opts.policies ?? (await loadPolicies(s));
  const entries = pols.map(({ p, pv, d }) => evaluatePolicy(p.key, pv.version, p.status, d, ctx));
  for (const e of entries) e.explanation = explainEntry(e);
  const decision = decide(entries.filter((e) => e.kind === "DLP"));
  if (opts.persist ?? true) {
    await uow().insert(policy_evaluations, {
      session_id: s.id, transaction_id: opts.transactionId, dry_run: opts.dryRun, context: publicContext(ctx), trace: entries,
      final_outcome: decision.outcome, decisive_policy: decision.decisive_policy,
    });
  }
  return { entries, decision };
}

// --------------------------------------------------------------------------- events

function ipFor(identityKey: string): string {
  const n = [...identityKey].reduce((t, c) => t + c.charCodeAt(0), 0);
  return `10.20.${(n % 200) + 10}.${(n % 97) + 20}`;
}

export async function newEvent(s: SessionRow, e: {
  timestamp: Date; run_number: number; actor: string | null; resource: string | null; action: string; result: string; source_type: string;
  summary: string; classification?: string | null; destination?: string | null; policy_id?: string | null; policy_version?: number | null;
  transaction_id?: string | null; extension?: Json; step_key?: string | null; provenance?: string;
}): Promise<EventRow> {
  s.event_seq = (s.event_seq ?? 0) + 1;
  const seq = s.event_seq;
  return uow().insert(security_events, {
    event_id: `evt-${s.id}-${pad(seq, 5)}`, session_id: s.id, organization_id: s.org_id, scenario_id: s.scenario_id, seq,
    run_number: e.run_number, timestamp: e.timestamp, actor_id: e.actor, resource_id: e.resource, action: e.action, result: e.result,
    data_classification: e.classification ?? null, source_type: e.source_type, source_system: SOURCE_SYSTEMS[e.source_type] ?? "kr-sim",
    provenance: e.provenance ?? "SIMULATED", policy_id: e.policy_id ?? null, policy_version: e.policy_version ?? null,
    destination: e.destination ?? null, transaction_id: e.transaction_id ?? null, related_event_ids: [], evidence_refs: [],
    summary: e.summary, extension: e.extension ?? {}, step_key: e.step_key ?? null,
  });
}

function link(events: EventRow[]): void {
  const ids = events.map((e) => e.event_id);
  for (const e of events) e.related_event_ids = uniqueSorted([...(e.related_event_ids ?? []), ...ids.filter((i) => i !== e.event_id)]);
}

async function nextAlertId(s: SessionRow): Promise<string> {
  const n = await uow().count(alerts, eq(alerts.session_id, s.id));
  return `alr-${s.id}-${pad(n + 1, 4)}`;
}

const TRANSFER_SOURCE: Record<string, string> = {
  EMAIL: "EMAIL_GATEWAY", CLOUD_STORAGE: "PROXY", AI_SERVICE: "PROXY", SFTP: "PROXY", REMOVABLE_MEDIA: "ENDPOINT", INTERNAL: "FILE_ACCESS",
};
const ACCESS_SOURCE: Record<string, string> = { DB_TABLE: "DATABASE", CLOUD_OBJECT: "CLOUD_STORAGE" };
const OUTCOME_TO_RESULT: Record<string, string> = { ALLOW: "ALLOWED", MONITOR: "ALLOWED", WARN: "ALLOWED_WITH_WARNING", BLOCK: "BLOCKED" };
const title = (s: string) => s.charAt(0).toUpperCase() + s.slice(1).toLowerCase();

/** Execute one simulated activity through identity, access, egress and DLP controls. */
export async function executeActivity(s: SessionRow, spec: Json, opts: { timestamp: Date; runNumber: number; stepKey?: string | null; learnerInitiated?: boolean }) {
  const { timestamp, runNumber: run_number } = opts;
  const step_key = opts.stepKey ?? null;
  const action: string = spec.action;
  const actor = await getIdentity(s, spec.actor);
  const commonExt: Json = { device: actor.attributes?.device ?? `KR-WS-${pad(actor.id, 4)}`, source_ip: ipFor(actor.key) };
  if (opts.learnerInitiated) commonExt.learner_initiated = true;
  const events: EventRow[] = [];
  const raised: AlertRow[] = [];
  const tx = `tx-${randomUUID().replace(/-/g, "").slice(0, 12)}`;
  const extCtx: Json = spec.context ?? {};

  if (action === "SIGN_IN") {
    const ok = actor.status === "ACTIVE";
    const ev = await newEvent(s, {
      timestamp, run_number, actor: actor.key, resource: null, action: "SIGN_IN", result: ok ? "SUCCESS" : "FAILURE", source_type: "IDENTITY",
      summary: `${actor.display_name} sign-in ${ok ? "succeeded" : "failed: account disabled"}`, transaction_id: tx, step_key,
      extension: { ...commonExt, mfa: ok ? "passed" : "not_attempted", failure_reason: ok ? null : "ACCOUNT_DISABLED" },
    });
    return { outcome: ok ? "SUCCESS" : "DENIED", events: [ev], alerts: [], reason: "Sign-in evaluated by identity provider", transaction_id: tx };
  }
  if (actor.status !== "ACTIVE") {
    const ev = await newEvent(s, {
      timestamp, run_number, actor: actor.key, resource: spec.resource ?? null, action, result: "DENIED", source_type: "IDENTITY",
      transaction_id: tx, step_key, summary: `${actor.display_name}: activity refused, account disabled`,
      extension: { ...commonExt, failure_reason: "ACCOUNT_DISABLED" },
    });
    return { outcome: "DENIED", events: [ev], alerts: [], reason: "Account disabled", transaction_id: tx };
  }
  if (!spec.resource) throw new DomainError("This action requires a resource");
  const asset = await getAsset(s, spec.resource);
  const dest = spec.destination ? await getDestination(s, spec.destination) : null;
  if (TRANSFER_ACTIONS.has(action) && action !== "EXPORT" && !dest) throw new DomainError(`Action ${action} requires a destination`);
  const recordCount: number | null = spec.record_count ?? null;
  const records = recordCount ?? asset.record_count;

  const path = await accessPath(s, actor, asset);
  const accessAction = action === "DOWNLOAD" || action === "EXPORT" ? action : "READ";
  const accessEv = await newEvent(s, {
    timestamp, run_number, actor: actor.key, resource: asset.key, action: accessAction, result: path.allowed ? "ALLOWED" : "DENIED",
    source_type: ACCESS_SOURCE[asset.asset_type] ?? "FILE_ACCESS", classification: asset.label_key, transaction_id: tx, step_key,
    summary: `${actor.display_name} ${accessAction.toLowerCase()} ${asset.name}: ${path.allowed ? "allowed via " + path.via : "denied (" + path.reason + ")"}`,
    extension: { ...commonExt, access_path: path.via ?? null, grant_key: path.grant_key ?? null, permission: path.permission ?? null,
      record_count: records, location: asset.location, denial_reason: path.reason ?? null },
  });
  events.push(accessEv);
  // Explicit relationship: earlier activity by the same actor on the same resource in this run.
  const prior = await uow().all(security_events, and(
    eq(security_events.session_id, s.id), eq(security_events.run_number, run_number), eq(security_events.actor_id, actor.key),
    eq(security_events.resource_id, asset.key), ne(security_events.transaction_id, tx)));
  if (!path.allowed) {
    link(events);
    accessEv.related_event_ids = uniqueSorted([...accessEv.related_event_ids, ...prior.map((p) => p.event_id)]);
    return { outcome: "DENIED", events, alerts: [], reason: path.reason, transaction_id: tx };
  }

  const ctx = await buildContext(s, { actor, asset, action, destination: dest, record_count: recordCount, context: extCtx, timestamp });
  let outcome = "ALLOWED";
  let reason = "Access permitted";

  if (dest && dest.blocked && !dest.internal) {
    const ev = await newEvent(s, {
      timestamp: addSeconds(timestamp, 5), run_number, actor: actor.key, resource: asset.key, action, result: "BLOCKED", source_type: "PROXY",
      destination: dest.key, classification: asset.label_key, transaction_id: tx, step_key,
      summary: `Egress to ${dest.domain || dest.name} blocked by destination blocklist`,
      extension: { ...commonExt, rule: "EGRESS_BLOCKLIST", domain: dest.domain },
    });
    events.push(ev);
    link(events);
    return { outcome: "BLOCKED", events, alerts: [], reason: "Destination is on the egress blocklist", transaction_id: tx };
  }

  const pols = await loadPolicies(s);
  const titles = Object.fromEntries(pols.map(({ p, d }) => [p.key, d.alert_title || d.name]));
  const { entries, decision } = await evaluate(s, ctx, { dryRun: false, transactionId: tx, policies: pols });
  const policyEvents: Record<string, EventRow> = {};
  const dlpMatched = entries.some((e) => e.matched && e.kind === "DLP");

  if ((TRANSFER_ACTIONS.has(action) && dest) || dlpMatched) {
    outcome = OUTCOME_TO_RESULT[decision.outcome];
    reason = decision.reason;
    const dlpEv = await newEvent(s, {
      timestamp: addSeconds(timestamp, 4), run_number, actor: actor.key, resource: asset.key, action, result: outcome, source_type: "DLP",
      destination: dest?.key ?? null, classification: asset.label_key, policy_id: decision.decisive_policy, policy_version: decision.decisive_version,
      transaction_id: tx, step_key,
      summary: `DLP decision ${decision.outcome} for ${action.toLowerCase()} of ${asset.name}` + (dest ? ` to ${dest.name}` : ""),
      extension: { ...commonExt, decision, detected_types: ctx.content.detected_types, record_count: records,
        matched_policies: entries.filter((e) => e.matched).map((e) => e.policy_key) },
    });
    events.push(dlpEv);
    for (const e of entries) if (e.matched && e.kind === "DLP") policyEvents[e.policy_key] = dlpEv;
  }
  if (TRANSFER_ACTIONS.has(action) && dest) {
    events.push(await newEvent(s, {
      timestamp: addSeconds(timestamp, 6), run_number, actor: actor.key, resource: asset.key, action,
      result: outcome === "BLOCKED" ? "BLOCKED" : "ALLOWED", source_type: TRANSFER_SOURCE[dest.kind] ?? "PROXY", destination: dest.key,
      classification: asset.label_key, transaction_id: tx, step_key,
      summary: `${title(action)} of ${asset.name} to ${dest.domain || dest.name} ${outcome === "BLOCKED" ? "stopped by DLP" : "completed"}`,
      extension: { ...commonExt, bytes: asset.size_bytes, domain: dest.domain, record_count: records, warning_shown: outcome === "ALLOWED_WITH_WARNING" },
    }));
  }
  for (const e of entries) {
    if (e.matched && e.kind === "DETECTION") {
      const detEv = await newEvent(s, {
        timestamp: addSeconds(timestamp, 30), run_number, actor: actor.key, resource: asset.key, action: "ANOMALY", result: "DETECTED",
        source_type: "DETECTION", classification: asset.label_key, policy_id: e.policy_key, policy_version: e.policy_version,
        destination: dest?.key ?? null, transaction_id: tx, step_key,
        summary: `Detection ${e.policy_key}: ${e.name} (${actor.display_name}, ${fmtInt(records)} records)`,
        extension: { ...commonExt, record_count: records, detection: e.name },
      });
      events.push(detEv);
      policyEvents[e.policy_key] = detEv;
    }
  }
  link(events);
  for (const ev of events) ev.related_event_ids = uniqueSorted([...ev.related_event_ids, ...prior.map((p) => p.event_id)]);

  for (const e of entries) {
    if (e.matched && e.alert) {
      const trigger = policyEvents[e.policy_key];
      raised.push(await uow().insert(alerts, {
        alert_id: await nextAlertId(s), session_id: s.id, run_number, title: `${titles[e.policy_key] ?? e.name}: ${actor.display_name} / ${asset.name}`,
        severity: e.severity, status: "NEW", policy_id: e.policy_key, policy_version: e.policy_version, triggering_event_id: trigger.event_id,
        event_ids: uniqueSorted([...events.map((x) => x.event_id), ...prior.map((p) => p.event_id)]), actor_id: actor.key, resource_id: asset.key,
        explanation: e.explanation, timestamp: trigger.timestamp, step_key,
      }));
    }
  }
  return { outcome, events, alerts: raised, reason, transaction_id: tx, decision, entries };
}

// --------------------------------------------------------------------------- timeline

/** Create (once) a test identity cloned from the original actor's initial role and groups. */
export async function ensureValidationIdentity(s: SessionRow, originalKey: string): Promise<IdentityRow> {
  const u = uow();
  const cloneKey = `${originalKey}-val`;
  const existing = await u.one(sim_identities, and(eq(sim_identities.session_id, s.id), eq(sim_identities.key, cloneKey))!);
  if (existing) return existing;
  const env = environmentTemplate();
  const tmpl = env.identities.find((i: Json) => i.key === originalKey);
  const clone = await u.insert(sim_identities, {
    session_id: s.id, key: cloneKey, display_name: `Validation clone of ${tmpl.display_name}`,
    email: `validation+${originalKey}@kestrelridge.example`, department: tmpl.department, title: tmpl.title,
    enterprise_role: tmpl.enterprise_role, employment_type: tmpl.employment_type, manager_key: null,
    attributes: { validation_clone_of: originalKey, device: "KR-VAL-0001" },
  });
  const initialGroups = env.groups.filter((g: Json) => g.members.includes(originalKey)).map((g: Json) => g.key);
  for (const g of await u.all(sim_groups, eq(sim_groups.session_id, s.id))) {
    if (initialGroups.includes(g.key) && !g.members.includes(cloneKey)) g.members = [...g.members, cloneKey];
  }
  return clone;
}

export async function lastActionSeq(s: SessionRow, types?: string[]): Promise<number> {
  const u = uow();
  await u.flush();
  const where = types?.length
    ? and(eq(scenario_actions.session_id, s.id), inArray(scenario_actions.action_type, types))
    : eq(scenario_actions.session_id, s.id);
  const rows = await u.db.select({ m: max(scenario_actions.seq) }).from(scenario_actions).where(where);
  return Number(rows[0]?.m ?? 0);
}

export async function recordAction(s: SessionRow, action_type: string, params: Json, result: Json = {}, provenance = "SIMULATED") {
  const seq = (await lastActionSeq(s)) + 1;
  return uow().insert(scenario_actions, { session_id: s.id, seq, action_type, params, result, provenance, sim_time: s.sim_clock });
}

export function advanceClock(s: SessionRow, minutes = 1): Date {
  s.sim_clock = addMinutes(s.sim_clock, minutes);
  return s.sim_clock;
}

export async function runTimeline(s: SessionRow, mode: string): Promise<Json> {
  const d = definitionFor(s);
  if (mode !== "standard" && mode !== "validation") throw new DomainError("mode must be 'standard' or 'validation'");
  if (mode === "validation" && s.run_count < 1) throw new DomainError("Run the business day at least once before a control-validation replay", 409);
  const params = variantParams(s);
  const gt = d.ground_truth;
  const runNumber = s.run_count + 1;
  const start = new Date(d.sim_start);
  const day = addDays(new Date(Date.UTC(start.getUTCFullYear(), start.getUTCMonth(), start.getUTCDate())), runNumber - 1);
  const substitutions: Record<string, string> = {};
  if (mode === "validation") {
    const clone = await ensureValidationIdentity(s, params.culprit);
    substitutions[params.culprit] = clone.key;
  }
  const outcomes: Json[] = [];
  const steps = sorted(d.timeline.map((st) => resolveStep(st, params)), (x) => x.at);
  for (const st of steps) {
    const [hh, mm] = st.at.split(":").map(Number);
    const ts = new Date(Date.UTC(day.getUTCFullYear(), day.getUTCMonth(), day.getUTCDate(), hh, mm));
    const spec = { ...st };
    if ((gt.culprit_steps ?? []).includes(st.key) && st.actor in substitutions) spec.actor = substitutions[st.actor];
    const res = await executeActivity(s, spec, { timestamp: ts, runNumber, stepKey: st.key });
    outcomes.push({ step: st.key, outcome: res.outcome, alerts: res.alerts.length });
  }
  s.run_count = runNumber;
  const endOfDay = new Date(Date.UTC(day.getUTCFullYear(), day.getUTCMonth(), day.getUTCDate(), 20, 30));
  if (s.sim_clock < endOfDay) s.sim_clock = endOfDay;
  const act = await recordAction(s, "RUN_TIMELINE", { mode, run_number: runNumber }, { events: s.event_seq, steps: outcomes.length });
  const runs = [...((s.flags ?? {}).runs ?? [])];
  runs.push({ run_number: runNumber, mode, action_seq: act.seq, sim_day: dateOnly(day) });
  s.flags = { ...(s.flags ?? {}), runs };
  const u = uow();
  const alertsN = await u.count(alerts, eq(alerts.session_id, s.id), eq(alerts.run_number, runNumber));
  const eventsN = await u.count(security_events, eq(security_events.session_id, s.id), eq(security_events.run_number, runNumber));
  // The per-step outcome list is learner-visible only as counts, so it does not reveal which step is malicious.
  return { run_number: runNumber, mode, sim_day: dateOnly(day), activities: outcomes.length, events_generated: eventsN,
    alerts_generated: alertsN, blocked_or_denied: outcomes.filter((o) => o.outcome === "BLOCKED" || o.outcome === "DENIED").length };
}
