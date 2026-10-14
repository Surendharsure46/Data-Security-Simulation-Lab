/** Correlation, risk model and remediation (with verification). */
import { and, asc, eq } from "drizzle-orm";
import { DomainError, pyIso, round, uniqueSorted } from "../common/util.js";
import { uow } from "../db/context.js";
import {
  access_grants, alerts, destinations as destinationsT, evidence_references, investigation_cases, remediation_actions, security_events,
  sim_groups, sim_identities,
} from "../db/schema.js";
import {
  accessPath, advanceClock, definitionFor, getAsset, getDestination, getIdentity, newEvent, recordAction, type EventRow, type IdentityRow,
  type SessionRow,
} from "./simulation.js";

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
export type AlertRow = typeof alerts.$inferSelect;
export type CaseRow = typeof investigation_cases.$inferSelect;
export type RemediationRow = typeof remediation_actions.$inferSelect;
type GrantRow = typeof access_grants.$inferSelect;

const CORRELATION_WINDOW_MS = 24 * 3600 * 1000;
export const PARTIES = ["PRIVACY_OFFICE", "LEGAL", "HR", "DATA_OWNER", "MANAGEMENT", "CISO"];
export const DISPOSITIONS = ["TRUE_POSITIVE", "BENIGN_POSITIVE", "FALSE_POSITIVE", "UNDETERMINED"];
export const DETERMINATIONS = [
  "CONFIRMED_DATA_EXFILTRATION", "ATTEMPTED_EXFILTRATION_PREVENTED", "POLICY_VIOLATION_NO_EXPOSURE", "BENIGN_ACTIVITY", "UNDETERMINED",
];
export const EXPOSURE_STATUSES = [
  "CONFIRMED_EXFILTRATION", "LIKELY_EXFILTRATION", "ATTEMPT_PREVENTED", "NO_EVIDENCE_OF_EXFILTRATION", "UNDETERMINED",
];
export const ROOT_CAUSES = [
  "EXCESSIVE_PERMISSION", "MISSING_CLASSIFICATION", "MONITOR_ONLY_POLICY", "MISSING_DATA_OWNER", "COMPROMISED_CREDENTIALS", "MALWARE",
  "PHISHING", "WEAK_ENCRYPTION", "MISSING_MFA", "USER_ERROR",
];
export const SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

// --------------------------------------------------------------------------- correlation

/** Events related to an alert with explicit reasons. Time proximity alone never links events. */
export async function correlate(s: SessionRow, alert: AlertRow): Promise<Json[]> {
  const u = uow();
  const trigger = await u.one(security_events, eq(security_events.event_id, alert.triggering_event_id));
  if (!trigger) return [];
  const t0 = trigger.timestamp.getTime();
  const out: Json[] = [];
  const evs = await u.all(security_events, eq(security_events.session_id, s.id), [asc(security_events.timestamp), asc(security_events.seq)]);
  for (const ev of evs) {
    const reasons: string[] = [];
    if ((alert.event_ids ?? []).includes(ev.event_id)) reasons.push("Listed in alert evidence");
    if (trigger.transaction_id && ev.transaction_id === trigger.transaction_id) reasons.push("Same transaction");
    if ((trigger.related_event_ids ?? []).includes(ev.event_id)) reasons.push("Explicit relation recorded by source");
    if (alert.actor_id && ev.actor_id === alert.actor_id) reasons.push("Same actor");
    if (alert.resource_id && ev.resource_id === alert.resource_id) reasons.push("Same resource");
    if (!reasons.length) continue;
    const delta = ev.timestamp.getTime() - t0;
    const has = (...xs: string[]) => xs.some((x) => reasons.includes(x));
    if (Math.abs(delta) > CORRELATION_WINDOW_MS && !has("Listed in alert evidence", "Same transaction")) continue;
    const strength = has("Same transaction", "Explicit relation recorded by source", "Listed in alert evidence") ? "strong"
      : reasons.length >= 2 ? "medium" : "weak";
    out.push({ event_id: ev.event_id, reasons, strength, minutes_from_trigger: round(delta / 60000, 1) });
  }
  return out;
}

// --------------------------------------------------------------------------- risk model

/** Documented, deterministic severity model (docs/ASSESSMENT.md). */
export function riskScore(a: { label_rank: number | null; records: number; destination_external: boolean; data_left_org: string }): Json {
  if (!["YES", "NO", "UNKNOWN"].includes(a.data_left_org)) throw new DomainError("data_left_org must be YES, NO or UNKNOWN");
  const impact = a.label_rank === null ? 2 : Math.max(0, Math.min(a.label_rank, 3));
  const volume = a.records >= 10_000 ? 2 : a.records >= 1_000 ? 1 : 0;
  const dest = a.destination_external ? 2 : 0;
  const left = ({ YES: 2, UNKNOWN: 1, NO: 0 } as Record<string, number>)[a.data_left_org];
  const score = impact + volume + dest + left;
  const severity = score >= 8 ? "CRITICAL" : score >= 6 ? "HIGH" : score >= 3 ? "MEDIUM" : "LOW";
  return {
    score, severity, components: { sensitivity: impact, volume, destination: dest, data_left_org: left },
    notes: a.label_rank !== null ? [] : ["Label unknown: sensitivity scored as 2 (assume Confidential) until classified."],
  };
}

// --------------------------------------------------------------------------- remediation

function catalog(s: SessionRow) {
  return new Map(definitionFor(s).remediation_catalog.map((r) => [r.type, r]));
}

async function probeSignIn(s: SessionRow, ident: IdentityRow): Promise<EventRow> {
  const ok = ident.status === "ACTIVE";
  return newEvent(s, {
    timestamp: s.sim_clock, run_number: 0, actor: ident.key, resource: null, action: "SIGN_IN", result: ok ? "SUCCESS" : "FAILURE",
    source_type: "IDENTITY", summary: `Verification probe: sign-in as ${ident.display_name} ${ok ? "succeeded" : "refused (account disabled)"}`,
    extension: { verification_probe: true, failure_reason: ok ? null : "ACCOUNT_DISABLED" },
  });
}

async function members(s: SessionRow, grant: GrantRow): Promise<string[]> {
  if (grant.principal_type === "IDENTITY") return [grant.principal_key];
  const g = await uow().one(sim_groups, and(eq(sim_groups.session_id, s.id), eq(sim_groups.key, grant.principal_key))!);
  return g ? [...g.members] : [];
}

async function identityOrNull(s: SessionRow, key: string) {
  return uow().one(sim_identities, and(eq(sim_identities.session_id, s.id), eq(sim_identities.key, key))!);
}

async function grantByKey(s: SessionRow, key: string) {
  return uow().one(access_grants, and(eq(access_grants.session_id, s.id), eq(access_grants.key, key))!);
}

/** Re-check the current environment for the effect of a remediation action. */
export async function verifyState(s: SessionRow, rem: RemediationRow, emitProbe = true): Promise<Json> {
  const t = rem.action_type;
  if (t === "DISABLE_ACCOUNT" || t === "ENABLE_ACCOUNT") {
    const ident = await getIdentity(s, rem.target_key);
    const want = t === "DISABLE_ACCOUNT" ? "DISABLED" : "ACTIVE";
    const probe = emitProbe ? await probeSignIn(s, ident) : null;
    return { verified: ident.status === want, check: `Identity status is ${ident.status} (expected ${want})`, probe_event_id: probe?.event_id ?? null };
  }
  if (t === "REVOKE_SESSIONS") {
    const ident = await getIdentity(s, rem.target_key);
    const ok = ident.sessions_revoked_at !== null;
    return { verified: ok, check: ok ? "Existing sessions terminated" : "No session revocation recorded",
      caveat: ident.status === "DISABLED" ? null : "The account can still authenticate again; revoke sessions does not disable it." };
  }
  if (t === "BLOCK_DESTINATION") {
    const dest = await getDestination(s, rem.target_key);
    let probe: EventRow | null = null;
    if (emitProbe) {
      probe = await newEvent(s, {
        timestamp: s.sim_clock, run_number: 0, actor: null, resource: null, action: "EGRESS_TEST", result: dest.blocked ? "BLOCKED" : "ALLOWED",
        source_type: "PROXY", destination: dest.key,
        summary: `Verification probe: connection to ${dest.domain || dest.name} ${dest.blocked ? "blocked" : "allowed"}`,
        extension: { verification_probe: true, domain: dest.domain },
      });
    }
    return { verified: dest.blocked, check: `Destination blocklist flag = ${dest.blocked ? "True" : "False"}`, probe_event_id: probe?.event_id ?? null,
      caveat: "Blocks every user's traffic to this destination, including legitimate use." };
  }
  if (t === "QUARANTINE_ASSET") {
    const asset = await getAsset(s, rem.target_key);
    const still: string[] = [];
    const grants = await uow().all(access_grants, and(eq(access_grants.session_id, s.id), eq(access_grants.asset_key, asset.key)));
    for (const g of grants) {
      for (const m of await members(s, g)) {
        const ident = await identityOrNull(s, m);
        if (!ident) continue;
        const p = await accessPath(s, ident, asset);
        if (p.allowed && !String(p.via ?? "").includes("exemption")) still.push(m);
      }
    }
    const list = uniqueSorted(still).map((x) => `'${x}'`).join(", ");
    return { verified: asset.quarantined && !still.length, check: `Quarantined=${asset.quarantined ? "True" : "False"}; non-exempt identities with access: [${list}]` };
  }
  if (t === "REVOKE_GRANT") {
    const grant = await grantByKey(s, rem.target_key);
    if (!grant) return { verified: false, check: "Grant not found" };
    const asset = await getAsset(s, grant.asset_key);
    const residual: Json[] = [];
    for (const m of await members(s, grant)) {
      const ident = await identityOrNull(s, m);
      if (ident) {
        const p = await accessPath(s, ident, asset);
        if (p.allowed) residual.push({ identity: m, via: p.via });
      }
    }
    return { verified: grant.status === "REVOKED", check: `Grant ${grant.key} status ${grant.status}`, former_members_with_other_access: residual };
  }
  if (t === "PRESERVE_EVIDENCE") {
    const ident = await getIdentity(s, rem.target_key);
    const ok = Boolean(ident.attributes?.evidence_preserved_at);
    return { verified: ok, check: ok ? "Forensic snapshot and mailbox hold recorded" : "No preservation recorded",
      snapshot_id: ident.attributes?.evidence_snapshot_id ?? null };
  }
  if (t === "REIMAGE_DEVICE") {
    const ident = await getIdentity(s, rem.target_key);
    const destroyed = Boolean(ident.attributes?.evidence_destroyed);
    return { verified: true, check: "Device rebuilt", local_evidence: destroyed ? "DESTROYED (no prior preservation)" : "Snapshot preserved before reimage" };
  }
  if (t === "REQUEST_EXTERNAL_TAKEDOWN") {
    return { verified: false, check: "Request recorded",
      caveat: "The external provider's response is outside this simulation. Removal of copied data cannot be confirmed." };
  }
  if (t === "ESCALATE") return { verified: true, check: `Escalation to ${rem.target_key} recorded` };
  return { verified: false, check: "Unknown action" };
}

export async function applyRemediation(s: SessionRow, a: {
  action_type: string; target_key: string; justification: string; case_id: number | null; confirm_destructive: boolean;
}): Promise<RemediationRow> {
  const { action_type, target_key } = a;
  const spec = catalog(s).get(action_type);
  if (!spec) throw new DomainError(`Action ${action_type} is not permitted in this scenario`);
  if (spec.destructive && !a.confirm_destructive) {
    throw new DomainError(`${action_type} is destructive. Resubmit with confirm_destructive=true after reviewing the impact.`, 409);
  }
  const u = uow();
  if (a.case_id !== null && !(await u.one(investigation_cases, and(eq(investigation_cases.id, a.case_id), eq(investigation_cases.session_id, s.id))!))) {
    throw new DomainError("Case not found in this session", 404);
  }
  advanceClock(s);
  const now = s.sim_clock;
  let before: Json = {};
  let after: Json = {};

  if (spec.target_type === "IDENTITY") {
    const ident = await getIdentity(s, target_key);
    if (ident.employment_type === "TEST") throw new DomainError("Validation identities cannot be targeted");
    before = { status: ident.status, attributes: { ...ident.attributes } };
    const attrs: Json = { ...ident.attributes };
    if (action_type === "DISABLE_ACCOUNT") ident.status = "DISABLED";
    else if (action_type === "ENABLE_ACCOUNT") ident.status = "ACTIVE";
    else if (action_type === "REVOKE_SESSIONS") ident.sessions_revoked_at = now;
    else if (action_type === "PRESERVE_EVIDENCE") {
      attrs.evidence_preserved_at = pyIso(now);
      attrs.evidence_snapshot_id = `SNAP-${ident.key}-${Math.floor(now.getTime() / 1000)}`;
    } else if (action_type === "REIMAGE_DEVICE") {
      attrs.device_reimaged_at = pyIso(now);
      if (!attrs.evidence_preserved_at) attrs.evidence_destroyed = true;
    }
    ident.attributes = attrs;
    after = { status: ident.status, attributes: { ...attrs } };
  } else if (spec.target_type === "DESTINATION") {
    const dest = await getDestination(s, target_key);
    if (dest.internal) throw new DomainError("Internal destinations cannot be blocked or targeted for takedown");
    before = { blocked: dest.blocked };
    if (action_type === "BLOCK_DESTINATION") dest.blocked = true;
    after = { blocked: dest.blocked };
  } else if (spec.target_type === "ASSET") {
    const asset = await getAsset(s, target_key);
    before = { quarantined: asset.quarantined };
    asset.quarantined = true;
    after = { quarantined: true };
  } else if (spec.target_type === "GRANT") {
    const grant = await grantByKey(s, target_key);
    if (!grant) throw new DomainError(`Unknown grant '${target_key}'`, 404);
    if (grant.status === "REVOKED") throw new DomainError("Grant already revoked", 409);
    before = { status: grant.status };
    grant.status = "REVOKED";
    grant.revoked_at = now;
    after = { status: "REVOKED" };
  } else if (spec.target_type === "PARTY") {
    if (!PARTIES.includes(target_key)) throw new DomainError(`Escalation target must be one of ${JSON.stringify(PARTIES).replace(/"/g, "'").replace(/,/g, ", ")}`);
  }

  const seq = (await u.count(remediation_actions, eq(remediation_actions.session_id, s.id))) + 1;
  const rem = await u.insert(remediation_actions, {
    session_id: s.id, case_id: a.case_id, seq, action_type, target_key, justification: a.justification, status: "APPLIED",
    before_state: before, after_state: after, sim_time: now, verification: {},
  });
  rem.verification = await verifyState(s, rem);
  rem.status = action_type === "ESCALATE" || action_type === "REQUEST_EXTERNAL_TAKEDOWN" ? "RECORDED"
    : rem.verification.verified ? "VERIFIED" : "VERIFICATION_FAILED";
  await recordAction(s, `REMEDIATION:${action_type}`, { target: target_key, case_id: a.case_id }, { remediation_id: rem.id, status: rem.status });
  return rem;
}

/** The session's primary case: most linked evidence, latest on ties. Used for grading and reports alike. */
export async function primaryCase(s: SessionRow): Promise<CaseRow | undefined> {
  const u = uow();
  let best: CaseRow | undefined;
  let bestN = -1;
  for (const c of await u.all(investigation_cases, eq(investigation_cases.session_id, s.id), [asc(investigation_cases.id)])) {
    const n = await u.count(evidence_references, eq(evidence_references.case_id, c.id));
    if (n >= bestN) {
      best = c;
      bestN = n;
    }
  }
  return best;
}

export async function destinationList(s: SessionRow) {
  return uow().all(destinationsT, eq(destinationsT.session_id, s.id), [asc(destinationsT.key)]);
}

