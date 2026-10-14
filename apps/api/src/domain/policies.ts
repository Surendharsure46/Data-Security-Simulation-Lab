/** Policy management: versioning, status, dry-run testing, test suites and change records. */
import type { PolicyDefinition } from "@threatready/contracts";
import { and, eq } from "drizzle-orm";
import { deepEqual, DomainError, pyIso, round } from "../common/util.js";
import { uow } from "../db/context.js";
import { change_records, policies, policy_test_runs, policy_versions } from "../db/schema.js";
import { diffDefinitions, validateDefinition } from "./policy-engine.js";
import {
  advanceClock, buildContext, definitionFor, evaluate, getAsset, getDestination, getIdentity, loadPolicies, policyVersions, publicContext,
  recordAction, type LoadedPolicy, type PolicyRow, type PolicyVersionRow, type SessionRow,
} from "./simulation.js";

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
export type TestRunRow = typeof policy_test_runs.$inferSelect;

const KEY_RE = /^POL-[A-Z0-9-]{2,40}$/;
const scopeNote = (n: number) => `Measured against ${n} labelled synthetic test cases in this scenario only. These rates describe this `
  + "test set and are not an estimate of production detection performance.";

export { validateDefinition };

export async function getPolicy(s: SessionRow, key: string): Promise<PolicyRow> {
  const p = await uow().one(policies, and(eq(policies.session_id, s.id), eq(policies.key, key))!);
  if (!p) throw new DomainError(`Unknown policy '${key}'`, 404);
  return p;
}

export async function createPolicy(s: SessionRow, author: string, key: string, raw: unknown, note: string): Promise<PolicyRow> {
  if (!KEY_RE.test(key)) throw new DomainError("Policy key must look like POL-XXXX (uppercase letters, digits, hyphens)");
  const u = uow();
  if (await u.one(policies, and(eq(policies.session_id, s.id), eq(policies.key, key))!)) throw new DomainError("A policy with this key already exists", 409);
  const definition = validateDefinition(raw);
  advanceClock(s);
  const p = await u.insert(policies, { session_id: s.id, key, kind: definition.kind, status: "ENABLED", current_version: 1, baseline: false });
  await u.insert(policy_versions, { policy_id: p.id, version: 1, definition, change_note: note || "Created", author });
  await recordAction(s, "POLICY_CREATE", { policy: key, version: 1 });
  return p;
}

export async function updatePolicy(s: SessionRow, author: string, key: string, raw: unknown, note: string): Promise<PolicyVersionRow> {
  const p = await getPolicy(s, key);
  const definition = validateDefinition(raw);
  if (definition.kind !== p.kind) throw new DomainError("Policy kind cannot change between versions; create a new policy instead");
  const versions = await policyVersions(p.id);
  const current = versions.find((v) => v.version === p.current_version)!;
  if (deepEqual(JSON.parse(JSON.stringify(definition)), current.definition)) throw new DomainError("No changes compared with the current version", 409);
  advanceClock(s);
  const v = await uow().insert(policy_versions, {
    policy_id: p.id, version: Math.max(...versions.map((x) => x.version)) + 1, definition, change_note: note || "Updated", author,
  });
  p.current_version = v.version;
  await recordAction(s, "POLICY_UPDATE", { policy: key, version: v.version });
  return v;
}

export async function setStatus(s: SessionRow, key: string, status: string): Promise<PolicyRow> {
  if (status !== "ENABLED" && status !== "DISABLED") throw new DomainError("status must be ENABLED or DISABLED");
  const p = await getPolicy(s, key);
  if (p.status === status) throw new DomainError(`Policy already ${status}`, 409);
  p.status = status;
  advanceClock(s);
  await recordAction(s, "POLICY_STATUS", { policy: key, status });
  return p;
}

export async function rollback(s: SessionRow, author: string, key: string, toVersion: number): Promise<PolicyVersionRow> {
  const p = await getPolicy(s, key);
  const target = (await policyVersions(p.id)).find((v) => v.version === toVersion);
  if (!target) throw new DomainError("Version not found", 404);
  return updatePolicy(s, author, key, target.definition, `Rollback to v${toVersion}`);
}

export async function diff(s: SessionRow, key: string, a: number, b: number): Promise<Json[]> {
  const p = await getPolicy(s, key);
  const versions = await policyVersions(p.id);
  const va = versions.find((v) => v.version === a);
  const vb = versions.find((v) => v.version === b);
  if (!va || !vb) throw new DomainError("Version not found", 404);
  return diffDefinitions(va.definition, vb.definition);
}

async function contextFor(s: SessionRow, spec: Json): Promise<Json> {
  const actor = await getIdentity(s, spec.actor);
  const asset = await getAsset(s, spec.resource);
  const dest = spec.destination ? await getDestination(s, spec.destination) : null;
  const hour = Number.parseInt(String(spec.hour ?? 12), 10);
  return buildContext(s, {
    actor, asset, action: spec.action, destination: dest, record_count: spec.record_count ?? null, context: spec.context ?? {},
    timestamp: new Date(Date.UTC(2026, 2, 9, ((hour % 24) + 24) % 24, 0)),
  });
}

/**
 * Evaluate a hypothetical activity. Access control is NOT applied: this tests policy logic only.
 * `candidate` optionally evaluates an unsaved policy definition alongside (or instead of) the saved version with the same key,
 * so a learner can preview the effect of an edit before saving it.
 */
export async function dryRun(s: SessionRow, spec: Json, candidate?: { key?: string | null; definition: unknown } | null): Promise<Json> {
  const ctx = await contextFor(s, spec);
  let pols: LoadedPolicy[] = await loadPolicies(s);
  if (candidate) {
    const key = candidate.key || "POL-DRAFT";
    const d: PolicyDefinition = validateDefinition(candidate.definition);
    pols = pols.filter((x) => x.p.key !== key);
    pols.push({
      p: { key, kind: d.kind, status: "ENABLED", current_version: 0 } as PolicyRow,
      pv: { version: 0, definition: d } as unknown as PolicyVersionRow, d,
    });
  }
  const res = await evaluate(s, ctx, { dryRun: true, transactionId: `dry-${s.event_seq}`, policies: pols, persist: !candidate });
  if (!candidate) advanceClock(s);
  return { context: publicContext(ctx), entries: res.entries, decision: res.decision,
    note: "Policy-only evaluation: access permissions, account status and egress blocklists are not applied in dry runs.",
    draft_included: Boolean(candidate) };
}

function metrics(results: Json[]): Json {
  const tp = results.filter((r) => r.should_prevent && r.prevented).length;
  const fn = results.filter((r) => r.should_prevent && !r.prevented).length;
  const fp = results.filter((r) => !r.should_prevent && r.prevented).length;
  const tn = results.filter((r) => !r.should_prevent && !r.prevented).length;
  return {
    total: results.length, tp, fp, tn, fn,
    precision: tp + fp ? round(tp / (tp + fp), 3) : null,
    recall: tp + fn ? round(tp / (tp + fn), 3) : null,
    accuracy: results.length ? round((tp + tn) / results.length, 3) : null,
    alerts_on_allowed_cases: results.filter((r) => !r.should_prevent && r.alerts.length).length,
    scope_note: scopeNote(results.length),
  };
}

export async function runTestSuite(s: SessionRow): Promise<TestRunRow> {
  const d = definitionFor(s);
  if (!d.policy_test_suite.length) throw new DomainError("This scenario has no labelled policy test suite");
  const pols = await loadPolicies(s);
  const results: Json[] = [];
  for (const c of d.policy_test_suite) {
    const ctx = await contextFor(s, c);
    const res = await evaluate(s, ctx, { dryRun: true, transactionId: `suite-${c.id}`, policies: pols, persist: false });
    const outcome = res.decision.outcome;
    const prevented = outcome === "BLOCK";
    results.push({ id: c.id, description: c.description, should_prevent: c.should_prevent, outcome, prevented,
      decisive_policy: res.decision.decisive_policy, alerts: res.entries.filter((e) => e.matched && e.alert).map((e) => e.policy_key),
      correct: prevented === c.should_prevent });
  }
  const u = uow();
  const n = (await u.count(policy_test_runs, eq(policy_test_runs.session_id, s.id))) + 1;
  const run = await u.insert(policy_test_runs, {
    session_id: s.id, run_number: n, results, metrics: metrics(results),
    policy_snapshot: Object.fromEntries(pols.map(({ p, pv }) => [p.key, { version: pv.version, status: p.status }])),
  });
  await recordAction(s, "POLICY_TEST_SUITE", { run_number: n }, { metrics: run.metrics });
  return run;
}

export function compareRuns(a: TestRunRow, b: TestRunRow): Json {
  const ra = new Map(a.results.map((r) => [r.id, r]));
  const changed: Json[] = [];
  for (const r of b.results) {
    const prev = ra.get(r.id);
    if (prev && prev.outcome !== r.outcome) {
      const kind = r.correct && !prev.correct ? "fixed" : prev.correct && !r.correct ? "regressed" : "changed";
      changed.push({ id: r.id, description: r.description, before: prev.outcome, after: r.outcome, kind });
    }
  }
  const policyChanges: Json = {};
  for (const [k, v] of Object.entries(b.policy_snapshot)) {
    if (!deepEqual(a.policy_snapshot[k], v)) policyChanges[k] = { before: a.policy_snapshot[k] ?? null, after: v };
  }
  return { from_run: a.run_number, to_run: b.run_number, changed, regressions: changed.filter((c) => c.kind === "regressed").length,
    fixes: changed.filter((c) => c.kind === "fixed").length, policy_changes: policyChanges };
}

export async function createChangeRecord(s: SessionRow, a: {
  policy_key: string; from_version: number; to_version: number; reason: string; expected_impact: string; rollback_plan: string;
  test_run_id: number | null;
}) {
  const p = await getPolicy(s, a.policy_key);
  const versions = new Set((await policyVersions(p.id)).map((v) => v.version));
  if (!versions.has(a.from_version) || !versions.has(a.to_version)) throw new DomainError("Versions must exist on the policy");
  const u = uow();
  if (a.test_run_id !== null && !(await u.one(policy_test_runs, and(eq(policy_test_runs.id, a.test_run_id), eq(policy_test_runs.session_id, s.id))!))) {
    throw new DomainError("Test run not found in this session", 404);
  }
  const cr = await u.insert(change_records, { session_id: s.id, ...a });
  await recordAction(s, "CHANGE_RECORD", { policy: a.policy_key, from: a.from_version, to: a.to_version });
  return cr;
}

export async function serializePolicy(p: PolicyRow): Promise<Json> {
  const versions = await policyVersions(p.id);
  const cur = versions.find((v) => v.version === p.current_version)!;
  return { key: p.key, kind: p.kind, status: p.status, baseline: p.baseline, current_version: p.current_version, definition: cur.definition,
    versions: versions.map((v) => ({ version: v.version, author: v.author, change_note: v.change_note, created_at: pyIso(v.created_at) })) };
}
