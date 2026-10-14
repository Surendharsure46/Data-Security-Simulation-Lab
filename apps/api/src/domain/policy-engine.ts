/**
 * Deterministic policy evaluation engine (the schema lives in @threatready/contracts).
 *
 * Precedence:
 * 1. DISABLED policies are skipped (still listed in the trace).
 * 2. A policy matches when its scope and condition group evaluate to true.
 * 3. The first matching exception (in list order) replaces the outcome with ALLOW or MONITOR and suppresses the
 *    alert unless the exception sets keep_alert.
 * 4. The final decision is the most restrictive effective outcome among matched policies: BLOCK > WARN > MONITOR >
 *    ALLOW. Ties break on priority (lower first) then policy key, so the decisive policy is deterministic.
 * 5. If nothing matches, the decision is ALLOW with decisive_policy = null.
 * 6. Every matched, non-excepted policy with alert = true raises its own alert.
 * 7. A field missing from the context makes its condition false (except not_exists); the trace records missing.
 * 8. DETECTION policies may only MONITOR: detection is separate from enforcement.
 */
import { PolicyDefinitionSchema, type Condition, type ConditionGroup, type PolicyDefinition } from "@threatready/contracts";
import { DomainError, pyRepr } from "../common/util.js";

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

export const OUTCOME_RANK: Record<string, number> = { ALLOW: 0, MONITOR: 1, WARN: 2, BLOCK: 3 };
const MISSING = Symbol("missing");

export function parsePolicy(raw: unknown): PolicyDefinition {
  return PolicyDefinitionSchema.parse(raw);
}

export function validateDefinition(raw: unknown): PolicyDefinition {
  const r = PolicyDefinitionSchema.safeParse(raw);
  if (!r.success) {
    const msgs = r.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`);
    throw new DomainError("Invalid policy definition — " + msgs.slice(0, 8).join("; "), 422);
  }
  return r.data;
}

function resolve(ctx: Json, path: string): unknown {
  let cur: unknown = ctx;
  for (const part of path.split(".")) {
    if (cur === null || typeof cur !== "object" || Array.isArray(cur) || !(part in (cur as Json))) return MISSING;
    cur = (cur as Json)[part];
  }
  return cur === null || cur === undefined ? MISSING : cur;
}

const norm = (v: unknown) => (typeof v === "string" ? v.toLowerCase() : v);

export function evalCondition(cond: Condition, ctx: Json): Json {
  const actual = resolve(ctx, cond.field);
  const missing = actual === MISSING;
  const rec: Json = { field: cond.field, op: cond.op, value: cond.value, actual: missing ? null : actual, missing };
  if (cond.op === "not_exists") return { ...rec, result: missing };
  if (cond.op === "exists") return { ...rec, result: !missing };
  if (missing) return { ...rec, result: false };
  const { op, value: val } = cond;
  const ranks: Record<string, number> = ctx._label_ranks ?? {};
  let result = false;
  switch (op) {
    case "eq": result = norm(actual) === norm(val); break;
    case "neq": result = norm(actual) !== norm(val); break;
    case "in": result = (val as unknown[]).map(norm).includes(norm(actual)); break;
    case "not_in": result = !(val as unknown[]).map(norm).includes(norm(actual)); break;
    case "contains_any": case "contains_all": case "contains_none": {
      const items = new Set((Array.isArray(actual) ? actual : [actual]).map(norm));
      const wanted = (val as unknown[]).map(norm);
      if (op === "contains_any") result = wanted.some((w) => items.has(w));
      else if (op === "contains_all") result = wanted.every((w) => items.has(w));
      else result = !wanted.some((w) => items.has(w));
      break;
    }
    case "gt": case "gte": case "lt": case "lte": {
      const a = typeof actual === "number" ? actual : typeof actual === "string" && actual.trim() !== "" ? Number(actual) : NaN;
      if (Number.isNaN(a) || typeof actual === "boolean") {
        rec.error = `Type mismatch: could not convert ${pyRepr(actual)} to a number`;
        result = false;
      } else {
        const v = val as number;
        result = op === "gt" ? a > v : op === "gte" ? a >= v : op === "lt" ? a < v : a <= v;
      }
      break;
    }
    case "label_at_least": case "label_below": {
      if (!Object.hasOwn(ranks, String(val))) {
        rec.error = `Unknown label '${String(val)}'`;
      } else {
        const actualRank = Object.hasOwn(ranks, String(actual)) ? ranks[String(actual)] : undefined;
        if (actualRank === undefined) rec.error = `Resource label '${String(actual)}' not in label scheme`;
        else result = op === "label_at_least" ? actualRank >= ranks[String(val)] : actualRank < ranks[String(val)];
      }
      break;
    }
  }
  rec.result = Boolean(result);
  return rec;
}

const isGroup = (c: Condition | ConditionGroup): c is ConditionGroup => "conditions" in c;

export function evalGroup(group: ConditionGroup, ctx: Json): Json {
  const children = group.conditions.map((c) => (isGroup(c) ? evalGroup(c, ctx) : evalCondition(c, ctx)));
  const results = children.map((ch) => ch.result as boolean);
  const result = group.match === "all" ? results.every(Boolean) : results.some(Boolean);
  return { group: group.match, result, children };
}

export function evaluatePolicy(key: string, version: number, status: string, definition: PolicyDefinition, ctx: Json): Json {
  const entry: Json = {
    policy_key: key, policy_version: version, name: definition.name, kind: definition.kind, status, priority: definition.priority,
    configured_outcome: definition.outcome, severity: definition.severity, matched: false, exception: null, effective_outcome: null,
    alert: false, escalate: false,
  };
  if (status !== "ENABLED") return { ...entry, skipped_reason: "Policy disabled" };
  const action = resolve(ctx, "action.type");
  if (definition.applies_to_actions.length && (action === MISSING || !definition.applies_to_actions.includes(action as string))) {
    return { ...entry, skipped_reason: `Out of scope: action not in ${pyRepr(definition.applies_to_actions)}`, scope_match: false };
  }
  entry.scope_match = true;
  const trace = evalGroup(definition.conditions, ctx);
  entry.condition_trace = trace;
  if (!trace.result) return entry;
  entry.matched = true;
  let outcome: string = definition.outcome;
  let alert = definition.alert;
  for (const exc of definition.exceptions) {
    const excTrace = evalGroup(exc.when, ctx);
    if (excTrace.result) {
      entry.exception = { id: exc.id, description: exc.description, trace: excTrace };
      outcome = exc.outcome;
      alert = alert && exc.keep_alert;
      break;
    }
  }
  entry.effective_outcome = outcome;
  entry.alert = alert;
  entry.escalate = definition.escalate && entry.exception === null;
  return entry;
}

export function decide(entries: Json[]): Json {
  const matched = entries.filter((e) => e.matched);
  if (!matched.length) return { outcome: "ALLOW", decisive_policy: null, decisive_version: null, reason: "No enabled policy matched" };
  const best = [...matched].sort((a, b) =>
    OUTCOME_RANK[b.effective_outcome] - OUTCOME_RANK[a.effective_outcome] || a.priority - b.priority || (a.policy_key < b.policy_key ? -1 : a.policy_key > b.policy_key ? 1 : 0))[0];
  let reason = `${best.policy_key} v${best.policy_version} (${best.name}) produced ${best.effective_outcome}`;
  if (best.exception) reason += ` via exception '${best.exception.id}'`;
  if (matched.length > 1) reason += `; ${matched.length} policies matched, most restrictive outcome wins`;
  return { outcome: best.effective_outcome, decisive_policy: best.policy_key, decisive_version: best.policy_version, reason };
}

/** Deterministic plain-language explanation of one policy trace entry (no AI involved). */
export function explainEntry(entry: Json): string {
  if (entry.skipped_reason) return `${entry.policy_key} was not evaluated: ${entry.skipped_reason}.`;
  const lines: string[] = [];
  const walk = (node: Json) => {
    if ("group" in node) {
      for (const ch of node.children) walk(ch);
      return;
    }
    const actual = node.missing ? "missing" : pyRepr(node.actual);
    const val = node.value === null || node.value === undefined ? "" : ` ${pyRepr(node.value)}`;
    lines.push(`${node.field} ${node.op}${val} — actual ${actual} → ${node.result ? "met" : "NOT met"}`);
  };
  walk(entry.condition_trace ?? { group: "all", children: [] });
  let head = entry.matched ? `${entry.policy_key} matched; effective outcome ${entry.effective_outcome}.` : `${entry.policy_key} did not match.`;
  if (entry.exception) head += ` Exception '${entry.exception.id}' applied: ${entry.exception.description}.`;
  return head + " " + lines.join("; ");
}

/** Structural diff between two policy definitions (JSON-like). */
export function diffDefinitions(before: unknown, after: unknown, path = ""): Json[] {
  const changes: Json[] = [];
  const isObj = (x: unknown): x is Json => x !== null && typeof x === "object" && !Array.isArray(x);
  if (isObj(before) && isObj(after)) {
    for (const k of [...new Set([...Object.keys(before), ...Object.keys(after)])].sort()) {
      const p = path ? `${path}.${k}` : k;
      if (!(k in before)) changes.push({ path: p, change: "added", before: null, after: after[k] });
      else if (!(k in after)) changes.push({ path: p, change: "removed", before: before[k], after: null });
      else changes.push(...diffDefinitions(before[k], after[k], p));
    }
  } else if (Array.isArray(before) && Array.isArray(after)) {
    for (let i = 0; i < Math.max(before.length, after.length); i++) {
      const p = `${path}[${i}]`;
      if (i >= before.length) changes.push({ path: p, change: "added", before: null, after: after[i] });
      else if (i >= after.length) changes.push({ path: p, change: "removed", before: before[i], after: null });
      else changes.push(...diffDefinitions(before[i], after[i], p));
    }
  } else if (JSON.stringify(before) !== JSON.stringify(after)) {
    changes.push({ path, change: "changed", before, after });
  }
  return changes;
}
