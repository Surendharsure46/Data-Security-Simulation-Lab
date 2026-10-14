/**
 * Unit tests for the policy language and evaluator (exact/partial/no match, missing and malformed input, multiple matches,
 * exceptions, conflicts, disabled policies, versions and regressions).
 */
import { PolicyDefinitionSchema, type PolicyDefinition } from "@threatready/contracts";
import { describe, expect, it } from "vitest";
import { decide, diffDefinitions, evaluatePolicy, explainEntry } from "../src/domain/policy-engine.js";

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
const RANKS = { public: 0, internal: 1, confidential: 2, restricted: 3 };

function ctx(over: Json = {}): Json {
  const base: Json = {
    action: { type: "UPLOAD" },
    actor: { id: "u-x", department: "Support", employment_type: "CONTRACTOR", groups: ["grp-a"] },
    content: { label: "restricted", detected_types: ["CREDIT_CARD", "EMAIL_ADDRESS"], record_count: 50000 },
    destination: { id: "dst-personal-cloud", sanctioned: false, internal: false, category: "PERSONAL" },
    context: { ticket_id: null },
    _label_ranks: RANKS,
  };
  for (const [k, v] of Object.entries(over)) base[k] = v && typeof v === "object" && !Array.isArray(v) ? { ...(base[k] ?? {}), ...v } : v;
  return base;
}

const rawPol = (over: Json = {}): Json => ({
  name: "Block restricted to unsanctioned",
  kind: "DLP",
  applies_to_actions: ["UPLOAD", "EMAIL"],
  conditions: { match: "all", conditions: [
    { field: "destination.sanctioned", op: "eq", value: false },
    { field: "content.label", op: "label_at_least", value: "confidential" },
  ] },
  outcome: "BLOCK",
  severity: "HIGH",
  ...over,
});
const pol = (over: Json = {}): PolicyDefinition => PolicyDefinitionSchema.parse(rawPol(over));

describe("policy engine", () => {
  it("exact match blocks", () => {
    const e = evaluatePolicy("P1", 1, "ENABLED", pol(), ctx());
    expect(e.matched && e.effective_outcome === "BLOCK" && e.alert).toBe(true);
    expect(decide([e]).outcome).toBe("BLOCK");
  });

  it("partial match does not fire", () => {
    const e = evaluatePolicy("P1", 1, "ENABLED", pol(), ctx({ destination: { sanctioned: true } }));
    expect(e.matched).toBe(false);
    expect(e.condition_trace.children.map((c: Json) => c.result)).toEqual([false, true]);
  });

  it("no match defaults to allow", () => {
    const e = evaluatePolicy("P1", 1, "ENABLED", pol(), ctx({ content: { label: "public" } }));
    expect(decide([e])).toEqual({ outcome: "ALLOW", decisive_policy: null, decisive_version: null, reason: "No enabled policy matched" });
  });

  it("a missing field makes the condition false and is traced", () => {
    const c = ctx();
    c.content = { detected_types: [] }; // unlabeled asset
    const e = evaluatePolicy("P1", 1, "ENABLED", pol(), c);
    const label = e.condition_trace.children[1];
    expect(label.missing && !label.result && !e.matched).toBe(true);
  });

  it("not_exists matches a missing field", () => {
    const p = pol({ conditions: { match: "all", conditions: [{ field: "context.ticket_id", op: "not_exists" }] } });
    expect(evaluatePolicy("P", 1, "ENABLED", p, ctx()).matched).toBe(true);
  });

  it("skips out-of-scope actions", () => {
    const e = evaluatePolicy("P1", 1, "ENABLED", pol(), ctx({ action: { type: "DOWNLOAD" } }));
    expect(e.matched).toBe(false);
    expect(e.skipped_reason).toContain("Out of scope");
  });

  it.each([
    { conditions: { match: "all", conditions: [{ field: "nope.field", op: "eq", value: 1 }] } },
    { conditions: { match: "all", conditions: [{ field: "content.record_count", op: "gte", value: "many" }] } },
    { conditions: { match: "all", conditions: [{ field: "actor.id", op: "in", value: [] }] } },
    { conditions: { match: "all", conditions: [] } },
    { outcome: "DELETE_EVERYTHING" },
    { kind: "DETECTION", outcome: "BLOCK" },
    { unexpected: true },
    { conditions: { match: "all", conditions: [{ match: "any", conditions: [{ match: "all", conditions: [
      { match: "any", conditions: [{ field: "actor.id", op: "eq", value: "x" }] }] }] }] } },
  ])("rejects malformed definition %#", (bad) => {
    expect(PolicyDefinitionSchema.safeParse(rawPol(bad)).success).toBe(false);
  });

  it("a type mismatch is false, not a crash", () => {
    const p = pol({ conditions: { match: "all", conditions: [{ field: "actor.department", op: "gt", value: 3 }] } });
    const e = evaluatePolicy("P", 1, "ENABLED", p, ctx());
    expect(e.matched).toBe(false);
    expect(e.condition_trace.children[0].error).toContain("Type mismatch");
  });

  it("skips disabled policies", () => {
    const e = evaluatePolicy("P1", 1, "DISABLED", pol(), ctx());
    expect(e.matched).toBe(false);
    expect(e.skipped_reason).toBe("Policy disabled");
  });

  it("an exception overrides the outcome and suppresses the alert", () => {
    const p = pol({ exceptions: [{ id: "EX1", description: "Approved partner",
      when: { match: "all", conditions: [{ field: "actor.department", op: "eq", value: "Support" }] }, outcome: "MONITOR" }] });
    const e = evaluatePolicy("P1", 1, "ENABLED", p, ctx());
    expect(e.matched && e.effective_outcome === "MONITOR" && !e.alert && e.exception.id === "EX1").toBe(true);
    expect(explainEntry(e)).toContain("Exception 'EX1' applied");
  });

  it("the first matching exception wins", () => {
    const ex = (id: string, outcome: string) => ({ id, description: `exception ${id}`, outcome, keep_alert: true,
      when: { match: "all", conditions: [{ field: "actor.id", op: "eq", value: "u-x" }] } });
    const e = evaluatePolicy("P1", 1, "ENABLED", pol({ exceptions: [ex("A", "ALLOW"), ex("B", "MONITOR")] }), ctx());
    expect(e.exception.id).toBe("A");
    expect(e.effective_outcome).toBe("ALLOW");
    expect(e.alert).toBe(true);
  });

  it("the most restrictive outcome wins regardless of order", () => {
    const warn = evaluatePolicy("P-WARN", 1, "ENABLED", pol({ outcome: "WARN", priority: 1 }), ctx());
    const block = evaluatePolicy("P-BLOCK", 1, "ENABLED", pol({ outcome: "BLOCK", priority: 500 }), ctx());
    const monitor = evaluatePolicy("P-MON", 1, "ENABLED", pol({ outcome: "MONITOR" }), ctx());
    for (const order of [[warn, block, monitor], [monitor, warn, block], [block, monitor, warn]]) {
      const d = decide(order);
      expect(d.outcome).toBe("BLOCK");
      expect(d.decisive_policy).toBe("P-BLOCK");
      expect(d.reason).toContain("3 policies matched");
    }
  });

  it("ties break on priority then key", () => {
    const a = evaluatePolicy("P-B", 1, "ENABLED", pol({ priority: 50 }), ctx());
    const b = evaluatePolicy("P-A", 1, "ENABLED", pol({ priority: 50 }), ctx());
    const c = evaluatePolicy("P-C", 1, "ENABLED", pol({ priority: 10 }), ctx());
    expect(decide([a, b]).decisive_policy).toBe("P-A");
    expect(decide([a, b, c]).decisive_policy).toBe("P-C");
  });

  it("an explicit allow does not override a block", () => {
    const allow = evaluatePolicy("P-ALLOW", 1, "ENABLED", pol({ outcome: "ALLOW", priority: 1 }), ctx());
    const block = evaluatePolicy("P-BLOCK", 1, "ENABLED", pol({ outcome: "BLOCK" }), ctx());
    expect(decide([allow, block]).outcome).toBe("BLOCK");
  });

  it("supports contains operators and label_below", () => {
    const p = pol({ conditions: { match: "any", conditions: [
      { field: "content.detected_types", op: "contains_all", value: ["CREDIT_CARD", "EMAIL_ADDRESS"] },
      { field: "content.label", op: "label_below", value: "internal" }] } });
    expect(evaluatePolicy("P", 1, "ENABLED", p, ctx()).matched).toBe(true);
    const p2 = pol({ conditions: { match: "all", conditions: [{ field: "content.detected_types", op: "contains_none", value: ["CREDIT_CARD"] }] } });
    expect(evaluatePolicy("P", 1, "ENABLED", p2, ctx()).matched).toBe(false);
  });

  it("reports an unknown label in a condition", () => {
    const p = pol({ conditions: { match: "all", conditions: [{ field: "content.label", op: "label_at_least", value: "top-secret" }] } });
    const e = evaluatePolicy("P", 1, "ENABLED", p, ctx());
    expect(e.matched).toBe(false);
    expect(e.condition_trace.children[0].error).toContain("Unknown label");
  });

  it("diffs versions and shows the regression effect", () => {
    const v1 = JSON.parse(JSON.stringify(pol()));
    const v2 = JSON.parse(JSON.stringify(pol({ outcome: "MONITOR" })));
    expect(diffDefinitions(v1, v2)).toContainEqual({ path: "outcome", change: "changed", before: "BLOCK", after: "MONITOR" });
    expect(decide([evaluatePolicy("P", 1, "ENABLED", PolicyDefinitionSchema.parse(v1), ctx())]).outcome).toBe("BLOCK");
    expect(decide([evaluatePolicy("P", 2, "ENABLED", PolicyDefinitionSchema.parse(v2), ctx())]).outcome).toBe("MONITOR");
  });

  it("detection policies never enforce", () => {
    const det = PolicyDefinitionSchema.parse({ name: "Bulk", kind: "DETECTION",
      conditions: { match: "all", conditions: [{ field: "content.record_count", op: "gte", value: 10000 }] }, outcome: "MONITOR" });
    const e = evaluatePolicy("D", 1, "ENABLED", det, ctx());
    expect(e.matched).toBe(true);
    expect(e.effective_outcome).toBe("MONITOR");
  });

  it("compares strings case-insensitively", () => {
    const p = pol({ conditions: { match: "all", conditions: [{ field: "actor.department", op: "in", value: ["support"] }] } });
    expect(evaluatePolicy("P", 1, "ENABLED", p, ctx()).matched).toBe(true);
  });
});
