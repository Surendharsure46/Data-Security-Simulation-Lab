/**
 * DLP / detection policy language.
 *
 * A policy is a validated structured document. Conditions are {field, op, value} triples combined in
 * all/any groups (max depth 3). No code is ever executed from a policy definition. The evaluator lives
 * in the API (domain/policy-engine.ts); this schema is shared with the web policy editor.
 */
import { z } from "zod";

export const POLICY_FIELDS: Record<string, string> = {
  "action.type": "Activity type, e.g. DOWNLOAD, EXPORT, EMAIL, UPLOAD, COPY_TO_USB, AI_PROMPT",
  "actor.id": "Synthetic identity key",
  "actor.department": "Department of the acting identity",
  "actor.role": "Enterprise role of the acting identity",
  "actor.employment_type": "EMPLOYEE, CONTRACTOR, SERVICE or TEST",
  "actor.groups": "List of group keys the actor belongs to",
  "content.label": "Current classification label key of the resource (null if unlabeled)",
  "content.label_rank": "Numeric rank of the label (higher = more sensitive)",
  "content.detected_types": "Sensitive-data detector keys found by content inspection",
  "content.max_confidence": "Highest detector confidence (LOW/MEDIUM/HIGH)",
  "content.match_count": "Total detector matches in inspected content",
  "content.record_count": "Number of records involved in the activity",
  "resource.id": "Asset key",
  "resource.system": "Hosting system of the asset",
  "resource.department": "Owning department of the asset",
  "resource.owner_assigned": "Whether the asset has a data owner",
  "destination.id": "Destination key",
  "destination.kind": "EMAIL, CLOUD_STORAGE, REMOVABLE_MEDIA, SFTP, AI_SERVICE, INTERNAL",
  "destination.category": "INTERNAL, SANCTIONED_PARTNER, PERSONAL, UNSANCTIONED",
  "destination.sanctioned": "Destination is approved by the organisation",
  "destination.internal": "Destination is inside the organisation",
  "destination.domain": "Destination domain",
  "context.business_justification": "Free-text justification supplied with the activity",
  "context.ticket_id": "Change/support ticket reference supplied with the activity",
  "context.after_hours": "Activity occurred outside 07:00-19:00 UTC",
  "context.device_managed": "Activity came from a managed device",
};

export const OPERATORS = [
  "eq", "neq", "in", "not_in", "contains_any", "contains_all", "contains_none",
  "gt", "gte", "lt", "lte", "exists", "not_exists", "label_at_least", "label_below",
] as const;
export const OUTCOMES = ["ALLOW", "MONITOR", "WARN", "BLOCK"] as const;
export const SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;

export type Operator = (typeof OPERATORS)[number];
export type Outcome = (typeof OUTCOMES)[number];
export type Severity = (typeof SEVERITIES)[number];

export interface Condition {
  field: string;
  op: Operator;
  value: unknown;
}
export interface ConditionGroup {
  match: "all" | "any";
  conditions: (Condition | ConditionGroup)[];
}

const LIST_OPS = new Set(["in", "not_in", "contains_any", "contains_all", "contains_none"]);
const NUM_OPS = new Set(["gt", "gte", "lt", "lte"]);
const LABEL_OPS = new Set(["label_at_least", "label_below"]);

export const ConditionSchema = z
  .strictObject({
    field: z.string().refine((v) => v in POLICY_FIELDS, {
      error: (iss) => `Unknown field '${String(iss.input)}'. Allowed: ${Object.keys(POLICY_FIELDS).sort().join(", ")}`,
    }),
    op: z.enum(OPERATORS),
    value: z.unknown().optional(),
  })
  .superRefine((c, ctx) => {
    const v = c.value;
    if (LIST_OPS.has(c.op)) {
      if (!Array.isArray(v) || v.length === 0) ctx.addIssue({ code: "custom", message: `Operator '${c.op}' requires a non-empty list value` });
    } else if (NUM_OPS.has(c.op)) {
      if (typeof v !== "number" || !Number.isFinite(v)) ctx.addIssue({ code: "custom", message: `Operator '${c.op}' requires a numeric value` });
    } else if (LABEL_OPS.has(c.op)) {
      if (typeof v !== "string" || !v) ctx.addIssue({ code: "custom", message: `Operator '${c.op}' requires a label key` });
    } else if (c.op !== "exists" && c.op !== "not_exists" && (v === undefined || v === null)) {
      ctx.addIssue({ code: "custom", message: `Operator '${c.op}' requires a value` });
    }
  })
  .transform((c): Condition => ({ field: c.field, op: c.op, value: c.op === "exists" || c.op === "not_exists" ? null : (c.value ?? null) }));

function depth(g: ConditionGroup): number {
  const sub = g.conditions.filter((c): c is ConditionGroup => "conditions" in c).map(depth);
  return 1 + (sub.length ? Math.max(...sub) : 0);
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- recursive schema: input type differs from output (defaults)
const RawGroup: z.ZodType<ConditionGroup, any> = z.lazy(() =>
  z.strictObject({
    match: z.enum(["all", "any"]).default("all"),
    conditions: z.array(GroupItem).min(1).max(25),
  }),
);

// A list item is a nested group when it has "conditions", otherwise a condition. Routing explicitly (instead of
// z.union) keeps the precise validation message, e.g. "Unknown field 'x'", for the policy editor.
const GroupItem: z.ZodType<Condition | ConditionGroup, any> = z.unknown().transform((v, ctx) => {
  const schema = v !== null && typeof v === "object" && "conditions" in v ? RawGroup : ConditionSchema;
  const r = schema.safeParse(v);
  if (r.success) return r.data;
  for (const iss of r.error.issues) ctx.addIssue({ code: "custom", message: iss.message, path: iss.path as PropertyKey[] });
  return z.NEVER;
});

export const ConditionGroupSchema = RawGroup.superRefine((g, ctx) => {
  if (depth(g) > 3) ctx.addIssue({ code: "custom", message: "Condition groups may be nested at most 3 levels deep" });
});

export const PolicyExceptionSchema = z.strictObject({
  id: z.string().min(1).max(40),
  description: z.string().min(3).max(500),
  when: ConditionGroupSchema,
  outcome: z.enum(["ALLOW", "MONITOR"]).default("ALLOW"),
  keep_alert: z.boolean().default(false),
});

export const PolicyTestCaseSchema = z.strictObject({
  name: z.string().min(1).max(120),
  actor: z.string(),
  resource: z.string(),
  action: z.string(),
  destination: z.string().nullable().default(null),
  record_count: z.number().int().nullable().default(null),
  context: z.record(z.string(), z.unknown()).default({}),
  expected_outcome: z.enum(OUTCOMES),
});

export const PolicyDefinitionSchema = z
  .strictObject({
    name: z.string().min(3).max(120),
    description: z.string().max(2000).default(""),
    kind: z.enum(["DLP", "DETECTION"]).default("DLP"),
    priority: z.number().int().min(1).max(1000).default(100),
    applies_to_actions: z.array(z.string()).max(20).default([]),
    conditions: ConditionGroupSchema,
    outcome: z.enum(OUTCOMES),
    severity: z.enum(SEVERITIES).default("MEDIUM"),
    alert: z.boolean().default(true),
    escalate: z.boolean().default(false),
    alert_title: z.string().max(200).default(""),
    exceptions: z.array(PolicyExceptionSchema).max(20).default([]),
    test_cases: z.array(PolicyTestCaseSchema).max(50).default([]),
  })
  .superRefine((p, ctx) => {
    if (p.kind === "DETECTION" && p.outcome !== "MONITOR") {
      ctx.addIssue({ code: "custom", message: "DETECTION policies must use outcome MONITOR (detection does not enforce)" });
    }
    const ids = p.exceptions.map((e) => e.id);
    if (new Set(ids).size !== ids.length) ctx.addIssue({ code: "custom", message: "Exception ids must be unique within a policy" });
  });

export type PolicyDefinition = z.output<typeof PolicyDefinitionSchema>;
export type PolicyException = z.output<typeof PolicyExceptionSchema>;
export type PolicyTestCase = z.output<typeof PolicyTestCaseSchema>;
