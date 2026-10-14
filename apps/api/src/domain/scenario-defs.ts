/**
 * Scenario definition schema, validation and loading.
 *
 * Scenario definitions are JSON documents in content/scenarios. They are validated with Zod and cross-checked
 * against the environment template before the application serves them. Definitions contain no executable code:
 * task checks, rubric checks and critical conditions refer to a fixed server-side registry.
 *
 * `publicView` is the only representation sent to learners. It omits the timeline, variant parameters, the policy
 * test-suite expectations and ground truth.
 */
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { environmentTemplate } from "../content/company.js";

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

export const SCENARIO_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "content", "scenarios");
export const ACTIONS = new Set(["SIGN_IN", "DOWNLOAD", "EXPORT", "EMAIL", "UPLOAD", "COPY_TO_USB", "AI_PROMPT", "PRINT"]);
export const TRANSFER_ACTIONS = new Set(["EMAIL", "UPLOAD", "COPY_TO_USB", "AI_PROMPT", "PRINT", "EXPORT"]);

export const TASK_CHECKS = new Set([
  "scan_count_at_least", "assets_viewed", "asset_labeled_with_owner", "grants_reviewed", "learner_policy_versions_at_least",
  "dry_runs_with_distinct_outcomes", "run_count_at_least", "run_alerts_dispositioned", "case_evidence_at_least", "case_note_kinds",
  "case_scope_recorded", "remediation_category_applied", "control_fix_after_run", "validation_run_after_last_fix", "case_report_fields",
]);
export const RUBRIC_CHECKS = new Set([
  "label_matches", "grants_revoked", "alert_dispositions", "case_determination", "case_severity", "case_evidence_coverage",
  "case_notes_quality", "case_scope", "validation_exfil_prevented", "validation_legitimate_allowed", "dlp_blocks_canonical_exfil",
  "subject_contained", "escalated_to", "report_completeness",
]);
export const CRITICAL_CHECKS = new Set(["evidence_destroyed", "exfil_not_verified_closed"]);

const Variant = z.strictObject({ key: z.string(), params: z.record(z.string(), z.string()) });
const TimelineStep = z.strictObject({
  key: z.string().regex(/^S\d{2}$/),
  at: z.string().regex(/^\d{2}:\d{2}$/),
  actor: z.string(),
  action: z.string(),
  resource: z.string().nullable().default(null),
  destination: z.string().nullable().default(null),
  record_count: z.number().int().min(0).nullable().default(null),
  context: z.record(z.string(), z.unknown()).default({}),
});
const TaskCheck = z.strictObject({
  type: z.string().refine((t) => TASK_CHECKS.has(t), { error: (i) => `Unknown task check '${String(i.input)}'` }),
  params: z.record(z.string(), z.any()).default({}),
});
const Task = z.strictObject({
  key: z.string(),
  stage: z.string(),
  phase: z.enum(["UNDERSTAND", "INSPECT", "ACT", "OBSERVE", "VALIDATE", "SUBMIT"]).default("ACT"),
  title: z.string(),
  description: z.string(),
  check: TaskCheck,
});
const RemediationType = z.strictObject({
  type: z.string(),
  category: z.enum(["PRESERVATION", "CONTAINMENT", "ERADICATION", "RECOVERY", "ESCALATION"]),
  target_type: z.enum(["IDENTITY", "DESTINATION", "ASSET", "GRANT", "PARTY"]),
  title: z.string(),
  description: z.string(),
  destructive: z.boolean().default(false),
});
const TestSuiteCase = z.strictObject({
  id: z.string(), description: z.string(), actor: z.string(), resource: z.string(), action: z.string(),
  destination: z.string().nullable().default(null), record_count: z.number().int().nullable().default(null),
  context: z.record(z.string(), z.unknown()).default({}), should_prevent: z.boolean(),
});
const Category = z.strictObject({ name: z.string(), weight: z.number().positive() });
const Criterion = z.strictObject({
  key: z.string(), category: z.string(), points: z.number().positive(), check: z.string(),
  params: z.record(z.string(), z.any()).default({}), description: z.string(), lessons: z.array(z.string()).default([]),
});
const CriticalCondition = z.strictObject({ key: z.string(), check: z.string(), description: z.string() });
const Rubric = z.strictObject({
  version: z.string(),
  pass_threshold: z.number().min(0).max(100),
  categories: z.record(z.string(), Category),
  criteria: z.array(Criterion),
  critical_conditions: z.array(CriticalCondition).default([]),
}).superRefine((r, ctx) => {
  const total = Object.values(r.categories).reduce((s, c) => s + c.weight, 0);
  if (Math.abs(total - 100) > 1e-6) ctx.addIssue({ code: "custom", message: `Category weights must total 100 (got ${total})` });
  for (const c of r.criteria) {
    if (!(c.category in r.categories)) ctx.addIssue({ code: "custom", message: `Criterion ${c.key} references unknown category ${c.category}` });
    if (!RUBRIC_CHECKS.has(c.check)) ctx.addIssue({ code: "custom", message: `Criterion ${c.key} uses unknown check ${c.check}` });
  }
  for (const cc of r.critical_conditions) if (!CRITICAL_CHECKS.has(cc.check)) ctx.addIssue({ code: "custom", message: `Critical condition ${cc.key} uses unknown check ${cc.check}` });
  for (const cat of Object.keys(r.categories)) if (!r.criteria.some((c) => c.category === cat)) ctx.addIssue({ code: "custom", message: `Category ${cat} has no criteria` });
});

export const ScenarioDefinitionSchema = z.strictObject({
  id: z.string().regex(/^[a-z0-9-]+$/),
  version: z.string().regex(/^\d+\.\d+\.\d+$/),
  title: z.string(),
  summary: z.string(),
  briefing: z.string(),
  level: z.enum(["L0", "L1", "L2", "L3", "L4", "L5"]),
  difficulty: z.string(),
  modules: z.array(z.string()),
  estimated_minutes: z.number().int(),
  objectives: z.array(z.string()),
  prerequisites: z.array(z.string()).default([]),
  environment: z.record(z.string(), z.unknown()),
  sim_start: z.string(),
  variants: z.array(Variant).min(1),
  timeline: z.array(TimelineStep),
  tasks: z.array(Task),
  hints: z.record(z.string(), z.array(z.string())).default({}),
  remediation_catalog: z.array(RemediationType),
  policy_test_suite: z.array(TestSuiteCase).default([]),
  rubric: Rubric,
  ground_truth: z.record(z.string(), z.any()),
}).superRefine((d, ctx) => {
  const env = environmentTemplate();
  const set = (xs: Json[]) => new Set(xs.map((x) => x.key as string));
  const idents = set(env.identities), assets = set(env.assets), dests = set(env.destinations), labels = set(env.labels), grants = set(env.grants);
  const fail = (message: string) => ctx.addIssue({ code: "custom", message });
  const stepKeys = d.timeline.map((s) => s.key);
  if (new Set(stepKeys).size !== stepKeys.length) fail("Duplicate timeline step keys");
  for (const v of d.variants) {
    for (const value of Object.values(v.params)) {
      if ((value.startsWith("u-") || value.startsWith("svc-")) && !idents.has(value)) fail(`Variant ${v.key} references unknown identity ${value}`);
      if (value.startsWith("dst-") && !dests.has(value)) fail(`Variant ${v.key} references unknown destination ${value}`);
    }
    for (const step of d.timeline) {
      let r: Json;
      try { r = resolveStep(step as TimelineStepT, v.params); } catch (e) { fail((e as Error).message); continue; }
      if (!idents.has(r.actor)) fail(`Step ${step.key} actor ${r.actor} unknown`);
      if (!ACTIONS.has(r.action)) fail(`Step ${step.key} action ${r.action} unknown`);
      if (r.resource && !assets.has(r.resource)) fail(`Step ${step.key} resource ${r.resource} unknown`);
      if (r.destination && !dests.has(r.destination)) fail(`Step ${step.key} destination ${r.destination} unknown`);
    }
  }
  const taskKeys = new Set(d.tasks.map((t) => t.key));
  for (const k of Object.keys(d.hints)) if (!taskKeys.has(k)) fail(`Hints reference unknown task ${k}`);
  for (const c of d.policy_test_suite) {
    if (!idents.has(c.actor) || !assets.has(c.resource) || (c.destination && !dests.has(c.destination))) fail(`Test case ${c.id} references unknown entities`);
  }
  const gt = d.ground_truth;
  for (const [asset, accepted] of Object.entries((gt.labels ?? {}) as Record<string, string[]>)) {
    if (!assets.has(asset) || !accepted.every((l) => labels.has(l))) fail(`Ground-truth label entry for ${asset} invalid`);
  }
  for (const g of (gt.excessive_grants ?? []) as string[]) if (!grants.has(g)) fail(`Ground-truth grant ${g} unknown`);
  for (const group of Object.values((gt.alert_groups ?? {}) as Record<string, { steps: string[] }>)) {
    for (const s of group.steps) if (!stepKeys.includes(s)) fail(`Ground-truth step ${s} unknown`);
  }
});

export type ScenarioDefinition = z.output<typeof ScenarioDefinitionSchema>;
export type TimelineStepT = z.output<typeof TimelineStep>;

const VAR = /^\$([a-z_]+)$/;

function sub(value: string | null, params: Record<string, string>): string | null {
  if (typeof value === "string") {
    const m = VAR.exec(value);
    if (m) {
      if (!(m[1] in params)) throw new Error(`Unbound scenario variable ${value}`);
      return params[m[1]];
    }
  }
  return value;
}

export function resolveStep(step: TimelineStepT, params: Record<string, string>): Json {
  return {
    key: step.key, at: step.at, actor: sub(step.actor, params), action: sub(step.action, params),
    resource: sub(step.resource, params), destination: sub(step.destination, params), record_count: step.record_count,
    context: { ...step.context },
  };
}

export function loadDefinition(path: string): ScenarioDefinition {
  return ScenarioDefinitionSchema.parse(JSON.parse(readFileSync(path, "utf8")));
}

let cache: Map<string, ScenarioDefinition> | null = null;

export function allDefinitions(): Map<string, ScenarioDefinition> {
  if (!cache) {
    cache = new Map();
    for (const f of readdirSync(SCENARIO_DIR).filter((x) => x.endsWith(".json")).sort()) {
      const d = loadDefinition(join(SCENARIO_DIR, f));
      cache.set(d.id, d);
    }
  }
  return cache;
}

export function getDefinition(id: string): ScenarioDefinition | undefined {
  return allDefinitions().get(id);
}

/** Learner-safe representation. Never includes timeline, variants, ground truth or expectations. */
export function publicView(d: ScenarioDefinition): Json {
  return {
    id: d.id, version: d.version, title: d.title, summary: d.summary, briefing: d.briefing, level: d.level, difficulty: d.difficulty,
    modules: d.modules, estimated_minutes: d.estimated_minutes, objectives: d.objectives, prerequisites: d.prerequisites,
    variant_count: d.variants.length,
    tasks: d.tasks.map((t) => ({ key: t.key, stage: t.stage, phase: t.phase, title: t.title, description: t.description })),
    hint_counts: Object.fromEntries(Object.entries(d.hints).map(([k, v]) => [k, v.length])),
    remediation_catalog: d.remediation_catalog,
    policy_test_suite_size: d.policy_test_suite.length,
    rubric: {
      version: d.rubric.version, pass_threshold: d.rubric.pass_threshold, categories: d.rubric.categories,
      criteria: d.rubric.criteria.map((c) => ({ key: c.key, category: c.category, points: c.points, description: c.description })),
      critical_conditions: d.rubric.critical_conditions.map((c) => ({ key: c.key, description: c.description })),
    },
  };
}
