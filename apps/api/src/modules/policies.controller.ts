/** DLP Policy Studio and Data Security Engineering endpoints. */
import { Controller, Get, Param, Put } from "@nestjs/common";
import {
  ChangeRecordIn, OPERATORS, OUTCOMES, POLICY_FIELDS, PolicyDefinitionSchema, PolicyIn, PolicyStatusIn, PolicyTestIn, PolicyUpdateIn, RollbackIn,
  SEVERITIES,
} from "@threatready/contracts";
import { and, asc, desc, eq } from "drizzle-orm";
import { z } from "zod";
import { DomainError, iso } from "../common/util.js";
import { type Principal, uow } from "../db/context.js";
import { change_records, policies, policy_evaluations, policy_test_runs } from "../db/schema.js";
import { parsePolicy } from "../domain/policy-engine.js";
import * as svc from "../domain/policies.js";
import { loadSession } from "../domain/session-lifecycle.js";
import { definitionFor, policyVersions } from "../domain/simulation.js";
import { CurrentPrincipal, IdParam, Permission, PERMISSIONS, PostCreated, PostOk, ZBody, ZQuery } from "../platform/http.js";

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
const read = (id: number, p: Principal) => loadSession(id, p, { write: false });
const write = (id: number, p: Principal) => loadSession(id, p, { write: true });

const DiffQuery = z.object({ a: z.coerce.number().int(), b: z.coerce.number().int() });

let languageSchema: unknown;
function policyJsonSchema(): unknown {
  languageSchema ??= z.toJSONSchema(PolicyDefinitionSchema, { io: "input", unrepresentable: "any" });
  return languageSchema;
}

@Controller("api/sessions/:sessionId/policies")
@Permission(PERMISSIONS.SELF)
export class PoliciesController {
  @Get("language")
  async language(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal) {
    await read(id, p);
    return {
      fields: POLICY_FIELDS, operators: OPERATORS, outcomes: OUTCOMES, severities: SEVERITIES,
      actions: ["DOWNLOAD", "EXPORT", "EMAIL", "UPLOAD", "COPY_TO_USB", "AI_PROMPT", "PRINT"],
      precedence: [
        "Disabled policies are skipped.",
        "A policy matches when its action scope and condition group are true; missing fields make a condition false.",
        "The first matching exception replaces the outcome with ALLOW or MONITOR and suppresses the alert unless keep_alert is set.",
        "The final DLP decision is the most restrictive outcome: BLOCK > WARN > MONITOR > ALLOW; ties break on priority then key.",
        "Detection policies only MONITOR and raise alerts; they never enforce.",
        "If nothing matches the activity is allowed.",
      ],
      schema: policyJsonSchema(),
    };
  }

  @Get()
  async list(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal) {
    const s = await read(id, p);
    const out: Json[] = [];
    for (const pol of await uow().all(policies, eq(policies.session_id, s.id), [asc(policies.key)])) out.push(await svc.serializePolicy(pol));
    return out;
  }

  @PostCreated()
  async create(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal, @ZBody(PolicyIn) body: z.infer<typeof PolicyIn>) {
    const s = await write(id, p);
    return svc.serializePolicy(await svc.createPolicy(s, p.email, body.key, body.definition, body.change_note));
  }

  // Static paths are declared before ":key" so they are not captured as a policy key.
  @PostOk("test")
  async test(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal, @ZBody(PolicyTestIn) body: z.infer<typeof PolicyTestIn>) {
    const s = await write(id, p);
    const ctx = Object.fromEntries(Object.entries(body.context).filter(([k]) => ["business_justification", "ticket_id", "device_managed"].includes(k)));
    return svc.dryRun(s, { actor: body.actor, action: body.action, resource: body.resource, destination: body.destination ?? null,
      record_count: body.record_count ?? null, hour: body.hour, context: ctx }, body.draft ?? null);
  }

  @Get(":key")
  async get(@IdParam("sessionId") id: number, @Param("key") key: string, @CurrentPrincipal() p: Principal) {
    const s = await read(id, p);
    const pol = await svc.getPolicy(s, key);
    const out = await svc.serializePolicy(pol);
    out.version_definitions = Object.fromEntries((await policyVersions(pol.id)).map((v) => [v.version, v.definition]));
    return out;
  }

  @Put(":key")
  async update(@IdParam("sessionId") id: number, @Param("key") key: string, @CurrentPrincipal() p: Principal,
    @ZBody(PolicyUpdateIn) body: z.infer<typeof PolicyUpdateIn>) {
    const s = await write(id, p);
    const v = await svc.updatePolicy(s, p.email, key, body.definition, body.change_note);
    return { key, version: v.version, policy: await svc.serializePolicy(await svc.getPolicy(s, key)) };
  }

  @PostOk(":key/status")
  async status(@IdParam("sessionId") id: number, @Param("key") key: string, @CurrentPrincipal() p: Principal,
    @ZBody(PolicyStatusIn) body: z.infer<typeof PolicyStatusIn>) {
    const s = await write(id, p);
    return svc.serializePolicy(await svc.setStatus(s, key, body.status));
  }

  @PostOk(":key/rollback")
  async rollback(@IdParam("sessionId") id: number, @Param("key") key: string, @CurrentPrincipal() p: Principal,
    @ZBody(RollbackIn) body: z.infer<typeof RollbackIn>) {
    const s = await write(id, p);
    const v = await svc.rollback(s, p.email, key, body.to_version);
    return { key, version: v.version };
  }

  @Get(":key/diff")
  async diff(@IdParam("sessionId") id: number, @Param("key") key: string, @CurrentPrincipal() p: Principal,
    @ZQuery(DiffQuery) q: z.infer<typeof DiffQuery>) {
    const s = await read(id, p);
    return { key, from_version: q.a, to_version: q.b, changes: await svc.diff(s, key, q.a, q.b) };
  }

  /** Run the test cases embedded in a policy definition against the current policy set. */
  @PostOk(":key/test-cases/run")
  async runEmbedded(@IdParam("sessionId") id: number, @Param("key") key: string, @CurrentPrincipal() p: Principal) {
    const s = await write(id, p);
    const pol = await svc.getPolicy(s, key);
    const cur = (await policyVersions(pol.id)).find((v) => v.version === pol.current_version)!;
    const cases = parsePolicy(cur.definition).test_cases;
    if (!cases.length) throw new DomainError("This policy version has no embedded test cases", 404);
    const out: Json[] = [];
    for (const tc of cases) {
      const res = await svc.dryRun(s, { actor: tc.actor, action: tc.action, resource: tc.resource, destination: tc.destination,
        record_count: tc.record_count, context: tc.context });
      out.push({ name: tc.name, expected: tc.expected_outcome, actual: res.decision.outcome, passed: tc.expected_outcome === res.decision.outcome,
        reason: res.decision.reason });
    }
    return { policy: key, version: pol.current_version, results: out, passed: out.filter((r) => r.passed).length, total: out.length };
  }
}

function runOut(r: typeof policy_test_runs.$inferSelect): Json {
  return { id: r.id, run_number: r.run_number, policy_snapshot: r.policy_snapshot, results: r.results, metrics: r.metrics, created_at: iso(r.created_at) };
}

@Controller("api/sessions/:sessionId/engineering")
@Permission(PERMISSIONS.SELF)
export class EngineeringController {
  @Get("test-suite")
  async suite(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal) {
    const s = await read(id, p);
    return { cases: definitionFor(s).policy_test_suite,
      note: "Labelled synthetic dataset for policy engineering. 'should_prevent' is the expected enforcement outcome." };
  }

  @PostOk("test-suite/run")
  async suiteRun(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal) {
    return runOut(await svc.runTestSuite(await write(id, p)));
  }

  @Get("test-suite/runs")
  async suiteRuns(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal) {
    const s = await read(id, p);
    return (await uow().all(policy_test_runs, eq(policy_test_runs.session_id, s.id), [asc(policy_test_runs.run_number)])).map(runOut);
  }

  @Get("test-suite/compare")
  async compare(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal, @ZQuery(DiffQuery) q: z.infer<typeof DiffQuery>) {
    const s = await read(id, p);
    const u = uow();
    const ra = await u.one(policy_test_runs, and(eq(policy_test_runs.session_id, s.id), eq(policy_test_runs.run_number, q.a))!);
    const rb = await u.one(policy_test_runs, and(eq(policy_test_runs.session_id, s.id), eq(policy_test_runs.run_number, q.b))!);
    if (!ra || !rb) throw new DomainError("Run not found", 404);
    return svc.compareRuns(ra, rb);
  }

  @Get("dry-runs")
  async dryRuns(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal) {
    const s = await read(id, p);
    return (await uow().all(policy_evaluations, and(eq(policy_evaluations.session_id, s.id), eq(policy_evaluations.dry_run, true)),
      [desc(policy_evaluations.id)])).slice(0, 50)
      .map((e) => ({ id: e.id, context: e.context, outcome: e.final_outcome, decisive_policy: e.decisive_policy, trace: e.trace, created_at: iso(e.created_at) }));
  }

  @PostCreated("change-records")
  async createChange(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal, @ZBody(ChangeRecordIn) body: z.infer<typeof ChangeRecordIn>) {
    const s = await write(id, p);
    const cr = await svc.createChangeRecord(s, { ...body, test_run_id: body.test_run_id ?? null });
    return { id: cr.id };
  }

  @Get("change-records")
  async changes(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal) {
    const s = await read(id, p);
    return (await uow().all(change_records, eq(change_records.session_id, s.id), [asc(change_records.id)])).map((c) => ({ id: c.id,
      policy_key: c.policy_key, from_version: c.from_version, to_version: c.to_version, reason: c.reason, expected_impact: c.expected_impact,
      rollback_plan: c.rollback_plan, test_run_id: c.test_run_id, created_at: iso(c.created_at) }));
  }
}
