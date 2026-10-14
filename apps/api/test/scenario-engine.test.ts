/** Scenario lifecycle, reproducibility, correlation, remediation verification and engineering metrics. */
import { describe, expect, it } from "vitest";
import { runAsSystem, uow } from "../src/db/context.js";
import { scenario_sessions } from "../src/db/schema.js";
import { scoreSession } from "../src/domain/assessment.js";
import { BLOCK_POLICY, goodInvestigation, goodRemediation, prepareAndRunBaseline } from "./flow.js";
import { type Agent, api, useApp } from "./helpers.js";

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

async function outcomes(h: Agent, sid: number, run: number) {
  const evs: Json[] = await api(h, "GET", `/api/sessions/${sid}/events?run=${run}`);
  return evs.map((e) => [e.timestamp, e.actor_id, e.action, e.resource_id, e.source_type, e.result, e.policy_id]);
}

const criteria = (attempt: Json) => Object.fromEntries((attempt.criteria as Json[]).map((c) => [c.key, c]));

describe("scenario engine", () => {
  const t = useApp();

  it("replays reproducibly across sessions", async () => {
    const h = await t.register("learner1");
    const sids: number[] = [];
    for (let i = 0; i < 2; i++) {
      const sid = (await api(h, "POST", "/api/sessions", { scenario_id: "customer-data-export", variant: "A" })).id;
      await api(h, "POST", `/api/sessions/${sid}/timeline/run`, { mode: "standard" });
      sids.push(sid);
    }
    expect(await outcomes(h, sids[0], 1)).toEqual(await outcomes(h, sids[1], 1));
  });

  it("reset restores the initial state and keeps attempts", async () => {
    const h = await t.register("learner1");
    const sid = await t.sessionA(h);
    const base = `/api/sessions/${sid}`;
    expect(await outcomes(h, sid, 1)).toEqual([]);
    await api(h, "POST", `${base}/timeline/run`, { mode: "standard" });
    const first = await outcomes(h, sid, 1);
    await api(h, "POST", `${base}/submit`, { confirm: true });
    expect((await h.post(`${base}/reset`).send({ confirm: false })).status).toBe(409);
    const s = await api(h, "POST", `${base}/reset`, { confirm: true, new_variant: false });
    expect([s.attempt_number, s.status, s.run_count]).toEqual([2, "ACTIVE", 0]);
    expect(await api(h, "GET", `${base}/events`)).toEqual([]);
    expect((await api(h, "GET", `${base}/assets/ast-cust-export-q1`)).label_key).toBeNull();
    await api(h, "POST", `${base}/timeline/run`, { mode: "standard" });
    expect(await outcomes(h, sid, 1)).toEqual(first);
    expect(await api(h, "GET", `${base}/attempts`)).toHaveLength(1);
  });

  it("reset with a new variant changes the subject", async () => {
    const h = await t.register("learner1");
    const base = `/api/sessions/${await t.sessionA(h)}`;
    await api(h, "POST", `${base}/reset`, { confirm: true, new_variant: true });
    await api(h, "POST", `${base}/timeline/run`, { mode: "standard" });
    const actors = new Set((await api(h, "GET", `${base}/events?resource=ast-cust-export-q1`) as Json[]).map((e) => e.actor_id));
    expect(actors.has("u-rsilva")).toBe(true);
    expect(actors.has("u-jokafor")).toBe(false);
  });

  it("pause blocks changes until resume", async () => {
    const h = await t.register("learner1");
    const base = `/api/sessions/${await t.sessionA(h)}`;
    await api(h, "POST", `${base}/pause`);
    expect((await h.post(`${base}/discovery/scan`)).status).toBe(409);
    await api(h, "POST", `${base}/resume`);
    expect((await h.post(`${base}/discovery/scan`)).status).toBe(200);
  });

  it("alerts reference events and correlation is explained", async () => {
    const h = await t.register("learner1");
    const base = `/api/sessions/${await t.sessionA(h)}`;
    await api(h, "POST", `${base}/timeline/run`, { mode: "standard" });
    const alert = (await api(h, "GET", `${base}/alerts`) as Json[]).find((a) => a.actor_id === "u-jokafor")!;
    const detail = await api(h, "GET", `${base}/alerts/${alert.alert_id}`);
    expect(alert.event_ids).toContain(alert.triggering_event_id);
    expect([detail.policy_id, detail.policy_version]).toEqual(["POL-DET-BULK", 1]);
    const reasons = new Set((detail.correlated as Json[]).flatMap((c) => c.reasons));
    expect(reasons.has("Same actor") && reasons.has("Same resource")).toBe(true);
    // The later upload by the same actor of the same resource is correlated with an explicit reason.
    const upload = (detail.correlated as Json[]).filter((c) => c.event.action === "UPLOAD");
    expect(upload.length).toBeGreaterThan(0);
    expect(upload.every((c) => c.reasons.length)).toBe(true);
    // Unrelated activity (payroll email) is not correlated merely by time.
    expect((detail.correlated as Json[]).filter((c) => c.event.actor_id === "u-dkowalski")).toEqual([]);
  });

  it("events follow the common schema", async () => {
    const h = await t.register("learner1");
    const base = `/api/sessions/${await t.sessionA(h)}`;
    await api(h, "POST", `${base}/timeline/run`, { mode: "standard" });
    const required = ["event_id", "timestamp", "organization_id", "scenario_id", "scenario_session_id", "actor_id", "resource_id", "action", "result",
      "data_classification", "source_type", "source_system", "provenance", "policy_id", "policy_version", "destination", "related_event_ids",
      "evidence_refs", "extension"];
    for (const e of await api(h, "GET", `${base}/events`) as Json[]) {
      for (const k of required) expect(e, k).toHaveProperty(k);
      expect(e.provenance).toBe("SIMULATED");
      expect(e.source_system.startsWith("kr-sim-")).toBe(true);
      expect(e.timestamp.endsWith("Z")).toBe(true);
      expect(e).not.toHaveProperty("step_key");
    }
  });

  it("revoking sessions alone does not stop sign-in", async () => {
    const h = await t.register("learner1");
    const base = `/api/sessions/${await t.sessionA(h)}`;
    const r = await api(h, "POST", `${base}/remediation`, { action_type: "REVOKE_SESSIONS", target_key: "u-jokafor", justification: "Terminate active sessions" });
    expect(r.verification.caveat).toContain("still authenticate");
    expect((await api(h, "POST", `${base}/activities`, { actor: "u-jokafor", action: "SIGN_IN" })).outcome).toBe("SUCCESS");
    await api(h, "POST", `${base}/remediation`, { action_type: "DISABLE_ACCOUNT", target_key: "u-jokafor", justification: "Disable pending investigation" });
    expect((await api(h, "POST", `${base}/activities`, { actor: "u-jokafor", action: "SIGN_IN" })).outcome).toBe("DENIED");
  });

  it("blocking a destination disrupts legitimate use in the replay", async () => {
    const h = await t.register("learner1");
    const base = `/api/sessions/${await t.sessionA(h)}`;
    await api(h, "POST", `${base}/timeline/run`, { mode: "standard" });
    await api(h, "POST", `${base}/remediation`, { action_type: "BLOCK_DESTINATION", target_key: "dst-personal-cloud", justification: "Stop uploads to personal cloud" });
    await api(h, "POST", `${base}/timeline/run`, { mode: "validation" });
    const brochure: Json[] = await api(h, "GET", `${base}/events?run=2&actor=u-emorales`);
    expect(brochure.some((e) => e.result === "BLOCKED" && e.source_type === "PROXY")).toBe(true);
    const crit = criteria(await api(h, "POST", `${base}/submit`, { confirm: true }));
    expect(crit["RV-PATH-CLOSED"].earned).toBe(crit["RV-PATH-CLOSED"].points);
    expect(crit["RV-NO-DISRUPTION"].earned).toBeLessThan(crit["RV-NO-DISRUPTION"].points);
  });

  it("flags control changes made after the last replay", async () => {
    const h = await t.register("learner1");
    const sid = await t.sessionA(h);
    const base = `/api/sessions/${sid}`;
    await prepareAndRunBaseline(h, sid);
    await goodRemediation(h, sid, await goodInvestigation(h, sid));
    await api(h, "POST", `${base}/policies/POL-DLP-CUSTOMER/status`, { status: "DISABLED" });
    const progress = Object.fromEntries((await api(h, "GET", base)).progress.map((x: Json) => [x.key, x.done]));
    expect(progress.verify).toBe(false);
    const crit = criteria(await api(h, "POST", `${base}/submit`, { confirm: true }));
    expect(crit["RV-PATH-CLOSED"].earned).toBe(crit["RV-PATH-CLOSED"].points / 2);
    expect(crit["RV-DLP-DEPTH"].earned).toBe(0);
  });

  it("preventing exfiltration before the run changes the expected conclusions", async () => {
    const h = await t.register("learner1");
    const sid = await t.sessionA(h);
    const base = `/api/sessions/${sid}`;
    await api(h, "POST", `${base}/policies`, { key: "POL-DLP-CUSTOMER", definition: BLOCK_POLICY });
    await api(h, "POST", `${base}/classification/assign`, { asset_key: "ast-cust-export-q1", label_key: "restricted", justification: "Bulk customer PII with card numbers" });
    await api(h, "POST", `${base}/timeline/run`, { mode: "standard" });
    expect((await api(h, "GET", `${base}/events?run=1&actor=u-jokafor&source_type=PROXY`))[0].result).toBe("BLOCKED");
    expect(await goodInvestigation(h, sid)).toBeTruthy(); // claims CONFIRMED exfiltration, which the events contradict
    const crit = criteria(await api(h, "POST", `${base}/submit`, { confirm: true }));
    expect(crit["DA-DETERMINATION"].earned).toBeLessThan(crit["DA-DETERMINATION"].points);
    expect(crit["EQ-SCOPE"].earned).toBeLessThan(crit["EQ-SCOPE"].points);
  });

  it("scores identical state identically", async () => {
    const h = await t.register("learner1");
    const sid = await t.sessionA(h);
    await prepareAndRunBaseline(h, sid);
    await goodRemediation(h, sid, await goodInvestigation(h, sid));
    const [a, b] = await runAsSystem(async () => {
      const s = (await uow().get(scenario_sessions, sid))!;
      return [await scoreSession(s), await scoreSession(s)];
    });
    expect(a).toEqual(b);
  });

  it("passes the full flow on variant B", async () => {
    const h = await t.register("learner1");
    const sid = (await api(h, "POST", "/api/sessions", { scenario_id: "customer-data-export", variant: "B" })).id;
    await prepareAndRunBaseline(h, sid);
    const alerts: Json[] = await api(h, "GET", `/api/sessions/${sid}/alerts?run=1`);
    const policies = new Set(alerts.filter((a) => a.actor_id === "u-rsilva").map((a) => a.policy_id));
    expect(policies.has("POL-DET-BULK") && policies.has("POL-DLP-EMAIL")).toBe(true);
    const cid = await goodInvestigation(h, sid, "u-rsilva", "u-mchen", "EMAIL");
    await goodRemediation(h, sid, cid, "u-rsilva");
    const attempt = await api(h, "POST", `/api/sessions/${sid}/submit`, { confirm: true });
    expect(attempt.passed, JSON.stringify(attempt.criteria)).toBe(true);
    expect(attempt.critical_failures).toEqual([]);
  });

  it("measures the engineering test suite and detects regressions", async () => {
    const h = await t.register("learner1");
    const sid = await t.sessionA(h);
    const base = `/api/sessions/${sid}`;
    const r1 = await api(h, "POST", `${base}/engineering/test-suite/run`);
    expect(r1.metrics.tp).toBe(0);
    expect(r1.metrics.recall).toBe(0);
    expect(r1.metrics.scope_note).toContain("not an estimate of production");
    await api(h, "POST", `${base}/policies`, { key: "POL-DLP-CUSTOMER", definition: BLOCK_POLICY });
    const r2 = await api(h, "POST", `${base}/engineering/test-suite/run`);
    expect(r2.metrics.recall).toBeGreaterThanOrEqual(0.8);
    expect(r2.metrics.fp).toBe(0);
    const cmp = await api(h, "GET", `${base}/engineering/test-suite/compare?a=1&b=2`);
    expect(cmp.fixes).toBeGreaterThanOrEqual(5);
    expect(cmp.regressions).toBe(0);
    expect(cmp.policy_changes).toHaveProperty("POL-DLP-CUSTOMER");
    const cr = await api(h, "POST", `${base}/engineering/change-records`, { policy_key: "POL-DLP-CUSTOMER", from_version: 1, to_version: 1,
      reason: "Introduce enforcement for customer data", expected_impact: "Blocks personal-destination transfers", rollback_plan: "Disable policy",
      test_run_id: r2.id });
    expect(cr.id).toBeTruthy();
  });

  it("versions, diffs, rolls back and previews draft policies", async () => {
    const h = await t.register("learner1");
    const base = `/api/sessions/${await t.sessionA(h)}`;
    const d = (await api(h, "GET", `${base}/policies/POL-DLP-CLOUD`)).definition;
    d.outcome = "BLOCK";
    const spec = { actor: "u-jokafor", action: "UPLOAD", resource: "ast-product-brochure", destination: "dst-personal-cloud" };
    expect((await api(h, "POST", `${base}/policies/test`, { ...spec, draft: { key: "POL-DLP-CLOUD", definition: d } })).draft_included).toBe(true);
    await api(h, "PUT", `${base}/policies/POL-DLP-CLOUD`, { definition: d, change_note: "Move to enforcement" });
    const diff = await api(h, "GET", `${base}/policies/POL-DLP-CLOUD/diff?a=1&b=2`);
    expect((diff.changes as Json[]).some((c) => c.path === "outcome" && c.after === "BLOCK")).toBe(true);
    expect((await h.put(`${base}/policies/POL-DLP-CLOUD`).send({ definition: d, change_note: "no-op" })).status).toBe(409);
    await api(h, "POST", `${base}/policies/POL-DLP-CLOUD/rollback`, { to_version: 1 });
    const p = await api(h, "GET", `${base}/policies/POL-DLP-CLOUD`);
    expect(p.current_version).toBe(3);
    expect(p.definition.outcome).toBe("MONITOR");
  });

  it("produces every report type in every format", async () => {
    const h = await t.register("learner1");
    const sid = await t.sessionA(h);
    const base = `/api/sessions/${sid}`;
    await prepareAndRunBaseline(h, sid);
    await goodRemediation(h, sid, await goodInvestigation(h, sid));
    await api(h, "POST", `${base}/engineering/test-suite/run`);
    for (const type of await api(h, "GET", `${base}/reports`) as Json[]) {
      for (const fmt of type.formats) {
        const r = await h.get(`${base}/reports/${type.type}?format=${fmt}`);
        expect(r.status, `${type.type} ${fmt}: ${r.text}`).toBe(200);
        expect(r.text.trim().length).toBeGreaterThan(0);
      }
    }
    const md = (await h.get(`${base}/reports/case-report?format=md`)).text;
    for (let n = 1; n < 15; n++) expect(md).toContain(`## ${n}.`);
    const exported = await h.get(`${base}/export/events`);
    expect(exported.status).toBe(200);
    expect(exported.text.split("\n").length - 1).toBe((await api(h, "GET", `${base}/events`)).length);
  });
});
