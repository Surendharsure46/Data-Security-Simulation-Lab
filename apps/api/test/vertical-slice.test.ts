/** End-to-end API test of the reference scenario (Section 10 of the specification). */
import { describe, expect, it } from "vitest";
import { BLOCK_POLICY, goodInvestigation, goodRemediation, prepareAndRunBaseline } from "./flow.js";
import { api, useApp } from "./helpers.js";

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

describe("reference scenario", () => {
  const t = useApp();

  it("passes the full scenario with evidence", async () => {
    const h = await t.register("learner1");
    const sid = await t.sessionA(h);
    const base = `/api/sessions/${sid}`;
    const run1 = await prepareAndRunBaseline(h, sid);
    expect(run1.run_number).toBe(1);
    expect(run1.alerts_generated).toBe(5); // S00, S03, S07, S08 (now labeled), S06

    // The labelled export now matches the monitor-only pilot policy: the upload is alerted but still ALLOWED.
    const ev: Json[] = await api(h, "GET", `${base}/events?actor=u-jokafor&run=1&source_type=PROXY`);
    expect(ev.length).toBeGreaterThan(0);
    expect(ev[0].result).toBe("ALLOWED");
    expect(ev[0].provenance).toBe("SIMULATED");

    const cid = await goodInvestigation(h, sid);
    await goodRemediation(h, sid, cid);

    // Validation replay: the clone of the original actor is stopped; legitimate business continues.
    const val: Json[] = await api(h, "GET", `${base}/events?run=2&actor=u-jokafor-val`);
    expect(val.some((e) => ["DENIED", "BLOCKED"].includes(e.result))).toBe(true);
    const payroll: Json[] = await api(h, "GET", `${base}/events?run=2&actor=u-dkowalski&source_type=EMAIL_GATEWAY`);
    expect(payroll[0].result).toBe("ALLOWED");
    expect((await api(h, "GET", `${base}/alerts?run=2`) as Json[]).filter((a) => a.actor_id === "u-dkowalski")).toEqual([]);

    const progress: Json[] = (await api(h, "GET", base)).progress;
    expect(progress.filter((x) => !x.done).map((x) => x.key)).toEqual([]);

    const attempt = await api(h, "POST", `${base}/submit`, { confirm: true });
    expect(attempt.passed, JSON.stringify(attempt.criteria)).toBe(true);
    expect(attempt.total_score).toBeGreaterThanOrEqual(90);
    expect(attempt.critical_failures).toEqual([]);
    expect(attempt.disclaimer.toLowerCase()).toContain("not a professional certification");

    const report: string = await api(h, "GET", `${base}/reports/case-report?format=md`);
    expect(report).toContain("Execution mode: SIMULATED");
    expect(report).toContain("u-jokafor");
    expect(report).toContain("CONFIRMED_EXFILTRATION");
    // Session is read-only after submission.
    expect((await h.post(`${base}/discovery/scan`)).status).toBe(409);
  });

  it("a policy change changes the outcome of the same action", async () => {
    const h = await t.register("learner1");
    const base = `/api/sessions/${await t.sessionA(h)}`;
    const spec = { actor: "u-jokafor", action: "UPLOAD", resource: "ast-cust-export-q1", destination: "dst-personal-cloud" };
    expect((await api(h, "POST", `${base}/activities`, spec)).outcome).toBe("ALLOWED");
    await api(h, "POST", `${base}/policies`, { key: "POL-DLP-BLOCK", definition: BLOCK_POLICY });
    const second = await api(h, "POST", `${base}/activities`, spec);
    expect(second.outcome).toBe("BLOCKED");
    expect(second.decision.decisive_policy).toBe("POL-DLP-BLOCK");
    expect(second.alerts[0].policy_id).toBe("POL-DLP-BLOCK");
    expect(second.events.map((e: Json) => e.event_id)).toContain(second.alerts[0].triggering_event_id);
  });

  it("destroying evidence is a critical failure", async () => {
    const h = await t.register("learner1");
    const sid = await t.sessionA(h);
    const base = `/api/sessions/${sid}`;
    await prepareAndRunBaseline(h, sid);
    const cid = await goodInvestigation(h, sid);
    const body = { action_type: "REIMAGE_DEVICE", target_key: "u-jokafor", justification: "Rebuild the device quickly", case_id: cid };
    expect((await h.post(`${base}/remediation`).send(body)).status).toBe(409); // destructive action requires explicit confirmation
    await api(h, "POST", `${base}/remediation`, { ...body, confirm_destructive: true });
    await goodRemediation(h, sid, cid);
    const attempt = await api(h, "POST", `${base}/submit`, { confirm: true });
    expect(attempt.passed).toBe(false);
    expect(attempt.critical_failures.map((c: Json) => c.key)).toContain("CF-EVIDENCE-DESTROYED");
  });

  it("skipping the validation replay is a critical failure", async () => {
    const h = await t.register("learner1");
    const sid = await t.sessionA(h);
    await prepareAndRunBaseline(h, sid);
    const attempt = await api(h, "POST", `/api/sessions/${sid}/submit`, { confirm: true });
    expect(attempt.passed).toBe(false);
    expect(attempt.critical_failures.map((c: Json) => c.key)).toContain("CF-NOT-VERIFIED");
    expect(attempt.missing_tasks.length).toBeGreaterThan(0);
    expect(attempt.recommendations.length).toBeGreaterThan(0);
  });
});
