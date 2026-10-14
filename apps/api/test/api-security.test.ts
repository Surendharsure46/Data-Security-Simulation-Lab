/** Authentication, authorization, isolation, input validation, answer protection and HTTP hardening. */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { CONTROLLERS } from "../src/app.module.js";
import { resetConfig, setConfig } from "../src/config.js";
import { runInRequest, tx } from "../src/db/context.js";
import { scenario_sessions } from "../src/db/schema.js";
import { listRoutes } from "../src/platform/openapi.js";
import { type ConsoleMail, getPorts } from "../src/ports/index.js";
import { prepareAndRunBaseline } from "./flow.js";
import { api, PASSWORD, useApp } from "./helpers.js";

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

describe("authentication", () => {
  const t = useApp();

  it("requires a session", async () => {
    const a = t.agent();
    expect((await a.get("/api/sessions")).status).toBe(401);
    expect((await a.get("/api/sessions").set("Cookie", "threatready.session_token=forged.value")).status).toBe(401);
  });

  it("rejects weak passwords and invalid email addresses", async () => {
    const r = await t.agent().post("/api/auth/register").send({ email: "not an email", display_name: "X", password: "short" });
    expect(r.status).toBe(422);
    expect(r.body.detail).toBe("Invalid input");
    expect([...new Set(r.body.errors.map((e: Json) => e.field))].sort()).toEqual(["email", "password"]);
    const weak = await t.agent().post("/api/auth/register").send({ email: "w@example.com", display_name: "W", password: "alllowercase1" });
    expect(weak.status).toBe(422);
  });

  it("normalises email case and prevents duplicate accounts", async () => {
    const a = t.agent();
    const r = await a.post("/api/auth/register").send({ email: "Learner.Two+lab@Example.com", display_name: "L2", password: PASSWORD });
    expect(r.status).toBe(201);
    expect(r.body.user.email).toBe("learner.two+lab@example.com");
    expect(String(r.headers["set-cookie"])).toMatch(/HttpOnly/i);
    expect((await t.agent().post("/api/auth/login").send({ email: "LEARNER.two+lab@example.com", password: PASSWORD })).status).toBe(200);
    expect((await t.agent().post("/api/auth/register").send({ email: "learner.two+lab@example.com", display_name: "Dup", password: PASSWORD })).status).toBe(409);
  });

  it("logs in, logs out and revokes the session", async () => {
    await t.register("alice");
    expect((await t.agent().post("/api/auth/login").send({ email: "alice@example.com", password: "Wrong-Pass-123" })).status).toBe(401);
    const a = t.agent();
    expect((await a.post("/api/auth/login").send({ email: "ALICE@example.com", password: PASSWORD })).status).toBe(200);
    expect((await api(a, "GET", "/api/auth/me")).email).toBe("alice@example.com");
    expect((await a.post("/api/auth/logout")).status).toBe(200);
    expect((await a.get("/api/auth/me")).status).toBe(401);
  });

  it("rate-limits login attempts", async () => {
    await t.register("bob");
    setConfig({ loginRateLimitPerMinute: 3 });
    try {
      const codes: number[] = [];
      for (let i = 0; i < 5; i++) codes.push((await t.agent().post("/api/auth/login").send({ email: "bob@example.com", password: "nope" })).status);
      expect(codes.slice(0, 3)).toEqual([401, 401, 401]);
      expect(codes.slice(3)).toContain(429);
    } finally {
      resetConfig();
    }
  });

  it("closes Better Auth's own sign-up endpoint", async () => {
    const r = await t.agent().post("/api/identity/sign-up/email").send({ email: "x@example.com", password: PASSWORD, name: "X" });
    expect(r.status).toBe(404);
  });

  it("deactivated users lose access immediately", async () => {
    const admin = await t.staff("root", "admin");
    const h = await t.register("leaver");
    const users: Json[] = await api(admin, "GET", "/api/admin/users");
    const leaver = users.find((u) => u.email === "leaver@example.com")!;
    await api(admin, "PATCH", `/api/admin/users/${leaver.id}`, { is_active: false });
    expect((await h.get("/api/auth/me")).status).toBe(401);
    expect((await t.agent().post("/api/auth/login").send({ email: "leaver@example.com", password: PASSWORD })).status).toBe(401);
    const me = users.find((u) => u.email === "root@example.com")!;
    expect((await admin.patch(`/api/admin/users/${me.id}`).send({ role: "learner" })).status).toBe(409);
  });
});

describe("authorization", () => {
  const t = useApp();

  it("every route declares an access policy", () => {
    const routes = listRoutes(CONTROLLERS as never);
    expect(routes.length).toBeGreaterThan(100);
    const missing = routes.filter((r) => !r.isPublic && !r.permission).map((r) => `${r.method.toUpperCase()} ${r.path}`);
    expect(missing).toEqual([]);
    const publicRoutes = routes.filter((r) => r.isPublic).map((r) => `${r.method.toUpperCase()} ${r.path}`).sort();
    expect(publicRoutes).toEqual(["GET /api/auth/config", "GET /api/career/public", "GET /api/health", "POST /api/auth/login", "POST /api/auth/register"]);
  });

  // Request bodies are validated before the session is loaded, so a malformed body may answer 422 first; that reveals
  // nothing about the session. Nothing may succeed, and nothing may answer 403 (which would confirm the id exists).
  it("another learner gets 404 on every session route", async () => {
    const owner = await t.register("learner1");
    const sid = await t.sessionA(owner);
    await prepareAndRunBaseline(owner, sid);
    const other = await t.register("mallory");
    const routes = listRoutes(CONTROLLERS as never).filter((r) => r.path.startsWith("/api/sessions/:sessionId"));
    expect(routes.length).toBeGreaterThan(50);
    for (const r of routes) {
      const path = r.path.replace(":sessionId", String(sid)).replace(/:[A-Za-z]+/g, "1");
      const res = await other[r.method as "get"](path).send({});
      expect(r.body || r.query ? [404, 422] : [404], `${r.method.toUpperCase()} ${path} -> ${res.status} ${res.text}`).toContain(res.status);
    }
    const listed: Json[] = await api(other, "GET", "/api/sessions?all_users=true");
    expect(listed.map((s) => s.id)).not.toContain(sid);
  });

  it("staff can read but not modify learner sessions; admin routes need roles", async () => {
    const learner = await t.register("learner1");
    const sid = await t.sessionA(learner);
    const staff = await t.staff("coach", "instructor");
    expect((await staff.get(`/api/sessions/${sid}`)).status).toBe(200);
    expect((await staff.post(`/api/sessions/${sid}/discovery/scan`)).status).toBe(403);
    expect((await staff.get("/api/admin/users")).status).toBe(200);
    expect((await staff.put("/api/admin/integrations/siem-export").send({ enabled: false })).status).toBe(403);
    expect((await learner.get("/api/admin/users")).status).toBe(403);
    expect((await learner.get("/api/admin/audit")).status).toBe(403);
    const audit: Json[] = await api(staff, "GET", "/api/admin/audit");
    expect(audit.some((r) => r.action === "session.start")).toBe(true);
  });

  it("row-level security hides other users' rows even without a WHERE clause", async () => {
    const a = await t.register("learner1");
    await t.sessionA(a);
    const b = await t.register("learner2");
    const bMe = await api(b, "GET", "/api/auth/me");
    const rows = await runInRequest({ userId: bMe.id, sessionId: "x", orgId: bMe.org_id, role: "learner", staff: false, email: bMe.email,
      displayName: "b", mfaVerified: false }, () => tx().select().from(scenario_sessions));
    expect(rows).toEqual([]);
  });
});

describe("answer protection and validation", () => {
  const t = useApp();

  it("never exposes hidden answers through the API", async () => {
    const h = await t.register("learner1");
    const sid = await t.sessionA(h);
    const base = `/api/sessions/${sid}`;
    await prepareAndRunBaseline(h, sid);
    const blobs: string[] = [];
    for (const p of ["/api/scenarios", "/api/scenarios/customer-data-export", base, `${base}/events`, `${base}/alerts`, `${base}/actions`,
      `${base}/reports/remediation-verification?format=json`, `${base}/reports/assessment?format=json`]) blobs.push((await h.get(p)).text);
    const text = blobs.join("\n");
    for (const secret of ["ground_truth", "step_key", "culprit", "malicious_steps", "alert_groups", "exfil_step", '"S08"', "excessive_grants",
      "exfil_destination", "ambiguous_actor"]) expect(text, secret).not.toContain(secret);
    expect(JSON.stringify((await h.get(`${base}/reports/assessment?format=json`)).body)).toContain("Not yet submitted");
  });

  it("assessment mode disables hints and randomises the variant", async () => {
    const h = await t.register("learner1");
    const r = await h.post("/api/sessions").send({ scenario_id: "customer-data-export", mode: "ASSESSMENT", variant: "A" });
    expect((await h.post(`/api/sessions/${r.body.id}/hints/classify`)).status).toBe(403);
    expect(r.body).not.toHaveProperty("variant");
  });

  it("hints are progressive in guided mode", async () => {
    const h = await t.register("learner1");
    const base = `/api/sessions/${await t.sessionA(h)}`;
    const a = await api(h, "POST", `${base}/hints/classify`);
    const b = await api(h, "POST", `${base}/hints/classify`);
    const c = await api(h, "POST", `${base}/hints/classify`);
    expect([a.hints.length, b.hints.length, c.remaining, c.hints.length]).toEqual([1, 2, 0, 2]);
    expect((await h.post(`${base}/hints/constructor`)).status).toBe(404);
  });

  it("validates input and maps domain errors", async () => {
    const h = await t.register("learner1");
    const base = `/api/sessions/${await t.sessionA(h)}`;
    let r = await h.post(`${base}/classification/assign`).send({ asset_key: "ast-cust-export-q1", label_key: "top-secret", justification: "this is long enough" });
    expect(r.status).toBe(400);
    expect(r.body.detail).toContain("Unknown label");
    r = await h.post(`${base}/classification/assign`).send({ asset_key: "ast-cust-export-q1", label_key: "constructor", justification: "this is long enough" });
    expect(r.status).toBe(400);
    r = await h.post(`${base}/classification/assign`).send({ asset_key: "ast-cust-export-q1", label_key: "restricted", justification: "x", owner_key: "svc-crm-sync" });
    expect(r.status).toBe(422);
    r = await h.post(`${base}/classification/assign`).send({ asset_key: "ast-cust-export-q1", label_key: "restricted",
      justification: "service accounts cannot own data", owner_key: "svc-crm-sync" });
    expect(r.status).toBe(400);
    expect((await h.post(`${base}/policies`).send({ key: "POL-BAD", definition: { name: "bad", conditions: {}, outcome: "BLOCK" } })).status).toBe(422);
    expect((await h.post(`${base}/timeline/run`).send({ mode: "validation" })).status).toBe(409);
    expect((await h.post(`${base}/cases/1/notes`).send({ kind: "OBSERVATION", text: "no case" })).status).toBe(404);
    expect((await h.post(`${base}/remediation`).send({ action_type: "DELETE_TENANT", target_key: "x", justification: "not permitted at all" })).status).toBe(400);
    expect((await h.get("/api/sessions/abc")).status).toBe(422);
    expect((await h.post(`${base}/discovery/scan`).set("Content-Type", "application/json").send("{bad json")).status).toBe(400);
  });

  it("observations must cite evidence and evidence must exist", async () => {
    const h = await t.register("learner1");
    const base = `/api/sessions/${await t.sessionA(h)}`;
    const cid = (await api(h, "POST", `${base}/cases`, { title: "Test case" })).id;
    expect((await h.post(`${base}/cases/${cid}/notes`).send({ kind: "OBSERVATION", text: "Unsupported claim" })).status).toBe(400);
    expect((await h.post(`${base}/cases/${cid}/evidence`).send({ ref_type: "EVENT", ref_id: "evt-999-99999" })).status).toBe(404);
  });
});

describe("HTTP hardening", () => {
  const t = useApp();

  it("sets security headers", async () => {
    const r = await t.agent().get("/api/health");
    expect(r.status).toBe(200);
    expect(r.headers["x-content-type-options"]).toBe("nosniff");
    expect(r.headers["x-frame-options"]).toBe("DENY");
    expect(r.headers["content-security-policy"]).toContain("default-src 'none'");
    expect(r.headers["cache-control"]).toBe("no-store");
    expect(r.headers["x-powered-by"]).toBeUndefined();
  });

  it("refuses cross-origin state-changing requests", async () => {
    const h = await t.register("learner1");
    const r = await h.post("/api/sessions").set("Origin", "https://evil.example").send({ scenario_id: "customer-data-export" });
    expect(r.status).toBe(403);
    const ok = await h.post("/api/sessions").set("Origin", "http://localhost:5173").send({ scenario_id: "customer-data-export" });
    expect(ok.status).toBe(201);
  });

  it("returns the uniform error shape for unknown routes", async () => {
    const r = await t.agent().get("/api/does-not-exist");
    expect(r.status).toBe(404);
    expect(r.body).toEqual({ detail: "Not Found" });
  });

  it("neutralises spreadsheet formula injection in CSV exports", async () => {
    const h = await t.register("learner1");
    const base = `/api/sessions/${await t.sessionA(h)}`;
    await api(h, "POST", `${base}/classification/assign`, { asset_key: "ast-pricing-model", label_key: "confidential", justification: '=HYPERLINK("http://evil.example")' });
    const csv = (await h.get(`${base}/reports/classification-register?format=csv`)).text;
    expect(csv.replace(/'=HYPERLINK/g, "")).not.toContain("=HYPERLINK");
  });

  it("escapes learner content in HTML reports", async () => {
    const h = await t.register("learner1");
    const base = `/api/sessions/${await t.sessionA(h)}`;
    const cid = (await api(h, "POST", `${base}/cases`, { title: "XSS check" })).id;
    await api(h, "PATCH", `${base}/cases/${cid}`, { summary: "<script>alert(1)</script>" });
    const r = await h.get(`${base}/reports/case-report?format=html`);
    expect(r.text).not.toContain("<script>alert(1)</script>");
    expect(r.text).toContain("&lt;script&gt;");
    expect(r.headers["content-security-policy"]).toContain("default-src 'none'");
  });

  it("serves an OpenAPI document outside production", async () => {
    const r = await t.agent().get("/api/openapi.json");
    expect(r.status).toBe(200);
    expect(r.body.openapi).toBe("3.1.0");
    expect(r.body.paths["/api/sessions/{sessionId}/policies"].post.requestBody).toBeDefined();
  });
});

describe("production identity policies", () => {
  beforeAll(() => {
    setConfig({ requireEmailVerification: true, requireStaffMfa: true });
  });
  afterAll(() => resetConfig());
  const t = useApp();

  it("requires email verification before the first sign-in", async () => {
    const mail = getPorts().mail as ConsoleMail;
    const a = t.agent();
    const r = await a.post("/api/auth/register").send({ email: "verify@example.com", display_name: "V", password: PASSWORD });
    expect(r.status).toBe(201);
    expect(r.body).toEqual({ user: null, verification_required: true });
    const login = await t.agent().post("/api/auth/login").send({ email: "verify@example.com", password: PASSWORD });
    expect(login.status).toBe(403);
    expect(login.body.detail).toContain("Verify your email");
    const msg = mail.outbox.filter((m) => m.to === "verify@example.com").at(-1)!;
    const link = new URL(msg.text.match(/https?:\/\/\S+/)![0]);
    await t.agent().get(link.pathname + link.search);
    expect((await t.agent().post("/api/auth/login").send({ email: "verify@example.com", password: PASSWORD })).status).toBe(200);
  });

  it("refuses staff permissions without a second factor", async () => {
    const a = t.agent();
    await a.post("/api/auth/register").send({ email: "coach@example.com", display_name: "Coach", password: PASSWORD });
    await t.database.executeSql(`update "user" set role = 'instructor', email_verified = true where email = 'coach@example.com'`);
    const staff = t.agent();
    expect((await staff.post("/api/auth/login").send({ email: "coach@example.com", password: PASSWORD })).status).toBe(200);
    const r = await staff.get("/api/admin/users");
    expect(r.status).toBe(403);
    expect(r.body.detail).toContain("two-factor");
    expect((await staff.get("/api/career/profile")).status).toBe(200); // own learning still works
  });
});
