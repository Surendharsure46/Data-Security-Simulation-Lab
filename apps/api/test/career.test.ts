/**
 * Learning journey: public welcome content, role choice, Levels 0-5 (fundamentals, knowledge check, labs), mission assessment
 * branches and automatic level unlocks.
 */
import { describe, expect, it } from "vitest";
import { LEVEL_CHECKS, MISSIONS, checkId, validateCareerContent } from "../src/content/career.js";
import { servedQuestions } from "../src/domain/career.js";
import { goodInvestigation, goodRemediation, prepareAndRunBaseline } from "./flow.js";
import { type Agent, api, type TestContext, useApp } from "./helpers.js";

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const EXPLANATION = "I inspected the data, made the change the lab asked for and verified the result: the control now behaves as "
  + "required and legitimate work still succeeds.";
const VARIANT_ACTORS: Record<string, [string, string, string]> = { A: ["u-jokafor", "u-rsilva", "UPLOAD"], B: ["u-rsilva", "u-mchen", "EMAIL"] };

const levelQuestions = (level: number) => servedQuestions(LEVEL_CHECKS[level], checkId(level));
const answers = (mid: string) => servedQuestions(MISSIONS[mid].business_problem.questions, mid).map((q) => q.answer);
const checkAnswers = (level: number) => levelQuestions(level).map((q) => q.answer);

/** Variants are never exposed by the API; tests read the hidden value from the database. */
async function sessionVariant(t: TestContext, sid: number): Promise<string> {
  return ((await t.database.executeSql("select variant from scenario_sessions where id = $1", [sid])).rows[0] as Json).variant;
}

async function readAll(h: Agent, level: number): Promise<Json> {
  let d = await api(h, "GET", `/api/career/levels/${level}`);
  for (const item of d.fundamentals) d = await api(h, "POST", `/api/career/levels/${level}/read/${item.key}`);
  return d;
}

async function unlockLabs(h: Agent, level: number): Promise<Json> {
  await readAll(h, level);
  const r = await api(h, "POST", `/api/career/levels/${level}/check`, { answers: checkAnswers(level) });
  expect(r.passed).toBe(true);
  return r;
}

const start = (h: Agent, mid: string) => api(h, "POST", `/api/career/missions/${mid}/start`);

async function understand(h: Agent, attempt: Json): Promise<void> {
  expect((await api(h, "POST", `/api/career/attempts/${attempt.id}/understand`, { answers: answers(attempt.mission.id) })).passed).toBe(true);
}

const submit = (h: Agent, attempt: Json, cited: number[] = []) =>
  api(h, "POST", `/api/career/attempts/${attempt.id}/submit`, { explanation: EXPLANATION, cited_evidence: cited });

async function doDemo(h: Agent): Promise<void> {
  await api(h, "POST", "/api/career/demo/scan", {});
  await api(h, "POST", "/api/career/demo/classify", { label: "restricted" });
  await api(h, "POST", "/api/career/demo/transfer", { destination: "dst-personal-webmail" });
  await api(h, "POST", "/api/career/demo/transfer", { destination: "dst-helpwise-sftp" });
}

async function doHashing(h: Agent): Promise<void> {
  const files: string[] = (await api(h, "GET", "/api/labs/encryption")).files;
  const digests: Record<string, string> = {};
  for (const f of files) digests[f] = (await api(h, "POST", "/api/labs/encryption/hash", { file: f })).sha256;
  const manifest = (await api(h, "GET", "/api/labs/encryption")).manifest.original_batch_sha256;
  await api(h, "POST", "/api/labs/encryption/hash/answer", { modified_file: Object.entries(digests).find(([, d]) => d !== manifest)![0] });
}

async function completeLevel0(h: Agent): Promise<Json> {
  await unlockLabs(h, 0);
  const a = await start(h, "MSN-001");
  await understand(h, a);
  await doDemo(h);
  expect((await submit(h, a)).status).toBe("PASSED");
  const b = await start(h, "MSN-002");
  await understand(h, b);
  await doHashing(h);
  return submit(h, b);
}

async function solveScenario(t: TestContext, h: Agent, attempt: Json): Promise<number[]> {
  const sid = attempt.session.id;
  const [culprit, ambiguous, exfil] = VARIANT_ACTORS[await sessionVariant(t, sid)];
  await prepareAndRunBaseline(h, sid);
  const cid = await goodInvestigation(h, sid, culprit, ambiguous, exfil);
  await goodRemediation(h, sid, cid, culprit);
  return (await api(h, "GET", `/api/career/attempts/${attempt.id}`)).evidence_options.items.map((e: Json) => e.id);
}

describe("career content", () => {
  it("is consistent", async () => {
    await validateCareerContent();
  });

  it("shuffles answer positions but keeps them stable", () => {
    const positions = [0, 1, 2, 3, 4, 5].flatMap((lv) => levelQuestions(lv).map((q) => q.answer));
    expect(new Set(positions).size).toBeGreaterThanOrEqual(3); // not always the same option
    expect(levelQuestions(2)).toEqual(levelQuestions(2));
  });
});

describe("learning journey", () => {
  const t = useApp();

  it("public content needs no login and hides answers", async () => {
    const r = await t.agent().get("/api/career/public");
    expect(r.status).toBe(200);
    expect(r.body.levels.map((lv: Json) => lv.level)).toEqual([0, 1, 2, 3, 4, 5]);
    const roles = new Set(r.body.roles.map((x: Json) => x.key));
    expect(roles.has("soc-analyst") && roles.has("dlp-engineer")).toBe(true);
    expect(r.body.welcome.sections.length).toBeGreaterThan(0);
    expect(r.text).not.toContain("answer");
  });

  it("choosing a role starts the journey at level zero", async () => {
    const h = await t.register("learner1");
    let prof = await api(h, "GET", "/api/career/profile");
    expect(prof.onboarding_complete).toBe(false);
    expect(prof.career_level).toBe(0);
    expect((await api(h, "GET", "/api/career/levels/0")).unlocked).toBe(false);
    expect((await h.put("/api/career/role").send({ role: "astronaut" })).status).toBe(422);
    prof = await api(h, "PUT", "/api/career/role", { role: "soc-analyst" });
    expect(prof.onboarding_complete).toBe(true);
    expect(prof.role_title).toBe("Trainee Data Security SOC Analyst");
    expect((await api(h, "GET", "/api/curriculum")).selected_pathway).toBe("soc-analyst");
    const j = await api(h, "GET", "/api/career/journey");
    expect(j.levels.map((lv: Json) => lv.status)).toEqual(["CURRENT", "LOCKED", "LOCKED", "LOCKED", "LOCKED", "LOCKED"]);
    expect([j.next_step.type, j.next_step.key]).toEqual(["learn", "briefing"]);
  });

  it("guides level steps in order", async () => {
    const h = await t.register("learner1");
    await api(h, "PUT", "/api/career/role", { role: "foundation" });
    let d = await api(h, "GET", "/api/career/levels/0");
    expect(d.fundamentals[0].type).toBe("briefing");
    expect(d.fundamentals[0]).toHaveProperty("organization");
    expect(JSON.stringify(d.check.questions)).not.toContain("answer");
    expect(d.steps.find((s: Json) => s.type === "check").status).toBe("LOCKED");
    expect((await h.post("/api/career/levels/0/check").send({ answers: checkAnswers(0) })).status).toBe(409);
    expect((await h.post("/api/career/missions/MSN-001/start")).status).toBe(409);
    expect((await api(h, "GET", "/api/career/levels/1")).status).toBe("LOCKED");
    expect((await h.post("/api/career/levels/1/read/M01-L3")).status).toBe(409);
    d = await readAll(h, 0);
    expect(d.next_step.type).toBe("check");
    const wrong = await api(h, "POST", "/api/career/levels/0/check", { answers: checkAnswers(0).map((a) => (a + 1) % 4) });
    expect(wrong.passed).toBe(false);
    expect(JSON.stringify(wrong)).not.toContain("answer");
    const ok = await api(h, "POST", "/api/career/levels/0/check", { answers: checkAnswers(0) });
    expect(ok.passed).toBe(true);
    expect(ok.next.next_mission.id).toBe("MSN-001");
    d = await api(h, "GET", "/api/career/levels/0");
    expect(d.steps.filter((s: Json) => s.type === "mission").map((s: Json) => s.status)).toEqual(["CURRENT", "LOCKED"]);
    expect((await h.post("/api/career/missions/MSN-002/start")).status).toBe(409);
  });

  it("demo lab: fail branch, retry and level up", async () => {
    const h = await t.register("learner1");
    await api(h, "PUT", "/api/career/role", { role: "dlp-engineer" });
    await unlockLabs(h, 0);
    const a = await start(h, "MSN-001");
    expect(a.mission.kind).toBe("DEMO");
    expect(JSON.stringify(a.mission)).not.toContain("expected_label");
    expect((await h.post(`/api/career/attempts/${a.id}/submit`).send({ explanation: EXPLANATION })).status).toBe(409);
    await understand(h, a);
    await api(h, "POST", "/api/career/demo/scan", {});
    const failed = await submit(h, a);
    expect(failed.status).toBe("NOT_PASSED");
    expect(failed.outcome.skill_gaps.length && failed.outcome.remedial_lessons.length).toBeTruthy();
    expect(failed.retry_options).toEqual(["PRACTICE"]);
    const again = await api(h, "POST", `/api/career/attempts/${a.id}/retry`, { strategy: "PRACTICE" });
    expect(again.understanding.carried_over_from).toBe(1);
    expect(again.phases.find((p: Json) => p.key === "INSPECT").items[0].done).toBe(false); // the demo restarts on retry
    await doDemo(h);
    const passed = await submit(h, again);
    expect(passed.status).toBe("PASSED");
    expect(passed.outcome.next.next_mission.id).toBe("MSN-002");

    const b = await start(h, "MSN-002");
    expect(b.mission.exercises[0].steps.length).toBeGreaterThan(0);
    await understand(h, b);
    await doHashing(h);
    const nxt = (await submit(h, b)).outcome.next;
    expect([nxt.level_completed, nxt.level_unlocked, nxt.new_title]).toEqual([0, 1, "Junior DLP Engineer"]);
    const promo = (await api(h, "GET", "/api/career/promotion")).pending;
    expect([promo.level, promo.completed_level]).toEqual([1, 0]);
    expect(promo.missions.length).toBeGreaterThan(0);
    await api(h, "POST", "/api/career/promotion/acknowledge");
    const j = await api(h, "GET", "/api/career/journey");
    expect(j.levels.slice(0, 3).map((lv: Json) => lv.status)).toEqual(["COMPLETED", "CURRENT", "LOCKED"]);
    expect(j.pending_promotion).toBeNull();
  });

  it("scenario lab pass records skills; mission sessions are locked to the mission", async () => {
    const h = await t.register("learner1");
    await api(h, "PUT", "/api/career/role", { role: "soc-analyst" });
    await completeLevel0(h);
    await api(h, "POST", "/api/career/promotion/acknowledge");
    await unlockLabs(h, 1);
    const a = await start(h, "MSN-101");
    expect(a.session.mode).toBe("GUIDED");
    await understand(h, a);
    const cited = await solveScenario(t, h, a);
    const sid = a.session.id;
    expect((await h.post(`/api/sessions/${sid}/submit`).send({ confirm: true })).status).toBe(409);
    expect((await h.post(`/api/sessions/${sid}/reset`).send({ confirm: true })).status).toBe(409);
    expect((await h.post(`/api/career/attempts/${a.id}/submit`).send({ explanation: EXPLANATION, cited_evidence: [99999] })).status).toBe(422);
    const done = await submit(h, a, cited);
    expect(done.status).toBe("PASSED");
    expect(done.outcome.required.every((r: Json) => r.met)).toBe(true);
    const skills = new Set(done.outcome.skills_recorded.map((s: Json) => s.skill));
    expect(skills.has("data-classification") && skills.has("control-validation")).toBe(true);
    expect(done.outcome.next.next_mission.id).toBe("MSN-102");
  });

  it("scenario fail branch offers practice or a new variant", async () => {
    const h = await t.register("learner1");
    await api(h, "PUT", "/api/career/role", { role: "soc-analyst" });
    await completeLevel0(h);
    await unlockLabs(h, 1);
    const a = await start(h, "MSN-101");
    await understand(h, a);
    const sid = a.session.id;
    await prepareAndRunBaseline(h, sid);
    const cid = (await api(h, "POST", `/api/sessions/${sid}/cases`, { title: "Thin case", alert_ids: [] })).id;
    const ev = await api(h, "POST", `/api/sessions/${sid}/cases/${cid}/evidence`, { ref_type: "ASSET", ref_id: "ast-cust-export-q1" });
    const done = await submit(h, a, [ev.id]);
    expect(done.status).toBe("NOT_PASSED");
    expect(done.outcome.required.some((r: Json) => !r.met)).toBe(true);
    expect(done.outcome.skill_gaps.map((g: Json) => g.skill)).toContain("control-validation");
    expect(done.retry_options).toEqual(["PRACTICE", "NEW_VARIANT"]);
    const practice = await api(h, "POST", `/api/career/attempts/${a.id}/retry`, { strategy: "PRACTICE" });
    expect(practice.session.mode).toBe("GUIDED");
    expect(await sessionVariant(t, practice.session.id)).toBe(await sessionVariant(t, sid));
    const nv = await api(h, "POST", `/api/career/attempts/${practice.id}/retry`, { strategy: "NEW_VARIANT" });
    expect(await sessionVariant(t, nv.session.id)).not.toBe(await sessionVariant(t, practice.session.id));
    expect((await api(h, "GET", `/api/career/attempts/${practice.id}`)).status).toBe("ABANDONED");
  });

  it("completing level one unlocks level two, where practice does not count", async () => {
    const h = await t.register("learner1");
    await api(h, "PUT", "/api/career/role", { role: "data-protection-engineer" });
    await completeLevel0(h);
    await unlockLabs(h, 1);
    const a = await start(h, "MSN-101");
    await understand(h, a);
    await submit(h, a, await solveScenario(t, h, a));
    const b = await start(h, "MSN-102");
    await understand(h, b);
    await api(h, "POST", "/api/labs/encryption/file/encrypt", { passphrase: "Correct-Horse-42!" });
    await api(h, "POST", "/api/labs/encryption/file/decrypt", { passphrase: "Wrong-Passphrase-1" });
    await api(h, "POST", "/api/labs/encryption/file/decrypt", { passphrase: "Correct-Horse-42!" });
    await api(h, "POST", "/api/labs/encryption/file/tamper");
    await api(h, "POST", "/api/labs/encryption/file/decrypt", { passphrase: "Correct-Horse-42!" });
    expect((await submit(h, b)).status).toBe("PASSED");
    const c = await start(h, "MSN-103");
    await understand(h, c);
    await api(h, "POST", "/api/labs/database/reset");
    await api(h, "POST", "/api/labs/database/grants/revoke", { role: "support_agent", table: "customers" });
    await api(h, "POST", "/api/labs/database/query", { role: "support_agent", sql: "SELECT * FROM customers" });
    await api(h, "POST", "/api/labs/database/query", { role: "support_agent", sql: "SELECT * FROM customers_masked LIMIT 5" });
    await api(h, "POST", "/api/labs/database/lookup", { mode: "vulnerable", email: "x' OR '1'='1" });
    await api(h, "POST", "/api/labs/database/lookup", { mode: "parameterized", email: "x' OR '1'='1" });
    const done = await submit(h, c);
    expect(done.status, JSON.stringify(done.outcome.required)).toBe("PASSED");
    expect(done.outcome.next.level_unlocked).toBe(2);
    const prof = await api(h, "GET", "/api/career/profile");
    expect([prof.career_level, prof.role_title, prof.pending_promotion]).toEqual([2, "Data Protection Engineer", 2]);

    await unlockLabs(h, 2);
    const d = await start(h, "MSN-201");
    expect(d.session.mode).toBe("ASSESSMENT");
    expect(d.counts).toBe(true);
    const practice = await api(h, "POST", `/api/career/attempts/${d.id}/retry`, { strategy: "PRACTICE" });
    expect(practice.counts).toBe(false);
    expect(practice).toHaveProperty("practice_note");
  });

  it("keeps attempts private", async () => {
    const h = await t.register("learner1");
    await api(h, "PUT", "/api/career/role", { role: "foundation" });
    await unlockLabs(h, 0);
    const a = await start(h, "MSN-001");
    const other = await t.register("learner2");
    expect((await other.get(`/api/career/attempts/${a.id}`)).status).toBe(404);
    expect((await other.post(`/api/career/attempts/${a.id}/understand`).send({ answers: [1, 1] })).status).toBe(404);
  });
});
