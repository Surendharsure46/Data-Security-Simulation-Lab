/**
 * Learning journey: role choice, Levels 0-5, fundamentals, knowledge checks, lab missions and level unlocks.
 *
 *     Choose role -> Level n: read fundamentals -> pass the knowledge check -> complete every lab mission
 *     (Understand -> Inspect -> Act -> Observe -> Validate -> Submit evidence and explanation ->
 *     server-side competency assessment -> required criteria?
 *         no  -> skill gaps + remedial lessons -> retry with practice or a new variant
 *         yes -> record skills and outcome -> next lab)
 *     -> level complete -> congratulations (pending_promotion) -> Level n+1 unlocked automatically.
 *
 * Scenario missions reuse the scenario and assessment engines unchanged. Lab missions are assessed from the server-verified
 * lab_exercise_results rows the labs record; the demo lab from the demo progress recorded by the real detector and
 * policy-engine endpoints.
 */
import { createHash } from "node:crypto";
import type { PolicyDefinition } from "@threatready/contracts";
import { and, asc, desc, eq, inArray, isNotNull } from "drizzle-orm";
import { audit } from "../common/audit.js";
import { DomainError, iso, pyRepr, Rng, round, sorted } from "../common/util.js";
import * as C from "../content/career.js";
import { LESSONS, QUIZZES } from "../content/curriculum.js";
import { type Principal, uow } from "../db/context.js";
import {
  alerts, evidence_references, lab_exercise_results, learner_profiles, mission_attempts, scenario_sessions, security_events, skill_records, user,
} from "../db/schema.js";
import { getState, passedExercises } from "../labs/common.js";
import { taskProgress } from "./assessment.js";
import { maxConfidence, scanText } from "./detection.js";
import { primaryCase } from "./investigation.js";
import { decide, evaluatePolicy, explainEntry, parsePolicy } from "./policy-engine.js";
import { getDefinition } from "./scenario-defs.js";
import { type AttemptRow, startScenarioSession, submitScenarioSession } from "./session-lifecycle.js";
import type { SessionRow } from "./simulation.js";

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
export type ProfileRow = typeof learner_profiles.$inferSelect;
export type MissionAttemptRow = typeof mission_attempts.$inferSelect;

const LESSON_BY_ID = new Map(LESSONS.map((x) => [x.id, x]));
const PREVENTED = ["BLOCKED", "DENIED", "FAILURE"];
const SKILL_GAP_THRESHOLD = 70;
const CHECK_PASS_MARK = 0.8; // 4 of 5

// --------------------------------------------------------------------------- questions (options shuffled, answers server-side)

/**
 * Questions with their options in a stable, shuffled order so the right answer is not always in the same place. The order
 * depends only on the salt and the question text, so the same learner sees the same order every time and grading stays
 * deterministic. Each returned question keeps its (remapped) `answer`; callers strip it before sending questions out.
 */
export function servedQuestions(qs: C.Question[], salt: string): C.Question[] {
  return qs.map((q) => {
    const seed = Number.parseInt(createHash("sha256").update(`${salt}|${q.q}`).digest("hex").slice(0, 8), 16);
    const order = new Rng(seed).shuffle(q.options.map((_, i) => i));
    return { q: q.q, options: order.map((i) => q.options[i]), answer: order.indexOf(q.answer) };
  });
}

export function publicQuestions(qs: C.Question[], salt: string) {
  return servedQuestions(qs, salt).map((q) => ({ q: q.q, options: q.options }));
}

const levelQuestions = (level: number) => servedQuestions(C.LEVEL_CHECKS[level], C.checkId(level));
const missionQuestions = (mid: string) => servedQuestions(C.MISSIONS[mid].business_problem.questions, mid);

// --------------------------------------------------------------------------- profile and role

export async function getProfile(userId: string): Promise<ProfileRow> {
  const u = uow();
  const found = await u.one(learner_profiles, eq(learner_profiles.user_id, userId));
  if (found) return found;
  await u.db.insert(learner_profiles).values({ user_id: userId, onboarding_step: "ROLE", onboarding: {}, career_level: 0 }).onConflictDoNothing();
  return (await u.one(learner_profiles, eq(learner_profiles.user_id, userId)))!;
}

const roleOf = (p: ProfileRow) => C.ROLES.find((r) => r.key === p.desired_role) ?? null;
const touch = (p: ProfileRow) => { p.updated_at = new Date(); };

export function profileOut(p: ProfileRow): Json {
  const lv = C.levelDef(p.career_level);
  return {
    onboarding_complete: p.onboarding_step === "DONE", desired_role: p.desired_role, role: roleOf(p), career_level: p.career_level,
    role_title: p.role_title, joined_at: iso(p.joined_at), pending_promotion: p.pending_promotion,
    level: lv ? { level: lv.level, title: lv.title, summary: lv.summary } : null, top_level: C.TOP_LEVEL,
  };
}

export async function chooseRole(pr: Principal, roleKey: string): Promise<ProfileRow> {
  if (!C.ROLE_KEYS.includes(roleKey)) throw new DomainError(`Unknown role; choose one of ${pyRepr(C.ROLE_KEYS)}`, 422);
  const p = await getProfile(pr.userId);
  const first = p.onboarding_step !== "DONE";
  p.desired_role = roleKey;
  p.role_title = C.roleTitle(roleKey, p.career_level);
  if (first) {
    p.onboarding_step = "DONE";
    p.joined_at = new Date();
  }
  touch(p);
  // Keep the Learning Library pathway aligned with the chosen role.
  const st = await getState(pr.userId, "profile", { pathway: "foundation" });
  st.state = { ...(st.state ?? {}), pathway: roleKey };
  await audit({ user_id: pr.userId, org_id: pr.orgId, action: "career.role", target_type: "role", target_id: roleKey, detail: { first_time: first } });
  return p;
}

/** Content for the public welcome and get-started pages (no answers, nothing user-specific). */
export function publicContent(): Json {
  return {
    welcome: C.WELCOME, platform: C.PLATFORM, roles: C.ROLES, phases: C.PHASES,
    levels: C.LEVELS.map((lv) => ({ level: lv.level, title: lv.title, summary: lv.summary, icon: lv.icon, labs: lv.missions.length,
      lessons: fundamentals(lv.level).length })),
  };
}

// --------------------------------------------------------------------------- interactive demo (real detectors and policy engine)

const demoProgress = (p: ProfileRow): Json => ({ ...((p.onboarding ?? {}).demo ?? {}) });

function setDemo(p: ProfileRow, changes: Json): Json {
  const demo = { ...demoProgress(p), ...changes };
  p.onboarding = { ...(p.onboarding ?? {}), demo };
  touch(p);
  return demo;
}

function resetDemo(p: ProfileRow): void {
  p.onboarding = { ...(p.onboarding ?? {}), demo: {} };
}

function demoFlags(p: ProfileRow): Record<string, boolean> {
  const d = demoProgress(p);
  return Object.fromEntries((C.DEMO.completion as string[]).map((k) => [k, Boolean(d[k])]));
}

export async function demoScan(userId: string, text: string | null | undefined): Promise<Json> {
  const p = await getProfile(userId);
  const results = scanText(text ?? C.DEMO.record);
  setDemo(p, { scanned: true });
  return {
    provenance: "SIMULATED",
    findings: Object.values(results).map((r) => ({ detector: r.detector, match_count: r.match_count, confidence: r.confidence, evidence: r.evidence })),
    explanation: "Detectors combine patterns with validators (for example the Luhn checksum for card numbers) and nearby "
      + "keywords. Findings carry masked evidence, so scan results, cases and reports never repeat the full value.",
    demo: demoFlags(p),
  };
}

export async function demoClassify(userId: string, label: string): Promise<Json> {
  const keys = new Set(C.DEMO.labels.map((l) => l.key));
  if (!keys.has(label)) throw new DomainError(`Unknown label; choose one of ${pyRepr(sorted(keys))}`, 422);
  const p = await getProfile(userId);
  const correct = label === C.DEMO.expected_label;
  setDemo(p, { label, ...(correct ? { classified: true } : {}) });
  return { label, correct, feedback: C.DEMO.label_feedback[label], demo: demoFlags(p) };
}

export async function demoTransfer(userId: string, destination: string): Promise<Json> {
  const dest = C.DEMO.destinations.find((d) => d.key === destination);
  if (!dest) throw new DomainError("Unknown demo destination", 422);
  const p = await getProfile(userId);
  const label: string | undefined = demoProgress(p).label;
  const results = scanText(C.DEMO.record);
  const ranks = Object.fromEntries(C.DEMO.labels.map((l) => [l.key, l.rank]));
  const ctx = {
    action: { type: dest.kind === "SFTP" ? "UPLOAD" : "EMAIL" },
    actor: { id: "you", department: "Customer Operations", role: "Support Agent", employment_type: "EMPLOYEE", groups: [] },
    content: { label: label ?? null, label_rank: label ? ranks[label] ?? null : null, detected_types: sorted(Object.keys(results)),
      max_confidence: maxConfidence(results), match_count: Object.values(results).reduce((n, r) => n + r.match_count, 0), record_count: 1 },
    destination: { kind: dest.kind, category: dest.category, sanctioned: dest.sanctioned, internal: dest.internal, id: dest.key, domain: "" },
    context: { after_hours: false, device_managed: true },
    _label_ranks: ranks,
  };
  const entry = evaluatePolicy("DEMO-DLP", 1, "ENABLED", parsePolicy(C.DEMO.policy) as PolicyDefinition, ctx);
  entry.explanation = explainEntry(entry);
  const decision = decide([entry]);
  if (decision.outcome === "BLOCK") setDemo(p, { observed_block: true });
  else if (decision.outcome === "ALLOW") setDemo(p, { observed_allow: true });
  const consequence = decision.outcome === "BLOCK"
    ? "The transfer was stopped before the data left the company. An alert would go to the SOC."
    : "The transfer went through. Legitimate business transfers must keep working — over-blocking is a failure too.";
  return { provenance: "SIMULATED", destination: dest, label_used: label ?? null, decision, trace: [entry], consequence, demo: demoFlags(p) };
}

export function demoContent(): Json {
  return Object.fromEntries(Object.entries(C.DEMO).filter(([k]) => !["expected_label", "label_feedback", "completion"].includes(k)));
}

// --------------------------------------------------------------------------- levels: fundamentals and knowledge checks

function fundamentals(level: number): Json[] {
  const lv = C.levelDef(level)!;
  return [...lv.intro_items, ...LESSONS.filter((x) => x.level === `L${level}`).map((x) => ({ type: "lesson", key: x.id, title: x.title }))];
}

function itemContent(item: Json): Json {
  if (item.type === "lesson") {
    const x = LESSON_BY_ID.get(item.key)!;
    return { ...item, module: x.module, body: x.body, practice: x.practice };
  }
  if (item.type === "briefing") return { ...item, organization: C.ORGANIZATION };
  return { ...item };
}

const readSet = (p: ProfileRow) => new Set<string>((p.onboarding ?? {}).read ?? []);

function requireUnlocked(p: ProfileRow, level: number): C.JourneyLevel {
  const lv = C.levelDef(level);
  if (!lv) throw new DomainError("Level not found", 404);
  if (p.onboarding_step !== "DONE") throw new DomainError("Choose your role to start the journey", 409);
  if (level > p.career_level) throw new DomainError(`Level ${level} is locked. Complete Level ${p.career_level} first.`, 409);
  return lv;
}

export async function markRead(pr: Principal, level: number, key: string): Promise<Json> {
  const p = await getProfile(pr.userId);
  requireUnlocked(p, level);
  if (!fundamentals(level).some((i) => i.key === key)) throw new DomainError("Unknown fundamentals item for this level", 404);
  const read = readSet(p);
  read.add(`L${level}:${key}`);
  p.onboarding = { ...(p.onboarding ?? {}), read: sorted(read) };
  touch(p);
  return levelDetail(pr, level);
}

async function checkPassed(userId: string, level: number): Promise<boolean> {
  return (await uow().count(lab_exercise_results, eq(lab_exercise_results.user_id, userId), eq(lab_exercise_results.lab, "knowledge"),
    eq(lab_exercise_results.exercise, C.checkId(level)), eq(lab_exercise_results.passed, true))) > 0;
}

export async function answerLevelCheck(pr: Principal, level: number, answers: number[]): Promise<Json> {
  const p = await getProfile(pr.userId);
  requireUnlocked(p, level);
  const read = readSet(p);
  if (fundamentals(level).some((i) => !read.has(`L${level}:${i.key}`))) throw new DomainError("Review every fundamentals lesson before the knowledge check", 409);
  const qs = levelQuestions(level);
  if (answers.length !== qs.length) throw new DomainError(`Expected ${qs.length} answers`, 422);
  const correct = qs.map((q, i) => answers[i] === q.answer);
  const score = correct.filter(Boolean).length / qs.length;
  const passed = score >= CHECK_PASS_MARK;
  await uow().insert(lab_exercise_results, { user_id: pr.userId, lab: "knowledge", exercise: C.checkId(level), passed, provenance: "SIMULATED",
    detail: { score, correct } });
  const nxt = passed ? await advance(pr, p) : null;
  return { score, passed, correct, pass_mark: CHECK_PASS_MARK, next: nxt };
}

// --------------------------------------------------------------------------- mission catalogue

function mission(mid: string): C.Mission {
  const m = Object.hasOwn(C.MISSIONS, mid) ? C.MISSIONS[mid] : undefined;
  if (!m) throw new DomainError("Mission not found", 404);
  return m;
}

function requiredItems(m: C.Mission): Json[] {
  if (m.kind === "LAB") return m.exercises!.map((ex) => ({ key: ex.exercise, label: ex.title, requirement: "Verified by the lab" }));
  if (m.kind === "DEMO") return m.items!.map((i) => ({ key: i.key, label: i.title, requirement: "Completed in the demo lab" }));
  const d = getDefinition(m.scenario_id!)!;
  const crit = new Map(d.rubric.criteria.map((c) => [c.key, c]));
  return (m.required_criteria ?? []).map((rc) => {
    if ("criterion" in rc) {
      const c = crit.get(rc.criterion)!;
      const req = rc.min_fraction >= 1 ? "full credit" : `at least ${Math.round(rc.min_fraction * 100)}% of its points`;
      return { key: rc.criterion, label: c.description, requirement: req };
    }
    const cat = d.rubric.categories[rc.category];
    return { key: rc.category, label: `${cat.name} category`, requirement: `at least ${rc.min_percent}%` };
  });
}

/** Learner-safe mission view. Comprehension answers are never included. */
export function missionPublic(mid: string): Json {
  const m = mission(mid);
  const { questions, ...bp } = m.business_problem;
  const lv = C.levelDef(m.level)!;
  const out: Json = {
    id: mid, kind: m.kind, level: m.level, level_title: lv.title, title: m.title, assigned_by: m.assigned_by,
    business_problem: { ...bp, questions: publicQuestions(questions, mid) }, required: requiredItems(m), min_explanation: m.min_explanation ?? 80,
  };
  if (m.kind === "SCENARIO") {
    const d = getDefinition(m.scenario_id!)!;
    Object.assign(out, { scenario_id: d.id, scenario_title: d.title, briefing: d.briefing, mode: m.mode, min_score: m.min_score,
      estimated_minutes: d.estimated_minutes, hints: m.mode === "GUIDED", execution_mode: "SIMULATED" });
  } else if (m.kind === "LAB") {
    Object.assign(out, { lab: m.lab, route: C.LAB_ROUTES[m.lab!], min_score: 100,
      exercises: m.exercises!.map((ex) => ({ exercise: ex.exercise, phase: ex.phase, title: ex.title, steps: ex.steps })) });
  } else {
    Object.assign(out, { min_score: 100, demo: demoContent() });
  }
  return out;
}

async function passedMissions(userId: string): Promise<Set<string>> {
  const rows = await uow().all(mission_attempts, and(eq(mission_attempts.user_id, userId), eq(mission_attempts.status, "PASSED")));
  return new Set(rows.map((r) => r.mission_id).filter((mid) => Object.hasOwn(C.MISSIONS, mid)));
}

async function levelComplete(userId: string, level: number, passed?: Set<string>): Promise<boolean> {
  const ps = passed ?? (await passedMissions(userId));
  return (await checkPassed(userId, level)) && C.levelDef(level)!.missions.every((mid) => ps.has(mid));
}

export async function assignedMissionId(userId: string, p: ProfileRow): Promise<string | null> {
  const lv = C.levelDef(p.career_level);
  if (!lv || p.onboarding_step !== "DONE" || !(await checkPassed(userId, p.career_level))) return null;
  const passed = await passedMissions(userId);
  return lv.missions.find((mid) => !passed.has(mid)) ?? null;
}

const activeAttempt = (userId: string, mid: string) => uow().one(mission_attempts,
  and(eq(mission_attempts.user_id, userId), eq(mission_attempts.mission_id, mid), eq(mission_attempts.status, "IN_PROGRESS"))!,
  [desc(mission_attempts.id)]);
const latestAttempt = (userId: string, mid: string) => uow().one(mission_attempts,
  and(eq(mission_attempts.user_id, userId), eq(mission_attempts.mission_id, mid))!, [desc(mission_attempts.id)]);

/**
 * Load a mission attempt. Staff may read attempts in their own organization; nobody else learns that the id exists.
 * Writes are owner-only.
 */
export async function loadAttempt(pr: Principal, attemptId: number, opts: { write: boolean }): Promise<MissionAttemptRow> {
  const a = await uow().get(mission_attempts, attemptId);
  if (!a || !Object.hasOwn(C.MISSIONS, a.mission_id)) throw new DomainError("Lab attempt not found", 404);
  if (a.user_id !== pr.userId) {
    const owner = await uow().one(user, eq(user.id, a.user_id));
    if (opts.write || !pr.staff || !owner || owner.org_id !== pr.orgId) throw new DomainError("Lab attempt not found", 404);
  }
  return a;
}

// --------------------------------------------------------------------------- level views

export async function levelDetail(pr: Principal, level: number): Promise<Json> {
  const p = await getProfile(pr.userId);
  const lv = C.levelDef(level);
  if (!lv) throw new DomainError("Level not found", 404);
  const unlocked = p.onboarding_step === "DONE" && level <= p.career_level;
  const read = readSet(p);
  const passed = await passedMissions(pr.userId);
  const check = await checkPassed(pr.userId, level);
  const steps: Json[] = [];
  const fund = fundamentals(level).map(itemContent);
  for (const i of fund) steps.push({ type: "learn", key: i.key, title: i.title, done: read.has(`L${level}:${i.key}`) });
  const allRead = steps.every((s) => s.done);
  steps.push({ type: "check", key: C.checkId(level), title: `Level ${level} knowledge check`, done: check });
  const firstOpenMission = lv.missions.find((mid) => !passed.has(mid)) ?? null;
  for (const mid of lv.missions) {
    const m = C.MISSIONS[mid];
    const latest = await latestAttempt(pr.userId, mid);
    steps.push({ type: "mission", key: mid, title: m.title, kind: m.kind, lab: m.lab ?? null, mode: m.mode ?? null, done: passed.has(mid),
      latest_attempt: latest ? { id: latest.id, status: latest.status, score: latest.score } : null });
  }
  // Steps are sequential: everything up to the first unfinished step is reachable.
  let reachable = unlocked;
  for (const s of steps) {
    if (s.type === "check" && !allRead) reachable = false;
    if (s.type === "mission" && (!check || (s.key !== firstOpenMission && !s.done))) {
      s.status = s.done ? "DONE" : "LOCKED";
      continue;
    }
    s.status = s.done ? "DONE" : reachable ? "CURRENT" : "LOCKED";
    if (!s.done && reachable) reachable = s.type === "learn"; // every lesson is open once the level is unlocked
  }
  const current = steps.find((s) => s.status === "CURRENT") ?? null;
  for (const s of steps) if (s.status === "CURRENT" && s !== current) s.status = "OPEN";
  const complete = check && lv.missions.every((mid) => passed.has(mid));
  return {
    level, title: lv.title, summary: lv.summary, icon: lv.icon, before_you_start: lv.before_you_start, responsibilities: lv.responsibilities,
    challenge: lv.challenge, rank_title: C.roleTitle(p.desired_role, level), status: complete ? "COMPLETED" : unlocked ? "CURRENT" : "LOCKED",
    unlocked, fundamentals: fund, steps, progress: { done: steps.filter((s) => s.done).length, total: steps.length }, next_step: current,
    check: { passed: check, pass_mark: CHECK_PASS_MARK, questions: publicQuestions(C.LEVEL_CHECKS[level], C.checkId(level)) },
  };
}

async function levelSummary(pr: Principal, level: number): Promise<Json> {
  const d = await levelDetail(pr, level);
  return { level: d.level, title: d.title, summary: d.summary, icon: d.icon, status: d.status, unlocked: d.unlocked, progress: d.progress,
    rank_title: d.rank_title, next_step: d.next_step, labs: C.levelDef(level)!.missions.length };
}

// --------------------------------------------------------------------------- starting and retrying missions

export async function startMission(pr: Principal, mid: string, strategy = "ASSIGNED", previous?: MissionAttemptRow | null): Promise<MissionAttemptRow> {
  const p = await getProfile(pr.userId);
  if (p.onboarding_step !== "DONE") throw new DomainError("Choose your role to start the journey", 409);
  const m = mission(mid);
  if (m.level > p.career_level) throw new DomainError(`This lab belongs to Level ${m.level}, which is still locked`, 409);
  if (!(await checkPassed(pr.userId, m.level))) throw new DomainError(`Pass the Level ${m.level} knowledge check before starting its labs`, 409);
  const passed = await passedMissions(pr.userId);
  if (passed.has(mid)) throw new DomainError("You have already passed this lab", 409);
  const firstOpen = C.levelDef(m.level)!.missions.find((x) => !passed.has(x)) ?? null;
  if (mid !== firstOpen) throw new DomainError("Labs in a level are taken in order. Finish the current lab first.", 409);
  const active = await activeAttempt(pr.userId, mid);
  if (active) {
    if (strategy === "ASSIGNED") return active;
    active.status = "ABANDONED";
    previous = previous ?? active;
  }
  if (m.kind !== "SCENARIO" && strategy === "NEW_VARIANT") throw new DomainError("This lab has no variants; retry with practice instead", 422);
  const u = uow();
  const n = (await u.count(mission_attempts, eq(mission_attempts.user_id, pr.userId), eq(mission_attempts.mission_id, mid))) + 1;
  let understanding: Json = {};
  if (previous && previous.understanding?.passed) understanding = { ...previous.understanding, carried_over_from: previous.attempt_number };
  let sessionId: number | null = null;
  let counts = true;
  if (m.kind === "SCENARIO") {
    const prevSession = previous?.session_id ? await u.get(scenario_sessions, previous.session_id) : undefined;
    let s: SessionRow;
    if (strategy === "PRACTICE") s = await startScenarioSession(pr, m.scenario_id!, "GUIDED", prevSession?.variant ?? null);
    else if (strategy === "NEW_VARIANT") s = await startScenarioSession(pr, m.scenario_id!, m.mode!, null, { excludeVariant: prevSession?.variant ?? null });
    else s = await startScenarioSession(pr, m.scenario_id!, m.mode!);
    sessionId = s.id;
    counts = s.mode === m.mode;
  } else if (m.kind === "DEMO" && previous) {
    resetDemo(p); // a retry repeats the demo from the start
  }
  const a = await u.insert(mission_attempts, { user_id: pr.userId, mission_id: mid, attempt_number: n, strategy, counts, status: "IN_PROGRESS",
    session_id: sessionId, understanding, cited_evidence: [], outcome: {} });
  await audit({ user_id: pr.userId, org_id: pr.orgId, action: "mission.start", target_type: "mission_attempt", target_id: a.id,
    detail: { mission: mid, strategy, counts } });
  return a;
}

export async function retry(pr: Principal, a: MissionAttemptRow, strategy: string): Promise<MissionAttemptRow> {
  if (a.status === "PASSED") throw new DomainError("This lab is already passed", 409);
  if (a.status === "ABANDONED") throw new DomainError("This attempt was replaced by a newer one", 409);
  const latest = await latestAttempt(pr.userId, a.mission_id);
  if (latest && latest.id !== a.id) throw new DomainError("Retry from the latest attempt of this lab", 409);
  return startMission(pr, a.mission_id, strategy, a);
}

// --------------------------------------------------------------------------- mission view

async function sessionObservations(s: SessionRow): Promise<Json> {
  const u = uow();
  const runs: Json[] = [];
  for (const r of (s.flags ?? {}).runs ?? []) {
    const n = r.run_number;
    runs.push({
      run_number: n, mode: r.mode, sim_day: r.sim_day,
      events: await u.count(security_events, eq(security_events.session_id, s.id), eq(security_events.run_number, n)),
      prevented_events: await u.count(security_events, eq(security_events.session_id, s.id), eq(security_events.run_number, n),
        inArray(security_events.result, PREVENTED)),
      alerts: await u.count(alerts, eq(alerts.session_id, s.id), eq(alerts.run_number, n)),
    });
  }
  return { runs };
}

async function evidenceOptions(s: SessionRow): Promise<Json> {
  const cs = await primaryCase(s);
  if (!cs) return { case_id: null, case_title: null, items: [] };
  const items = (await uow().all(evidence_references, eq(evidence_references.case_id, cs.id), [asc(evidence_references.id)]))
    .map((e) => ({ id: e.id, ref_type: e.ref_type, ref_id: e.ref_id, label: e.label }));
  return { case_id: cs.id, case_title: cs.title, items };
}

async function phases(userId: string, a: MissionAttemptRow, m: C.Mission, s: SessionRow | undefined): Promise<Json[]> {
  const items: Record<string, Json[]> = Object.fromEntries(C.PHASE_KEYS.map((k) => [k, []]));
  const und = a.understanding ?? {};
  items.UNDERSTAND.push({ key: "understand", kind: "check", title: "Answer the business-problem check",
    description: "Server-graded; the correct options are never sent to your browser.", done: Boolean(und.passed),
    steps: ["Read the business problem.", "Answer the questions and click 'Check answers'."] });
  if (m.kind === "SCENARIO" && s) {
    for (const t of await taskProgress(s)) {
      items[t.phase].push({ key: t.key, kind: "task", title: t.title, description: t.description, done: t.done, hints_available: t.hints_available });
    }
  } else if (m.kind === "LAB") {
    const passed = await passedExercises(userId, m.lab!);
    for (const ex of m.exercises!) {
      items[ex.phase].push({ key: ex.exercise, kind: "lab_exercise", title: ex.title, description: `Verified server-side by the ${m.lab} lab.`,
        steps: ex.steps, done: passed.has(ex.exercise), route: C.LAB_ROUTES[m.lab!] });
    }
  } else {
    const flags = demoFlags(await getProfile(userId));
    for (const it of m.items!) {
      items[it.phase].push({ key: it.key, kind: "demo_step", title: it.title, steps: it.steps, description: "Recorded by the demo lab.", done: flags[it.key] });
    }
  }
  const minExp = m.min_explanation ?? 80;
  items.SUBMIT.push({ key: "submission", kind: "submission", title: "Submit your explanation",
    description: `At least ${minExp} characters` + (m.kind === "SCENARIO" ? "; cite case evidence." : "."), done: a.submitted_at !== null,
    steps: ["Explain what you found, what you did and how you know it worked.", "Click 'Submit for assessment'."] });
  return C.PHASES.map((ph) => {
    const its = items[ph.key];
    return { ...ph, items: its, done: its.length ? its.every((i) => i.done) : null,
      note: its.length ? null : "Covered inside the lab: every action shows its real result immediately." };
  });
}

export async function attemptOut(userId: string, a: MissionAttemptRow): Promise<Json> {
  const m = mission(a.mission_id);
  const s = a.session_id ? await uow().get(scenario_sessions, a.session_id) : undefined;
  const ph = await phases(userId, a, m, s);
  const workItems = ph.filter((x) => x.key !== "UNDERSTAND" && x.key !== "SUBMIT").flatMap((x) => x.items as Json[]);
  const und = a.understanding ?? {};
  const latest = await latestAttempt(userId, a.mission_id);
  const retryOptions = ["NOT_PASSED", "PRACTICE_PASSED", "IN_PROGRESS"].includes(a.status) && latest && latest.id === a.id
    ? ["PRACTICE", ...(m.kind === "SCENARIO" ? ["NEW_VARIANT"] : [])] : [];
  const out: Json = {
    id: a.id, mission: missionPublic(a.mission_id), attempt_number: a.attempt_number, strategy: a.strategy, counts: a.counts, status: a.status,
    started_at: iso(a.started_at), submitted_at: iso(a.submitted_at),
    understanding: { passed: Boolean(und.passed), score: und.score ?? null, correct: und.correct ?? null, carried_over_from: und.carried_over_from ?? null },
    phases: ph,
    readiness: { understanding_passed: Boolean(und.passed), work_done: workItems.filter((i) => i.done).length, work_total: workItems.length,
      session_status: s?.status ?? null },
    explanation: a.explanation, cited_evidence: a.cited_evidence, score: a.score,
    outcome: a.outcome && Object.keys(a.outcome).length ? a.outcome : null, retry_options: retryOptions,
    session: null, observations: null, evidence_options: null,
  };
  if (s) {
    out.session = { id: s.id, mode: s.mode, status: s.status, attempt_number: s.attempt_number, run_count: s.run_count, execution_mode: "SIMULATED" };
    out.observations = await sessionObservations(s);
    out.evidence_options = await evidenceOptions(s);
  }
  if (!a.counts && a.status === "IN_PROGRESS") {
    out.practice_note = "Practice attempt: guided mode with hints. It is assessed and shows your skill gaps, but the "
      + "lab is only passed by an attempt in independent assessment mode.";
  }
  return out;
}

// --------------------------------------------------------------------------- understanding gate

export function answerUnderstanding(a: MissionAttemptRow, answers: number[]): Json {
  if (a.status !== "IN_PROGRESS") throw new DomainError(`Attempt is ${a.status}`, 409);
  mission(a.mission_id);
  const qs = missionQuestions(a.mission_id);
  if (answers.length !== qs.length) throw new DomainError(`Expected ${qs.length} answers`, 422);
  const correct = qs.map((q, i) => answers[i] === q.answer);
  const score = correct.filter(Boolean).length / qs.length;
  const passed = score >= 0.75;
  a.understanding = { passed: passed || Boolean(a.understanding?.passed), score, correct, answered_at: iso(new Date()) };
  return { score, passed, correct };
}

// --------------------------------------------------------------------------- submission and competency assessment

function lessons(ids: string[]): Json[] {
  const out: Json[] = [];
  const seen = new Set<string>();
  for (const lid of ids) {
    const x = LESSON_BY_ID.get(lid);
    if (seen.has(lid) || !x) continue;
    seen.add(lid);
    out.push({ id: lid, title: x.title, module: x.module, body: x.body, practice: x.practice, has_quiz: Object.hasOwn(QUIZZES, lid) });
  }
  return out;
}

function evaluateScenario(m: C.Mission, at: AttemptRow): Json {
  const crit = new Map(at.criteria.map((c) => [c.key, c]));
  const required: Json[] = [];
  const unmet = new Map<string, string[]>();
  const addUnmet = (skill: string, line: string) => { if (!unmet.has(skill)) unmet.set(skill, []); unmet.get(skill)!.push(line); };
  const items = requiredItems(m);
  (m.required_criteria ?? []).forEach((rc, idx) => {
    const item = items[idx];
    let met: boolean, actual: string, why: string;
    if ("criterion" in rc) {
      const c = crit.get(rc.criterion)!;
      const frac = c.points ? c.earned / c.points : 0;
      met = frac + 1e-9 >= rc.min_fraction;
      actual = `${c.earned}/${c.points} points`;
      why = c.explanation;
      if (!met) addUnmet(C.CRITERION_SKILLS[c.key], `${c.description}: ${why}`);
    } else {
      const cs = at.category_scores[rc.category];
      met = cs.percent + 1e-9 >= rc.min_percent;
      actual = `${cs.percent}%`;
      why = `${cs.name} scored ${cs.percent}%.`;
      if (!met) {
        for (const c of at.criteria) if (c.category === rc.category && c.earned < c.points) addUnmet(C.CRITERION_SKILLS[c.key], `${c.description}: ${c.explanation}`);
      }
    }
    required.push({ ...item, met, actual, explanation: why });
  });
  const tally = new Map<string, [number, number]>();
  for (const c of at.criteria) {
    const k = C.CRITERION_SKILLS[c.key];
    const t = tally.get(k) ?? [0, 0];
    t[0] += c.earned;
    t[1] += c.points;
    tally.set(k, t);
  }
  const skills = [...tally.entries()].map(([k, [e, p]]) => ({ skill: k, name: C.SKILLS[k].name, proficiency: p ? Math.round(100 * e / p) : 0,
    criteria: at.criteria.filter((c) => C.CRITERION_SKILLS[c.key] === k).map((c) => c.key) }));
  const gaps: Json[] = [];
  for (const sk of skills) {
    const because = [...(unmet.get(sk.skill) ?? [])];
    if (sk.proficiency < SKILL_GAP_THRESHOLD) {
      for (const c of at.criteria) {
        const line = `${c.description}: ${c.explanation}`;
        if (C.CRITERION_SKILLS[c.key] === sk.skill && c.earned < c.points && !because.includes(line)) because.push(line);
      }
    }
    if (because.length) gaps.push({ ...sk, because });
  }
  const scoreOk = at.total_score >= m.min_score!;
  const passed = scoreOk && !at.critical_failures.length && required.every((r) => r.met);
  const lessonIds = [...gaps.flatMap((g) => C.SKILLS[g.skill].lessons), ...at.recommendations.map((r) => r.lesson_id as string)];
  return {
    kind: "SCENARIO", score: at.total_score, min_score: m.min_score, score_ok: scoreOk, assessment_passed: at.passed, assessment_attempt_id: at.id,
    critical_failures: at.critical_failures, required, passed, category_scores: at.category_scores, criteria: at.criteria,
    missing_tasks: at.missing_tasks, skills, skill_gaps: gaps, remedial_lessons: lessons(lessonIds).slice(0, 6), inputs_digest: at.inputs_digest,
    mode_label: at.mode === "GUIDED" ? "Guided practice result" : "Independent assessment result",
  };
}

async function evaluateLab(userId: string, m: C.Mission): Promise<Json> {
  const rows = new Map<string, typeof lab_exercise_results.$inferSelect>();
  for (const r of await uow().all(lab_exercise_results, and(eq(lab_exercise_results.user_id, userId), eq(lab_exercise_results.lab, m.lab!),
    eq(lab_exercise_results.passed, true)), [asc(lab_exercise_results.id)])) rows.set(r.exercise, r);
  const required: Json[] = [];
  const missing: C.MissionExercise[] = [];
  const items = requiredItems(m);
  m.exercises!.forEach((ex, i) => {
    const r = rows.get(ex.exercise);
    if (!r) missing.push(ex);
    required.push({ ...items[i], met: Boolean(r), actual: r ? `verified ${iso(r.created_at)} (${r.provenance})` : "not yet verified",
      explanation: r ? "Recorded by the lab from a real result." : "The lab has not verified this exercise." });
  });
  const total = m.exercises!.length;
  const score = round(100 * (total - missing.length) / total, 2);
  const skill = C.LAB_SKILLS[m.lab!];
  const skills = [{ skill, name: C.SKILLS[skill].name, proficiency: Math.round(score), criteria: m.exercises!.map((ex) => ex.exercise) }];
  const gaps = missing.length ? [{ ...skills[0], because: missing.map((ex) => `Not verified: ${ex.title}`) }] : [];
  const wanted = new Set(m.exercises!.map((ex) => ex.exercise));
  const evidence = [...rows.entries()].filter(([e]) => wanted.has(e))
    .map(([e, r]) => ({ lab: m.lab, exercise: e, provenance: r.provenance, verified_at: iso(r.created_at) }));
  return { kind: "LAB", score, min_score: 100, score_ok: !missing.length, critical_failures: [], required, passed: !missing.length, skills,
    skill_gaps: gaps, remedial_lessons: lessons(missing.map((ex) => C.exerciseLesson(m.lab!, ex.exercise)!).filter(Boolean)), lab_evidence: evidence };
}

function evaluateDemo(p: ProfileRow, m: C.Mission): Json {
  const flags = demoFlags(p);
  const required = requiredItems(m).map((item) => ({ ...item, met: flags[item.key], actual: flags[item.key] ? "done" : "not done",
    explanation: flags[item.key] ? "Recorded by the demo lab." : "Not completed yet." }));
  const done = Object.values(flags).filter(Boolean).length;
  const score = round(100 * done / Object.keys(flags).length, 2);
  const skills = [{ skill: "data-classification", name: C.SKILLS["data-classification"].name, proficiency: Math.round(score), criteria: Object.keys(flags) }];
  const missing = m.items!.filter((i) => !flags[i.key]).map((i) => i.title);
  const gaps = missing.length ? [{ ...skills[0], because: missing.map((t) => `Not completed: ${t}`) }] : [];
  return { kind: "DEMO", score, min_score: 100, score_ok: !missing.length, critical_failures: [], required, passed: !missing.length, skills,
    skill_gaps: gaps, remedial_lessons: missing.length ? lessons(["M01-L2", "M02-L1"]) : [],
    lab_evidence: Object.entries(flags).map(([k, v]) => ({ demo_step: k, done: v })) };
}

async function recordSkills(userId: string, a: MissionAttemptRow, outcome: Json): Promise<Json[]> {
  const recorded: Json[] = [];
  for (const sk of outcome.skills) {
    await uow().insert(skill_records, { user_id: userId, skill_key: sk.skill, proficiency: sk.proficiency, mission_id: a.mission_id,
      mission_attempt_id: a.id, evidence: { score: outcome.score, criteria: sk.criteria, assessment_attempt_id: outcome.assessment_attempt_id ?? null } });
    recorded.push({ skill: sk.skill, name: sk.name, proficiency: sk.proficiency });
  }
  return recorded;
}

/** 'More labs in the current level?' If not, unlock the next level(s) automatically. */
async function advance(pr: Principal, p: ProfileRow): Promise<Json> {
  const passed = await passedMissions(pr.userId);
  const start = p.career_level;
  // Earlier work can complete more than one level at once.
  while ((await levelComplete(pr.userId, p.career_level, passed)) && p.career_level < C.TOP_LEVEL) p.career_level += 1;
  const topDone = p.career_level === C.TOP_LEVEL && (await levelComplete(pr.userId, C.TOP_LEVEL, passed));
  if (p.career_level > start) {
    p.role_title = C.roleTitle(p.desired_role, p.career_level);
    p.pending_promotion = p.career_level;
    touch(p);
    await audit({ user_id: pr.userId, org_id: pr.orgId, action: "career.level_unlocked", target_type: "level", target_id: p.career_level,
      detail: { from: start, role_title: p.role_title } });
    return { more_missions: false, level_completed: start, level_unlocked: p.career_level, new_title: p.role_title };
  }
  if (topDone) {
    if (p.pending_promotion !== C.JOURNEY_COMPLETE && !(p.onboarding ?? {}).journey_complete_seen) p.pending_promotion = C.JOURNEY_COMPLETE;
    return { more_missions: false, level_completed: C.TOP_LEVEL, journey_complete: true };
  }
  const nxt = await assignedMissionId(pr.userId, p);
  if (nxt) return { more_missions: true, next_mission: { id: nxt, title: C.MISSIONS[nxt].title } };
  return { more_missions: false };
}

export async function submitAttempt(pr: Principal, a: MissionAttemptRow, rawExplanation: string, cited: number[]): Promise<MissionAttemptRow> {
  if (a.status !== "IN_PROGRESS") throw new DomainError(`Attempt is ${a.status}; nothing to submit`, 409);
  if (!a.understanding?.passed) throw new DomainError("Answer the business-problem check before submitting", 409);
  const m = mission(a.mission_id);
  const explanation = rawExplanation.trim();
  const minExp = m.min_explanation ?? 80;
  if (explanation.length < minExp) {
    throw new DomainError(`Your explanation needs at least ${minExp} characters: what happened, what you did and how you verified it`, 422);
  }
  const p = await getProfile(pr.userId);
  let outcome: Json;
  if (m.kind === "SCENARIO") {
    const s = a.session_id ? await uow().get(scenario_sessions, a.session_id) : undefined;
    if (!s) throw new DomainError("The lab session no longer exists; retry the lab", 409);
    if (s.status !== "ACTIVE") throw new DomainError(`The lab workspace is ${s.status}; resume it before submitting`, 409);
    const options = new Map<number, Json>((await evidenceOptions(s)).items.map((e: Json) => [e.id, e]));
    if (!cited.length) throw new DomainError("Cite at least one evidence item from your investigation case", 422);
    if (cited.some((i) => !options.has(i))) throw new DomainError("Cited evidence must come from your primary investigation case", 422);
    a.cited_evidence = [...new Set(cited)].map((i) => {
      const o = options.get(i)!;
      return { id: o.id, ref_type: o.ref_type, ref_id: o.ref_id, label: o.label };
    });
    const at = await submitScenarioSession(s, pr);
    a.assessment_attempt_id = at.id;
    outcome = evaluateScenario(m, at);
  } else if (m.kind === "LAB") {
    outcome = await evaluateLab(pr.userId, m);
    a.cited_evidence = outcome.lab_evidence;
  } else {
    outcome = evaluateDemo(p, m);
    a.cited_evidence = outcome.lab_evidence;
  }
  a.explanation = explanation;
  a.submitted_at = new Date();
  a.score = outcome.score;
  if (outcome.passed && a.counts) {
    a.status = "PASSED";
    outcome.skills_recorded = await recordSkills(pr.userId, a, outcome);
    outcome.next = await advance(pr, p);
  } else if (outcome.passed) {
    a.status = "PRACTICE_PASSED";
    outcome.next = { practice_only: true };
  } else {
    a.status = "NOT_PASSED";
  }
  a.outcome = outcome;
  await audit({ user_id: pr.userId, org_id: pr.orgId, action: "mission.submit", target_type: "mission_attempt", target_id: a.id,
    detail: { mission: a.mission_id, status: a.status, score: a.score } });
  return a;
}

// --------------------------------------------------------------------------- journey overview and celebration

export async function skillsSummary(userId: string): Promise<Json[]> {
  const latest = new Map<string, typeof skill_records.$inferSelect>();
  for (const r of await uow().all(skill_records, eq(skill_records.user_id, userId), [asc(skill_records.id)])) latest.set(r.skill_key, r);
  return Object.entries(C.SKILLS).map(([key, sk]) => {
    const r = latest.get(key);
    return { skill: key, name: sk.name, description: sk.description, proficiency: r?.proficiency ?? null, mission_id: r?.mission_id ?? null,
      recorded_at: r ? iso(r.recorded_at) : null };
  });
}

export function promotionOut(p: ProfileRow): Json | null {
  if (p.pending_promotion === null) return null;
  if (p.pending_promotion === C.JOURNEY_COMPLETE) {
    return { journey_complete: true, level: null, completed_level: C.TOP_LEVEL, title: "Journey complete", new_title: p.role_title,
      summary: "You have completed all six levels, from Foundation to Mastery.", responsibilities: [], challenge: "", missions: [] };
  }
  const lv = C.levelDef(p.pending_promotion)!;
  const prev = C.levelDef(p.pending_promotion - 1)!;
  return { journey_complete: false, level: lv.level, completed_level: prev.level, completed_title: prev.title, title: lv.title,
    new_title: p.role_title, summary: lv.summary, responsibilities: lv.responsibilities, challenge: lv.challenge,
    missions: lv.missions.map((mid) => ({ id: mid, title: C.MISSIONS[mid].title, kind: C.MISSIONS[mid].kind })) };
}

export function acknowledgePromotion(p: ProfileRow): void {
  if (p.pending_promotion === C.JOURNEY_COMPLETE) p.onboarding = { ...(p.onboarding ?? {}), journey_complete_seen: true };
  p.pending_promotion = null;
  touch(p);
}

export async function journey(pr: Principal): Promise<Json> {
  const p = await getProfile(pr.userId);
  const levels: Json[] = [];
  for (const lv of C.LEVELS) levels.push(await levelSummary(pr, lv.level));
  const current = levels.find((lv) => lv.level === p.career_level) ?? levels[0];
  const assigned = await assignedMissionId(pr.userId, p);
  const active = assigned ? await activeAttempt(pr.userId, assigned) : undefined;
  const recent = (await uow().all(mission_attempts, and(eq(mission_attempts.user_id, pr.userId), isNotNull(mission_attempts.submitted_at)),
    [desc(mission_attempts.id)])).slice(0, 10).filter((r) => Object.hasOwn(C.MISSIONS, r.mission_id)).slice(0, 6);
  const complete = levels.every((lv) => lv.status === "COMPLETED");
  return {
    profile: profileOut(p), levels, current_level: current,
    next_step: complete ? null : current.next_step && { ...current.next_step, level: current.level, active_attempt_id: active?.id ?? null },
    overall_progress: { done: levels.reduce((n, lv) => n + lv.progress.done, 0), total: levels.reduce((n, lv) => n + lv.progress.total, 0) },
    journey_complete: complete, skills: await skillsSummary(pr.userId),
    recent_outcomes: recent.map((r) => ({ attempt_id: r.id, mission_id: r.mission_id, title: C.MISSIONS[r.mission_id].title,
      level: C.MISSIONS[r.mission_id].level, status: r.status, score: r.score, submitted_at: iso(r.submitted_at) })),
    pending_promotion: promotionOut(p),
    organization: { name: C.ORGANIZATION.company.name, team: C.ORGANIZATION.team },
  };
}

