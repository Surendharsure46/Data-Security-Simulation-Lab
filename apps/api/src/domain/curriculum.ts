/** Learning paths, lesson completion, knowledge checks and the learner dashboard. */
import { and, desc, eq, inArray } from "drizzle-orm";
import { DomainError, iso } from "../common/util.js";
import { LESSONS, LEVELS, MODULES, PATHWAYS, QUIZZES, type LessonCheck } from "../content/curriculum.js";
import { type Principal, uow } from "../db/context.js";
import {
  assessment_attempts, change_records, lab_exercise_results, policy_test_runs, remediation_actions, scenario_sessions,
} from "../db/schema.js";
import { getState } from "../labs/common.js";
import { taskProgress } from "./assessment.js";
import type { SessionRow } from "./simulation.js";

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

/** Evaluates lesson completion for one user from persisted evidence. */
class Completion {
  private tasks = new Map<number, Record<string, boolean>>();

  private constructor(
    readonly earned: Set<string>,
    private readonly sessions: SessionRow[],
    private readonly labs: Set<string>,
    private readonly testRuns: number,
    private readonly changeRecords: number,
    private readonly attempts: (typeof assessment_attempts.$inferSelect)[],
  ) {}

  static async load(userId: string, earned: Iterable<string>): Promise<Completion> {
    const u = uow();
    const sessions = await u.all(scenario_sessions, eq(scenario_sessions.user_id, userId));
    const labs = new Set((await u.all(lab_exercise_results, and(eq(lab_exercise_results.user_id, userId), eq(lab_exercise_results.passed, true))))
      .map((r) => `${r.lab}:${r.exercise}`));
    const sids = sessions.map((s) => s.id);
    const testRuns = sids.length ? await u.count(policy_test_runs, inArray(policy_test_runs.session_id, sids)) : 0;
    const changeRecords = sids.length ? await u.count(change_records, inArray(change_records.session_id, sids)) : 0;
    const attempts = await u.all(assessment_attempts, eq(assessment_attempts.user_id, userId));
    // Scenario tasks completed in earlier attempts stay earned after a session reset.
    return new Completion(new Set(earned), sessions, labs, testRuns, changeRecords, attempts);
  }

  private async tasksFor(s: SessionRow): Promise<Record<string, boolean>> {
    if (!this.tasks.has(s.id)) {
      try {
        this.tasks.set(s.id, Object.fromEntries((await taskProgress(s)).map((t) => [t.key, t.done])));
      } catch {
        this.tasks.set(s.id, {}); // scenario definition removed
      }
    }
    return this.tasks.get(s.id)!;
  }

  async done(check: LessonCheck): Promise<boolean> {
    switch (check.type) {
      case "scenario_task": {
        const key = `${check.scenario}:${check.task}`;
        if (this.earned.has(key)) return true;
        for (const s of this.sessions) {
          if (s.scenario_id === check.scenario && (await this.tasksFor(s))[check.task!]) {
            this.earned.add(key);
            return true;
          }
        }
        return false;
      }
      case "lab_exercise": return this.labs.has(`${check.lab}:${check.exercise}`);
      case "policy_test_suite_run": return this.testRuns >= 1;
      case "policy_test_suite_runs": return this.testRuns >= (check.count ?? 2);
      case "change_record": return this.changeRecords >= 1;
      case "assessment_passed": return this.attempts.some((a) => a.passed && a.mode === check.mode && a.scenario_id === check.scenario);
      default: return false;
    }
  }
}

const profile = (userId: string) => getState(userId, "profile", { pathway: "foundation" });

/** Persist currently completed scenario tasks before a reset wipes session state. */
export async function rememberCompletedTasks(userId: string): Promise<void> {
  await buildCurriculum(userId);
}

export async function buildCurriculum(userId: string): Promise<Json> {
  const prof = await profile(userId);
  const comp = await Completion.load(userId, prof.state.earned_tasks ?? []);
  const pathwayId = prof.state.pathway ?? "foundation";
  const pathway = PATHWAYS.find((p) => p.id === pathwayId) ?? PATHWAYS[0];
  const lessonDone: Record<string, boolean> = {};
  for (const lesson of LESSONS) lessonDone[lesson.id] = await comp.done(lesson.check);
  const earnedNow = [...comp.earned].sort();
  if (JSON.stringify([...(prof.state.earned_tasks ?? [])].sort()) !== JSON.stringify(earnedNow)) {
    prof.state = { ...prof.state, earned_tasks: earnedNow };
  }
  const unlocked: Record<string, boolean> = {};
  for (const lv of LEVELS) {
    const reqs = lv.unlock.requires;
    let ok = reqs.every((r) => unlocked[r]);
    if (ok && reqs.length) {
      const prevDone = LESSONS.filter((x) => x.level === reqs[reqs.length - 1] && lessonDone[x.id]).length;
      ok = prevDone >= lv.unlock.min_lessons_in_previous;
    }
    unlocked[lv.id] = ok;
  }
  const modules = new Map(MODULES.map((m) => [m.id, m]));
  const lessonsOut = LESSONS.map((lesson) => {
    let available = unlocked[lesson.level] || pathway.lessons.includes(lesson.id);
    if (modules.get(lesson.module)!.status === "PLANNED" && lesson.check.type !== "assessment_passed") available = false;
    const { check: _check, ...rest } = lesson;
    return { ...rest, completed: lessonDone[lesson.id], available, check_type: lesson.check.type, in_pathway: pathway.lessons.includes(lesson.id),
      has_quiz: Object.hasOwn(QUIZZES, lesson.id) };
  });
  const levelsOut = LEVELS.map((lv) => {
    const ls = LESSONS.filter((x) => x.level === lv.id);
    return { ...lv, unlocked: unlocked[lv.id], lessons_total: ls.length, lessons_completed: ls.filter((x) => lessonDone[x.id]).length };
  });
  const modulesOut = MODULES.map((m) => {
    const ls = LESSONS.filter((x) => x.module === m.id);
    return { ...m, lessons_total: ls.length, lessons_completed: ls.filter((x) => lessonDone[x.id]).length };
  });
  const pathwaysOut = PATHWAYS.map((p) => ({ ...p, completed: p.lessons.filter((x) => lessonDone[x]).length, total: p.lessons.length,
    selected: p.id === pathway.id }));
  return { levels: levelsOut, modules: modulesOut, lessons: lessonsOut, pathways: pathwaysOut, selected_pathway: pathway.id };
}

export async function setPathway(userId: string, pathwayId: string): Promise<Json> {
  if (!PATHWAYS.some((p) => p.id === pathwayId)) throw new DomainError("Unknown pathway", 422);
  const st = await profile(userId);
  st.state = { ...st.state, pathway: pathwayId };
  return { pathway: pathwayId };
}

export function getQuiz(lessonId: string): Json {
  const qs = Object.hasOwn(QUIZZES, lessonId) ? QUIZZES[lessonId] : undefined;
  if (!qs) throw new DomainError("No knowledge check for this lesson", 404);
  return { lesson_id: lessonId, questions: qs.map((q) => ({ q: q.q, options: q.options })), pass_mark: 0.75 };
}

export async function submitQuiz(userId: string, lessonId: string, answers: number[]): Promise<Json> {
  const qs = Object.hasOwn(QUIZZES, lessonId) ? QUIZZES[lessonId] : undefined;
  if (!qs) throw new DomainError("No knowledge check for this lesson", 404);
  if (answers.length !== qs.length) throw new DomainError(`Expected ${qs.length} answers`, 422);
  const correct = qs.map((q, i) => answers[i] === q.answer);
  const score = correct.filter(Boolean).length / qs.length;
  const passed = score >= 0.75;
  await uow().insert(lab_exercise_results, { user_id: userId, lab: "knowledge", exercise: lessonId, passed, provenance: "SIMULATED",
    detail: { score, correct } });
  // Only per-question correctness is returned, not the correct option, so the check can be retaken meaningfully.
  return { lesson_id: lessonId, score, passed, correct };
}

export async function dashboard(p: Principal): Promise<Json> {
  const u = uow();
  const cur = await buildCurriculum(p.userId);
  const sessions = (await u.all(scenario_sessions, eq(scenario_sessions.user_id, p.userId), [desc(scenario_sessions.updated_at)])).slice(0, 5);
  const attempts = (await u.all(assessment_attempts, eq(assessment_attempts.user_id, p.userId), [desc(assessment_attempts.id)])).slice(0, 10);
  const labs = (await u.all(lab_exercise_results, eq(lab_exercise_results.user_id, p.userId), [desc(lab_exercise_results.id)])).slice(0, 10);
  const pathway = cur.pathways.find((x: Json) => x.selected);
  const nxt = cur.lessons.find((x: Json) => pathway.lessons.includes(x.id) && x.available && !x.completed)
    ?? cur.lessons.find((x: Json) => x.available && !x.completed) ?? null;
  const proficiency = cur.modules.map((m: Json) => ({ module: m.id, title: m.title, completed: m.lessons_completed, total: m.lessons_total,
    percent: m.lessons_total ? Math.round(100 * m.lessons_completed / m.lessons_total) : 0 }));
  const allSessionIds = (await u.all(scenario_sessions, eq(scenario_sessions.user_id, p.userId))).map((s) => s.id);
  const unverified = allSessionIds.length
    ? await u.count(remediation_actions, inArray(remediation_actions.session_id, allSessionIds), eq(remediation_actions.status, "VERIFICATION_FAILED"))
    : 0;
  return {
    user: { display_name: p.displayName, role: p.role },
    pathway, levels: cur.levels.map((lv: Json) => ({ id: lv.id, title: lv.title, unlocked: lv.unlocked, lessons_total: lv.lessons_total,
      lessons_completed: lv.lessons_completed })),
    next_lesson: nxt, proficiency, latest_assessment_categories: attempts[0]?.category_scores ?? {},
    recommendations: attempts[0]?.recommendations ?? [], unverified_remediations: unverified,
    recent_sessions: sessions.map((s) => ({ id: s.id, scenario_id: s.scenario_id, status: s.status, mode: s.mode, attempt_number: s.attempt_number,
      updated_at: iso(s.updated_at) })),
    recent_attempts: attempts.map((a) => ({ id: a.id, session_id: a.session_id, score: a.total_score, passed: a.passed, mode: a.mode,
      submitted_at: iso(a.submitted_at) })),
    recent_labs: labs.map((r) => ({ lab: r.lab, exercise: r.exercise, passed: r.passed, provenance: r.provenance, created_at: iso(r.created_at) })),
  };
}
