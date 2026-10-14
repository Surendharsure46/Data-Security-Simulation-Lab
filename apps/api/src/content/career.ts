/**
 * Learning-journey content (data in data/career.json): welcome, platform overview, roles, Levels 0-5, missions
 * (labs), knowledge checks and skills.
 *
 *   Welcome page -> Let's Get Started -> platform overview + choose a role -> sign up / sign in ->
 *   Level 0..5 = fundamentals -> knowledge check -> hands-on labs (Understand -> Inspect -> Act -> Observe ->
 *   Validate -> Submit) -> server-side assessment -> skills recorded or skill gaps + retry -> level complete ->
 *   congratulations popup -> next level unlocked automatically.
 *
 * Comprehension and knowledge-check answers never leave the server. `validateCareerContent` cross-checks every
 * reference at start-up and in tests.
 */
import data from "./data/career.json" with { type: "json" };
import { LESSONS } from "./curriculum.js";

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

export interface Question { q: string; options: string[]; answer: number }
export interface BusinessProblem { statement: string; stakes: string[]; success_looks_like: string[]; questions: Question[] }
export interface MissionExercise { exercise: string; phase: string; title: string; steps: string[] }
export interface DemoItem { key: string; phase: string; title: string; steps: string[] }
export interface Mission {
  kind: "SCENARIO" | "LAB" | "DEMO";
  level: number;
  title: string;
  assigned_by: string;
  business_problem: BusinessProblem;
  min_explanation?: number;
  scenario_id?: string;
  mode?: "GUIDED" | "ASSESSMENT";
  min_score?: number;
  required_criteria?: ({ criterion: string; min_fraction: number } | { category: string; min_percent: number })[];
  lab?: string;
  exercises?: MissionExercise[];
  items?: DemoItem[];
}
export interface JourneyLevel {
  level: number;
  title: string;
  icon: string;
  summary: string;
  before_you_start: string[];
  responsibilities: string[];
  challenge: string;
  intro_items: { type: "briefing" | "text"; key: string; title: string; body?: string }[];
  missions: string[];
}
export interface Role { key: string; title: string; icon: string; summary: string; focus: string[] }
export interface Skill { name: string; description: string; lessons: string[] }

export const PHASES = data.phases as { key: string; title: string; summary: string }[];
export const PHASE_KEYS = PHASES.map((p) => p.key);
export const WELCOME = data.welcome as Json;
export const PLATFORM = data.platform as Json;
export const ROLES = data.roles as Role[];
export const ROLE_KEYS = ROLES.map((r) => r.key);
export const RANKS = data.ranks as string[];
export const ORGANIZATION = data.organization as Json;
export const DEMO = data.demo as Json & {
  record: string; expected_label: string; label_feedback: Record<string, string>; completion: string[];
  labels: { key: string; name: string; rank: number; description: string }[];
  destinations: { key: string; name: string; category: string; kind: string; sanctioned: boolean; internal: boolean }[];
  policy: Json;
};
export const DEMO_STEPS = data.demo_steps as DemoItem[];
export const SKILLS = data.skills as Record<string, Skill>;
export const CRITERION_SKILLS = data.criterion_skills as Record<string, string>;
export const LAB_ROUTES = data.lab_routes as Record<string, string>;
export const LAB_SKILLS = data.lab_skills as Record<string, string>;
const EXERCISE_LESSONS_RAW = data.exercise_lessons as Record<string, string>;
export const MISSIONS = data.missions as unknown as Record<string, Mission>;
export const LEVEL_CHECKS = Object.fromEntries(Object.entries(data.level_checks).map(([k, v]) => [Number(k), v])) as Record<number, Question[]>;
export const LEVELS = data.levels as unknown as JourneyLevel[];
export const TOP_LEVEL = LEVELS[LEVELS.length - 1].level;
export const JOURNEY_COMPLETE = TOP_LEVEL + 1; // pending_promotion value meaning "all six levels complete"

export function exerciseLesson(lab: string, exercise: string): string | undefined {
  return EXERCISE_LESSONS_RAW[`${lab}:${exercise}`];
}

export function roleTitle(roleKey: string | null | undefined, level: number): string {
  const role = ROLES.find((r) => r.key === roleKey) ?? ROLES[0];
  return `${RANKS[level]} ${role.title}`.trim();
}

export function levelDef(level: number): JourneyLevel | undefined {
  return LEVELS.find((lv) => lv.level === level);
}

export function checkId(level: number): string {
  return `LEVEL-L${level}`;
}

/** Cross-check every reference. Throws on the first problem. */
export async function validateCareerContent(): Promise<void> {
  const { LAB_EXERCISES } = await import("../labs/registry.js");
  const { getDefinition } = await import("../domain/scenario-defs.js");
  const lessonIds = new Set(LESSONS.map((x) => x.id));
  const fail = (m: string) => { throw new Error(m); };
  for (const [key, skill] of Object.entries(SKILLS)) for (const l of skill.lessons) if (!lessonIds.has(l)) fail(`Skill ${key} references unknown lesson ${l}`);
  for (const role of ROLES) for (const sk of role.focus) if (!(sk in SKILLS)) fail(`Role ${role.key} references unknown skill ${sk}`);
  if (LEVELS.map((l) => l.level).join(",") !== "0,1,2,3,4,5" || RANKS.length !== 6) fail("Levels must be exactly 0..5");
  for (const lv of LEVELS) {
    const qs = LEVEL_CHECKS[lv.level];
    if (!qs?.length || qs.some((q) => q.answer < 0 || q.answer >= q.options.length)) fail(`Level ${lv.level} knowledge check missing or invalid`);
    if (!LESSONS.some((x) => x.level === `L${lv.level}`)) fail(`Level ${lv.level} has no fundamentals lessons`);
  }
  for (const l of Object.values(EXERCISE_LESSONS_RAW)) if (!lessonIds.has(l)) fail(`Exercise lesson ${l} unknown`);
  const listed = LEVELS.flatMap((lv) => lv.missions);
  if ([...listed].sort().join() !== Object.keys(MISSIONS).sort().join() || new Set(listed).size !== listed.length) fail("Every mission must appear in exactly one level");
  for (const [mid, m] of Object.entries(MISSIONS)) {
    if (!levelDef(m.level)?.missions.includes(mid)) fail(`Mission ${mid} level mismatch`);
    for (const q of m.business_problem.questions) if (q.answer < 0 || q.answer >= q.options.length) fail(`Mission ${mid} has an invalid answer index`);
    if (m.kind === "SCENARIO") {
      const d = getDefinition(m.scenario_id!);
      if (!d) fail(`Mission ${mid} references unknown scenario ${m.scenario_id}`);
      const crit = new Set(d!.rubric.criteria.map((c) => c.key));
      for (const rc of m.required_criteria ?? []) {
        if ("criterion" in rc && !crit.has(rc.criterion)) fail(`Mission ${mid} requires unknown criterion ${rc.criterion}`);
        if ("category" in rc && !(rc.category in d!.rubric.categories)) fail(`Mission ${mid} requires unknown category ${rc.category}`);
      }
      for (const c of d!.rubric.criteria) if (!(c.key in CRITERION_SKILLS)) fail(`Criterion ${c.key} of ${d!.id} has no skill mapping`);
    } else if (m.kind === "LAB") {
      const lab = LAB_EXERCISES[m.lab!];
      if (!lab || !(m.lab! in LAB_ROUTES)) fail(`Mission ${mid} references unknown lab ${m.lab}`);
      for (const ex of m.exercises ?? []) {
        if (!lab.exercises.includes(ex.exercise)) fail(`Mission ${mid} references unknown exercise ${ex.exercise}`);
        if (!PHASE_KEYS.includes(ex.phase) || ["UNDERSTAND", "SUBMIT"].includes(ex.phase)) fail(`Mission ${mid} exercise ${ex.exercise} has invalid phase`);
        if (!exerciseLesson(m.lab!, ex.exercise)) fail(`Mission ${mid} exercise ${ex.exercise} has no lesson`);
      }
    } else if (m.kind === "DEMO") {
      if ((m.items ?? []).map((i) => i.key).join() !== DEMO.completion.join()) fail(`Mission ${mid} demo items must match the demo completion steps`);
    } else fail(`Mission ${mid} has unknown kind`);
  }
}
