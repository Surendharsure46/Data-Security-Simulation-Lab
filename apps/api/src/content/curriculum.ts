/**
 * Curriculum content: levels, modules, lessons, pathways and knowledge checks (data in data/curriculum.json).
 * Lesson completion is always tied to a server-verified activity (scenario task, lab exercise or graded knowledge
 * check). Reading a lesson never completes it. Module `status` is an honest implementation status shown in the UI.
 */
import data from "./data/curriculum.json" with { type: "json" };

export const REF = "customer-data-export";

export interface LessonCheck {
  type: "scenario_task" | "lab_exercise" | "policy_test_suite_run" | "policy_test_suite_runs" | "change_record" | "assessment_passed";
  scenario?: string;
  task?: string;
  lab?: string;
  exercise?: string;
  count?: number;
  mode?: string;
}
export interface Lesson {
  id: string;
  module: string;
  level: string;
  title: string;
  body: string;
  practice: string;
  check: LessonCheck;
}
export interface Module { id: string; title: string; route: string; status: string; mode: string; summary: string }
export interface CurriculumLevel {
  id: string;
  title: string;
  prerequisites: string[];
  objectives: string[];
  practical_tasks: string[];
  scenario_variations: string[];
  required_evidence: string[];
  rubric: string;
  critical_failures: string[];
  remediation: string[];
  unlock: { requires: string[]; min_lessons_in_previous: number };
}
export interface Pathway { id: string; title: string; audience: string; lessons: string[] }
export interface QuizQuestion { q: string; options: string[]; answer: number }

export const MODULES = data.modules as Module[];
export const LESSONS = data.lessons as Lesson[];
export const LEVELS = data.levels as CurriculumLevel[];
export const PATHWAYS = data.pathways as Pathway[];
// Knowledge checks. Correct answers never leave the server.
export const QUIZZES = data.quizzes as Record<string, QuizQuestion[]>;
