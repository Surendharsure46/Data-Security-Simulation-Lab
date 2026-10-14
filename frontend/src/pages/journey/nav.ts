import { api } from "../../api";
import type { LevelStep, MissionAttempt } from "../../types";

/** Resolve the route for a level step; lab steps start (or resume) the lab attempt first. */
export async function stepRoute(level: number, step: LevelStep): Promise<string> {
  if (step.type === "learn") return `/levels/${level}/learn/${encodeURIComponent(step.key)}`;
  if (step.type === "check") return `/levels/${level}/check`;
  // The latest attempt holds the work in progress, the result or the retry options; otherwise start the lab.
  if (step.latest_attempt && step.latest_attempt.status !== "ABANDONED") return `/missions/${step.latest_attempt.id}`;
  const a = await api.post<MissionAttempt>(`/api/career/missions/${step.key}/start`);
  return `/missions/${a.id}`;
}

export const STEP_ICON: Record<string, string> = { learn: "📘", check: "✅", mission: "🧪" };

export function stepLabel(step: LevelStep) {
  if (step.type === "learn") return "Lesson";
  if (step.type === "check") return "Knowledge check";
  if (step.kind === "SCENARIO") return step.mode === "ASSESSMENT" ? "Simulation lab · independent" : "Simulation lab · guided";
  if (step.kind === "DEMO") return "Interactive lab";
  return `Hands-on lab · ${step.lab}`;
}
