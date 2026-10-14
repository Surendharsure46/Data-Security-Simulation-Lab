/**
 * Hands-on lab helpers. Each lab keeps per-user state in `lab_states` and records exercise results in
 * `lab_exercise_results` with explicit provenance (REAL_LAB or SIMULATED).
 */
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { and, eq } from "drizzle-orm";
import { getConfig } from "../config.js";
import { DomainError } from "../common/util.js";
import { uow } from "../db/context.js";
import { lab_exercise_results, lab_states } from "../db/schema.js";

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
export type LabStateRow = typeof lab_states.$inferSelect;

/**
 * Per-user lab directory built only from server-side identifiers. Better Auth user ids are random and never reused,
 * so a recreated database cannot hand one user another user's leftover lab files.
 */
export function labDir(userId: string, lab: string): string {
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(userId) || !/^[a-z0-9-]{1,40}$/.test(lab)) throw new DomainError("Invalid lab path", 400);
  const d = join(getConfig().labDataDir, `user-${userId}`, lab);
  mkdirSync(d, { recursive: true });
  return d;
}

/** Get-or-create, safe against two concurrent first requests (unique user_id + lab). */
export async function getState(userId: string, lab: string, dflt: Json): Promise<LabStateRow> {
  const u = uow();
  const where = and(eq(lab_states.user_id, userId), eq(lab_states.lab, lab))!;
  const st = await u.one(lab_states, where);
  if (st) return st;
  await u.db.insert(lab_states).values({ user_id: userId, lab, state: dflt }).onConflictDoNothing();
  return (await u.one(lab_states, where))!;
}

export function setState(st: LabStateRow, changes: Json): void {
  st.state = { ...(st.state ?? {}), ...changes };
  st.updated_at = new Date();
}

export async function recordResult(userId: string, lab: string, exercise: string, passed: boolean, provenance: string, detail: Json): Promise<void> {
  await uow().insert(lab_exercise_results, { user_id: userId, lab, exercise, passed, provenance, detail });
}

export async function passedExercises(userId: string, lab: string): Promise<Set<string>> {
  const rows = await uow().all(lab_exercise_results, and(eq(lab_exercise_results.user_id, userId), eq(lab_exercise_results.lab, lab),
    eq(lab_exercise_results.passed, true)));
  return new Set(rows.map((r) => r.exercise));
}
