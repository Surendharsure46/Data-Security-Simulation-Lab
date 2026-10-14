/** Migrations (schema + row-level security backstop) and the background worker's jobs. */
import { mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { PGlite } from "@electric-sql/pglite";
import { describe, expect, it } from "vitest";
import { getConfig } from "../src/config.js";
import { fromPglite } from "../src/db/client.js";
import { cleanupLabFiles, QUEUES, startWorker } from "../src/worker/jobs.js";
import { useApp } from "./helpers.js";

const OWNED_TABLES = [
  "scenario_sessions", "scenario_actions", "sim_identities", "sim_groups", "data_assets", "access_grants", "destinations", "classification_labels",
  "classification_rules", "discovery_scans", "classification_findings", "classification_assignments", "policies", "policy_versions",
  "policy_evaluations", "policy_test_runs", "change_records", "security_events", "alerts", "investigation_cases", "case_notes",
  "evidence_references", "remediation_actions", "assessment_attempts", "lab_exercise_results", "lab_states", "learner_profiles",
  "mission_attempts", "skill_records",
];

describe("migrations", () => {
  it("apply cleanly, are idempotent and enable row-level security on every owned table", async () => {
    const client = new PGlite();
    const db = fromPglite(client);
    await db.migrate();
    await db.migrate(); // already applied: no-op
    const rows = (await db.executeSql("select relname, relrowsecurity from pg_class where relkind = 'r' and relnamespace = 'public'::regnamespace")).rows as
      { relname: string; relrowsecurity: boolean }[];
    const rls = new Map(rows.map((r) => [r.relname, r.relrowsecurity]));
    for (const t of OWNED_TABLES) expect(rls.get(t), t).toBe(true);
    const role = (await db.executeSql("select rolcanlogin from pg_roles where rolname = 'threatready_app'")).rows[0] as { rolcanlogin: boolean };
    expect(role.rolcanlogin).toBe(false);
    await client.close();
  });
});

describe("worker jobs", () => {
  const t = useApp();

  it("removes lab directories of users that no longer exist", async () => {
    const h = await t.register("learner1");
    await h.post("/api/labs/database/reset");
    const root = getConfig().labDataDir;
    const orphan = join(root, "user-deletedUser123");
    mkdirSync(join(orphan, "database"), { recursive: true });
    const r = await cleanupLabFiles(t.database);
    expect(r.removed).toContain("user-deletedUser123");
    expect(existsSync(orphan)).toBe(false);
    const me = (await h.get("/api/auth/me")).body;
    expect(existsSync(join(root, `user-${me.id}`))).toBe(true);
  });

  it("pg-boss installs on the same database and runs the cleanup job", async () => {
    const boss = await startWorker(t.database);
    try {
      const id = (await boss.send(QUEUES.LAB_CLEANUP, {}))!;
      let state: string | undefined;
      for (let i = 0; i < 40 && state !== "completed"; i++) {
        await new Promise((r) => setTimeout(r, 250));
        state = (await boss.getJobById(QUEUES.LAB_CLEANUP, id))?.state;
      }
      expect(state).toBe("completed");
    } finally {
      await boss.stop({ graceful: false });
    }
  });
});
