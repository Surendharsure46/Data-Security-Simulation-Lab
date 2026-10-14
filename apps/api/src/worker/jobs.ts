/**
 * Background jobs (pg-boss on the same PostgreSQL database; no extra infrastructure). The worker role runs them; the api
 * role only enqueues. Jobs run as the table owner, outside row-level security, and must never act on user input directly.
 */
import { existsSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { Logger } from "@nestjs/common";
import { inArray } from "drizzle-orm";
import { PgBoss } from "pg-boss";
import { getConfig } from "../config.js";
import type { Database } from "../db/client.js";
import { user } from "../db/schema.js";

export const QUEUES = { LAB_CLEANUP: "maintenance.lab-cleanup" } as const;
const log = new Logger("Worker");

/** Remove lab directories whose owner no longer exists (account deleted). */
export async function cleanupLabFiles(database: Database): Promise<{ removed: string[] }> {
  const root = getConfig().labDataDir;
  if (!existsSync(root)) return { removed: [] };
  const dirs = readdirSync(root, { withFileTypes: true }).filter((d) => d.isDirectory() && /^user-[A-Za-z0-9_-]+$/.test(d.name));
  const ids = dirs.map((d) => d.name.slice("user-".length));
  if (!ids.length) return { removed: [] };
  const live = new Set((await database.db.select({ id: user.id }).from(user).where(inArray(user.id, ids))).map((r) => r.id));
  const removed: string[] = [];
  for (const d of dirs) {
    if (!live.has(d.name.slice("user-".length))) {
      rmSync(join(root, d.name), { recursive: true, force: true });
      removed.push(d.name);
    }
  }
  return { removed };
}

export async function startWorker(database: Database): Promise<PgBoss> {
  const boss = new PgBoss({ db: { executeSql: database.executeSql }, schema: "pgboss" });
  boss.on("error", (e) => log.error(e instanceof Error ? e.message : String(e)));
  await boss.start();
  await boss.createQueue(QUEUES.LAB_CLEANUP);
  await boss.work(QUEUES.LAB_CLEANUP, async () => {
    const r = await cleanupLabFiles(database);
    log.log(`lab cleanup removed ${r.removed.length} orphaned directories`);
    return r;
  });
  await boss.schedule(QUEUES.LAB_CLEANUP, "15 3 * * *");
  log.log("Worker started (pg-boss)");
  return boss;
}
