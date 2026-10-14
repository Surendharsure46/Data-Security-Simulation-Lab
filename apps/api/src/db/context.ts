/**
 * Request context (AsyncLocalStorage): the current principal and the unit of work bound to the request's
 * transaction. API requests run as the restricted role `threatready_app` with app.user_id / app.org_id / app.staff
 * set for the row-level security policies. The worker and start-up tasks run as the table owner ("system").
 */
import { AsyncLocalStorage } from "node:async_hooks";
import { sql } from "drizzle-orm";
import type { Database, Db } from "./client.js";
import { UnitOfWork } from "./uow.js";

export type PlatformRole = "learner" | "instructor" | "admin";

export interface Principal {
  userId: string;
  sessionId: string;
  orgId: number;
  role: PlatformRole;
  staff: boolean;
  email: string;
  displayName: string;
  mfaVerified: boolean;
}

interface Ctx {
  uow: UnitOfWork;
  tx: Db;
  principal?: Principal;
}

const als = new AsyncLocalStorage<Ctx>();
let database: Database | null = null;
let restrictedRole = true;

export function setDatabase(d: Database): void {
  database = d;
}

/**
 * Check that this database user can switch to threatready_app (needs the role and membership). If not, API requests run
 * without the role switch: application checks still apply, but the row-level security backstop does not.
 */
export async function probeRestrictedRole(d: Database): Promise<boolean> {
  try {
    await d.db.transaction(async (t) => {
      await (t as unknown as Db).execute(sql`set local role threatready_app`);
    });
    restrictedRole = true;
  } catch {
    restrictedRole = false;
  }
  return restrictedRole;
}

export function getDatabase(): Database {
  if (!database) throw new Error("Database not initialised");
  return database;
}

export function uow(): UnitOfWork {
  const c = als.getStore();
  if (!c) throw new Error("No request context: domain code must run inside runInRequest/runAsSystem");
  return c.uow;
}

export function tx(): Db {
  return uow().db;
}

export function currentPrincipal(): Principal | undefined {
  return als.getStore()?.principal;
}

async function run<T>(principal: Principal | undefined, restricted: boolean, fn: () => Promise<T>): Promise<T> {
  const existing = als.getStore();
  if (existing) return fn(); // nested call: reuse the surrounding transaction
  return getDatabase().db.transaction(async (t) => {
    const txDb = t as unknown as Db;
    if (restricted && restrictedRole) {
      await txDb.execute(sql`select set_config('app.user_id', ${principal?.userId ?? ""}, true),
        set_config('app.org_id', ${principal ? String(principal.orgId) : ""}, true),
        set_config('app.staff', ${principal?.staff ? "true" : "false"}, true)`);
      await txDb.execute(sql`set local role threatready_app`);
    }
    const ctx: Ctx = { uow: new UnitOfWork(txDb), tx: txDb, principal };
    return als.run(ctx, async () => {
      const result = await fn();
      await ctx.uow.flush();
      return result;
    });
  });
}

/** API request: restricted role + RLS settings for the principal (or an anonymous principal for public routes). */
export function runInRequest<T>(principal: Principal | undefined, fn: () => Promise<T>): Promise<T> {
  return run(principal, true, fn);
}

/** Worker jobs, start-up seeding and test setup: table owner, RLS not applied. */
export function runAsSystem<T>(fn: () => Promise<T>, principal?: Principal): Promise<T> {
  return run(principal, false, fn);
}
