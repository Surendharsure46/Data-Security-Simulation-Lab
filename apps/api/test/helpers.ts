/**
 * Test harness: one migrated PGlite template per test file, cloned for every test (fast and fully isolated), a real
 * NestJS application on top, and supertest agents that keep the Better Auth session cookie like a browser does.
 */
import { PGlite } from "@electric-sql/pglite";
import type { NestExpressApplication } from "@nestjs/platform-express";
import request from "supertest";
import { afterAll, afterEach, beforeAll, beforeEach, expect } from "vitest";
import { fromPglite, type Database } from "../src/db/client.js";
import { loginLimiter } from "../src/modules/auth.controller.js";
import { createApp, initPlatform } from "../src/server.js";

export const PASSWORD = "Synthetic-Pass-123";
export type Agent = ReturnType<typeof request.agent>;

export interface TestContext {
  app: NestExpressApplication;
  database: Database;
  /** A new cookie-keeping client (a separate browser). */
  agent(): Agent;
  /** Register a learner and return their signed-in client. */
  register(name: string): Promise<Agent>;
  /** Create a staff user (role set directly in the database) and return their signed-in client. */
  staff(name: string, role: "instructor" | "admin"): Promise<Agent>;
  /** A learner with a GUIDED session on the reference scenario, variant A. */
  sessionA(agent: Agent): Promise<number>;
}

export function useApp(): TestContext {
  let template: PGlite;
  const ctx = {} as TestContext;

  beforeAll(async () => {
    template = new PGlite();
    await fromPglite(template).migrate();
  });

  beforeEach(async () => {
    loginLimiter.reset();
    ctx.database = fromPglite((await template.clone()) as PGlite);
    await initPlatform({ database: ctx.database, migrate: false });
    ctx.app = await createApp({ logger: process.env.TEST_LOG ? ["error", "warn"] : false });
    const server = ctx.app.getHttpServer();
    ctx.agent = () => request.agent(server);
    ctx.register = async (name: string) => {
      const a = ctx.agent();
      const r = await a.post("/api/auth/register").send({ email: `${name}@example.com`, display_name: name, password: PASSWORD });
      expect(r.status, r.text).toBe(201);
      return a;
    };
    ctx.staff = async (name: string, role: "instructor" | "admin") => {
      const a = await ctx.register(name);
      await ctx.database.executeSql(`update "user" set role = $1 where email = $2`, [role, `${name}@example.com`]);
      return a;
    };
    ctx.sessionA = async (a: Agent) => {
      const r = await a.post("/api/sessions").send({ scenario_id: "customer-data-export", mode: "GUIDED", variant: "A" });
      expect(r.status, r.text).toBe(201);
      return r.body.id as number;
    };
  });

  afterEach(async () => {
    await ctx.app?.close();
    await ctx.database?.close();
  });

  afterAll(async () => {
    await template?.close();
  });

  return ctx;
}

/** Call the API and assert the status, returning the parsed body (JSON) or text. */
export async function api(a: Agent, method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE", path: string, body?: unknown,
  expectStatus: number | number[] = [200, 201]): Promise<any> { // eslint-disable-line @typescript-eslint/no-explicit-any
  const m = method.toLowerCase() as "get";
  let req = a[m](path);
  if (body !== undefined) req = req.send(body as object);
  const r = await req;
  const ok = Array.isArray(expectStatus) ? expectStatus : [expectStatus];
  expect(ok, `${method} ${path} -> ${r.status}: ${r.text}`).toContain(r.status);
  return (r.headers["content-type"] ?? "").startsWith("application/json") ? r.body : r.text;
}
