/**
 * Application factory shared by main.ts (api / worker / all roles), the CLI and the test suite.
 */
import "reflect-metadata";
import { existsSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import { Logger, type LogLevel } from "@nestjs/common";
import { NestFactory } from "@nestjs/core";
import type { NestExpressApplication } from "@nestjs/platform-express";
import { toNodeHandler } from "better-auth/node";
import { eq } from "drizzle-orm";
import express, { type NextFunction, type Request, type Response } from "express";
import { AppModule, CONTROLLERS } from "./app.module.js";
import { getConfig } from "./config.js";
import { validateCareerContent } from "./content/career.js";
import { createDatabase, type Database } from "./db/client.js";
import { getDatabase, probeRestrictedRole, setDatabase } from "./db/context.js";
import { user } from "./db/schema.js";
import { allDefinitions } from "./domain/scenario-defs.js";
import { createAuth, getAuth, IDENTITY_BASE_PATH } from "./platform/auth.js";
import { mountOpenApi } from "./platform/openapi.js";

const API_CSP = "default-src 'none'; frame-ancestors 'none'";
const UI_CSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
  + "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";
const UNSAFE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/** Open the database, apply pending migrations (unless THREATREADY_MIGRATE_ON_START=false), initialise identity and validate content. */
export async function initPlatform(opts: { database?: Database; migrate?: boolean } = {}): Promise<Database> {
  const cfg = getConfig();
  const database = opts.database ?? createDatabase(cfg.databaseUrl);
  if (opts.migrate ?? cfg.migrateOnStart) await database.migrate();
  setDatabase(database);
  if (!(await probeRestrictedRole(database))) {
    new Logger("Database").warn("Cannot switch to role threatready_app (missing CREATEROLE or membership); row-level security is NOT enforced. "
      + "Run as a database owner with CREATEROLE, or grant the role: GRANT threatready_app TO <app user>.");
  }
  createAuth(database);
  allDefinitions(); // fail fast on an invalid scenario definition
  await validateCareerContent(); // and on a broken mission / skill reference
  return database;
}

/** Create (or promote) the bootstrap administrator when THREATREADY_BOOTSTRAP_ADMIN_PASSWORD is set. */
export async function ensureBootstrapAdmin(): Promise<void> {
  const cfg = getConfig();
  if (!cfg.bootstrapAdminPassword) return;
  const db = getDatabase().db;
  const existing = (await db.select().from(user).where(eq(user.email, cfg.bootstrapAdminEmail)).limit(1))[0];
  if (!existing) {
    await getAuth().api.signUpEmail({ body: { email: cfg.bootstrapAdminEmail, password: cfg.bootstrapAdminPassword, name: "Administrator" } });
  }
  await db.update(user).set({ role: "admin", is_active: true, emailVerified: true }).where(eq(user.email, cfg.bootstrapAdminEmail));
}

function securityHeaders(req: Request, res: Response, next: NextFunction): void {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  if (getConfig().production) res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  if (req.path.startsWith("/api/")) {
    // Handlers may replace this with a per-response policy (HTML reports).
    res.setHeader("Content-Security-Policy", API_CSP);
    res.setHeader("Cache-Control", "no-store");
  } else {
    res.setHeader("Content-Security-Policy", UI_CSP);
  }
  next();
}

/**
 * Cross-site request forgery defence for cookie sessions: SameSite=Lax cookies plus an Origin check on every
 * state-changing request. Browsers always send Origin on cross-origin fetches; non-browser clients send none.
 */
function originCheck(req: Request, res: Response, next: NextFunction): void {
  if (UNSAFE_METHODS.has(req.method) && req.path.startsWith("/api/")) {
    const origin = req.headers.origin;
    if (origin) {
      const host = req.headers.host;
      const sameHost = host !== undefined && (origin === `http://${host}` || origin === `https://${host}`);
      if (!sameHost && !getConfig().trustedOrigins.includes(origin)) {
        res.status(403).json({ detail: "Cross-origin request refused" });
        return;
      }
    }
  }
  next();
}

export async function createApp(opts: { logger?: LogLevel[] | false } = {}): Promise<NestExpressApplication> {
  const cfg = getConfig();
  const app = await NestFactory.create<NestExpressApplication>(AppModule, {
    bodyParser: false,
    logger: opts.logger ?? (cfg.env === "test" ? false : ["error", "warn", "log"]),
  });
  if (cfg.production) app.set("trust proxy", 1); // behind the ALB
  app.disable("x-powered-by");
  app.use(securityHeaders);
  app.use(originCheck);

  // Better Auth's own endpoints (session, two-factor, password change). Public sign-up is closed here: registration goes
  // through POST /api/auth/register so the self-registration policy and validation apply.
  const identity = toNodeHandler(getAuth());
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (!req.path.startsWith(`${IDENTITY_BASE_PATH}/`)) return next();
    if (req.path.startsWith(`${IDENTITY_BASE_PATH}/sign-up`)) {
      res.status(404).json({ detail: "Not Found" });
      return;
    }
    void identity(req, res);
  });

  app.use(express.json({ limit: "1mb" }));
  if (!cfg.production) mountOpenApi(app, CONTROLLERS);

  const dist = resolve(cfg.frontendDist);
  if (existsSync(join(dist, "index.html"))) {
    app.use("/assets", express.static(join(dist, "assets"), { immutable: true, maxAge: "1y", index: false }));
    app.use((req: Request, res: Response, next: NextFunction) => {
      if (req.method !== "GET" || req.path.startsWith("/api/") || req.path === "/api") return next();
      const candidate = resolve(dist, `.${decodeURIComponent(req.path)}`);
      if (req.path !== "/" && candidate.startsWith(dist + sep) && existsSync(candidate) && !candidate.endsWith(sep)) return res.sendFile(candidate);
      return res.sendFile(join(dist, "index.html"));
    });
  } else if (cfg.production) {
    new Logger("Server").warn(`Frontend build not found at ${dist}; serving the API only`);
  }
  await app.init();
  return app;
}
