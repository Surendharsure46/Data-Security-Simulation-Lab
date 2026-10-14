/**
 * Configuration from environment variables (prefix THREATREADY_), validated with Zod at start-up.
 * A `.env` file in the repository root or apps/api is loaded by `loadEnvFiles` (development convenience).
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";

export const API_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const REPO_DIR = resolve(API_DIR, "..", "..");

const bool = z.enum(["true", "false", "1", "0"]).transform((v) => v === "true" || v === "1");

const Env = z.object({
  THREATREADY_ENV: z.enum(["development", "test", "production"]).default("development"),
  THREATREADY_ROLE: z.enum(["api", "worker", "all"]).default("all"),
  THREATREADY_PORT: z.coerce.number().int().default(8000),
  THREATREADY_HOST: z.string().default("127.0.0.1"),
  /** postgres://… for PostgreSQL (RDS in production); pglite://<dir> or pglite://memory for the embedded database. */
  THREATREADY_DATABASE_URL: z.string().default(`pglite://${join(API_DIR, "var", "pgdata").replace(/\\/g, "/")}`),
  THREATREADY_LAB_DATA_DIR: z.string().default(join(API_DIR, "var", "labs")),
  THREATREADY_FRONTEND_DIST: z.string().default(join(REPO_DIR, "apps", "web", "dist")),
  /** Public origin of the app (cookies, Better Auth callbacks, CSRF origin check). */
  THREATREADY_PUBLIC_URL: z.string().default("http://localhost:5173"),
  THREATREADY_TRUSTED_ORIGINS: z.string().default("http://localhost:5173,http://127.0.0.1:5173,http://localhost:8000,http://127.0.0.1:8000"),
  THREATREADY_AUTH_SECRET: z.string().min(32).optional(),
  THREATREADY_ALLOW_SELF_REGISTRATION: bool.default(true),
  THREATREADY_REQUIRE_EMAIL_VERIFICATION: bool.optional(),
  THREATREADY_REQUIRE_STAFF_MFA: bool.optional(),
  THREATREADY_LOGIN_RATE_LIMIT_PER_MINUTE: z.coerce.number().int().default(10),
  THREATREADY_API_RATE_LIMIT_PER_MINUTE: z.coerce.number().int().default(600),
  THREATREADY_BOOTSTRAP_ADMIN_EMAIL: z.string().default("admin@threatready.local"),
  THREATREADY_BOOTSTRAP_ADMIN_PASSWORD: z.string().optional(),
  THREATREADY_DEFAULT_ORGANIZATION: z.string().default("Threatready Training Org"),
  THREATREADY_SENTRY_DSN: z.string().optional(),
  THREATREADY_STORAGE_DRIVER: z.enum(["local", "s3"]).default("local"),
  THREATREADY_MAIL_DRIVER: z.enum(["console", "ses"]).default("console"),
  THREATREADY_LLM_DRIVER: z.enum(["none", "anthropic"]).default("none"),
});

export type Config = ReturnType<typeof buildConfig>;

function buildConfig(env: Record<string, string | undefined>) {
  const e = Env.parse(env);
  const production = e.THREATREADY_ENV === "production";
  if (production && !e.THREATREADY_AUTH_SECRET) throw new Error("THREATREADY_AUTH_SECRET (32+ characters) is required in production");
  if (e.THREATREADY_BOOTSTRAP_ADMIN_PASSWORD !== undefined && e.THREATREADY_BOOTSTRAP_ADMIN_PASSWORD.length < 12) {
    throw new Error("THREATREADY_BOOTSTRAP_ADMIN_PASSWORD must be at least 12 characters");
  }
  return {
    env: e.THREATREADY_ENV,
    production,
    role: e.THREATREADY_ROLE,
    port: e.THREATREADY_PORT,
    host: e.THREATREADY_HOST,
    databaseUrl: e.THREATREADY_DATABASE_URL,
    labDataDir: e.THREATREADY_LAB_DATA_DIR,
    frontendDist: e.THREATREADY_FRONTEND_DIST,
    publicUrl: e.THREATREADY_PUBLIC_URL,
    trustedOrigins: e.THREATREADY_TRUSTED_ORIGINS.split(",").map((s) => s.trim()).filter(Boolean),
    // Development secret is only for local use; production refuses to start without a real one.
    authSecret: e.THREATREADY_AUTH_SECRET ?? "threatready-development-secret-not-for-production-use",
    allowSelfRegistration: e.THREATREADY_ALLOW_SELF_REGISTRATION,
    requireEmailVerification: e.THREATREADY_REQUIRE_EMAIL_VERIFICATION ?? production,
    requireStaffMfa: e.THREATREADY_REQUIRE_STAFF_MFA ?? production,
    loginRateLimitPerMinute: e.THREATREADY_LOGIN_RATE_LIMIT_PER_MINUTE,
    apiRateLimitPerMinute: e.THREATREADY_API_RATE_LIMIT_PER_MINUTE,
    bootstrapAdminEmail: e.THREATREADY_BOOTSTRAP_ADMIN_EMAIL.toLowerCase(),
    bootstrapAdminPassword: e.THREATREADY_BOOTSTRAP_ADMIN_PASSWORD,
    defaultOrganization: e.THREATREADY_DEFAULT_ORGANIZATION,
    sentryDsn: e.THREATREADY_SENTRY_DSN,
    storageDriver: e.THREATREADY_STORAGE_DRIVER,
    mailDriver: e.THREATREADY_MAIL_DRIVER,
    llmDriver: e.THREATREADY_LLM_DRIVER,
  };
}

/** Minimal .env loader (KEY=VALUE lines); real environment variables always win. */
export function loadEnvFiles(): void {
  for (const file of [join(REPO_DIR, ".env"), join(API_DIR, ".env")]) {
    if (!existsSync(file)) continue;
    for (const line of readFileSync(file, "utf8").split(/\r?\n/)) {
      const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/.exec(line);
      if (!m || line.trimStart().startsWith("#")) continue;
      const value = m[2].replace(/^["']|["']$/g, "");
      if (process.env[m[1]] === undefined) process.env[m[1]] = value;
    }
  }
}

let cached: Config | null = null;

export function getConfig(): Config {
  if (!cached) cached = buildConfig(process.env);
  return cached;
}

/** Tests override settings per suite. */
export function setConfig(overrides: Partial<Config>): Config {
  cached = { ...getConfig(), ...overrides };
  return cached;
}

export function resetConfig(): void {
  cached = null;
}
