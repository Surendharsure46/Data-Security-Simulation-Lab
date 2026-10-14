/**
 * Identity: Better Auth, in-process, with users, sessions and password hashes in our own PostgreSQL database.
 *
 * - Email + password accounts; passwords hashed with scrypt (Better Auth default).
 * - Sessions are opaque tokens in httpOnly cookies (SameSite=Lax; Secure in production). No bearer tokens.
 * - TOTP two-factor plugin; staff accounts must enrol when THREATREADY_REQUIRE_STAFF_MFA is on.
 * - Better Auth's own endpoints are mounted at /api/identity (session, two-factor, password change). Registration and
 *   login go through the Threatready wrappers at /api/auth/* so validation, self-registration policy and the audit trail
 *   stay in one place.
 */
import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { twoFactor } from "better-auth/plugins";
import { asc, eq } from "drizzle-orm";
import { getConfig } from "../config.js";
import { getPorts } from "../ports/index.js";
import type { Database } from "../db/client.js";
import type { PlatformRole, Principal } from "../db/context.js";
import { account, organizations, session, twoFactor as twoFactorTable, user, verification } from "../db/schema.js";

export const IDENTITY_BASE_PATH = "/api/identity";
export const STAFF_ROLES: PlatformRole[] = ["instructor", "admin"];

function build(database: Database) {
  const cfg = getConfig();
  return betterAuth({
    appName: "Threatready",
    secret: cfg.authSecret,
    baseURL: cfg.publicUrl,
    basePath: IDENTITY_BASE_PATH,
    trustedOrigins: cfg.trustedOrigins,
    database: drizzleAdapter(database.db, {
      provider: "pg",
      schema: { user, session, account, verification, twoFactor: twoFactorTable },
    }),
    emailAndPassword: {
      enabled: true,
      minPasswordLength: 10,
      maxPasswordLength: 128,
      autoSignIn: true,
      requireEmailVerification: cfg.requireEmailVerification,
    },
    emailVerification: {
      sendOnSignUp: cfg.requireEmailVerification,
      autoSignInAfterVerification: true,
      // Delivered through the MailPort (console in development; the SES adapter is a stub in this release).
      sendVerificationEmail: async ({ user: u, url }) => {
        await getPorts().mail.send({ to: u.email, subject: "Verify your Threatready email address",
          text: `Open this link to verify your email address and activate your account:
${url}

If you did not sign up, ignore this message.` });
      },
    },
    user: {
      additionalFields: {
        role: { type: "string", required: false, input: false, defaultValue: "learner" },
        org_id: { type: "number", required: false, input: false },
        is_active: { type: "boolean", required: false, input: false, defaultValue: true },
      },
    },
    session: { expiresIn: 60 * 60 * 12, updateAge: 60 * 60 },
    // In-app limiter for Better Auth's own endpoints; the /api/auth wrappers are limited by the Nest throttler.
    rateLimit: { enabled: cfg.production, window: 60, max: cfg.apiRateLimitPerMinute },
    advanced: {
      cookiePrefix: "threatready",
      useSecureCookies: cfg.production,
      defaultCookieAttributes: { httpOnly: true, sameSite: "lax" },
    },
    databaseHooks: {
      user: {
        create: {
          before: async (u) => ({ data: { ...u, org_id: (u as { org_id?: number }).org_id ?? (await defaultOrganizationId(database)) } }),
        },
      },
    },
    plugins: [twoFactor({ issuer: "Threatready" })],
  });
}

export type Auth = ReturnType<typeof build>;
let instance: Auth | null = null;

export function createAuth(database: Database): Auth {
  instance = build(database);
  return instance;
}

export function getAuth(): Auth {
  if (!instance) throw new Error("Auth not initialised");
  return instance;
}

/** The default organization (created on first use). Single-tenant deployments have exactly one. */
export async function defaultOrganizationId(database: Database): Promise<number> {
  const rows = await database.db.select().from(organizations).orderBy(asc(organizations.id)).limit(1);
  if (rows[0]) return rows[0].id;
  const created = await database.db.insert(organizations).values({ name: getConfig().defaultOrganization, slug: "default" })
    .onConflictDoNothing().returning();
  if (created[0]) return created[0].id;
  return (await database.db.select().from(organizations).where(eq(organizations.slug, "default")))[0].id;
}

interface SessionUser { id: string; email: string; name: string; role?: string | null; org_id?: number | null; is_active?: boolean | null;
  twoFactorEnabled?: boolean | null }

/** Resolve the caller from the session cookie. Returns null for anonymous, expired or deactivated users. */
export async function resolvePrincipal(headers: Headers): Promise<Principal | null> {
  const res = await getAuth().api.getSession({ headers });
  if (!res) return null;
  const u = res.user as unknown as SessionUser;
  if (u.is_active === false || u.org_id === null || u.org_id === undefined) return null;
  const role = (["learner", "instructor", "admin"].includes(u.role ?? "") ? u.role : "learner") as PlatformRole;
  return {
    userId: u.id, sessionId: res.session.id, orgId: u.org_id, role, staff: STAFF_ROLES.includes(role), email: u.email, displayName: u.name,
    // With the two-factor plugin a session only exists after the second factor was verified.
    mfaVerified: Boolean(u.twoFactorEnabled),
  };
}

export function userOut(p: Principal) {
  return { id: p.userId, email: p.email, display_name: p.displayName, role: p.role, org_id: p.orgId, mfa_enabled: p.mfaVerified };
}
