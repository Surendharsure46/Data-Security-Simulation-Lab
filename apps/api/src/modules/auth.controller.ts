/**
 * Threatready auth wrappers over Better Auth. Registration and login go through here so request validation, the
 * self-registration policy, login throttling and the audit trail stay in one place. Session cookies are set by Better Auth
 * and forwarded unchanged (httpOnly, SameSite=Lax, Secure in production).
 */
import { Controller, Get, HttpException, Req, Res } from "@nestjs/common";
import { LoginIn, RegisterIn } from "@threatready/contracts";
import { eq } from "drizzle-orm";
import type { Request, Response } from "express";
import { z } from "zod";
import { audit } from "../common/audit.js";
import { getConfig } from "../config.js";
import { getDatabase, type Principal, runAsSystem } from "../db/context.js";
import { user } from "../db/schema.js";
import { getAuth, resolvePrincipal, userOut } from "../platform/auth.js";
import { CurrentPrincipal, NoTransaction, Permission, PERMISSIONS, PostCreated, PostOk, Public, toHeaders, ZBody } from "../platform/http.js";

/** In-memory sliding-window limiter (per process). The API tier also has the global Nest throttler. */
class RateLimiter {
  private hits = new Map<string, number[]>();

  check(key: string, limit: number, windowMs = 60_000): boolean {
    const now = Date.now();
    const q = (this.hits.get(key) ?? []).filter((t) => now - t < windowMs);
    if (q.length >= limit) {
      this.hits.set(key, q);
      return false;
    }
    q.push(now);
    this.hits.set(key, q);
    if (this.hits.size > 50_000) this.hits.clear(); // bound memory under abuse
    return true;
  }

  reset(): void {
    this.hits.clear();
  }
}

export const loginLimiter = new RateLimiter();

function forwardCookies(from: globalThis.Response, res: Response): void {
  const cookies = from.headers.getSetCookie();
  if (cookies.length) res.setHeader("Set-Cookie", cookies);
}

const clientIp = (req: Request) => req.ip ?? req.socket.remoteAddress ?? "unknown";

async function findUserByEmail(email: string) {
  return (await getDatabase().db.select().from(user).where(eq(user.email, email)).limit(1))[0];
}

@Controller("api/auth")
@NoTransaction()
export class AuthController {
  @PostCreated("register")
  @Public()
  async register(@ZBody(RegisterIn) body: z.infer<typeof RegisterIn>, @Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const cfg = getConfig();
    if (!cfg.allowSelfRegistration) throw new HttpException("Self-registration is disabled; ask an administrator for an account", 403);
    if (!loginLimiter.check(`register:${clientIp(req)}`, cfg.loginRateLimitPerMinute)) {
      throw new HttpException("Too many attempts; wait a minute and try again", 429);
    }
    if (await findUserByEmail(body.email)) throw new HttpException("An account with this email already exists", 409);
    const r = await getAuth().api.signUpEmail({ body: { email: body.email, password: body.password, name: body.display_name }, headers: toHeaders(req),
      asResponse: true });
    if (!r.ok) {
      if (r.status === 422 || r.status === 400) throw new HttpException("An account with this email already exists", 409);
      throw new HttpException("Registration failed", r.status >= 500 ? 500 : r.status);
    }
    forwardCookies(r, res);
    const created = await findUserByEmail(body.email);
    await runAsSystem(() => audit({ user_id: created!.id, org_id: created!.org_id, action: "user.register", target_type: "user", target_id: created!.id }));
    const p = await principalFromCookies(r);
    // With email verification on, no session exists until the emailed link is opened.
    return { user: p ? userOut(p) : null, verification_required: !p && cfg.requireEmailVerification };
  }

  @PostOk("login")
  @Public()
  async login(@ZBody(LoginIn) body: z.infer<typeof LoginIn>, @Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const limit = getConfig().loginRateLimitPerMinute;
    if (!(loginLimiter.check(`login-ip:${clientIp(req)}`, limit * 3) && loginLimiter.check(`login-user:${body.email}`, limit))) {
      throw new HttpException("Too many login attempts; wait a minute and try again", 429);
    }
    const u = await findUserByEmail(body.email);
    const r = await getAuth().api.signInEmail({ body: { email: body.email, password: body.password }, headers: toHeaders(req), asResponse: true });
    if (r.status === 403 && u?.is_active) throw new HttpException("Verify your email address first: open the link we sent you", 403);
    if (!r.ok || !u || !u.is_active) {
      if (u) await runAsSystem(() => audit({ user_id: u.id, org_id: u.org_id, action: "auth.login_failed", target_type: "user", target_id: u.id }));
      if (r.ok) await revoke(r); // deactivated account: discard the session Better Auth just created
      throw new HttpException("Invalid email or password", 401);
    }
    forwardCookies(r, res);
    const payload = (await r.clone().json().catch(() => ({}))) as { twoFactorRedirect?: boolean };
    if (payload.twoFactorRedirect) return { two_factor_required: true, user: null };
    await runAsSystem(() => audit({ user_id: u.id, org_id: u.org_id, action: "auth.login", target_type: "user", target_id: u.id }));
    const p = await principalFromCookies(r);
    return { two_factor_required: false, user: p ? userOut(p) : null };
  }

  @PostOk("logout")
  @Permission(PERMISSIONS.SELF)
  async logout(@CurrentPrincipal() p: Principal, @Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const r = await getAuth().api.signOut({ headers: toHeaders(req), asResponse: true });
    forwardCookies(r, res);
    await runAsSystem(() => audit({ user_id: p.userId, org_id: p.orgId, action: "auth.logout" }));
    return { ok: true };
  }

  @Get("me")
  @Permission(PERMISSIONS.SELF)
  me(@CurrentPrincipal() p: Principal) {
    return userOut(p);
  }

  @Get("config")
  @Public()
  authConfig() {
    const cfg = getConfig();
    return { self_registration: cfg.allowSelfRegistration, email_verification_required: cfg.requireEmailVerification,
      staff_mfa_required: cfg.requireStaffMfa, identity_base_path: "/api/identity" };
  }
}

async function principalFromCookies(r: globalThis.Response): Promise<Principal | null> {
  const cookie = r.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
  return cookie ? resolvePrincipal(new Headers({ cookie })) : null;
}

async function revoke(r: globalThis.Response): Promise<void> {
  const cookie = r.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
  if (cookie) await getAuth().api.signOut({ headers: new Headers({ cookie }) }).catch(() => undefined);
}
