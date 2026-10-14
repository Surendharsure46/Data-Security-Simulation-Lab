/**
 * HTTP platform layer shared by every controller.
 *
 * Authorization chain (fail closed):
 *   identity (Better Auth session cookie) → tenant (user's organization) → role → permission (static map below)
 *   → entitlement (stub: every organization is entitled to every module today) → resource ownership (domain code returns
 *   404, never 403, for objects outside the caller's scope) → row-level security in PostgreSQL as a backstop.
 *
 * Every route must declare `@Permission(...)` or `@Public()`. A route with neither is refused at runtime and fails the
 * route-coverage test in CI.
 */
import {
  applyDecorators, type CallHandler, type CanActivate, createParamDecorator, type ExecutionContext, HttpCode, HttpException, Injectable,
  Logger, type NestInterceptor, Post, SetMetadata, type ArgumentsHost, Catch, type ExceptionFilter,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { ThrottlerException } from "@nestjs/throttler";
import type { Request, Response } from "express";
import { from, lastValueFrom, map, type Observable } from "rxjs";
import { z, ZodError, type ZodType } from "zod";
import { DomainError } from "../common/util.js";
import { type PlatformRole, type Principal, runInRequest } from "../db/context.js";
import { resolvePrincipal } from "./auth.js";
import { getConfig } from "../config.js";

// --------------------------------------------------------------------------- permissions

export const PERMISSIONS = {
  /** Own learning journey, scenario sessions, labs, curriculum. */
  SELF: "self",
  /** Read other learners' sessions, users and the audit log in the same organization. */
  STAFF_READ: "staff.read",
  /** Change users and integrations. */
  ADMIN_MANAGE: "admin.manage",
} as const;
export type PermissionKey = (typeof PERMISSIONS)[keyof typeof PERMISSIONS];

export const ROLE_PERMISSIONS: Record<PlatformRole, PermissionKey[]> = {
  learner: [PERMISSIONS.SELF],
  instructor: [PERMISSIONS.SELF, PERMISSIONS.STAFF_READ],
  admin: [PERMISSIONS.SELF, PERMISSIONS.STAFF_READ, PERMISSIONS.ADMIN_MANAGE],
};
const STAFF_PERMISSIONS = new Set<PermissionKey>([PERMISSIONS.STAFF_READ, PERMISSIONS.ADMIN_MANAGE]);

export const PERMISSION_KEY = "threatready:permission";
export const PUBLIC_KEY = "threatready:public";
export const NO_TX_KEY = "threatready:no-transaction";

export const Permission = (p: PermissionKey) => SetMetadata(PERMISSION_KEY, p);
/** Anonymous access allowed; the principal is still attached when a valid session exists. */
export const Public = () => SetMetadata(PUBLIC_KEY, true);
/** The handler manages its own database access (Better Auth wrappers). */
export const NoTransaction = () => SetMetadata(NO_TX_KEY, true);

/** POST that answers 200 (Nest defaults POST to 201; the API contract uses 200 except for creations). */
export const PostOk = (path?: string) => applyDecorators(Post(path), HttpCode(200));
export const PostCreated = (path?: string) => applyDecorators(Post(path), HttpCode(201));

export interface AppRequest extends Request {
  principal?: Principal;
}

/** Entitlement check (stub). Billing/plan gating plugs in here through the PaymentPort later. */
export function entitled(_principal: Principal, _permission: PermissionKey): boolean {
  return true;
}

@Injectable()
export class AuthGuard implements CanActivate {
  private readonly log = new Logger("AuthGuard");

  constructor(private readonly reflector: Reflector) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const targets = [ctx.getHandler(), ctx.getClass()];
    const isPublic = this.reflector.getAllAndOverride<boolean>(PUBLIC_KEY, targets);
    const permission = this.reflector.getAllAndOverride<PermissionKey>(PERMISSION_KEY, targets);
    const req = ctx.switchToHttp().getRequest<AppRequest>();
    const principal = await resolvePrincipal(toHeaders(req));
    if (principal) req.principal = principal;
    if (isPublic) return true;
    if (!permission) {
      this.log.error(`Route ${req.method} ${req.path} declares no permission; refusing (fail closed)`);
      throw new HttpException("Route has no access policy", 403);
    }
    if (!principal) throw new HttpException("Authentication required", 401);
    if (!ROLE_PERMISSIONS[principal.role].includes(permission)) throw new HttpException("Insufficient role for this operation", 403);
    if (STAFF_PERMISSIONS.has(permission) && getConfig().requireStaffMfa && !principal.mfaVerified) {
      throw new HttpException("Staff operations require two-factor authentication; enrol in Settings first", 403);
    }
    if (!entitled(principal, permission)) throw new HttpException("Your organization's plan does not include this feature", 402);
    return true;
  }
}

export function toHeaders(req: Request): Headers {
  const h = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    if (Array.isArray(v)) for (const x of v) h.append(k, x);
    else if (v !== undefined) h.set(k, v);
  }
  return h;
}

/** The authenticated caller (guaranteed by AuthGuard on non-public routes). */
export const CurrentPrincipal = createParamDecorator((_d: unknown, ctx: ExecutionContext): Principal => {
  const p = ctx.switchToHttp().getRequest<AppRequest>().principal;
  if (!p) throw new HttpException("Authentication required", 401);
  return p;
});

// --------------------------------------------------------------------------- validation

export class ValidationFailed extends Error {
  constructor(readonly errors: { field: string; message: string }[]) {
    super("Invalid input");
  }
}

function parseWith<T extends ZodType>(schema: T, value: unknown): z.output<T> {
  const r = schema.safeParse(value ?? {});
  if (!r.success) throw new ValidationFailed(r.error.issues.map((i) => ({ field: i.path.join("."), message: i.message })));
  return r.data;
}

// Nest treats a decorator argument that has a `transform` method as a pipe (Zod schemas do), so schemas are wrapped.
export interface SchemaRef { zod: ZodType; from: "body" | "query" }
const SchemaParam = createParamDecorator((ref: SchemaRef, ctx: ExecutionContext) => {
  const req = ctx.switchToHttp().getRequest<Request>();
  return parseWith(ref.zod, ref.from === "body" ? req.body : req.query);
});
/** Request body validated by a Zod schema from @threatready/contracts. */
export const ZBody = (schema: ZodType) => SchemaParam({ zod: schema, from: "body" } satisfies SchemaRef);
/** Query string validated by a Zod schema (values arrive as strings; use z.coerce in the schema). */
export const ZQuery = (schema: ZodType) => SchemaParam({ zod: schema, from: "query" } satisfies SchemaRef);

const IntParam = z.coerce.number().int().min(1).max(2_147_483_647);
/** Positive integer path parameter (a malformed id is a 422 like any other invalid input). */
export const IdParam = createParamDecorator((name: string, ctx: ExecutionContext): number => {
  const raw = ctx.switchToHttp().getRequest<Request>().params[name];
  const r = IntParam.safeParse(raw);
  if (!r.success) throw new ValidationFailed([{ field: name, message: "Must be a positive integer" }]);
  return r.data;
});

// --------------------------------------------------------------------------- responses

/** A non-JSON response (Markdown, HTML, CSV, NDJSON) with explicit content type and headers. */
export class RawResponse {
  constructor(readonly body: string, readonly contentType: string, readonly headers: Record<string, string> = {}) {}
}

/**
 * Wraps every non-public-identity handler in one database transaction bound to the caller (restricted role + RLS settings)
 * and renders RawResponse values.
 */
@Injectable()
export class RequestTransactionInterceptor implements NestInterceptor {
  constructor(private readonly reflector: Reflector) {}

  intercept(ctx: ExecutionContext, next: CallHandler): Observable<unknown> {
    const req = ctx.switchToHttp().getRequest<AppRequest>();
    const res = ctx.switchToHttp().getResponse<Response>();
    const noTx = this.reflector.getAllAndOverride<boolean>(NO_TX_KEY, [ctx.getHandler(), ctx.getClass()]);
    const result$ = noTx ? next.handle() : from(runInRequest(req.principal, () => lastValueFrom(next.handle(), { defaultValue: undefined })));
    return result$.pipe(map((value) => {
      if (value instanceof RawResponse) {
        res.setHeader("Content-Type", value.contentType);
        for (const [k, v] of Object.entries(value.headers)) res.setHeader(k, v);
        return value.body;
      }
      return value;
    }));
  }
}

/** Error shape: {"detail": message}; validation errors add "errors": [{field, message}] with status 422. */
@Catch()
export class ApiExceptionFilter implements ExceptionFilter {
  private readonly log = new Logger("ApiExceptionFilter");

  catch(exc: unknown, host: ArgumentsHost): void {
    const res = host.switchToHttp().getResponse<Response>();
    if (res.headersSent) return;
    if (exc instanceof DomainError) {
      res.status(exc.statusCode).json({ detail: exc.message });
    } else if (exc instanceof ValidationFailed) {
      res.status(422).json({ detail: "Invalid input", errors: exc.errors });
    } else if (exc instanceof ZodError) {
      res.status(422).json({ detail: "Invalid input", errors: exc.issues.map((i) => ({ field: i.path.join("."), message: i.message })) });
    } else if (exc instanceof ThrottlerException) {
      res.status(429).json({ detail: "Too many requests; wait a minute and try again" });
    } else if (exc instanceof HttpException) {
      const body = exc.getResponse();
      let detail: unknown = typeof body === "string" ? body : (body as { message?: unknown }).message ?? exc.message;
      if (Array.isArray(detail)) detail = detail.join("; ");
      if (exc.getStatus() === 404 && detail === `Cannot ${host.switchToHttp().getRequest<Request>().method} ${host.switchToHttp().getRequest<Request>().path}`) detail = "Not Found";
      if (exc.getStatus() === 413) detail = "Request body too large";
      res.status(exc.getStatus()).json({ detail });
    } else if (isBodyParserError(exc)) {
      res.status(exc.status).json({ detail: exc.status === 413 ? "Request body too large" : "Malformed JSON body" });
    } else {
      this.log.error(exc instanceof Error ? exc.stack ?? exc.message : String(exc));
      res.status(500).json({ detail: "Internal error. The incident was logged; no details are exposed." });
    }
  }
}

function isBodyParserError(e: unknown): e is { status: number; type: string } {
  return typeof e === "object" && e !== null && "type" in e && typeof (e as { status?: unknown }).status === "number";
}
