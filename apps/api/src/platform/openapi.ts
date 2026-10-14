/**
 * OpenAPI 3.1 document generated from the controllers: paths and methods from Nest route metadata, request bodies and
 * query parameters from the Zod schemas bound with @ZBody / @ZQuery, and the access policy from @Permission / @Public.
 * Served at /api/openapi.json outside production.
 */
import { OpenAPIRegistry, OpenApiGeneratorV31 } from "@asteasolutions/zod-to-openapi";
import { RequestMethod } from "@nestjs/common";
import { METHOD_METADATA, PATH_METADATA, ROUTE_ARGS_METADATA } from "@nestjs/common/constants.js";
import type { NestExpressApplication } from "@nestjs/platform-express";
import type { NextFunction, Request, Response } from "express";
import { ZodObject, type ZodType } from "zod";
import { PERMISSION_KEY, PUBLIC_KEY, type SchemaRef } from "./http.js";

type Ctor = new (...args: never[]) => unknown;
const METHODS: Record<number, string> = {
  [RequestMethod.GET]: "get", [RequestMethod.POST]: "post", [RequestMethod.PUT]: "put", [RequestMethod.PATCH]: "patch", [RequestMethod.DELETE]: "delete",
};

export interface RouteInfo {
  method: string;
  path: string;
  controller: string;
  handler: string;
  permission?: string;
  isPublic: boolean;
  body?: ZodType;
  query?: ZodType;
}

function joinPath(a: string, b: string): string {
  return (`/${[a, b].filter(Boolean).join("/")}`.replace(/\/+/g, "/").replace(/\/$/, "")) || "/";
}

/** Every HTTP route with its access policy (also used by the route-coverage test). */
export function listRoutes(controllers: Ctor[]): RouteInfo[] {
  const out: RouteInfo[] = [];
  for (const ctrl of controllers) {
    const base = String(Reflect.getMetadata(PATH_METADATA, ctrl) ?? "");
    const classPermission = Reflect.getMetadata(PERMISSION_KEY, ctrl) as string | undefined;
    const classPublic = Reflect.getMetadata(PUBLIC_KEY, ctrl) as boolean | undefined;
    const proto = ctrl.prototype as Record<string, unknown>;
    for (const name of Object.getOwnPropertyNames(proto)) {
      if (name === "constructor") continue;
      const fn = proto[name] as object;
      const method = Reflect.getMetadata(METHOD_METADATA, fn) as number | undefined;
      if (method === undefined) continue;
      const sub = String(Reflect.getMetadata(PATH_METADATA, fn) ?? "");
      const args = (Reflect.getMetadata(ROUTE_ARGS_METADATA, ctrl, name) ?? {}) as Record<string, { data?: unknown }>;
      let body: ZodType | undefined;
      let query: ZodType | undefined;
      for (const arg of Object.values(args)) {
        const ref = arg.data as SchemaRef | undefined;
        if (!ref || typeof ref !== "object" || !("zod" in ref) || !("from" in ref)) continue;
        if (ref.from === "body") body = ref.zod;
        else query = ref.zod;
      }
      out.push({
        method: METHODS[method] ?? String(method), path: joinPath(base, sub), controller: ctrl.name, handler: name,
        permission: (Reflect.getMetadata(PERMISSION_KEY, fn) as string | undefined) ?? classPermission,
        isPublic: Boolean((Reflect.getMetadata(PUBLIC_KEY, fn) as boolean | undefined) ?? classPublic), body, query,
      });
    }
  }
  return out;
}

let cached: unknown;

export function buildOpenApi(controllers: Ctor[]): unknown {
  if (cached) return cached;
  const registry = new OpenAPIRegistry();
  registry.registerComponent("securitySchemes", "session", { type: "apiKey", in: "cookie", name: "threatready.session_token" });
  for (const r of listRoutes(controllers)) {
    const params = [...r.path.matchAll(/:([A-Za-z]+)/g)].map((m) => m[1]);
    registry.registerPath({
      method: r.method as "get",
      path: r.path.replace(/:([A-Za-z]+)/g, "{$1}"),
      tags: [r.controller.replace(/Controller$/, "")],
      operationId: `${r.controller}.${r.handler}`,
      summary: r.handler,
      description: r.isPublic ? "Public" : `Requires permission: ${r.permission ?? "(none: refused)"}`,
      security: r.isPublic ? [] : [{ session: [] }],
      parameters: params.map((p) => ({ name: p, in: "path" as const, required: true, schema: { type: "string" as const } })),
      request: {
        query: r.query instanceof ZodObject ? (r.query as never) : undefined,
        body: r.body ? { content: { "application/json": { schema: r.body as never } } } : undefined,
      },
      responses: {
        200: { description: "JSON response" },
        401: { description: "Authentication required" },
        403: { description: "Forbidden" },
        404: { description: "Not found (also returned for objects outside your scope)" },
        422: { description: "Invalid input: {detail, errors: [{field, message}]}" },
      },
    });
  }
  cached = new OpenApiGeneratorV31(registry.definitions).generateDocument({
    openapi: "3.1.0",
    info: { title: "Threatready API", version: "0.4.0", description: "Data Security Operations & Simulation Lab. All scenario data is synthetic." },
  });
  return cached;
}

export function mountOpenApi(app: NestExpressApplication, controllers: Ctor[]): void {
  app.use("/api/openapi.json", (req: Request, res: Response, next: NextFunction) => {
    if (req.method !== "GET") return next();
    try {
      res.json(buildOpenApi(controllers));
    } catch (e) {
      res.status(500).json({ detail: `OpenAPI generation failed: ${(e as Error).message}` });
    }
  });
}
