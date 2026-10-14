/** Administrator / lab settings: users, platform audit log and integration status. */
import { Controller, Get, Param, Patch, Put } from "@nestjs/common";
import { IntegrationToggleIn, UserUpdateIn } from "@threatready/contracts";
import { and, asc, desc, eq } from "drizzle-orm";
import { z } from "zod";
import { audit } from "../common/audit.js";
import { DomainError, iso, stableStringify } from "../common/util.js";
import { type Principal, uow } from "../db/context.js";
import { audit_records, integration_configs, security_events, session as sessionTable, user } from "../db/schema.js";
import { eventOut, loadSession } from "../domain/session-lifecycle.js";
import { CurrentPrincipal, IdParam, Permission, PERMISSIONS, RawResponse, ZBody, ZQuery } from "../platform/http.js";

// Honest connector registry. "tested" refers to automated tests in this repository.
export const CONNECTORS = [
  { key: "local-crypto", name: "Local cryptography (Node.js crypto / OpenSSL)", mode: "REAL_LAB", status: "IMPLEMENTED",
    capability: "AES-256-GCM file encryption, scrypt KDF, SHA-256/HMAC, envelope encryption and KEK rotation on disposable lab files.",
    mechanism: "In-process library calls; files under THREATREADY_LAB_DATA_DIR.", permissions: "Local filesystem write to the lab directory only.",
    tested: true, limitations: "Keys are lab keys stored for the exercise; not a key-management service." },
  { key: "sqlite-lab", name: "SQLite lab database", mode: "REAL_LAB", status: "IMPLEMENTED",
    capability: "Per-user disposable database: authorizer-enforced roles, injection demo, masking views, audit log, backup/restore.",
    mechanism: "node:sqlite with setAuthorizer and the online backup API.", permissions: "Local filesystem write to the lab directory only.",
    tested: true, limitations: "SQLite has no native roles; enforcement uses the authorizer callback, not GRANT/REVOKE." },
  { key: "siem-export", name: "Normalised event export (JSON Lines)", mode: "SIMULATED", status: "IMPLEMENTED",
    capability: "Download a session's simulated events in the common event schema for import into a SIEM of your choice.",
    mechanism: "GET /api/sessions/{id}/export/events", permissions: "Session read access.", tested: true,
    limitations: "Export only. Events remain labelled SIMULATED; no SIEM is contacted." },
  { key: "postgresql-lab", name: "PostgreSQL database-security lab", mode: "REAL_LAB", status: "NOT_IMPLEMENTED",
    capability: "Native GRANT/REVOKE, pgaudit and row-level security exercises.", mechanism: "Planned: an isolated per-learner PostgreSQL schema.",
    permissions: "Local PostgreSQL superuser for an isolated lab instance.", tested: false, limitations: "Not available in this release; use the SQLite lab." },
  { key: "wireshark", name: "Wireshark TLS inspection", mode: "REAL_LAB", status: "GUIDE_ONLY",
    capability: "Guided procedure for capturing your own lab traffic and identifying visible TLS metadata.", mechanism: "Manual, outside the platform.",
    permissions: "Capture only traffic you are authorised to capture.", tested: false,
    limitations: "The platform does not capture traffic. The in-app TLS exercise uses a simulated handshake summary." },
  { key: "microsoft-purview", name: "Microsoft Purview (classification / DLP)", mode: "INTEGRATED", status: "NOT_IMPLEMENTED",
    capability: "Read-only import of sensitivity labels and DLP alerts.", mechanism: "Would use official Microsoft Graph / Purview APIs.",
    permissions: "Requires a licensed tenant and an app registration with read-only consent.", tested: false,
    limitations: "No connector code exists. Nothing in the platform represents Purview telemetry." },
  { key: "microsoft-sentinel", name: "Microsoft Sentinel / other SIEM", mode: "INTEGRATED", status: "NOT_IMPLEMENTED", capability: "Ingest or query incidents.",
    mechanism: "Not implemented.", permissions: "Workspace reader role.", tested: false,
    limitations: "Use the JSON Lines export to load simulated events into your own SIEM lab." },
  { key: "aws-cloud", name: "AWS CloudTrail / S3 posture", mode: "INTEGRATED", status: "NOT_IMPLEMENTED", capability: "Read-only bucket policy and CloudTrail analysis.",
    mechanism: "Not implemented.", permissions: "Read-only IAM role in a sandbox account.", tested: false,
    limitations: "The Cloud DSPM lab is a local simulation; its events are not AWS telemetry." },
  { key: "ai-provider", name: "External AI explanations", mode: "INTEGRATED", status: "NOT_IMPLEMENTED", capability: "Optional natural-language explanations.",
    mechanism: "LlmPort exists with a no-op adapter; explanations are deterministic templates.", permissions: "None.", tested: false,
    limitations: "No data is sent to any AI provider." },
];

const AuditQuery = z.object({ limit: z.coerce.number().int().min(1).default(200) });

async function integrationRow(orgId: number, key: string) {
  return uow().one(integration_configs, and(eq(integration_configs.org_id, orgId), eq(integration_configs.connector, key))!);
}

@Controller("api")
export class AdminController {
  @Get("integrations")
  @Permission(PERMISSIONS.SELF)
  async integrations(@CurrentPrincipal() p: Principal) {
    const cfg = new Map((await uow().all(integration_configs, eq(integration_configs.org_id, p.orgId))).map((c) => [c.connector, c]));
    return CONNECTORS.map((c) => ({ ...c, enabled: c.status === "IMPLEMENTED" && (cfg.get(c.key)?.enabled ?? true) }));
  }

  @Put("admin/integrations/:key")
  @Permission(PERMISSIONS.ADMIN_MANAGE)
  async toggle(@Param("key") key: string, @CurrentPrincipal() p: Principal, @ZBody(IntegrationToggleIn) body: z.infer<typeof IntegrationToggleIn>) {
    const c = CONNECTORS.find((x) => x.key === key);
    if (!c) throw new DomainError("Unknown connector", 404);
    if (c.status !== "IMPLEMENTED") throw new DomainError("This connector is not implemented and cannot be enabled", 409);
    let row = await integrationRow(p.orgId, key);
    if (!row) row = await uow().insert(integration_configs, { org_id: p.orgId, connector: key, enabled: body.enabled, settings: {} });
    row.enabled = body.enabled;
    row.updated_at = new Date();
    await audit({ user_id: p.userId, org_id: p.orgId, action: "integration.toggle", target_type: "connector", target_id: key, detail: { enabled: body.enabled } });
    return { key, enabled: row.enabled };
  }

  @Get("sessions/:sessionId/export/events")
  @Permission(PERMISSIONS.SELF)
  async exportEvents(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal) {
    const s = await loadSession(id, p, { write: false });
    const row = await integrationRow(p.orgId, "siem-export");
    if (row && !row.enabled) throw new DomainError("Event export is disabled by an administrator", 403);
    const lines = (await uow().all(security_events, eq(security_events.session_id, s.id), [asc(security_events.seq)])).map((e) => stableStringify(eventOut(e)));
    return new RawResponse(lines.join("\n") + (lines.length ? "\n" : ""), "application/x-ndjson",
      { "Content-Disposition": `attachment; filename="threatready-session${s.id}-events.jsonl"` });
  }

  @Get("admin/users")
  @Permission(PERMISSIONS.STAFF_READ)
  async users(@CurrentPrincipal() p: Principal) {
    return (await uow().all(user, eq(user.org_id, p.orgId), [asc(user.createdAt)])).map((u) => ({ id: u.id, email: u.email, display_name: u.name,
      role: u.role, is_active: u.is_active, mfa_enabled: Boolean(u.twoFactorEnabled), created_at: iso(u.createdAt) }));
  }

  @Patch("admin/users/:userId")
  @Permission(PERMISSIONS.ADMIN_MANAGE)
  async updateUser(@Param("userId") userId: string, @CurrentPrincipal() p: Principal, @ZBody(UserUpdateIn) body: z.infer<typeof UserUpdateIn>) {
    const u = await uow().one(user, eq(user.id, userId));
    if (!u || u.org_id !== p.orgId) throw new DomainError("User not found", 404);
    if (u.id === p.userId) throw new DomainError("Administrators cannot change their own role or status", 409);
    if (body.role !== null && body.role !== undefined) u.role = body.role;
    if (body.is_active !== null && body.is_active !== undefined) {
      u.is_active = body.is_active;
      // Deactivation takes effect immediately: existing sessions are revoked.
      if (!body.is_active) await uow().delete(sessionTable, eq(sessionTable.userId, u.id));
    }
    u.updatedAt = new Date();
    await audit({ user_id: p.userId, org_id: p.orgId, action: "user.update", target_type: "user", target_id: u.id,
      detail: Object.fromEntries(Object.entries(body).filter(([, v]) => v !== null && v !== undefined)) });
    return { id: u.id, role: u.role, is_active: u.is_active };
  }

  @Get("admin/audit")
  @Permission(PERMISSIONS.STAFF_READ)
  async auditLog(@CurrentPrincipal() p: Principal, @ZQuery(AuditQuery) q: z.infer<typeof AuditQuery>) {
    const rows = await uow().db.select().from(audit_records).where(eq(audit_records.org_id, p.orgId)).orderBy(desc(audit_records.id)).limit(Math.min(q.limit, 1000));
    return rows.map((r) => ({ id: r.id, user_id: r.user_id, action: r.action, target_type: r.target_type, target_id: r.target_id, detail: r.detail,
      created_at: iso(r.created_at) }));
  }
}
