/** Audit trail: one immutable row per security-relevant platform action. */
import { uow } from "../db/context.js";
import { audit_records } from "../db/schema.js";

export async function audit(a: {
  user_id: string | null; org_id: number | null; action: string; target_type?: string | null; target_id?: unknown;
  detail?: Record<string, unknown>;
}): Promise<void> {
  await uow().insert(audit_records, {
    user_id: a.user_id, org_id: a.org_id, action: a.action, target_type: a.target_type ?? null,
    target_id: a.target_id === null || a.target_id === undefined ? null : String(a.target_id), detail: a.detail ?? {},
  });
}
