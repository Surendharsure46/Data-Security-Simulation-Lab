"""Administrator / lab settings: users, platform audit log and integration status."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import AuditRecord, IntegrationConfig, ScenarioSession, SecurityEvent, User
from ..security import current_user, require_role
from ..services.common import audit, iso
from .deps import event_out, read_session

router = APIRouter(prefix="/api", tags=["admin"])

# Honest connector registry. "tested" refers to automated tests in this repository.
CONNECTORS = [
    {"key": "local-crypto", "name": "Local cryptography (Python 'cryptography' library)", "mode": "REAL_LAB", "status": "IMPLEMENTED",
     "capability": "AES-256-GCM file encryption, scrypt KDF, SHA-256/HMAC, envelope encryption and KEK rotation on disposable lab files.",
     "mechanism": "In-process library calls; files under THREATREADY_LAB_DATA_DIR.", "permissions": "Local filesystem write to the lab directory only.",
     "tested": True, "limitations": "Keys are lab keys stored for the exercise; not a key-management service."},
    {"key": "sqlite-lab", "name": "SQLite lab database", "mode": "REAL_LAB", "status": "IMPLEMENTED",
     "capability": "Per-user disposable database: authorizer-enforced roles, injection demo, masking views, audit log, backup/restore.",
     "mechanism": "Python sqlite3 module with set_authorizer and backup API.", "permissions": "Local filesystem write to the lab directory only.",
     "tested": True, "limitations": "SQLite has no native roles; enforcement uses the authorizer callback, not GRANT/REVOKE."},
    {"key": "siem-export", "name": "Normalised event export (JSON Lines)", "mode": "SIMULATED", "status": "IMPLEMENTED",
     "capability": "Download a session's simulated events in the common event schema for import into a SIEM of your choice.",
     "mechanism": "GET /api/sessions/{id}/export/events", "permissions": "Session read access.", "tested": True,
     "limitations": "Export only. Events remain labelled SIMULATED; no SIEM is contacted."},
    {"key": "postgresql-lab", "name": "PostgreSQL database-security lab", "mode": "REAL_LAB", "status": "NOT_IMPLEMENTED",
     "capability": "Native GRANT/REVOKE, pgaudit and row-level security exercises.", "mechanism": "Planned: psycopg against a local container.",
     "permissions": "Local PostgreSQL superuser for an isolated lab instance.", "tested": False,
     "limitations": "Not available in this release; use the SQLite lab."},
    {"key": "wireshark", "name": "Wireshark TLS inspection", "mode": "REAL_LAB", "status": "GUIDE_ONLY",
     "capability": "Guided procedure for capturing your own lab traffic and identifying visible TLS metadata.",
     "mechanism": "Manual, outside the platform.", "permissions": "Capture only traffic you are authorised to capture.", "tested": False,
     "limitations": "The platform does not capture traffic. The in-app TLS exercise uses a simulated handshake summary."},
    {"key": "microsoft-purview", "name": "Microsoft Purview (classification / DLP)", "mode": "INTEGRATED", "status": "NOT_IMPLEMENTED",
     "capability": "Read-only import of sensitivity labels and DLP alerts.", "mechanism": "Would use official Microsoft Graph / Purview APIs.",
     "permissions": "Requires a licensed tenant and an app registration with read-only consent.", "tested": False,
     "limitations": "No connector code exists. Nothing in the platform represents Purview telemetry."},
    {"key": "microsoft-sentinel", "name": "Microsoft Sentinel / other SIEM", "mode": "INTEGRATED", "status": "NOT_IMPLEMENTED",
     "capability": "Ingest or query incidents.", "mechanism": "Not implemented.", "permissions": "Workspace reader role.", "tested": False,
     "limitations": "Use the JSON Lines export to load simulated events into your own SIEM lab."},
    {"key": "aws-cloud", "name": "AWS CloudTrail / S3 posture", "mode": "INTEGRATED", "status": "NOT_IMPLEMENTED",
     "capability": "Read-only bucket policy and CloudTrail analysis.", "mechanism": "Not implemented.", "permissions": "Read-only IAM role in a sandbox account.",
     "tested": False, "limitations": "The Cloud DSPM lab is a local simulation; its events are not AWS telemetry."},
    {"key": "ai-provider", "name": "External AI explanations", "mode": "INTEGRATED", "status": "NOT_IMPLEMENTED",
     "capability": "Optional natural-language explanations.", "mechanism": "Not implemented; explanations are deterministic templates.",
     "permissions": "None.", "tested": False, "limitations": "No data is sent to any AI provider."},
]


@router.get("/integrations")
def integrations(user: User = Depends(current_user), db: Session = Depends(get_db)):
    cfg = {c.connector: c for c in db.scalars(select(IntegrationConfig).where(IntegrationConfig.org_id == user.org_id))}
    return [{**c, "enabled": c["status"] == "IMPLEMENTED" and (cfg[c["key"]].enabled if c["key"] in cfg else True)} for c in CONNECTORS]


class IntegrationToggle(BaseModel):
    enabled: bool


@router.put("/admin/integrations/{key}")
def toggle_integration(key: str, body: IntegrationToggle, user: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    c = next((x for x in CONNECTORS if x["key"] == key), None)
    if c is None:
        raise HTTPException(404, "Unknown connector")
    if c["status"] != "IMPLEMENTED":
        raise HTTPException(409, "This connector is not implemented and cannot be enabled")
    row = db.scalar(select(IntegrationConfig).where(IntegrationConfig.org_id == user.org_id, IntegrationConfig.connector == key))
    if row is None:
        row = IntegrationConfig(org_id=user.org_id, connector=key, enabled=body.enabled, settings={})
        db.add(row)
    row.enabled = body.enabled
    audit(db, user_id=user.id, org_id=user.org_id, action="integration.toggle", target_type="connector", target_id=key,
          detail={"enabled": body.enabled})
    db.commit()
    return {"key": key, "enabled": row.enabled}


@router.get("/sessions/{session_id}/export/events")
def export_events(s: ScenarioSession = Depends(read_session), user: User = Depends(current_user), db: Session = Depends(get_db)):
    import json
    row = db.scalar(select(IntegrationConfig).where(IntegrationConfig.org_id == user.org_id, IntegrationConfig.connector == "siem-export"))
    if row is not None and not row.enabled:
        raise HTTPException(403, "Event export is disabled by an administrator")
    lines = [json.dumps(event_out(e), sort_keys=True) for e in db.scalars(
        select(SecurityEvent).where(SecurityEvent.session_id == s.id).order_by(SecurityEvent.seq))]
    return PlainTextResponse("\n".join(lines) + ("\n" if lines else ""), media_type="application/x-ndjson",
                             headers={"Content-Disposition": f'attachment; filename="threatready-session{s.id}-events.jsonl"'})


@router.get("/admin/users")
def users(user: User = Depends(require_role("admin", "instructor")), db: Session = Depends(get_db)):
    return [{"id": u.id, "username": u.username, "display_name": u.display_name, "role": u.role, "is_active": u.is_active,
             "created_at": iso(u.created_at)} for u in db.scalars(select(User).where(User.org_id == user.org_id).order_by(User.id))]


class RoleIn(BaseModel):
    role: Literal["learner", "instructor", "admin"] | None = None
    is_active: bool | None = None


@router.patch("/admin/users/{user_id}")
def update_user(user_id: int, body: RoleIn, admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    u = db.get(User, user_id)
    if u is None or u.org_id != admin.org_id:
        raise HTTPException(404, "User not found")
    if u.id == admin.id:
        raise HTTPException(409, "Administrators cannot change their own role or status")
    if body.role is not None:
        u.role = body.role
    if body.is_active is not None:
        u.is_active = body.is_active
    audit(db, user_id=admin.id, org_id=admin.org_id, action="user.update", target_type="user", target_id=u.id,
          detail=body.model_dump(exclude_none=True))
    db.commit()
    return {"id": u.id, "role": u.role, "is_active": u.is_active}


@router.get("/admin/audit")
def audit_log(limit: int = 200, user: User = Depends(require_role("admin", "instructor")), db: Session = Depends(get_db)):
    rows = db.scalars(select(AuditRecord).where(AuditRecord.org_id == user.org_id).order_by(AuditRecord.id.desc()).limit(min(limit, 1000)))
    return [{"id": r.id, "user_id": r.user_id, "action": r.action, "target_type": r.target_type, "target_id": r.target_id,
             "detail": r.detail, "created_at": iso(r.created_at)} for r in rows]
