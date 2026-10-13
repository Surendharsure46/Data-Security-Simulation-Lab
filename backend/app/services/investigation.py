"""Correlation, risk model and remediation (with verification)."""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    AccessGrant, Alert, DataAsset, Destination, InvestigationCase, RemediationAction, ScenarioSession,
    SecurityEvent, SimGroup, SimIdentity,
)
from .common import DomainError, as_utc
from .simulation import (
    access_path, advance_clock, definition_for, get_asset, get_destination, get_identity, new_event, record_action,
)

CORRELATION_WINDOW = timedelta(hours=24)
PARTIES = ["PRIVACY_OFFICE", "LEGAL", "HR", "DATA_OWNER", "MANAGEMENT", "CISO"]
DISPOSITIONS = ["TRUE_POSITIVE", "BENIGN_POSITIVE", "FALSE_POSITIVE", "UNDETERMINED"]
DETERMINATIONS = [
    "CONFIRMED_DATA_EXFILTRATION", "ATTEMPTED_EXFILTRATION_PREVENTED", "POLICY_VIOLATION_NO_EXPOSURE",
    "BENIGN_ACTIVITY", "UNDETERMINED",
]
EXPOSURE_STATUSES = [
    "CONFIRMED_EXFILTRATION", "LIKELY_EXFILTRATION", "ATTEMPT_PREVENTED", "NO_EVIDENCE_OF_EXFILTRATION", "UNDETERMINED",
]
ROOT_CAUSES = [
    "EXCESSIVE_PERMISSION", "MISSING_CLASSIFICATION", "MONITOR_ONLY_POLICY", "MISSING_DATA_OWNER",
    "COMPROMISED_CREDENTIALS", "MALWARE", "PHISHING", "WEAK_ENCRYPTION", "MISSING_MFA", "USER_ERROR",
]
SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


# --------------------------------------------------------------------------- correlation


def correlate(db: Session, s: ScenarioSession, alert: Alert) -> list[dict[str, Any]]:
    """Return events related to an alert with explicit reasons. Time proximity alone never links events."""
    trigger = db.scalar(select(SecurityEvent).where(SecurityEvent.event_id == alert.triggering_event_id))
    if trigger is None:
        return []
    t0 = as_utc(trigger.timestamp)
    out = []
    for ev in db.scalars(select(SecurityEvent).where(SecurityEvent.session_id == s.id).order_by(SecurityEvent.timestamp, SecurityEvent.seq)):
        reasons = []
        if ev.event_id in (alert.event_ids or []):
            reasons.append("Listed in alert evidence")
        if trigger.transaction_id and ev.transaction_id == trigger.transaction_id:
            reasons.append("Same transaction")
        if ev.event_id in (trigger.related_event_ids or []):
            reasons.append("Explicit relation recorded by source")
        if alert.actor_id and ev.actor_id == alert.actor_id:
            reasons.append("Same actor")
        if alert.resource_id and ev.resource_id == alert.resource_id:
            reasons.append("Same resource")
        if not reasons:
            continue
        delta = as_utc(ev.timestamp) - t0
        if abs(delta) > CORRELATION_WINDOW and not {"Listed in alert evidence", "Same transaction"} & set(reasons):
            continue
        strength = "strong" if {"Same transaction", "Explicit relation recorded by source", "Listed in alert evidence"} & set(reasons) else (
            "medium" if len(reasons) >= 2 else "weak")
        out.append({"event_id": ev.event_id, "reasons": reasons, "strength": strength,
                    "minutes_from_trigger": round(delta.total_seconds() / 60, 1)})
    return out


# --------------------------------------------------------------------------- risk model


def risk_score(*, label_rank: int | None, records: int, destination_external: bool, data_left_org: str) -> dict[str, Any]:
    """Documented, deterministic severity model (docs/ASSESSMENT.md)."""
    if data_left_org not in ("YES", "NO", "UNKNOWN"):
        raise DomainError("data_left_org must be YES, NO or UNKNOWN")
    impact = 2 if label_rank is None else max(0, min(label_rank, 3))
    volume = 2 if records >= 10_000 else 1 if records >= 1_000 else 0
    dest = 2 if destination_external else 0
    left = {"YES": 2, "UNKNOWN": 1, "NO": 0}[data_left_org]
    score = impact + volume + dest + left
    severity = "CRITICAL" if score >= 8 else "HIGH" if score >= 6 else "MEDIUM" if score >= 3 else "LOW"
    return {
        "score": score, "severity": severity,
        "components": {"sensitivity": impact, "volume": volume, "destination": dest, "data_left_org": left},
        "notes": [] if label_rank is not None else ["Label unknown: sensitivity scored as 2 (assume Confidential) until classified."],
    }


# --------------------------------------------------------------------------- remediation


def _catalog(s: ScenarioSession) -> dict[str, Any]:
    return {r.type: r for r in definition_for(s).remediation_catalog}


def _probe_sign_in(db: Session, s: ScenarioSession, ident: SimIdentity) -> SecurityEvent:
    ok = ident.status == "ACTIVE"
    return new_event(db, s, timestamp=as_utc(s.sim_clock), run_number=0, actor=ident.key, resource=None, action="SIGN_IN",
                     result="SUCCESS" if ok else "FAILURE", source_type="IDENTITY",
                     summary=f"Verification probe: sign-in as {ident.display_name} {'succeeded' if ok else 'refused (account disabled)'}",
                     extension={"verification_probe": True, "failure_reason": None if ok else "ACCOUNT_DISABLED"})


def _members(db: Session, s: ScenarioSession, grant: AccessGrant) -> list[str]:
    if grant.principal_type == "IDENTITY":
        return [grant.principal_key]
    g = db.scalar(select(SimGroup).where(SimGroup.session_id == s.id, SimGroup.key == grant.principal_key))
    return list(g.members) if g else []


def verify_state(db: Session, s: ScenarioSession, rem: RemediationAction, *, emit_probe: bool = True) -> dict[str, Any]:
    """Re-check the current environment for the effect of a remediation action."""
    t = rem.action_type
    if t in ("DISABLE_ACCOUNT", "ENABLE_ACCOUNT"):
        ident = get_identity(db, s, rem.target_key)
        want = "DISABLED" if t == "DISABLE_ACCOUNT" else "ACTIVE"
        probe = _probe_sign_in(db, s, ident) if emit_probe else None
        ok = ident.status == want
        return {"verified": ok, "check": f"Identity status is {ident.status} (expected {want})",
                "probe_event_id": probe.event_id if probe else None}
    if t == "REVOKE_SESSIONS":
        ident = get_identity(db, s, rem.target_key)
        ok = ident.sessions_revoked_at is not None
        return {"verified": ok, "check": "Existing sessions terminated" if ok else "No session revocation recorded",
                "caveat": None if ident.status == "DISABLED" else "The account can still authenticate again; revoke sessions does not disable it."}
    if t == "BLOCK_DESTINATION":
        dest = get_destination(db, s, rem.target_key)
        probe = None
        if emit_probe:
            probe = new_event(db, s, timestamp=as_utc(s.sim_clock), run_number=0, actor=None, resource=None, action="EGRESS_TEST",
                              result="BLOCKED" if dest.blocked else "ALLOWED", source_type="PROXY", destination=dest.key,
                              summary=f"Verification probe: connection to {dest.domain or dest.name} {'blocked' if dest.blocked else 'allowed'}",
                              extension={"verification_probe": True, "domain": dest.domain})
        return {"verified": dest.blocked, "check": f"Destination blocklist flag = {dest.blocked}",
                "probe_event_id": probe.event_id if probe else None,
                "caveat": "Blocks every user's traffic to this destination, including legitimate use."}
    if t == "QUARANTINE_ASSET":
        asset = get_asset(db, s, rem.target_key)
        still = []
        for g in db.scalars(select(AccessGrant).where(AccessGrant.session_id == s.id, AccessGrant.asset_key == asset.key)):
            for m in _members(db, s, g):
                ident = db.scalar(select(SimIdentity).where(SimIdentity.session_id == s.id, SimIdentity.key == m))
                if ident and access_path(db, s, ident, asset)["allowed"] and "exemption" not in (access_path(db, s, ident, asset)["via"] or ""):
                    still.append(m)
        return {"verified": asset.quarantined and not still, "check": f"Quarantined={asset.quarantined}; non-exempt identities with access: {sorted(set(still))}"}
    if t == "REVOKE_GRANT":
        grant = db.scalar(select(AccessGrant).where(AccessGrant.session_id == s.id, AccessGrant.key == rem.target_key))
        if grant is None:
            return {"verified": False, "check": "Grant not found"}
        asset = get_asset(db, s, grant.asset_key)
        residual = []
        for m in _members(db, s, grant):
            ident = db.scalar(select(SimIdentity).where(SimIdentity.session_id == s.id, SimIdentity.key == m))
            if ident:
                p = access_path(db, s, ident, asset)
                if p["allowed"]:
                    residual.append({"identity": m, "via": p["via"]})
        return {"verified": grant.status == "REVOKED", "check": f"Grant {grant.key} status {grant.status}",
                "former_members_with_other_access": residual}
    if t == "PRESERVE_EVIDENCE":
        ident = get_identity(db, s, rem.target_key)
        ok = bool(ident.attributes.get("evidence_preserved_at"))
        return {"verified": ok, "check": "Forensic snapshot and mailbox hold recorded" if ok else "No preservation recorded",
                "snapshot_id": ident.attributes.get("evidence_snapshot_id")}
    if t == "REIMAGE_DEVICE":
        ident = get_identity(db, s, rem.target_key)
        destroyed = bool(ident.attributes.get("evidence_destroyed"))
        return {"verified": True, "check": "Device rebuilt",
                "local_evidence": "DESTROYED (no prior preservation)" if destroyed else "Snapshot preserved before reimage"}
    if t == "REQUEST_EXTERNAL_TAKEDOWN":
        return {"verified": False, "check": "Request recorded",
                "caveat": "The external provider's response is outside this simulation. Removal of copied data cannot be confirmed."}
    if t == "ESCALATE":
        return {"verified": True, "check": f"Escalation to {rem.target_key} recorded"}
    return {"verified": False, "check": "Unknown action"}


def apply_remediation(db: Session, s: ScenarioSession, *, action_type: str, target_key: str, justification: str,
                      case_id: int | None, confirm_destructive: bool) -> RemediationAction:
    catalog = _catalog(s)
    if action_type not in catalog:
        raise DomainError(f"Action {action_type} is not permitted in this scenario")
    spec = catalog[action_type]
    if spec.destructive and not confirm_destructive:
        raise DomainError(f"{action_type} is destructive. Resubmit with confirm_destructive=true after reviewing the impact.", 409)
    if case_id is not None and db.scalar(select(InvestigationCase).where(
            InvestigationCase.id == case_id, InvestigationCase.session_id == s.id)) is None:
        raise DomainError("Case not found in this session", 404)
    advance_clock(s)
    before: dict[str, Any] = {}
    after: dict[str, Any] = {}

    if spec.target_type == "IDENTITY":
        ident = get_identity(db, s, target_key)
        if ident.employment_type == "TEST":
            raise DomainError("Validation identities cannot be targeted")
        before = {"status": ident.status, "attributes": dict(ident.attributes)}
        attrs = dict(ident.attributes)
        if action_type == "DISABLE_ACCOUNT":
            ident.status = "DISABLED"
        elif action_type == "ENABLE_ACCOUNT":
            ident.status = "ACTIVE"
        elif action_type == "REVOKE_SESSIONS":
            ident.sessions_revoked_at = as_utc(s.sim_clock)
        elif action_type == "PRESERVE_EVIDENCE":
            attrs["evidence_preserved_at"] = as_utc(s.sim_clock).isoformat()
            attrs["evidence_snapshot_id"] = f"SNAP-{ident.key}-{int(as_utc(s.sim_clock).timestamp())}"
        elif action_type == "REIMAGE_DEVICE":
            attrs["device_reimaged_at"] = as_utc(s.sim_clock).isoformat()
            if not attrs.get("evidence_preserved_at"):
                attrs["evidence_destroyed"] = True
        ident.attributes = attrs
        after = {"status": ident.status, "attributes": dict(ident.attributes)}
    elif spec.target_type == "DESTINATION":
        dest = get_destination(db, s, target_key)
        if dest.internal:
            raise DomainError("Internal destinations cannot be blocked or targeted for takedown")
        before = {"blocked": dest.blocked}
        if action_type == "BLOCK_DESTINATION":
            dest.blocked = True
        after = {"blocked": dest.blocked}
    elif spec.target_type == "ASSET":
        asset = get_asset(db, s, target_key)
        before = {"quarantined": asset.quarantined}
        asset.quarantined = True
        after = {"quarantined": True}
    elif spec.target_type == "GRANT":
        grant = db.scalar(select(AccessGrant).where(AccessGrant.session_id == s.id, AccessGrant.key == target_key))
        if grant is None:
            raise DomainError(f"Unknown grant '{target_key}'", 404)
        if grant.status == "REVOKED":
            raise DomainError("Grant already revoked", 409)
        before = {"status": grant.status}
        grant.status = "REVOKED"
        grant.revoked_at = as_utc(s.sim_clock)
        after = {"status": "REVOKED"}
    elif spec.target_type == "PARTY":
        if target_key not in PARTIES:
            raise DomainError(f"Escalation target must be one of {PARTIES}")

    seq = len(db.scalars(select(RemediationAction.id).where(RemediationAction.session_id == s.id)).all()) + 1
    rem = RemediationAction(
        session_id=s.id, case_id=case_id, seq=seq, action_type=action_type, target_key=target_key,
        justification=justification, status="APPLIED", before_state=before, after_state=after,
        sim_time=as_utc(s.sim_clock),
    )
    db.add(rem)
    db.flush()
    rem.verification = verify_state(db, s, rem)
    rem.status = "RECORDED" if action_type in ("ESCALATE", "REQUEST_EXTERNAL_TAKEDOWN") else (
        "VERIFIED" if rem.verification.get("verified") else "VERIFICATION_FAILED")
    record_action(db, s, f"REMEDIATION:{action_type}", {"target": target_key, "case_id": case_id},
                  {"remediation_id": rem.id, "status": rem.status})
    return rem


def primary_case(db: Session, s: ScenarioSession) -> InvestigationCase | None:
    """The session's primary case: most linked evidence, latest on ties. Used for grading and reports alike."""
    from ..models import EvidenceReference

    best, best_n = None, -1
    for c in db.scalars(select(InvestigationCase).where(InvestigationCase.session_id == s.id).order_by(InvestigationCase.id)):
        n = len(db.scalars(select(EvidenceReference.id).where(EvidenceReference.case_id == c.id)).all())
        if n >= best_n:
            best, best_n = c, n
    return best


def destinations(db: Session, s: ScenarioSession) -> list[Destination]:
    return list(db.scalars(select(Destination).where(Destination.session_id == s.id).order_by(Destination.key)))
