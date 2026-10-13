"""Simulation engine: environment provisioning, access control, activity execution,
policy evaluation, event and alert generation, and timeline runs.

All events produced here have provenance ``SIMULATED``. Source-system names are
prefixed ``kr-sim-`` so they can never be mistaken for vendor telemetry.
"""
from __future__ import annotations

import copy
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..content.company import environment_template
from ..models import (
    AccessGrant, Alert, ClassificationLabel, ClassificationRule, DataAsset, Destination, Policy,
    PolicyEvaluation, PolicyVersion, ScenarioAction, ScenarioSession, SecurityEvent, SimGroup, SimIdentity,
)
from . import detection
from .common import DomainError, as_utc
from .policy_engine import PolicyDefinition, decide, evaluate_policy, explain_entry
from .scenario_defs import TRANSFER_ACTIONS, ScenarioDefinition, get_definition, resolve_step

SOURCE_SYSTEMS = {
    "IDENTITY": "kr-sim-idp",
    "FILE_ACCESS": "kr-sim-file-audit",
    "DATABASE": "kr-sim-db-audit",
    "CLOUD_STORAGE": "kr-sim-object-store-audit",
    "DLP": "kr-sim-dlp",
    "DETECTION": "kr-sim-analytics",
    "EMAIL_GATEWAY": "kr-sim-mail-gateway",
    "PROXY": "kr-sim-web-proxy",
    "ENDPOINT": "kr-sim-endpoint-agent",
}
SECURITY_GROUP = "grp-security"

# ScenarioAction types that change a control. Used to decide whether a replay
# happened *after* the most recent fix.
CONTROL_CHANGE_ACTIONS = {
    "CLASSIFY", "POLICY_CREATE", "POLICY_UPDATE", "POLICY_STATUS", "GRANT_REVIEW_REVOKE",
    "REMEDIATION:REVOKE_GRANT", "REMEDIATION:BLOCK_DESTINATION", "REMEDIATION:QUARANTINE_ASSET",
    "CLASSIFICATION_RULE_UPDATE",
}


# --------------------------------------------------------------------------- provisioning


def provision_environment(db: Session, s: ScenarioSession) -> None:
    env = environment_template()
    sid = s.id
    for lab in env["labels"]:
        db.add(ClassificationLabel(session_id=sid, **lab))
    for ident in env["identities"]:
        db.add(SimIdentity(session_id=sid, **ident))
    for g in env["groups"]:
        db.add(SimGroup(session_id=sid, **copy.deepcopy(g)))
    for a in env["assets"]:
        db.add(DataAsset(session_id=sid, **a))
    for g in env["grants"]:
        db.add(AccessGrant(session_id=sid, **g))
    for d in env["destinations"]:
        db.add(Destination(session_id=sid, **d))
    for r in env["classification_rules"]:
        db.add(ClassificationRule(session_id=sid, **r))
    for p in env["policies"]:
        definition = PolicyDefinition.model_validate(p["definition"])
        pol = Policy(session_id=sid, key=p["key"], kind=definition.kind, status="ENABLED", current_version=1, baseline=True)
        pol.versions.append(PolicyVersion(version=1, definition=definition.model_dump(mode="json"),
                                          change_note="Baseline policy provided by the scenario", author="scenario-baseline"))
        db.add(pol)
    db.flush()


def definition_for(s: ScenarioSession) -> ScenarioDefinition:
    d = get_definition(s.scenario_id)
    if d is None:
        raise DomainError(f"Scenario {s.scenario_id} is not available", 404)
    return d


def variant_params(s: ScenarioSession) -> dict[str, str]:
    d = definition_for(s)
    for v in d.variants:
        if v.key == s.variant:
            return v.params
    raise DomainError("Session variant not found in scenario definition", 500)


# --------------------------------------------------------------------------- lookups


def get_identity(db: Session, s: ScenarioSession, key: str) -> SimIdentity:
    ident = db.scalar(select(SimIdentity).where(SimIdentity.session_id == s.id, SimIdentity.key == key))
    if ident is None:
        raise DomainError(f"Unknown identity '{key}'", 404)
    return ident


def get_asset(db: Session, s: ScenarioSession, key: str) -> DataAsset:
    a = db.scalar(select(DataAsset).where(DataAsset.session_id == s.id, DataAsset.key == key))
    if a is None:
        raise DomainError(f"Unknown asset '{key}'", 404)
    return a


def get_destination(db: Session, s: ScenarioSession, key: str) -> Destination:
    d = db.scalar(select(Destination).where(Destination.session_id == s.id, Destination.key == key))
    if d is None:
        raise DomainError(f"Unknown destination '{key}'", 404)
    return d


def label_ranks(db: Session, s: ScenarioSession) -> dict[str, int]:
    return {lab.key: lab.rank for lab in db.scalars(select(ClassificationLabel).where(ClassificationLabel.session_id == s.id))}


def groups_of(db: Session, s: ScenarioSession, identity_key: str) -> list[str]:
    return sorted(g.key for g in db.scalars(select(SimGroup).where(SimGroup.session_id == s.id)) if identity_key in (g.members or []))


def access_path(db: Session, s: ScenarioSession, identity: SimIdentity, asset: DataAsset) -> dict[str, Any]:
    """Explain whether ``identity`` can read ``asset`` and through which grant."""
    groups = groups_of(db, s, identity.key)
    if asset.quarantined:
        if identity.key == asset.owner_key or SECURITY_GROUP in groups:
            return {"allowed": True, "via": "quarantine exemption (owner/security)", "grant_key": None, "permission": "READ"}
        return {"allowed": False, "via": None, "grant_key": None, "reason": "Asset is quarantined"}
    grants = db.scalars(select(AccessGrant).where(
        AccessGrant.session_id == s.id, AccessGrant.asset_key == asset.key, AccessGrant.status == "ACTIVE"
    ).order_by(AccessGrant.key)).all()
    for g in grants:
        if g.principal_type == "IDENTITY" and g.principal_key == identity.key:
            return {"allowed": True, "via": f"direct grant {g.key}", "grant_key": g.key, "permission": g.permission}
    for g in grants:
        if g.principal_type == "GROUP" and g.principal_key in groups:
            return {"allowed": True, "via": f"group {g.principal_key} via grant {g.key}", "grant_key": g.key, "permission": g.permission}
    if identity.key == asset.owner_key:
        return {"allowed": True, "via": "data owner", "grant_key": None, "permission": "OWNER"}
    return {"allowed": False, "via": None, "grant_key": None, "reason": "No active grant for identity or its groups"}


# --------------------------------------------------------------------------- policy evaluation


def load_policies(db: Session, s: ScenarioSession) -> list[tuple[Policy, PolicyVersion, PolicyDefinition]]:
    out = []
    for p in db.scalars(select(Policy).where(Policy.session_id == s.id).order_by(Policy.key)):
        pv = next(v for v in p.versions if v.version == p.current_version)
        out.append((p, pv, PolicyDefinition.model_validate(pv.definition)))
    return out


def build_context(db: Session, s: ScenarioSession, *, actor: SimIdentity, asset: DataAsset, action: str,
                  destination: Destination | None, record_count: int | None, context: dict[str, Any],
                  timestamp: datetime) -> dict[str, Any]:
    scan = detection.scan_text(asset.content_sample)
    ranks = label_ranks(db, s)
    hour = as_utc(timestamp).hour
    ctx: dict[str, Any] = {
        "action": {"type": action},
        "actor": {
            "id": actor.key, "department": actor.department, "role": actor.enterprise_role,
            "employment_type": actor.employment_type, "groups": groups_of(db, s, actor.key),
        },
        "content": {
            "label": asset.label_key,
            "label_rank": ranks.get(asset.label_key) if asset.label_key else None,
            "detected_types": sorted(scan.keys()),
            "max_confidence": max((r.confidence for r in scan.values()), key=detection.CONFIDENCE_ORDER.get, default=None),
            "match_count": sum(r.match_count for r in scan.values()),
            "record_count": record_count if record_count is not None else asset.record_count,
        },
        "resource": {
            "id": asset.key, "system": asset.system, "department": asset.department,
            "owner_assigned": asset.owner_key is not None,
        },
        "context": {
            "business_justification": context.get("business_justification"),
            "ticket_id": context.get("ticket_id"),
            "after_hours": not (7 <= hour < 19),
            "device_managed": context.get("device_managed", True),
        },
        "_label_ranks": ranks,
    }
    if destination is not None:
        ctx["destination"] = {
            "id": destination.key, "kind": destination.kind, "category": destination.category,
            "sanctioned": destination.sanctioned, "internal": destination.internal, "domain": destination.domain,
        }
    return ctx


def evaluate(db: Session, s: ScenarioSession, ctx: dict[str, Any], *, dry_run: bool,
             transaction_id: str, policies: list[tuple[Policy, PolicyVersion, PolicyDefinition]] | None = None,
             persist: bool = True) -> dict[str, Any]:
    policies = policies if policies is not None else load_policies(db, s)
    entries = [evaluate_policy(p.key, pv.version, p.status, d, ctx) for p, pv, d in policies]
    for e in entries:
        e["explanation"] = explain_entry(e)
    dlp_entries = [e for e in entries if e["kind"] == "DLP"]
    decision = decide(dlp_entries)
    if persist:
        db.add(PolicyEvaluation(
            session_id=s.id, transaction_id=transaction_id, dry_run=dry_run,
            context={k: v for k, v in ctx.items() if not k.startswith("_")}, trace=entries,
            final_outcome=decision["outcome"], decisive_policy=decision["decisive_policy"],
        ))
    return {"entries": entries, "decision": decision}


# --------------------------------------------------------------------------- events


def _next_seq(s: ScenarioSession) -> int:
    s.event_seq = (s.event_seq or 0) + 1
    return s.event_seq


def _ip_for(identity_key: str) -> str:
    n = sum(ord(c) for c in identity_key)
    return f"10.20.{n % 200 + 10}.{n % 97 + 20}"


def new_event(db: Session, s: ScenarioSession, *, timestamp: datetime, run_number: int, actor: str | None,
              resource: str | None, action: str, result: str, source_type: str, summary: str,
              classification: str | None = None, destination: str | None = None, policy_id: str | None = None,
              policy_version: int | None = None, transaction_id: str | None = None,
              extension: dict[str, Any] | None = None, step_key: str | None = None,
              provenance: str = "SIMULATED") -> SecurityEvent:
    seq = _next_seq(s)
    ev = SecurityEvent(
        event_id=f"evt-{s.id}-{seq:05d}", session_id=s.id, organization_id=s.org_id, scenario_id=s.scenario_id,
        seq=seq, run_number=run_number, timestamp=timestamp, actor_id=actor, resource_id=resource, action=action,
        result=result, data_classification=classification, source_type=source_type,
        source_system=SOURCE_SYSTEMS.get(source_type, "kr-sim"), provenance=provenance, policy_id=policy_id,
        policy_version=policy_version, destination=destination, transaction_id=transaction_id,
        related_event_ids=[], evidence_refs=[], summary=summary, extension=extension or {}, step_key=step_key,
    )
    db.add(ev)
    return ev


def _link(events: list[SecurityEvent]) -> None:
    ids = [e.event_id for e in events]
    for e in events:
        e.related_event_ids = sorted(set((e.related_event_ids or []) + [i for i in ids if i != e.event_id]))


def _next_alert_id(db: Session, s: ScenarioSession) -> str:
    n = db.scalar(select(func.count(Alert.id)).where(Alert.session_id == s.id)) or 0
    return f"alr-{s.id}-{n + 1:04d}"


TRANSFER_SOURCE = {
    "EMAIL": "EMAIL_GATEWAY", "CLOUD_STORAGE": "PROXY", "AI_SERVICE": "PROXY", "SFTP": "PROXY",
    "REMOVABLE_MEDIA": "ENDPOINT", "INTERNAL": "FILE_ACCESS",
}
ACCESS_SOURCE = {"DB_TABLE": "DATABASE", "CLOUD_OBJECT": "CLOUD_STORAGE"}
OUTCOME_TO_RESULT = {"ALLOW": "ALLOWED", "MONITOR": "ALLOWED", "WARN": "ALLOWED_WITH_WARNING", "BLOCK": "BLOCKED"}


def execute_activity(db: Session, s: ScenarioSession, spec: dict[str, Any], *, timestamp: datetime,
                     run_number: int, step_key: str | None = None, learner_initiated: bool = False) -> dict[str, Any]:
    """Execute one simulated activity through identity, access, egress and DLP controls."""
    db.flush()  # make earlier activity visible to the correlation queries below (autoflush is off)
    action = spec["action"]
    actor = get_identity(db, s, spec["actor"])
    common_ext = {"device": actor.attributes.get("device", f"KR-WS-{actor.id:04d}"), "source_ip": _ip_for(actor.key)}
    if learner_initiated:
        common_ext["learner_initiated"] = True
    events: list[SecurityEvent] = []
    alerts: list[Alert] = []
    tx = f"tx-{uuid.uuid4().hex[:12]}"
    ext_ctx = spec.get("context") or {}

    if action == "SIGN_IN":
        ok = actor.status == "ACTIVE"
        ev = new_event(db, s, timestamp=timestamp, run_number=run_number, actor=actor.key, resource=None,
                       action="SIGN_IN", result="SUCCESS" if ok else "FAILURE", source_type="IDENTITY",
                       summary=f"{actor.display_name} sign-in {'succeeded' if ok else 'failed: account disabled'}",
                       transaction_id=tx, step_key=step_key,
                       extension={**common_ext, "mfa": "passed" if ok else "not_attempted",
                                  "failure_reason": None if ok else "ACCOUNT_DISABLED"})
        return {"outcome": "SUCCESS" if ok else "DENIED", "events": [ev], "alerts": [], "reason": "Sign-in evaluated by identity provider", "transaction_id": tx}

    if actor.status != "ACTIVE":
        ev = new_event(db, s, timestamp=timestamp, run_number=run_number, actor=actor.key, resource=spec.get("resource"),
                       action=action, result="DENIED", source_type="IDENTITY", transaction_id=tx, step_key=step_key,
                       summary=f"{actor.display_name}: activity refused, account disabled",
                       extension={**common_ext, "failure_reason": "ACCOUNT_DISABLED"})
        return {"outcome": "DENIED", "events": [ev], "alerts": [], "reason": "Account disabled", "transaction_id": tx}

    if not spec.get("resource"):
        raise DomainError("This action requires a resource")
    asset = get_asset(db, s, spec["resource"])
    dest = get_destination(db, s, spec["destination"]) if spec.get("destination") else None
    if action in TRANSFER_ACTIONS - {"EXPORT"} and dest is None:
        raise DomainError(f"Action {action} requires a destination")
    record_count = spec.get("record_count")
    records = record_count if record_count is not None else asset.record_count

    path = access_path(db, s, actor, asset)
    access_action = action if action in ("DOWNLOAD", "EXPORT") else "READ"
    access_ev = new_event(
        db, s, timestamp=timestamp, run_number=run_number, actor=actor.key, resource=asset.key, action=access_action,
        result="ALLOWED" if path["allowed"] else "DENIED", source_type=ACCESS_SOURCE.get(asset.asset_type, "FILE_ACCESS"),
        classification=asset.label_key, transaction_id=tx, step_key=step_key,
        summary=f"{actor.display_name} {access_action.lower()} {asset.name}: {'allowed via ' + path['via'] if path['allowed'] else 'denied (' + path['reason'] + ')'}",
        extension={**common_ext, "access_path": path.get("via"), "grant_key": path.get("grant_key"),
                   "permission": path.get("permission"), "record_count": records, "location": asset.location,
                   "denial_reason": path.get("reason")},
    )
    events.append(access_ev)
    # Explicit relationship: earlier activity by the same actor on the same resource in this run.
    prior = db.scalars(select(SecurityEvent).where(
        SecurityEvent.session_id == s.id, SecurityEvent.run_number == run_number,
        SecurityEvent.actor_id == actor.key, SecurityEvent.resource_id == asset.key,
        SecurityEvent.transaction_id != tx,
    )).all()
    if not path["allowed"]:
        _link(events)
        access_ev.related_event_ids = sorted(set(access_ev.related_event_ids + [p.event_id for p in prior]))
        return {"outcome": "DENIED", "events": events, "alerts": [], "reason": path["reason"], "transaction_id": tx}

    ctx = build_context(db, s, actor=actor, asset=asset, action=action, destination=dest,
                        record_count=record_count, context=ext_ctx, timestamp=timestamp)
    outcome = "ALLOWED"
    reason = "Access permitted"

    if dest is not None and dest.blocked and not dest.internal:
        ev = new_event(db, s, timestamp=timestamp + timedelta(seconds=5), run_number=run_number, actor=actor.key,
                       resource=asset.key, action=action, result="BLOCKED", source_type="PROXY", destination=dest.key,
                       classification=asset.label_key, transaction_id=tx, step_key=step_key,
                       summary=f"Egress to {dest.domain or dest.name} blocked by destination blocklist",
                       extension={**common_ext, "rule": "EGRESS_BLOCKLIST", "domain": dest.domain})
        events.append(ev)
        _link(events)
        return {"outcome": "BLOCKED", "events": events, "alerts": [], "reason": "Destination is on the egress blocklist", "transaction_id": tx}

    policies = load_policies(db, s)
    titles = {p.key: (d.alert_title or d.name) for p, _pv, d in policies}
    result = evaluate(db, s, ctx, dry_run=False, transaction_id=tx, policies=policies)
    decision = result["decision"]
    entries = result["entries"]
    policy_events: dict[str, SecurityEvent] = {}
    dlp_matched = any(e["matched"] and e["kind"] == "DLP" for e in entries)

    if (action in TRANSFER_ACTIONS and dest is not None) or dlp_matched:
        outcome = OUTCOME_TO_RESULT[decision["outcome"]]
        reason = decision["reason"]
        dlp_ev = new_event(
            db, s, timestamp=timestamp + timedelta(seconds=4), run_number=run_number, actor=actor.key, resource=asset.key,
            action=action, result=outcome, source_type="DLP", destination=dest.key if dest else None, classification=asset.label_key,
            policy_id=decision["decisive_policy"], policy_version=decision["decisive_version"], transaction_id=tx,
            step_key=step_key,
            summary=f"DLP decision {decision['outcome']} for {action.lower()} of {asset.name}" + (f" to {dest.name}" if dest else ""),
            extension={**common_ext, "decision": decision, "detected_types": ctx["content"]["detected_types"],
                       "record_count": records, "matched_policies": [e["policy_key"] for e in entries if e["matched"]]},
        )
        events.append(dlp_ev)
        for e in entries:
            if e["matched"] and e["kind"] == "DLP":
                policy_events[e["policy_key"]] = dlp_ev
    if action in TRANSFER_ACTIONS and dest is not None:
        transfer_src = TRANSFER_SOURCE.get(dest.kind, "PROXY")
        tr_ev = new_event(
            db, s, timestamp=timestamp + timedelta(seconds=6), run_number=run_number, actor=actor.key, resource=asset.key,
            action=action, result="BLOCKED" if outcome == "BLOCKED" else "ALLOWED", source_type=transfer_src,
            destination=dest.key, classification=asset.label_key, transaction_id=tx, step_key=step_key,
            summary=(f"{action.title()} of {asset.name} to {dest.domain or dest.name} "
                     f"{'stopped by DLP' if outcome == 'BLOCKED' else 'completed'}"),
            extension={**common_ext, "bytes": asset.size_bytes, "domain": dest.domain, "record_count": records,
                       "warning_shown": outcome == "ALLOWED_WITH_WARNING"},
        )
        events.append(tr_ev)

    for e in entries:
        if e["matched"] and e["kind"] == "DETECTION":
            det_ev = new_event(
                db, s, timestamp=timestamp + timedelta(seconds=30), run_number=run_number, actor=actor.key,
                resource=asset.key, action="ANOMALY", result="DETECTED", source_type="DETECTION",
                classification=asset.label_key, policy_id=e["policy_key"], policy_version=e["policy_version"],
                destination=dest.key if dest else None, transaction_id=tx, step_key=step_key,
                summary=f"Detection {e['policy_key']}: {e['name']} ({actor.display_name}, {records:,} records)",
                extension={**common_ext, "record_count": records, "detection": e["name"]},
            )
            events.append(det_ev)
            policy_events[e["policy_key"]] = det_ev

    _link(events)
    for ev in events:
        ev.related_event_ids = sorted(set(ev.related_event_ids + [p.event_id for p in prior]))

    for e in entries:
        if e["matched"] and e["alert"]:
            trigger = policy_events[e["policy_key"]]
            title_base = titles.get(e["policy_key"], e["name"])
            al = Alert(
                alert_id=_next_alert_id(db, s), session_id=s.id, run_number=run_number,
                title=f"{title_base}: {actor.display_name} / {asset.name}", severity=e["severity"], status="NEW",
                policy_id=e["policy_key"], policy_version=e["policy_version"], triggering_event_id=trigger.event_id,
                event_ids=sorted({ev.event_id for ev in events} | {p.event_id for p in prior}),
                actor_id=actor.key, resource_id=asset.key, explanation=e["explanation"],
                timestamp=trigger.timestamp, step_key=step_key,
            )
            db.add(al)
            db.flush()
            alerts.append(al)
    return {"outcome": outcome, "events": events, "alerts": alerts, "reason": reason, "transaction_id": tx,
            "decision": decision, "entries": entries}


# --------------------------------------------------------------------------- timeline


def ensure_validation_identity(db: Session, s: ScenarioSession, original_key: str) -> SimIdentity:
    """Create (once) a test identity cloned from the original actor's *initial* role and groups."""
    clone_key = f"{original_key}-val"
    existing = db.scalar(select(SimIdentity).where(SimIdentity.session_id == s.id, SimIdentity.key == clone_key))
    if existing:
        return existing
    tmpl = next(i for i in environment_template()["identities"] if i["key"] == original_key)
    clone = SimIdentity(
        session_id=s.id, key=clone_key, display_name=f"Validation clone of {tmpl['display_name']}",
        email=f"validation+{original_key}@kestrelridge.example", department=tmpl["department"], title=tmpl["title"],
        enterprise_role=tmpl["enterprise_role"], employment_type=tmpl["employment_type"], manager_key=None,
        attributes={"validation_clone_of": original_key, "device": "KR-VAL-0001"},
    )
    db.add(clone)
    initial_groups = [g["key"] for g in environment_template()["groups"] if original_key in g["members"]]
    for g in db.scalars(select(SimGroup).where(SimGroup.session_id == s.id)):
        if g.key in initial_groups and clone_key not in g.members:
            g.members = [*g.members, clone_key]
    db.flush()
    return clone


def last_action_seq(db: Session, s: ScenarioSession, types: set[str] | None = None) -> int:
    q = select(func.max(ScenarioAction.seq)).where(ScenarioAction.session_id == s.id)
    if types:
        q = q.where(ScenarioAction.action_type.in_(types))
    return db.scalar(q) or 0


def record_action(db: Session, s: ScenarioSession, action_type: str, params: dict[str, Any],
                  result: dict[str, Any] | None = None, provenance: str = "SIMULATED") -> ScenarioAction:
    seq = last_action_seq(db, s) + 1
    a = ScenarioAction(session_id=s.id, seq=seq, action_type=action_type, params=params, result=result or {},
                       provenance=provenance, sim_time=as_utc(s.sim_clock))
    db.add(a)
    db.flush()
    return a


def advance_clock(s: ScenarioSession, minutes: int = 1) -> datetime:
    s.sim_clock = as_utc(s.sim_clock) + timedelta(minutes=minutes)
    return s.sim_clock


def run_timeline(db: Session, s: ScenarioSession, mode: str) -> dict[str, Any]:
    d = definition_for(s)
    if mode not in ("standard", "validation"):
        raise DomainError("mode must be 'standard' or 'validation'")
    if mode == "validation" and s.run_count < 1:
        raise DomainError("Run the business day at least once before a control-validation replay", 409)
    params = variant_params(s)
    gt = d.ground_truth
    run_number = s.run_count + 1
    start = datetime.fromisoformat(d.sim_start.replace("Z", "+00:00"))
    day = (start + timedelta(days=run_number - 1)).date()
    substitutions: dict[str, str] = {}
    if mode == "validation":
        clone = ensure_validation_identity(db, s, params["culprit"])
        substitutions = {params["culprit"]: clone.key}
    outcomes = []
    steps = sorted((resolve_step(st, params) for st in d.timeline), key=lambda x: x["at"])
    for st in steps:
        hh, mm = (int(x) for x in st["at"].split(":"))
        ts = datetime(day.year, day.month, day.day, hh, mm, tzinfo=timezone.utc)
        spec = dict(st)
        if st["key"] in gt.get("culprit_steps", []) and st["actor"] in substitutions:
            spec["actor"] = substitutions[st["actor"]]
        res = execute_activity(db, s, spec, timestamp=ts, run_number=run_number, step_key=st["key"])
        outcomes.append({"step": st["key"], "outcome": res["outcome"], "alerts": len(res["alerts"])})
    s.run_count = run_number
    end_of_day = datetime(day.year, day.month, day.day, 20, 30, tzinfo=timezone.utc)
    if as_utc(s.sim_clock) < end_of_day:
        s.sim_clock = end_of_day
    action = record_action(db, s, "RUN_TIMELINE", {"mode": mode, "run_number": run_number},
                           {"events": s.event_seq, "steps": len(outcomes)})
    runs = list((s.flags or {}).get("runs", []))
    runs.append({"run_number": run_number, "mode": mode, "action_seq": action.seq, "sim_day": day.isoformat()})
    s.flags = {**(s.flags or {}), "runs": runs}
    db.flush()
    alerts = db.scalar(select(func.count(Alert.id)).where(Alert.session_id == s.id, Alert.run_number == run_number)) or 0
    events = db.scalar(select(func.count(SecurityEvent.id)).where(SecurityEvent.session_id == s.id, SecurityEvent.run_number == run_number)) or 0
    # The per-step outcome list is learner-visible only as counts, so it does not reveal which step is malicious.
    return {"run_number": run_number, "mode": mode, "sim_day": day.isoformat(), "activities": len(outcomes),
            "events_generated": events, "alerts_generated": alerts,
            "blocked_or_denied": sum(1 for o in outcomes if o["outcome"] in ("BLOCKED", "DENIED"))}
