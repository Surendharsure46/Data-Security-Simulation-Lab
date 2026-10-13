"""SQLAlchemy domain models.

Platform entities (Organization, User, AuthToken, AuditRecord) are global.
Simulation entities are scoped to a ScenarioSession: every session receives its own
copy of the synthetic enterprise so that learners cannot affect each other and a
session can be reset and replayed deterministically.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- platform


class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    slug: Mapped[str] = mapped_column(String(100), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    username: Mapped[str] = mapped_column(String(64), unique=True)
    display_name: Mapped[str] = mapped_column(String(120))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="learner")  # learner | instructor | admin
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuthToken(Base):
    __tablename__ = "auth_tokens"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class AuditRecord(Base):
    """Platform audit trail (who did what in the platform). Distinct from simulated SecurityEvents."""

    __tablename__ = "audit_records"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"), nullable=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(80))
    target_type: Mapped[str | None] = mapped_column(String(60), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# --------------------------------------------------------------------------- scenario sessions


class ScenarioSession(Base):
    __tablename__ = "scenario_sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    scenario_id: Mapped[str] = mapped_column(String(80))
    scenario_version: Mapped[str] = mapped_column(String(20))
    variant: Mapped[str] = mapped_column(String(20))
    mode: Mapped[str] = mapped_column(String(20))  # GUIDED | ASSESSMENT | PRACTICE
    status: Mapped[str] = mapped_column(String(20), default="ACTIVE")  # ACTIVE | PAUSED | SUBMITTED
    attempt_number: Mapped[int] = mapped_column(Integer, default=1)
    sim_clock: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    run_count: Mapped[int] = mapped_column(Integer, default=0)
    event_seq: Mapped[int] = mapped_column(Integer, default=0)
    hints_used: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    flags: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class ScenarioAction(Base):
    """Every learner action in a session, in order. Source for reports and reproducibility."""

    __tablename__ = "scenario_actions"
    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("scenario_sessions.id", ondelete="CASCADE"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    action_type: Mapped[str] = mapped_column(String(60))
    params: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    provenance: Mapped[str] = mapped_column(String(20), default="SIMULATED")
    sim_time: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# --------------------------------------------------------------------------- synthetic enterprise


class SimIdentity(Base):
    __tablename__ = "sim_identities"
    __table_args__ = (UniqueConstraint("session_id", "key"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("scenario_sessions.id", ondelete="CASCADE"), index=True)
    key: Mapped[str] = mapped_column(String(60))
    display_name: Mapped[str] = mapped_column(String(120))
    email: Mapped[str] = mapped_column(String(160))
    department: Mapped[str] = mapped_column(String(60))
    title: Mapped[str] = mapped_column(String(120))
    enterprise_role: Mapped[str] = mapped_column(String(60))
    employment_type: Mapped[str] = mapped_column(String(30))  # EMPLOYEE | CONTRACTOR | SERVICE | TEST
    manager_key: Mapped[str | None] = mapped_column(String(60), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="ACTIVE")  # ACTIVE | DISABLED
    sessions_revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class SimGroup(Base):
    __tablename__ = "sim_groups"
    __table_args__ = (UniqueConstraint("session_id", "key"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("scenario_sessions.id", ondelete="CASCADE"), index=True)
    key: Mapped[str] = mapped_column(String(60))
    name: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(Text, default="")
    members: Mapped[list[str]] = mapped_column(JSON, default=list)


class DataAsset(Base):
    __tablename__ = "data_assets"
    __table_args__ = (UniqueConstraint("session_id", "key"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("scenario_sessions.id", ondelete="CASCADE"), index=True)
    key: Mapped[str] = mapped_column(String(60))
    name: Mapped[str] = mapped_column(String(200))
    asset_type: Mapped[str] = mapped_column(String(40))  # FILE | DB_TABLE | CLOUD_OBJECT | DOCUMENT
    data_structure: Mapped[str] = mapped_column(String(20))  # STRUCTURED | UNSTRUCTURED | SEMI_STRUCTURED
    system: Mapped[str] = mapped_column(String(80))
    location: Mapped[str] = mapped_column(String(300))
    department: Mapped[str] = mapped_column(String(60))
    owner_key: Mapped[str | None] = mapped_column(String(60), nullable=True)
    label_key: Mapped[str | None] = mapped_column(String(40), nullable=True)
    record_count: Mapped[int] = mapped_column(Integer, default=0)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    description: Mapped[str] = mapped_column(Text, default="")
    content_sample: Mapped[str] = mapped_column(Text, default="")
    handling_notes: Mapped[str] = mapped_column(Text, default="")
    exception_note: Mapped[str] = mapped_column(Text, default="")
    quarantined: Mapped[bool] = mapped_column(Boolean, default=False)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class AccessGrant(Base):
    __tablename__ = "access_grants"
    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("scenario_sessions.id", ondelete="CASCADE"), index=True)
    key: Mapped[str] = mapped_column(String(60))
    asset_key: Mapped[str] = mapped_column(String(60))
    principal_type: Mapped[str] = mapped_column(String(20))  # IDENTITY | GROUP
    principal_key: Mapped[str] = mapped_column(String(60))
    permission: Mapped[str] = mapped_column(String(20))  # READ | WRITE | OWNER
    justification: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(20), default="ACTIVE")  # ACTIVE | REVOKED
    review_decision: Mapped[str | None] = mapped_column(String(20), nullable=True)  # KEEP | REVOKE
    review_note: Mapped[str] = mapped_column(Text, default="")
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Destination(Base):
    __tablename__ = "destinations"
    __table_args__ = (UniqueConstraint("session_id", "key"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("scenario_sessions.id", ondelete="CASCADE"), index=True)
    key: Mapped[str] = mapped_column(String(60))
    name: Mapped[str] = mapped_column(String(160))
    kind: Mapped[str] = mapped_column(String(30))  # EMAIL | CLOUD_STORAGE | REMOVABLE_MEDIA | SFTP | AI_SERVICE | INTERNAL
    domain: Mapped[str] = mapped_column(String(160), default="")
    category: Mapped[str] = mapped_column(String(30))  # INTERNAL | SANCTIONED_PARTNER | PERSONAL | UNSANCTIONED
    sanctioned: Mapped[bool] = mapped_column(Boolean, default=False)
    internal: Mapped[bool] = mapped_column(Boolean, default=False)
    blocked: Mapped[bool] = mapped_column(Boolean, default=False)


class ClassificationLabel(Base):
    __tablename__ = "classification_labels"
    __table_args__ = (UniqueConstraint("session_id", "key"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("scenario_sessions.id", ondelete="CASCADE"), index=True)
    key: Mapped[str] = mapped_column(String(40))
    name: Mapped[str] = mapped_column(String(80))
    rank: Mapped[int] = mapped_column(Integer)
    description: Mapped[str] = mapped_column(Text, default="")
    handling: Mapped[str] = mapped_column(Text, default="")


class ClassificationRule(Base):
    """Maps detector results to a recommended label. Editable by the learner."""

    __tablename__ = "classification_rules"
    __table_args__ = (UniqueConstraint("session_id", "key"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("scenario_sessions.id", ondelete="CASCADE"), index=True)
    key: Mapped[str] = mapped_column(String(60))
    name: Mapped[str] = mapped_column(String(160))
    detectors: Mapped[list[str]] = mapped_column(JSON, default=list)
    min_matches: Mapped[int] = mapped_column(Integer, default=1)
    min_confidence: Mapped[str] = mapped_column(String(10), default="MEDIUM")
    recommended_label: Mapped[str] = mapped_column(String(40))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    version: Mapped[int] = mapped_column(Integer, default=1)


class DiscoveryScan(Base):
    __tablename__ = "discovery_scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("scenario_sessions.id", ondelete="CASCADE"), index=True)
    scan_number: Mapped[int] = mapped_column(Integer)
    assets_scanned: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    rule_snapshot: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    sim_time: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ClassificationFinding(Base):
    __tablename__ = "classification_findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("scenario_sessions.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("discovery_scans.id", ondelete="CASCADE"))
    asset_key: Mapped[str] = mapped_column(String(60))
    detector: Mapped[str] = mapped_column(String(40))
    match_count: Mapped[int] = mapped_column(Integer)
    confidence: Mapped[str] = mapped_column(String(10))
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    recommended_label: Mapped[str | None] = mapped_column(String(40), nullable=True)
    rule_keys: Mapped[list[str]] = mapped_column(JSON, default=list)


class ClassificationAssignment(Base):
    """Append-only classification register history."""

    __tablename__ = "classification_assignments"
    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("scenario_sessions.id", ondelete="CASCADE"), index=True)
    asset_key: Mapped[str] = mapped_column(String(60))
    label_key: Mapped[str] = mapped_column(String(40))
    previous_label_key: Mapped[str | None] = mapped_column(String(40), nullable=True)
    owner_key: Mapped[str | None] = mapped_column(String(60), nullable=True)
    justification: Mapped[str] = mapped_column(Text)
    handling_notes: Mapped[str] = mapped_column(Text, default="")
    exception_note: Mapped[str] = mapped_column(Text, default="")
    assigned_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    sim_time: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# --------------------------------------------------------------------------- policies


class Policy(Base):
    __tablename__ = "policies"
    __table_args__ = (UniqueConstraint("session_id", "key"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("scenario_sessions.id", ondelete="CASCADE"), index=True)
    key: Mapped[str] = mapped_column(String(60))
    kind: Mapped[str] = mapped_column(String(20))  # DLP | DETECTION
    status: Mapped[str] = mapped_column(String(20), default="ENABLED")
    current_version: Mapped[int] = mapped_column(Integer, default=1)
    baseline: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    versions: Mapped[list["PolicyVersion"]] = relationship(
        back_populates="policy", cascade="all, delete-orphan", order_by="PolicyVersion.version"
    )


class PolicyVersion(Base):
    """Immutable policy definition snapshot. Evaluations reference a specific version."""

    __tablename__ = "policy_versions"
    __table_args__ = (UniqueConstraint("policy_id", "version"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    policy_id: Mapped[int] = mapped_column(ForeignKey("policies.id", ondelete="CASCADE"))
    version: Mapped[int] = mapped_column(Integer)
    definition: Mapped[dict[str, Any]] = mapped_column(JSON)
    change_note: Mapped[str] = mapped_column(Text, default="")
    author: Mapped[str] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    policy: Mapped[Policy] = relationship(back_populates="versions")


class PolicyEvaluation(Base):
    __tablename__ = "policy_evaluations"
    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("scenario_sessions.id", ondelete="CASCADE"), index=True)
    transaction_id: Mapped[str] = mapped_column(String(40))
    dry_run: Mapped[bool] = mapped_column(Boolean, default=False)
    context: Mapped[dict[str, Any]] = mapped_column(JSON)
    trace: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    final_outcome: Mapped[str] = mapped_column(String(20))
    decisive_policy: Mapped[str | None] = mapped_column(String(60), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PolicyTestRun(Base):
    __tablename__ = "policy_test_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("scenario_sessions.id", ondelete="CASCADE"), index=True)
    run_number: Mapped[int] = mapped_column(Integer)
    policy_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    results: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ChangeRecord(Base):
    __tablename__ = "change_records"
    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("scenario_sessions.id", ondelete="CASCADE"), index=True)
    policy_key: Mapped[str] = mapped_column(String(60))
    from_version: Mapped[int] = mapped_column(Integer)
    to_version: Mapped[int] = mapped_column(Integer)
    reason: Mapped[str] = mapped_column(Text)
    expected_impact: Mapped[str] = mapped_column(Text, default="")
    rollback_plan: Mapped[str] = mapped_column(Text, default="")
    test_run_id: Mapped[int | None] = mapped_column(ForeignKey("policy_test_runs.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# --------------------------------------------------------------------------- events & investigation


class SecurityEvent(Base):
    __tablename__ = "security_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[str] = mapped_column(String(40), unique=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("scenario_sessions.id", ondelete="CASCADE"), index=True)
    organization_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    scenario_id: Mapped[str] = mapped_column(String(80))
    seq: Mapped[int] = mapped_column(Integer)
    run_number: Mapped[int] = mapped_column(Integer, default=0)  # 0 = ad-hoc learner action
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    actor_id: Mapped[str | None] = mapped_column(String(60), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(60), nullable=True)
    action: Mapped[str] = mapped_column(String(40))
    result: Mapped[str] = mapped_column(String(30))
    data_classification: Mapped[str | None] = mapped_column(String(40), nullable=True)
    source_type: Mapped[str] = mapped_column(String(30))  # IDENTITY | FILE_ACCESS | DLP | PROXY | DETECTION | ...
    source_system: Mapped[str] = mapped_column(String(80))
    provenance: Mapped[str] = mapped_column(String(20))  # SIMULATED | REAL_LAB | INTEGRATED
    policy_id: Mapped[str | None] = mapped_column(String(60), nullable=True)
    policy_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination: Mapped[str | None] = mapped_column(String(60), nullable=True)
    transaction_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    related_event_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    evidence_refs: Mapped[list[str]] = mapped_column(JSON, default=list)
    summary: Mapped[str] = mapped_column(Text, default="")
    extension: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    step_key: Mapped[str | None] = mapped_column(String(60), nullable=True)  # internal; never serialized


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(primary_key=True)
    alert_id: Mapped[str] = mapped_column(String(40), unique=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("scenario_sessions.id", ondelete="CASCADE"), index=True)
    run_number: Mapped[int] = mapped_column(Integer, default=0)
    title: Mapped[str] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20), default="NEW")  # NEW | IN_PROGRESS | CLOSED
    disposition: Mapped[str | None] = mapped_column(String(30), nullable=True)
    disposition_note: Mapped[str] = mapped_column(Text, default="")
    policy_id: Mapped[str] = mapped_column(String(60))
    policy_version: Mapped[int] = mapped_column(Integer)
    triggering_event_id: Mapped[str] = mapped_column(String(40))
    event_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    actor_id: Mapped[str | None] = mapped_column(String(60), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(60), nullable=True)
    explanation: Mapped[str] = mapped_column(Text, default="")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    step_key: Mapped[str | None] = mapped_column(String(60), nullable=True)  # internal; never serialized


class InvestigationCase(Base):
    __tablename__ = "investigation_cases"
    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("scenario_sessions.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(20), default="OPEN")  # OPEN | CONTAINED | CLOSED
    alert_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    hypothesis: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    determination: Mapped[str | None] = mapped_column(String(40), nullable=True)
    subject_identities: Mapped[list[str]] = mapped_column(JSON, default=list)
    affected_asset_keys: Mapped[list[str]] = mapped_column(JSON, default=list)
    exposure_status: Mapped[str | None] = mapped_column(String(30), nullable=True)
    records_potentially_exposed: Mapped[int | None] = mapped_column(Integer, nullable=True)
    root_causes: Mapped[list[str]] = mapped_column(JSON, default=list)
    summary: Mapped[str] = mapped_column(Text, default="")
    root_cause_narrative: Mapped[str] = mapped_column(Text, default="")
    residual_risk: Mapped[str] = mapped_column(Text, default="")
    lessons_learned: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class CaseNote(Base):
    __tablename__ = "case_notes"
    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("investigation_cases.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(20))  # OBSERVATION | INFERENCE | UNKNOWN | HYPOTHESIS
    text: Mapped[str] = mapped_column(Text)
    evidence_ids: Mapped[list[int]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EvidenceReference(Base):
    __tablename__ = "evidence_references"
    __table_args__ = (UniqueConstraint("case_id", "ref_type", "ref_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("investigation_cases.id", ondelete="CASCADE"), index=True)
    ref_type: Mapped[str] = mapped_column(String(30))  # EVENT | ALERT | ASSET | IDENTITY | GRANT | POLICY_VERSION | FINDING
    ref_id: Mapped[str] = mapped_column(String(80))
    label: Mapped[str] = mapped_column(String(300))
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RemediationAction(Base):
    __tablename__ = "remediation_actions"
    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("scenario_sessions.id", ondelete="CASCADE"), index=True)
    case_id: Mapped[int | None] = mapped_column(ForeignKey("investigation_cases.id", ondelete="SET NULL"), nullable=True)
    seq: Mapped[int] = mapped_column(Integer)
    action_type: Mapped[str] = mapped_column(String(40))
    target_key: Mapped[str] = mapped_column(String(80))
    justification: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(20))  # APPLIED | VERIFIED | VERIFICATION_FAILED | RECORDED
    before_state: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    after_state: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    verification: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    provenance: Mapped[str] = mapped_column(String(20), default="SIMULATED")
    sim_time: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# --------------------------------------------------------------------------- assessment, labs, integrations


class AssessmentAttempt(Base):
    __tablename__ = "assessment_attempts"
    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("scenario_sessions.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    scenario_id: Mapped[str] = mapped_column(String(80))
    rubric_version: Mapped[str] = mapped_column(String(20))
    mode: Mapped[str] = mapped_column(String(20))
    total_score: Mapped[float] = mapped_column(Float)
    passed: Mapped[bool] = mapped_column(Boolean)
    category_scores: Mapped[dict[str, Any]] = mapped_column(JSON)
    criteria: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    critical_failures: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    missing_tasks: Mapped[list[str]] = mapped_column(JSON)
    recommendations: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    inputs_digest: Mapped[str] = mapped_column(String(64))
    attempt_number: Mapped[int] = mapped_column(Integer, default=1)
    variant: Mapped[str] = mapped_column(String(20), default="")
    report_snapshot: Mapped[str] = mapped_column(Text, default="")
    submitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class LabExerciseResult(Base):
    __tablename__ = "lab_exercise_results"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    lab: Mapped[str] = mapped_column(String(40))
    exercise: Mapped[str] = mapped_column(String(60))
    passed: Mapped[bool] = mapped_column(Boolean)
    provenance: Mapped[str] = mapped_column(String(20))
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class LabState(Base):
    """Per-user mutable state for stand-alone labs (cloud, privacy, AI, crypto config)."""

    __tablename__ = "lab_states"
    __table_args__ = (UniqueConstraint("user_id", "lab"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    lab: Mapped[str] = mapped_column(String(40))
    state: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class IntegrationConfig(Base):
    __tablename__ = "integration_configs"
    __table_args__ = (UniqueConstraint("org_id", "connector"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    connector: Mapped[str] = mapped_column(String(60))
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    settings: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # never holds secrets
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class IntegrationRun(Base):
    __tablename__ = "integration_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    connector: Mapped[str] = mapped_column(String(60))
    provenance: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20))
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
