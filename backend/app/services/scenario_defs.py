"""Scenario definition schema, validation and loading.

Scenario definitions are JSON documents in ``app/content/scenarios``. They are
validated with Pydantic and cross-checked against the environment template before
the application serves them. Definitions contain *no executable code*: task checks,
rubric checks and critical conditions refer to a fixed server-side registry.

``public_view`` is the only representation sent to learners. It omits the
timeline, variant parameters, the policy test-suite expectations and ground truth.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..content.company import environment_template

SCENARIO_DIR = Path(__file__).resolve().parent.parent / "content" / "scenarios"

ACTIONS = {"SIGN_IN", "DOWNLOAD", "EXPORT", "EMAIL", "UPLOAD", "COPY_TO_USB", "AI_PROMPT", "PRINT"}
TRANSFER_ACTIONS = {"EMAIL", "UPLOAD", "COPY_TO_USB", "AI_PROMPT", "PRINT", "EXPORT"}

TASK_CHECKS = {
    "scan_count_at_least", "assets_viewed", "asset_labeled_with_owner", "grants_reviewed",
    "learner_policy_versions_at_least", "dry_runs_with_distinct_outcomes", "run_count_at_least",
    "run_alerts_dispositioned", "case_evidence_at_least", "case_note_kinds", "case_scope_recorded",
    "remediation_category_applied", "control_fix_after_run", "validation_run_after_last_fix",
    "case_report_fields",
}
RUBRIC_CHECKS = {
    "label_matches", "grants_revoked", "alert_dispositions", "case_determination", "case_severity",
    "case_evidence_coverage", "case_notes_quality", "case_scope", "validation_exfil_prevented",
    "validation_legitimate_allowed", "dlp_blocks_canonical_exfil", "subject_contained", "escalated_to",
    "report_completeness",
}
CRITICAL_CHECKS = {"evidence_destroyed", "exfil_not_verified_closed"}


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Variant(Strict):
    key: str
    params: dict[str, str]


class TimelineStep(Strict):
    key: str = Field(pattern=r"^S\d{2}$")
    at: str = Field(pattern=r"^\d{2}:\d{2}$")
    actor: str
    action: str
    resource: str | None = None
    destination: str | None = None
    record_count: int | None = Field(default=None, ge=0)
    context: dict[str, Any] = Field(default_factory=dict)


class TaskCheck(Strict):
    type: str
    params: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _known(self) -> "TaskCheck":
        if self.type not in TASK_CHECKS:
            raise ValueError(f"Unknown task check '{self.type}'")
        return self


MissionPhase = Literal["UNDERSTAND", "INSPECT", "ACT", "OBSERVE", "VALIDATE", "SUBMIT"]


class Task(Strict):
    key: str
    stage: str
    # Mission-workflow phase the task belongs to (see app/content/career.py PHASES).
    phase: MissionPhase = "ACT"
    title: str
    description: str
    check: TaskCheck


class RemediationType(Strict):
    type: str
    category: Literal["PRESERVATION", "CONTAINMENT", "ERADICATION", "RECOVERY", "ESCALATION"]
    target_type: Literal["IDENTITY", "DESTINATION", "ASSET", "GRANT", "PARTY"]
    title: str
    description: str
    destructive: bool = False


class TestSuiteCase(Strict):
    id: str
    description: str
    actor: str
    resource: str
    action: str
    destination: str | None = None
    record_count: int | None = None
    context: dict[str, Any] = Field(default_factory=dict)
    should_prevent: bool


class Category(Strict):
    name: str
    weight: float = Field(gt=0)


class Criterion(Strict):
    key: str
    category: str
    points: float = Field(gt=0)
    check: str
    params: dict[str, Any] = Field(default_factory=dict)
    description: str
    lessons: list[str] = Field(default_factory=list)


class CriticalCondition(Strict):
    key: str
    check: str
    description: str


class Rubric(Strict):
    version: str
    pass_threshold: float = Field(ge=0, le=100)
    categories: dict[str, Category]
    criteria: list[Criterion]
    critical_conditions: list[CriticalCondition] = Field(default_factory=list)

    @model_validator(mode="after")
    def _consistent(self) -> "Rubric":
        total = sum(c.weight for c in self.categories.values())
        if abs(total - 100) > 1e-6:
            raise ValueError(f"Category weights must total 100 (got {total})")
        for c in self.criteria:
            if c.category not in self.categories:
                raise ValueError(f"Criterion {c.key} references unknown category {c.category}")
            if c.check not in RUBRIC_CHECKS:
                raise ValueError(f"Criterion {c.key} uses unknown check {c.check}")
        for cc in self.critical_conditions:
            if cc.check not in CRITICAL_CHECKS:
                raise ValueError(f"Critical condition {cc.key} uses unknown check {cc.check}")
        for cat in self.categories:
            if not any(c.category == cat for c in self.criteria):
                raise ValueError(f"Category {cat} has no criteria")
        return self


class ScenarioDefinition(Strict):
    id: str = Field(pattern=r"^[a-z0-9-]+$")
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    title: str
    summary: str
    briefing: str
    level: Literal["L0", "L1", "L2", "L3", "L4", "L5"]
    difficulty: str
    modules: list[str]
    estimated_minutes: int
    objectives: list[str]
    prerequisites: list[str] = Field(default_factory=list)
    environment: dict[str, Any]
    sim_start: str
    variants: list[Variant] = Field(min_length=1)
    timeline: list[TimelineStep]
    tasks: list[Task]
    hints: dict[str, list[str]] = Field(default_factory=dict)
    remediation_catalog: list[RemediationType]
    policy_test_suite: list[TestSuiteCase] = Field(default_factory=list)
    rubric: Rubric
    ground_truth: dict[str, Any]

    @model_validator(mode="after")
    def _referential_integrity(self) -> "ScenarioDefinition":
        env = environment_template()
        idents = {i["key"] for i in env["identities"]}
        assets = {a["key"] for a in env["assets"]}
        dests = {d["key"] for d in env["destinations"]}
        labels = {lab["key"] for lab in env["labels"]}
        grants = {g["key"] for g in env["grants"]}
        step_keys = [s.key for s in self.timeline]
        if len(step_keys) != len(set(step_keys)):
            raise ValueError("Duplicate timeline step keys")
        for v in self.variants:
            for value in v.params.values():
                if value.startswith(("u-", "svc-")) and value not in idents:
                    raise ValueError(f"Variant {v.key} references unknown identity {value}")
                if value.startswith("dst-") and value not in dests:
                    raise ValueError(f"Variant {v.key} references unknown destination {value}")
            for step in self.timeline:
                resolved = resolve_step(step, v.params)
                if resolved["actor"] not in idents:
                    raise ValueError(f"Step {step.key} actor {resolved['actor']} unknown")
                if resolved["action"] not in ACTIONS:
                    raise ValueError(f"Step {step.key} action {resolved['action']} unknown")
                if resolved["resource"] and resolved["resource"] not in assets:
                    raise ValueError(f"Step {step.key} resource {resolved['resource']} unknown")
                if resolved["destination"] and resolved["destination"] not in dests:
                    raise ValueError(f"Step {step.key} destination {resolved['destination']} unknown")
        task_keys = {t.key for t in self.tasks}
        for hint_key in self.hints:
            if hint_key not in task_keys:
                raise ValueError(f"Hints reference unknown task {hint_key}")
        for case in self.policy_test_suite:
            if case.actor not in idents or case.resource not in assets or (case.destination and case.destination not in dests):
                raise ValueError(f"Test case {case.id} references unknown entities")
        gt = self.ground_truth
        for asset, accepted in gt.get("labels", {}).items():
            if asset not in assets or not set(accepted) <= labels:
                raise ValueError(f"Ground-truth label entry for {asset} invalid")
        for g in gt.get("excessive_grants", []):
            if g not in grants:
                raise ValueError(f"Ground-truth grant {g} unknown")
        for group in gt.get("alert_groups", {}).values():
            for s in group["steps"]:
                if s not in step_keys:
                    raise ValueError(f"Ground-truth step {s} unknown")
        return self


_VAR = re.compile(r"^\$([a-z_]+)$")


def _sub(value: Any, params: dict[str, str]) -> Any:
    if isinstance(value, str):
        m = _VAR.match(value)
        if m:
            if m.group(1) not in params:
                raise ValueError(f"Unbound scenario variable {value}")
            return params[m.group(1)]
    return value


def resolve_step(step: TimelineStep, params: dict[str, str]) -> dict[str, Any]:
    return {
        "key": step.key,
        "at": step.at,
        "actor": _sub(step.actor, params),
        "action": _sub(step.action, params),
        "resource": _sub(step.resource, params),
        "destination": _sub(step.destination, params),
        "record_count": step.record_count,
        "context": dict(step.context),
    }


def load_definition(path: Path) -> ScenarioDefinition:
    return ScenarioDefinition.model_validate(json.loads(path.read_text(encoding="utf-8")))


@lru_cache
def all_definitions() -> dict[str, ScenarioDefinition]:
    defs = {}
    for p in sorted(SCENARIO_DIR.glob("*.json")):
        d = load_definition(p)
        defs[d.id] = d
    return defs


def get_definition(scenario_id: str) -> ScenarioDefinition | None:
    return all_definitions().get(scenario_id)


def public_view(d: ScenarioDefinition) -> dict[str, Any]:
    """Learner-safe representation. Never includes timeline, variants, ground truth or expectations."""
    return {
        "id": d.id,
        "version": d.version,
        "title": d.title,
        "summary": d.summary,
        "briefing": d.briefing,
        "level": d.level,
        "difficulty": d.difficulty,
        "modules": d.modules,
        "estimated_minutes": d.estimated_minutes,
        "objectives": d.objectives,
        "prerequisites": d.prerequisites,
        "variant_count": len(d.variants),
        "tasks": [{"key": t.key, "stage": t.stage, "phase": t.phase, "title": t.title, "description": t.description} for t in d.tasks],
        "hint_counts": {k: len(v) for k, v in d.hints.items()},
        "remediation_catalog": [r.model_dump() for r in d.remediation_catalog],
        "policy_test_suite_size": len(d.policy_test_suite),
        "rubric": {
            "version": d.rubric.version,
            "pass_threshold": d.rubric.pass_threshold,
            "categories": {k: v.model_dump() for k, v in d.rubric.categories.items()},
            "criteria": [
                {"key": c.key, "category": c.category, "points": c.points, "description": c.description}
                for c in d.rubric.criteria
            ],
            "critical_conditions": [{"key": c.key, "description": c.description} for c in d.rubric.critical_conditions],
        },
    }
