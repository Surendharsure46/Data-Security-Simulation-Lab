"""Deterministic policy evaluation engine.

Rule language
-------------
A policy is a validated structured document (``PolicyDefinition``). Conditions are
``{field, op, value}`` triples combined in ``all``/``any`` groups (max depth 3).
No code is ever executed from a policy definition.

Precedence (documented in docs/ARCHITECTURE.md)
-----------------------------------------------
1. DISABLED policies are skipped (still listed in the trace).
2. A policy *matches* when its scope and condition group evaluate to true.
3. If a matching policy has an exception whose condition group matches, the first
   matching exception (in list order) replaces the policy outcome with the exception
   outcome (ALLOW or MONITOR) and suppresses the alert unless the exception sets
   ``keep_alert``.
4. The final decision is the most restrictive effective outcome among matched
   policies: BLOCK > WARN > MONITOR > ALLOW. Ties are broken by ``priority``
   (lower number first) then policy key, so the decisive policy is deterministic.
5. If nothing matches, the decision is ALLOW with ``decisive_policy = None``.
6. Every matched, non-excepted policy with ``alert = true`` raises its own alert.
7. A field missing from the evaluation context makes its condition false
   (except ``not_exists``); the trace records ``missing = true``.
8. DETECTION policies may only MONITOR: detection is separate from enforcement.
"""
from __future__ import annotations

from typing import Any, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

OUTCOME_RANK = {"ALLOW": 0, "MONITOR": 1, "WARN": 2, "BLOCK": 3}
SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

FIELDS: dict[str, str] = {
    "action.type": "Activity type, e.g. DOWNLOAD, EXPORT, EMAIL, UPLOAD, COPY_TO_USB, AI_PROMPT",
    "actor.id": "Synthetic identity key",
    "actor.department": "Department of the acting identity",
    "actor.role": "Enterprise role of the acting identity",
    "actor.employment_type": "EMPLOYEE, CONTRACTOR, SERVICE or TEST",
    "actor.groups": "List of group keys the actor belongs to",
    "content.label": "Current classification label key of the resource (null if unlabeled)",
    "content.label_rank": "Numeric rank of the label (higher = more sensitive)",
    "content.detected_types": "Sensitive-data detector keys found by content inspection",
    "content.max_confidence": "Highest detector confidence (LOW/MEDIUM/HIGH)",
    "content.match_count": "Total detector matches in inspected content",
    "content.record_count": "Number of records involved in the activity",
    "resource.id": "Asset key",
    "resource.system": "Hosting system of the asset",
    "resource.department": "Owning department of the asset",
    "resource.owner_assigned": "Whether the asset has a data owner",
    "destination.id": "Destination key",
    "destination.kind": "EMAIL, CLOUD_STORAGE, REMOVABLE_MEDIA, SFTP, AI_SERVICE, INTERNAL",
    "destination.category": "INTERNAL, SANCTIONED_PARTNER, PERSONAL, UNSANCTIONED",
    "destination.sanctioned": "Destination is approved by the organisation",
    "destination.internal": "Destination is inside the organisation",
    "destination.domain": "Destination domain",
    "context.business_justification": "Free-text justification supplied with the activity",
    "context.ticket_id": "Change/support ticket reference supplied with the activity",
    "context.after_hours": "Activity occurred outside 07:00-19:00 UTC",
    "context.device_managed": "Activity came from a managed device",
}

Operator = Literal[
    "eq", "neq", "in", "not_in", "contains_any", "contains_all", "contains_none",
    "gt", "gte", "lt", "lte", "exists", "not_exists", "label_at_least", "label_below",
]
Outcome = Literal["ALLOW", "MONITOR", "WARN", "BLOCK"]
Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class Condition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    field: str
    op: Operator
    value: Any = None

    @field_validator("field")
    @classmethod
    def _known_field(cls, v: str) -> str:
        if v not in FIELDS:
            raise ValueError(f"Unknown field '{v}'. Allowed: {', '.join(sorted(FIELDS))}")
        return v

    @model_validator(mode="after")
    def _value_shape(self) -> "Condition":
        if self.op in ("in", "not_in", "contains_any", "contains_all", "contains_none"):
            if not isinstance(self.value, list) or not self.value:
                raise ValueError(f"Operator '{self.op}' requires a non-empty list value")
        elif self.op in ("gt", "gte", "lt", "lte"):
            if isinstance(self.value, bool) or not isinstance(self.value, (int, float)):
                raise ValueError(f"Operator '{self.op}' requires a numeric value")
        elif self.op in ("label_at_least", "label_below"):
            if not isinstance(self.value, str) or not self.value:
                raise ValueError(f"Operator '{self.op}' requires a label key")
        elif self.op in ("exists", "not_exists"):
            self.value = None
        elif self.value is None:
            raise ValueError(f"Operator '{self.op}' requires a value")
        return self


class ConditionGroup(BaseModel):
    model_config = ConfigDict(extra="forbid")
    match: Literal["all", "any"] = "all"
    conditions: list[Union[Condition, "ConditionGroup"]] = Field(min_length=1, max_length=25)

    @model_validator(mode="after")
    def _depth(self) -> "ConditionGroup":
        def depth(g: ConditionGroup) -> int:
            sub = [depth(c) for c in g.conditions if isinstance(c, ConditionGroup)]
            return 1 + (max(sub) if sub else 0)

        if depth(self) > 3:
            raise ValueError("Condition groups may be nested at most 3 levels deep")
        return self


class PolicyException(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1, max_length=40)
    description: str = Field(min_length=3, max_length=500)
    when: ConditionGroup
    outcome: Literal["ALLOW", "MONITOR"] = "ALLOW"
    keep_alert: bool = False


class PolicyTestCase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=120)
    actor: str
    resource: str
    action: str
    destination: str | None = None
    record_count: int | None = None
    context: dict[str, Any] = Field(default_factory=dict)
    expected_outcome: Outcome


class PolicyDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=3, max_length=120)
    description: str = Field(default="", max_length=2000)
    kind: Literal["DLP", "DETECTION"] = "DLP"
    priority: int = Field(default=100, ge=1, le=1000)
    applies_to_actions: list[str] = Field(default_factory=list, max_length=20)
    conditions: ConditionGroup
    outcome: Outcome
    severity: Severity = "MEDIUM"
    alert: bool = True
    escalate: bool = False
    alert_title: str = Field(default="", max_length=200)
    exceptions: list[PolicyException] = Field(default_factory=list, max_length=20)
    test_cases: list[PolicyTestCase] = Field(default_factory=list, max_length=50)

    @model_validator(mode="after")
    def _detection_only_monitors(self) -> "PolicyDefinition":
        if self.kind == "DETECTION" and self.outcome != "MONITOR":
            raise ValueError("DETECTION policies must use outcome MONITOR (detection does not enforce)")
        ids = [e.id for e in self.exceptions]
        if len(ids) != len(set(ids)):
            raise ValueError("Exception ids must be unique within a policy")
        return self


ConditionGroup.model_rebuild()


# --------------------------------------------------------------------------- evaluation

_MISSING = object()


def _resolve(ctx: dict[str, Any], path: str) -> Any:
    cur: Any = ctx
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return _MISSING
        cur = cur[part]
    return _MISSING if cur is None else cur


def _norm(v: Any) -> Any:
    return v.lower() if isinstance(v, str) else v


def eval_condition(cond: Condition, ctx: dict[str, Any]) -> dict[str, Any]:
    actual = _resolve(ctx, cond.field)
    missing = actual is _MISSING
    rec: dict[str, Any] = {
        "field": cond.field,
        "op": cond.op,
        "value": cond.value,
        "actual": None if missing else actual,
        "missing": missing,
    }
    if cond.op == "not_exists":
        rec["result"] = missing
        return rec
    if cond.op == "exists":
        rec["result"] = not missing
        return rec
    if missing:
        rec["result"] = False
        return rec

    op, val = cond.op, cond.value
    ranks: dict[str, int] = ctx.get("_label_ranks", {})
    try:
        if op == "eq":
            result = _norm(actual) == _norm(val)
        elif op == "neq":
            result = _norm(actual) != _norm(val)
        elif op == "in":
            result = _norm(actual) in [_norm(x) for x in val]
        elif op == "not_in":
            result = _norm(actual) not in [_norm(x) for x in val]
        elif op in ("contains_any", "contains_all", "contains_none"):
            items = {_norm(x) for x in (actual if isinstance(actual, list) else [actual])}
            wanted = {_norm(x) for x in val}
            result = {
                "contains_any": bool(items & wanted),
                "contains_all": wanted <= items,
                "contains_none": not (items & wanted),
            }[op]
        elif op in ("gt", "gte", "lt", "lte"):
            a = float(actual)
            result = {"gt": a > val, "gte": a >= val, "lt": a < val, "lte": a <= val}[op]
        elif op in ("label_at_least", "label_below"):
            if val not in ranks:
                rec["error"] = f"Unknown label '{val}'"
                result = False
            else:
                actual_rank = ranks.get(str(actual))
                if actual_rank is None:
                    rec["error"] = f"Resource label '{actual}' not in label scheme"
                    result = False
                else:
                    result = actual_rank >= ranks[val] if op == "label_at_least" else actual_rank < ranks[val]
        else:  # pragma: no cover - guarded by Literal
            result = False
    except (TypeError, ValueError) as exc:
        rec["error"] = f"Type mismatch: {exc}"
        result = False
    rec["result"] = bool(result)
    return rec


def eval_group(group: ConditionGroup, ctx: dict[str, Any]) -> dict[str, Any]:
    children = []
    for c in group.conditions:
        children.append(eval_group(c, ctx) if isinstance(c, ConditionGroup) else eval_condition(c, ctx))
    results = [ch["result"] for ch in children]
    result = all(results) if group.match == "all" else any(results)
    return {"group": group.match, "result": result, "children": children}


def evaluate_policy(key: str, version: int, status: str, definition: PolicyDefinition, ctx: dict[str, Any]) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "policy_key": key,
        "policy_version": version,
        "name": definition.name,
        "kind": definition.kind,
        "status": status,
        "priority": definition.priority,
        "configured_outcome": definition.outcome,
        "severity": definition.severity,
        "matched": False,
        "exception": None,
        "effective_outcome": None,
        "alert": False,
        "escalate": False,
    }
    if status != "ENABLED":
        entry["skipped_reason"] = "Policy disabled"
        return entry
    action = _resolve(ctx, "action.type")
    if definition.applies_to_actions and (action is _MISSING or action not in definition.applies_to_actions):
        entry["skipped_reason"] = f"Out of scope: action not in {definition.applies_to_actions}"
        entry["scope_match"] = False
        return entry
    entry["scope_match"] = True
    trace = eval_group(definition.conditions, ctx)
    entry["condition_trace"] = trace
    if not trace["result"]:
        return entry
    entry["matched"] = True
    outcome = definition.outcome
    alert = definition.alert
    for exc in definition.exceptions:
        exc_trace = eval_group(exc.when, ctx)
        if exc_trace["result"]:
            entry["exception"] = {"id": exc.id, "description": exc.description, "trace": exc_trace}
            outcome = exc.outcome
            alert = alert and exc.keep_alert
            break
    entry["effective_outcome"] = outcome
    entry["alert"] = alert
    entry["escalate"] = definition.escalate and entry["exception"] is None
    return entry


def decide(entries: list[dict[str, Any]]) -> dict[str, Any]:
    matched = [e for e in entries if e["matched"]]
    if not matched:
        return {"outcome": "ALLOW", "decisive_policy": None, "decisive_version": None, "reason": "No enabled policy matched"}
    best = sorted(
        matched,
        key=lambda e: (-OUTCOME_RANK[e["effective_outcome"]], e["priority"], e["policy_key"]),
    )[0]
    reason = f"{best['policy_key']} v{best['policy_version']} ({best['name']}) produced {best['effective_outcome']}"
    if best["exception"]:
        reason += f" via exception '{best['exception']['id']}'"
    if len(matched) > 1:
        reason += f"; {len(matched)} policies matched, most restrictive outcome wins"
    return {
        "outcome": best["effective_outcome"],
        "decisive_policy": best["policy_key"],
        "decisive_version": best["policy_version"],
        "reason": reason,
    }


def explain_entry(entry: dict[str, Any]) -> str:
    """Deterministic plain-language explanation of one policy trace entry (no AI involved)."""
    if entry.get("skipped_reason"):
        return f"{entry['policy_key']} was not evaluated: {entry['skipped_reason']}."

    def walk(node: dict[str, Any], out: list[str]) -> None:
        if "group" in node:
            for ch in node["children"]:
                walk(ch, out)
            return
        actual = "missing" if node["missing"] else repr(node["actual"])
        mark = "met" if node["result"] else "NOT met"
        val = "" if node["value"] is None else f" {node['value']!r}"
        out.append(f"{node['field']} {node['op']}{val} — actual {actual} → {mark}")

    lines: list[str] = []
    walk(entry.get("condition_trace", {"group": "all", "children": []}), lines)
    head = (
        f"{entry['policy_key']} matched; effective outcome {entry['effective_outcome']}."
        if entry["matched"]
        else f"{entry['policy_key']} did not match."
    )
    if entry.get("exception"):
        head += f" Exception '{entry['exception']['id']}' applied: {entry['exception']['description']}."
    return head + " " + "; ".join(lines)


def diff_definitions(before: Any, after: Any, path: str = "") -> list[dict[str, Any]]:
    """Structural diff between two policy definitions (JSON-like)."""
    changes: list[dict[str, Any]] = []
    if isinstance(before, dict) and isinstance(after, dict):
        for k in sorted(set(before) | set(after)):
            p = f"{path}.{k}" if path else k
            if k not in before:
                changes.append({"path": p, "change": "added", "before": None, "after": after[k]})
            elif k not in after:
                changes.append({"path": p, "change": "removed", "before": before[k], "after": None})
            else:
                changes.extend(diff_definitions(before[k], after[k], p))
    elif isinstance(before, list) and isinstance(after, list):
        for i in range(max(len(before), len(after))):
            p = f"{path}[{i}]"
            if i >= len(before):
                changes.append({"path": p, "change": "added", "before": None, "after": after[i]})
            elif i >= len(after):
                changes.append({"path": p, "change": "removed", "before": before[i], "after": None})
            else:
                changes.extend(diff_definitions(before[i], after[i], p))
    elif before != after:
        changes.append({"path": path, "change": "changed", "before": before, "after": after})
    return changes
