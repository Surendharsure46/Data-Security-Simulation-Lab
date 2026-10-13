"""Unit tests for the policy language and evaluator (exact/partial/no match, missing and malformed
input, multiple matches, exceptions, conflicts, disabled policies, versions and regressions)."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.services.policy_engine import PolicyDefinition, decide, diff_definitions, evaluate_policy, explain_entry

RANKS = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}


def ctx(**over):
    base = {
        "action": {"type": "UPLOAD"},
        "actor": {"id": "u-x", "department": "Support", "employment_type": "CONTRACTOR", "groups": ["grp-a"]},
        "content": {"label": "restricted", "detected_types": ["CREDIT_CARD", "EMAIL_ADDRESS"], "record_count": 50000},
        "destination": {"id": "dst-personal-cloud", "sanctioned": False, "internal": False, "category": "PERSONAL"},
        "context": {"ticket_id": None},
        "_label_ranks": RANKS,
    }
    for k, v in over.items():
        base[k] = {**base.get(k, {}), **v} if isinstance(v, dict) else v
    return base


def pol(**over):
    d = {
        "name": "Block restricted to unsanctioned",
        "kind": "DLP",
        "applies_to_actions": ["UPLOAD", "EMAIL"],
        "conditions": {"match": "all", "conditions": [
            {"field": "destination.sanctioned", "op": "eq", "value": False},
            {"field": "content.label", "op": "label_at_least", "value": "confidential"},
        ]},
        "outcome": "BLOCK",
        "severity": "HIGH",
    }
    d.update(over)
    return PolicyDefinition.model_validate(d)


def test_exact_match_blocks():
    e = evaluate_policy("P1", 1, "ENABLED", pol(), ctx())
    assert e["matched"] and e["effective_outcome"] == "BLOCK" and e["alert"]
    assert decide([e])["outcome"] == "BLOCK"


def test_partial_match_does_not_fire():
    e = evaluate_policy("P1", 1, "ENABLED", pol(), ctx(destination={"sanctioned": True}))
    assert not e["matched"]
    results = [c["result"] for c in e["condition_trace"]["children"]]
    assert results == [False, True]


def test_no_match_defaults_to_allow():
    e = evaluate_policy("P1", 1, "ENABLED", pol(), ctx(content={"label": "public"}))
    assert decide([e]) == {"outcome": "ALLOW", "decisive_policy": None, "decisive_version": None, "reason": "No enabled policy matched"}


def test_missing_field_makes_condition_false_and_is_traced():
    c = ctx()
    c["content"] = {"detected_types": []}  # unlabeled asset
    e = evaluate_policy("P1", 1, "ENABLED", pol(), c)
    label_cond = e["condition_trace"]["children"][1]
    assert label_cond["missing"] and not label_cond["result"] and not e["matched"]


def test_not_exists_matches_missing():
    p = pol(conditions={"match": "all", "conditions": [{"field": "context.ticket_id", "op": "not_exists"}]})
    assert evaluate_policy("P", 1, "ENABLED", p, ctx())["matched"]


def test_out_of_scope_action_is_skipped():
    e = evaluate_policy("P1", 1, "ENABLED", pol(), ctx(action={"type": "DOWNLOAD"}))
    assert not e["matched"] and "Out of scope" in e["skipped_reason"]


@pytest.mark.parametrize("bad", [
    {"conditions": {"match": "all", "conditions": [{"field": "nope.field", "op": "eq", "value": 1}]}},
    {"conditions": {"match": "all", "conditions": [{"field": "content.record_count", "op": "gte", "value": "many"}]}},
    {"conditions": {"match": "all", "conditions": [{"field": "actor.id", "op": "in", "value": []}]}},
    {"conditions": {"match": "all", "conditions": []}},
    {"outcome": "DELETE_EVERYTHING"},
    {"kind": "DETECTION", "outcome": "BLOCK"},
    {"unexpected": True},
    {"conditions": {"match": "all", "conditions": [{"match": "any", "conditions": [{"match": "all", "conditions": [
        {"match": "any", "conditions": [{"field": "actor.id", "op": "eq", "value": "x"}]}]}]}]}},
])
def test_malformed_definitions_rejected(bad):
    with pytest.raises(ValidationError):
        pol(**bad)


def test_type_mismatch_is_false_not_crash():
    p = pol(conditions={"match": "all", "conditions": [{"field": "actor.department", "op": "gt", "value": 3}]})
    e = evaluate_policy("P", 1, "ENABLED", p, ctx())
    assert not e["matched"] and "Type mismatch" in e["condition_trace"]["children"][0]["error"]


def test_disabled_policy_skipped():
    e = evaluate_policy("P1", 1, "DISABLED", pol(), ctx())
    assert not e["matched"] and e["skipped_reason"] == "Policy disabled"


def test_exception_overrides_outcome_and_suppresses_alert():
    p = pol(exceptions=[{"id": "EX1", "description": "Approved partner", "when": {"match": "all", "conditions": [
        {"field": "actor.department", "op": "eq", "value": "Support"}]}, "outcome": "MONITOR"}])
    e = evaluate_policy("P1", 1, "ENABLED", p, ctx())
    assert e["matched"] and e["effective_outcome"] == "MONITOR" and not e["alert"] and e["exception"]["id"] == "EX1"
    assert "Exception 'EX1' applied" in explain_entry(e)


def test_first_matching_exception_wins():
    def ex(i, outcome):
        return {"id": i, "description": f"exception {i}", "outcome": outcome, "keep_alert": True,
                "when": {"match": "all", "conditions": [{"field": "actor.id", "op": "eq", "value": "u-x"}]}}
    e = evaluate_policy("P1", 1, "ENABLED", pol(exceptions=[ex("A", "ALLOW"), ex("B", "MONITOR")]), ctx())
    assert e["exception"]["id"] == "A" and e["effective_outcome"] == "ALLOW" and e["alert"]


def test_most_restrictive_outcome_wins_regardless_of_order():
    warn = evaluate_policy("P-WARN", 1, "ENABLED", pol(outcome="WARN", priority=1), ctx())
    block = evaluate_policy("P-BLOCK", 1, "ENABLED", pol(outcome="BLOCK", priority=500), ctx())
    monitor = evaluate_policy("P-MON", 1, "ENABLED", pol(outcome="MONITOR"), ctx())
    for order in ([warn, block, monitor], [monitor, warn, block], [block, monitor, warn]):
        d = decide(order)
        assert d["outcome"] == "BLOCK" and d["decisive_policy"] == "P-BLOCK"
        assert "3 policies matched" in d["reason"]


def test_tie_breaks_on_priority_then_key():
    a = evaluate_policy("P-B", 1, "ENABLED", pol(priority=50), ctx())
    b = evaluate_policy("P-A", 1, "ENABLED", pol(priority=50), ctx())
    c = evaluate_policy("P-C", 1, "ENABLED", pol(priority=10), ctx())
    assert decide([a, b])["decisive_policy"] == "P-A"
    assert decide([a, b, c])["decisive_policy"] == "P-C"


def test_explicit_allow_does_not_override_block():
    allow = evaluate_policy("P-ALLOW", 1, "ENABLED", pol(outcome="ALLOW", priority=1), ctx())
    block = evaluate_policy("P-BLOCK", 1, "ENABLED", pol(outcome="BLOCK"), ctx())
    assert decide([allow, block])["outcome"] == "BLOCK"


def test_contains_operators_and_label_below():
    p = pol(conditions={"match": "any", "conditions": [
        {"field": "content.detected_types", "op": "contains_all", "value": ["CREDIT_CARD", "EMAIL_ADDRESS"]},
        {"field": "content.label", "op": "label_below", "value": "internal"}]})
    assert evaluate_policy("P", 1, "ENABLED", p, ctx())["matched"]
    p2 = pol(conditions={"match": "all", "conditions": [{"field": "content.detected_types", "op": "contains_none", "value": ["CREDIT_CARD"]}]})
    assert not evaluate_policy("P", 1, "ENABLED", p2, ctx())["matched"]


def test_unknown_label_in_condition_is_reported():
    p = pol(conditions={"match": "all", "conditions": [{"field": "content.label", "op": "label_at_least", "value": "top-secret"}]})
    e = evaluate_policy("P", 1, "ENABLED", p, ctx())
    assert not e["matched"] and "Unknown label" in e["condition_trace"]["children"][0]["error"]


def test_version_diff_and_regression_effect():
    v1 = pol().model_dump(mode="json")
    v2 = pol(outcome="MONITOR").model_dump(mode="json")
    changes = diff_definitions(v1, v2)
    assert {"path": "outcome", "change": "changed", "before": "BLOCK", "after": "MONITOR"} in changes
    # Regression: the same input decided by the two versions produces different outcomes.
    assert decide([evaluate_policy("P", 1, "ENABLED", PolicyDefinition.model_validate(v1), ctx())])["outcome"] == "BLOCK"
    assert decide([evaluate_policy("P", 2, "ENABLED", PolicyDefinition.model_validate(v2), ctx())])["outcome"] == "MONITOR"


def test_detection_policies_never_enforce():
    det = PolicyDefinition.model_validate({"name": "Bulk", "kind": "DETECTION", "conditions": {"match": "all", "conditions": [
        {"field": "content.record_count", "op": "gte", "value": 10000}]}, "outcome": "MONITOR"})
    e = evaluate_policy("D", 1, "ENABLED", det, ctx())
    assert e["matched"] and e["effective_outcome"] == "MONITOR"


def test_case_insensitive_string_comparison():
    p = pol(conditions={"match": "all", "conditions": [{"field": "actor.department", "op": "in", "value": ["support"]}]})
    assert evaluate_policy("P", 1, "ENABLED", p, ctx())["matched"]
