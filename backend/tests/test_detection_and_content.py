"""Detector, synthetic content and scenario-definition validation tests."""
from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from app.content.company import build_content, environment_template
from app.services import detection
from app.services.scenario_defs import SCENARIO_DIR, ScenarioDefinition, all_definitions, public_view


def test_luhn_and_iban_validators():
    assert detection.luhn_valid("4111111111111111")
    assert not detection.luhn_valid("4111111111111112")
    assert detection.iban_valid("DE89370400440532013000")
    assert not detection.iban_valid("DE89370400440532013001")


def test_card_detection_masks_evidence_and_downgrades_test_pans():
    res = detection.scan_text("card_number\n4111111111111111\n")
    card = res["CREDIT_CARD"]
    assert card.confidence == "LOW" and card.test_values == 1
    assert card.evidence[0]["masked_value"].endswith("1111") and "4111111111" not in card.evidence[0]["masked_value"]


def test_invalid_numbers_not_detected():
    res = detection.scan_text("ref 4111111111111112 ssn 000-12-3456 666-12-3456 912-12-3456")
    assert "CREDIT_CARD" not in res and "US_SSN" not in res


def test_keyword_proximity_raises_confidence():
    assert detection.scan_text("ssn: 123-45-6789")["US_SSN"].confidence == "HIGH"
    assert detection.scan_text("value 123-45-6789")["US_SSN"].confidence == "MEDIUM"


def test_dob_requires_keyword_and_secret_matches_prefixed_names():
    assert "DATE_OF_BIRTH" not in detection.scan_text("shipped 2026-03-09")
    assert "DATE_OF_BIRTH" in detection.scan_text("date_of_birth\n1984-05-02")
    sec = detection.scan_text("CRM_CLIENT_SECRET=krsim-SYNTHETIC-9f8e7d6c5b4a3921")["SECRET_CREDENTIAL"]
    assert sec.evidence[0]["masked_value"] == "CRM_CLIENT_SECRET=<redacted>"


def test_synthetic_content_is_detectable_and_deterministic():
    c1, c2 = build_content(), build_content()
    assert c1 == c2
    export = detection.scan_text(c1["ast-cust-export-q1"])
    assert {"CREDIT_CARD", "EMAIL_ADDRESS", "CUSTOMER_ACCOUNT", "DATE_OF_BIRTH", "PHONE_NUMBER"} <= set(export)
    assert export["CREDIT_CARD"].confidence == "HIGH"
    assert "IBAN" in detection.scan_text(c1["ast-payroll-mar"])
    assert "US_SSN" in detection.scan_text(c1["ast-hr-records"])
    assert "SECRET_CREDENTIAL" in detection.scan_text(c1["ast-api-config"])
    masked = detection.scan_text(c1["ast-cust-sample-masked"])
    assert "CREDIT_CARD" not in masked and "EMAIL_ADDRESS" not in masked


def test_synthetic_data_uses_reserved_domains_only():
    env = environment_template()
    blob = json.dumps(env)
    import re
    domains = set(re.findall(r"@([a-z0-9.-]+\.[a-z]+)", blob))
    assert all(d.endswith(".example") or d in {"example.com", "example.net", "example.org"} for d in domains), domains


def test_all_scenario_definitions_validate():
    defs = all_definitions()
    assert "customer-data-export" in defs


def test_public_view_never_contains_hidden_answers():
    d = all_definitions()["customer-data-export"]
    view = json.dumps(public_view(d))
    for secret in ("ground_truth", "u-jokafor", "u-rsilva", "\"timeline\":", "culprit", "TRUE_POSITIVE", "g-02", "S08"):
        assert secret not in view, secret


def test_invalid_scenario_definition_rejected():
    raw = json.loads((SCENARIO_DIR / "customer-data-export.json").read_text(encoding="utf-8"))
    bad = json.loads(json.dumps(raw))
    bad["timeline"][0]["actor"] = "u-nobody"
    with pytest.raises(ValidationError):
        ScenarioDefinition.model_validate(bad)
    bad2 = json.loads(json.dumps(raw))
    bad2["rubric"]["criteria"][0]["check"] = "os.system"
    with pytest.raises(ValidationError):
        ScenarioDefinition.model_validate(bad2)
    bad3 = json.loads(json.dumps(raw))
    bad3["rubric"]["categories"]["technical"]["weight"] = 50
    with pytest.raises(ValidationError):
        ScenarioDefinition.model_validate(bad3)
