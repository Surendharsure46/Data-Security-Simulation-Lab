"""SIMULATED labs: Cloud DSPM, Privacy & Governance and AI Data Security.

State lives in ``LabState`` per user. All cloud events are synthetic and labelled
as such; they are not AWS, Azure or Google Cloud telemetry. The AI lab performs
no model calls: retrieval is a deterministic keyword-overlap ranker so that the
access-control behaviour can be tested exactly.
"""
from __future__ import annotations

import copy
import random
import re
from datetime import date, timedelta
from typing import Any

from ..content.company import _name
from ..services import detection
from ..services.common import DomainError
from ..services.policy_engine import PolicyDefinition, decide, evaluate_policy

# =========================================================================== Cloud DSPM

ACCESS_BREADTH = {"PUBLIC_READ": 3, "ALL_AUTHENTICATED_USERS": 3, "CROSS_ACCOUNT": 2, "ORG_WIDE": 1, "RESTRICTED": 0}
SENSITIVITY = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}

CLOUD_INITIAL = {
    "buckets": [
        {"name": "kr-analytics-exports", "data_label": "restricted", "objects": 3, "records": 46990, "access": "ALL_AUTHENTICATED_USERS",
         "cross_account_principals": [], "encryption": False, "access_logging": False, "purpose": "Analytics team extracts",
         "business_requirement": None},
        {"name": "kr-marketing-site", "data_label": "public", "objects": 212, "records": 0, "access": "PUBLIC_READ",
         "cross_account_principals": [], "encryption": True, "access_logging": True, "purpose": "Static website for product pages",
         "business_requirement": "Must remain publicly readable: serves www.kestrelridge.example"},
        {"name": "kr-hr-scans", "data_label": "restricted", "objects": 1840, "records": 1840, "access": "CROSS_ACCOUNT",
         "cross_account_principals": ["acct-helpwise-vendor"], "encryption": True, "access_logging": False,
         "purpose": "Scanned HR onboarding forms", "business_requirement": None},
        {"name": "kr-app-logs", "data_label": "confidential", "objects": 9000, "records": 0, "access": "ORG_WIDE",
         "cross_account_principals": [], "encryption": True, "access_logging": True, "purpose": "Application logs (contain customer emails)",
         "business_requirement": None},
        {"name": "kr-db-backups", "data_label": "restricted", "objects": 30, "records": 48210, "access": "RESTRICTED",
         "cross_account_principals": [], "encryption": True, "access_logging": True, "purpose": "Nightly database backups",
         "business_requirement": None},
        {"name": "kr-dev-sandbox", "data_label": "internal", "objects": 57, "records": 0, "access": "PUBLIC_READ",
         "cross_account_principals": [], "encryption": False, "access_logging": False, "purpose": "Developer experiments",
         "business_requirement": None},
    ],
    "assessments": 0,
    "last_change_seq": 0,
    "last_assessment_seq": 0,
    "seq": 0,
    "change_log": [],
}
CLOUD_TARGET = 10  # total exposure of non-public data must be <= target


def exposure(b: dict[str, Any]) -> dict[str, Any]:
    s = SENSITIVITY[b["data_label"]]
    breadth = ACCESS_BREADTH[b["access"]]
    base = s * breadth
    extra = (0 if b["encryption"] else 1) + (0 if b["access_logging"] else 1) if s >= 2 else 0
    return {"score": base + extra, "sensitivity": s, "breadth": breadth, "missing_controls": extra,
            "formula": "sensitivity(0-3) × access breadth(0-3) + 1 per missing control (encryption, logging) when sensitivity ≥ 2"}


def cloud_assess(state: dict[str, Any]) -> dict[str, Any]:
    rows = []
    for b in state["buckets"]:
        e = exposure(b)
        rows.append({"bucket": b["name"], **e, "access": b["access"], "data_label": b["data_label"]})
    rows.sort(key=lambda r: (-r["score"], r["bucket"]))
    total = sum(r["score"] for r in rows if r["sensitivity"] > 0)
    return {"buckets": rows, "total_exposure_non_public": total, "target": CLOUD_TARGET, "provenance": "SIMULATED"}


def cloud_audit_events(state: dict[str, Any]) -> list[dict[str, Any]]:
    """Deterministic synthetic audit events reflecting the *current* configuration."""
    rng = random.Random(7)
    out = []
    for b in state["buckets"]:
        if b["access"] in ("PUBLIC_READ", "ALL_AUTHENTICATED_USERS"):
            for i in range(3):
                out.append({"time": f"2026-03-0{i + 3}T0{rng.randint(1, 9)}:{rng.randint(10, 59)}:00Z", "bucket": b["name"],
                            "principal": "anonymous" if b["access"] == "PUBLIC_READ" else f"external-account-{rng.randint(1000, 9999)}",
                            "operation": "GetObject", "source_ip": f"198.51.100.{rng.randint(2, 250)}", "result": "Success"})
        for p in b["cross_account_principals"]:
            out.append({"time": "2026-03-05T14:02:00Z", "bucket": b["name"], "principal": p, "operation": "ListObjects",
                        "source_ip": "203.0.113.77", "result": "Success"})
    for c in state.get("change_log", []):
        out.append({"time": "lab-time", "bucket": c["bucket"], "principal": "learner", "operation": f"PutBucketConfig:{c['field']}",
                    "source_ip": "10.20.0.1", "result": "Success"})
    for e in out:
        e["provenance"] = "SIMULATED"
        e["note"] = "Synthetic cloud audit event; not vendor telemetry."
    return out


CLOUD_ACCESS_OPTIONS = list(ACCESS_BREADTH)


def cloud_change(state: dict[str, Any], bucket: str, field: str, value: Any) -> dict[str, Any]:
    st = copy.deepcopy(state)
    b = next((x for x in st["buckets"] if x["name"] == bucket), None)
    if b is None:
        raise DomainError("Unknown bucket", 404)
    if field == "access":
        if value not in CLOUD_ACCESS_OPTIONS:
            raise DomainError(f"access must be one of {CLOUD_ACCESS_OPTIONS}")
        b["access"] = value
        if value != "CROSS_ACCOUNT":
            b["cross_account_principals"] = []
    elif field in ("encryption", "access_logging"):
        if not isinstance(value, bool):
            raise DomainError(f"{field} must be true or false")
        b[field] = value
    elif field == "remove_principal":
        if value not in b["cross_account_principals"]:
            raise DomainError("Principal not present")
        b["cross_account_principals"].remove(value)
        if not b["cross_account_principals"] and b["access"] == "CROSS_ACCOUNT":
            b["access"] = "RESTRICTED"
    else:
        raise DomainError("Unsupported change")
    st["seq"] += 1
    st["last_change_seq"] = st["seq"]
    st["change_log"].append({"seq": st["seq"], "bucket": bucket, "field": field, "value": value})
    return st


def cloud_remediation_result(state: dict[str, Any]) -> dict[str, Any]:
    a = cloud_assess(state)
    site = next(b for b in state["buckets"] if b["name"] == "kr-marketing-site")
    disrupted = site["access"] != "PUBLIC_READ"
    reassessed = state["last_assessment_seq"] >= state["last_change_seq"] and state["last_change_seq"] > 0
    passed = a["total_exposure_non_public"] <= CLOUD_TARGET and not disrupted and reassessed
    reasons = []
    if a["total_exposure_non_public"] > CLOUD_TARGET:
        reasons.append(f"Total exposure {a['total_exposure_non_public']} is above the target {CLOUD_TARGET}.")
    if disrupted:
        reasons.append("kr-marketing-site must remain publicly readable (documented business requirement).")
    if not reassessed:
        reasons.append("Run a re-assessment after your last change to verify the result.")
    return {"passed": passed, "reasons": reasons, "assessment": a}


# =========================================================================== Privacy & governance

PRIVACY_PURPOSE = ("Send product newsletters to people who explicitly opted in, and measure engagement. "
                   "No credit decisions, identity verification or payments are performed with this dataset.")
RETENTION_STANDARD = ("Kestrel Ridge records standard (fictional): inactive marketing leads are deleted after 24 months (730 days) "
                      "without activity; leads without valid marketing consent are deleted within 30 days of creation; "
                      "records under legal hold are never deleted until the hold is lifted.")
LEAD_FIELDS = ["lead_id", "full_name", "email", "phone", "date_of_birth", "national_id", "card_number", "city",
               "consent_marketing", "consent_date", "created_at", "last_activity", "legal_hold"]
REQUIRED_KEEP = {"lead_id", "email", "consent_marketing", "consent_date", "last_activity", "created_at", "legal_hold"}
REQUIRED_REMOVE = {"national_id", "card_number", "date_of_birth"}
LAB_TODAY = date(2026, 3, 9)


def privacy_initial() -> dict[str, Any]:
    rng = random.Random(99)
    leads = []
    for i in range(1, 31):
        f, l = _name(rng)
        created = LAB_TODAY - timedelta(days=rng.choice([10, 20, 45, 200, 400, 800, 900, 1200]))
        last = created + timedelta(days=rng.randint(0, max(1, (LAB_TODAY - created).days)))
        consent = rng.random() > 0.25
        leads.append({
            "lead_id": f"LD-{1000 + i}", "full_name": f"{f} {l}", "email": f"{f.lower()}.{l.lower()}@example.org",
            "phone": f"(312) 555-01{rng.randint(0, 99):02d}", "date_of_birth": f"{rng.randint(1960, 2003)}-0{rng.randint(1, 9)}-1{rng.randint(0, 9)}",
            "national_id": f"{rng.randint(100, 665):03d}-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}",
            "card_number": "", "city": rng.choice(["Austin", "Chicago", "Boston", "Denver"]),
            "consent_marketing": consent, "consent_date": created.isoformat() if consent else None,
            "created_at": created.isoformat(), "last_activity": last.isoformat(), "legal_hold": i in (4, 17),
        })
    for ld in leads[:6]:
        ld["card_number"] = "4" + "".join(str(rng.randint(0, 9)) for _ in range(15))
    return {"leads": leads, "field_decisions": {}, "retention": None, "deleted": [], "critical": None, "evaluations": 0}


def privacy_grade_minimization(decisions: dict[str, dict[str, str]]) -> dict[str, Any]:
    unknown = set(decisions) - set(LEAD_FIELDS)
    if unknown:
        raise DomainError(f"Unknown fields: {sorted(unknown)}")
    if set(decisions) != set(LEAD_FIELDS):
        raise DomainError("Decide KEEP or REMOVE for every field")
    for f, d in decisions.items():
        if d.get("decision") not in ("KEEP", "REMOVE") or len(d.get("reason", "").strip()) < 5:
            raise DomainError(f"Field {f}: decision must be KEEP or REMOVE with a reason (5+ characters)")
    removed = {f for f, d in decisions.items() if d["decision"] == "REMOVE"}
    missing_removals = sorted(REQUIRED_REMOVE - removed)
    wrongly_removed = sorted(REQUIRED_KEEP & removed)
    return {"passed": not missing_removals and not wrongly_removed, "missing_removals": missing_removals,
            "wrongly_removed": wrongly_removed,
            "note": "phone, full_name and city are judgement calls for this purpose; either decision is accepted with a reason."}


def privacy_evaluate(state: dict[str, Any], rule: dict[str, Any]) -> list[dict[str, Any]]:
    inactive_days = int(rule["inactive_days"])
    no_consent_days = int(rule["no_consent_days"])
    out = []
    for ld in state["leads"]:
        reasons = []
        if (LAB_TODAY - date.fromisoformat(ld["last_activity"])).days > inactive_days:
            reasons.append(f"inactive > {inactive_days} days")
        if not ld["consent_marketing"] and (LAB_TODAY - date.fromisoformat(ld["created_at"])).days > no_consent_days:
            reasons.append(f"no consent after {no_consent_days} days")
        if reasons:
            held = ld["legal_hold"] and rule["respect_legal_hold"]
            out.append({"lead_id": ld["lead_id"], "reasons": reasons, "legal_hold": ld["legal_hold"],
                        "action": "RETAIN (legal hold)" if held else "DELETE"})
    return out


def privacy_expected_deletions(state: dict[str, Any]) -> set[str]:
    ideal = {"inactive_days": 730, "no_consent_days": 30, "respect_legal_hold": True}
    return {r["lead_id"] for r in privacy_evaluate(state, ideal) if r["action"] == "DELETE"}


def privacy_report(state: dict[str, Any], minimization: dict[str, Any] | None) -> str:
    lines = ["# Privacy controls findings report (SIMULATED lab)", "",
             "> Synthetic dataset. This report records platform exercise results and is not legal advice. "
             "Confirm obligations with Legal / the Privacy Office.", "",
             f"**Documented purpose:** {PRIVACY_PURPOSE}", "", f"**Retention standard applied:** {RETENTION_STANDARD}", "",
             "## Data minimisation decisions", "", "| Field | Decision | Reason |", "|---|---|---|"]
    for f in LEAD_FIELDS:
        d = state["field_decisions"].get(f, {})
        lines.append(f"| {f} | {d.get('decision', '-')} | {d.get('reason', '-').replace('|', '/')} |")
    if minimization:
        lines += ["", f"Minimisation check: {'PASSED' if minimization['passed'] else 'NOT PASSED'}."]
    r = state.get("retention") or {}
    lines += ["", "## Retention and deletion", "",
              f"Rule: inactive > {r.get('inactive_days', '-')} days; no consent after {r.get('no_consent_days', '-')} days; "
              f"legal hold respected: {r.get('respect_legal_hold', '-')}.",
              f"Records deleted from the disposable dataset: {len(state['deleted'])} ({', '.join(state['deleted']) or 'none'}).",
              f"Records remaining: {len(state['leads'])}. Legal-hold records remaining: {sum(1 for x in state['leads'] if x['legal_hold'])}."]
    if state.get("critical"):
        lines += ["", f"**Critical issue:** {state['critical']}"]
    lines += ["", "## Open items for Legal / Privacy Office", "",
              "- Confirm the retention periods against applicable law for each jurisdiction where leads reside.",
              "- Confirm the lawful basis and consent wording for newsletter processing.",
              "- Decide whether historical copies in backups require separate deletion handling."]
    return "\n".join(lines)


# =========================================================================== AI data security

AI_DESTINATIONS = {
    "ai-unapproved": {"id": "ai-unapproved", "kind": "AI_SERVICE", "category": "UNSANCTIONED", "sanctioned": False, "internal": False,
                      "domain": "chat.genie.example"},
    "ai-approved": {"id": "ai-approved", "kind": "AI_SERVICE", "category": "INTERNAL", "sanctioned": True, "internal": True,
                    "domain": "ai.kestrelridge.example"},
}
AI_PROMPTS = [
    {"id": "P1", "actor_dept": "Customer Operations", "destination": "ai-unapproved", "should_block": True,
     "text": "Summarise these complaints: KRC-10293847 avery.castellano@example.com card 4532015112830366 disputed fee"},
    {"id": "P2", "actor_dept": "IT", "destination": "ai-unapproved", "should_block": True,
     "text": "Why does this config fail? CRM_CLIENT_SECRET=krsim-SYNTHETIC-9f8e7d6c5b4a3921"},
    {"id": "P3", "actor_dept": "Marketing", "destination": "ai-unapproved", "should_block": False,
     "text": "Write three subject lines for a newsletter about our no-annual-fee card"},
    {"id": "P4", "actor_dept": "Customer Operations", "destination": "ai-approved", "should_block": False,
     "text": "Draft a polite reply to customer KRC-55102938 about a statement copy request"},
    {"id": "P5", "actor_dept": "Finance", "destination": "ai-approved", "should_block": True,
     "text": "Reconcile payroll: KR-E-100231 DE89370400440532013000 net 4210.55"},
    {"id": "P6", "actor_dept": "Legal", "destination": "ai-unapproved", "should_block": True,
     "text": "STRICTLY CONFIDENTIAL draft settlement terms with PayBridge - rewrite more formally"},
    {"id": "P7", "actor_dept": "IT", "destination": "ai-approved", "should_block": False,
     "text": "Explain the difference between TLS 1.2 and TLS 1.3 in plain language"},
    {"id": "P8", "actor_dept": "Customer Operations", "destination": "ai-unapproved", "should_block": False,
     "text": "How do I politely decline a refund request? Give a generic template."},
]
AI_DEFAULT_POLICY = {
    "name": "AI prompt gateway (initial)",
    "description": "Initial rule: only payment cards to unapproved AI are monitored.",
    "kind": "DLP", "priority": 100, "applies_to_actions": ["AI_PROMPT"],
    "conditions": {"match": "all", "conditions": [
        {"field": "destination.sanctioned", "op": "eq", "value": False},
        {"field": "content.detected_types", "op": "contains_any", "value": ["CREDIT_CARD"]},
    ]},
    "outcome": "MONITOR", "severity": "MEDIUM", "alert": True,
}

RAG_DOCS = [
    {"id": "D1", "title": "Support macro: card replacement", "acl": ["grp-all-staff"], "text": "card replacement verify identity two factors reissue"},
    {"id": "D2", "title": "HR salary bands 2026", "acl": ["grp-hr"], "text": "salary bands compensation pay grade support agent rita silva salary"},
    {"id": "D3", "title": "Escalation notes for premier customers", "acl": ["grp-support-leads"], "text": "premier customer escalation notes refund approval"},
    {"id": "D4", "title": "Refund policy", "acl": ["grp-all-staff"], "text": "refund policy fee dispute approval decline template"},
    {"id": "D5", "title": "Disciplinary case file (HR)", "acl": ["grp-hr"], "text": "disciplinary case rita silva warning performance"},
    {"id": "D6", "title": "Product FAQ", "acl": ["grp-all-staff"], "text": "no annual fee cashback groceries product card"},
]
RAG_ROLES = {"support_agent": ["grp-all-staff", "grp-support-agents"], "support_lead": ["grp-all-staff", "grp-support-leads"],
             "hr_partner": ["grp-all-staff", "grp-hr"]}
RAG_TESTS = [
    {"id": "Q1", "role": "support_agent", "query": "what is rita silva salary", "forbidden": ["D2", "D5"], "expected_any": []},
    {"id": "Q2", "role": "support_agent", "query": "card replacement verify identity", "forbidden": [], "expected_any": ["D1"]},
    {"id": "Q3", "role": "support_agent", "query": "premier customer escalation refund", "forbidden": ["D3"], "expected_any": ["D4"]},
    {"id": "Q4", "role": "hr_partner", "query": "salary bands pay grade", "forbidden": [], "expected_any": ["D2"]},
]
AI_LOG_DEFAULT = {"prompt_logging": "full", "retention_days": 3650, "log_access": "all_staff", "vendor_training_opt_in": True}
AI_LOG_OPTIONS = {"prompt_logging": ["full", "redacted", "metadata_only", "none"], "log_access": ["all_staff", "it_admins", "security_only"]}


def ai_initial() -> dict[str, Any]:
    return {"gateway_policy": copy.deepcopy(AI_DEFAULT_POLICY), "rag": {"enforce_acl": False, "index_restricted_docs": True},
            "logging": copy.deepcopy(AI_LOG_DEFAULT)}


def ai_evaluate_prompts(policy_raw: dict[str, Any]) -> dict[str, Any]:
    try:
        pol = PolicyDefinition.model_validate(policy_raw)
    except Exception as exc:
        raise DomainError(f"Invalid gateway policy: {exc}", 422) from exc
    if pol.kind != "DLP":
        raise DomainError("Gateway policy must be a DLP policy")
    ranks = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}
    results = []
    for p in AI_PROMPTS:
        scan = detection.scan_text(p["text"])
        ctx = {"action": {"type": "AI_PROMPT"}, "actor": {"department": p["actor_dept"]},
               "content": {"detected_types": sorted(scan), "match_count": sum(r.match_count for r in scan.values()),
                           "max_confidence": max((r.confidence for r in scan.values()), key=detection.CONFIDENCE_ORDER.get, default=None)},
               "destination": AI_DESTINATIONS[p["destination"]], "_label_ranks": ranks}
        entry = evaluate_policy("AI-GATEWAY", 1, "ENABLED", pol, ctx)
        decision = decide([entry])
        blocked = decision["outcome"] == "BLOCK"
        results.append({"id": p["id"], "text": p["text"], "destination": p["destination"], "detected_types": sorted(scan),
                        "outcome": decision["outcome"], "should_block": p["should_block"], "correct": blocked == p["should_block"]})
    return {"results": results, "passed": all(r["correct"] for r in results),
            "correct": sum(r["correct"] for r in results), "total": len(results), "provenance": "SIMULATED"}


def _tokens(s: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", s.lower()))


def rag_retrieve(cfg: dict[str, Any], role: str, query: str, k: int = 2) -> list[dict[str, Any]]:
    if role not in RAG_ROLES:
        raise DomainError("Unknown role")
    groups = set(RAG_ROLES[role])
    docs = [d for d in RAG_DOCS if cfg["index_restricted_docs"] or "grp-hr" not in d["acl"]]
    if cfg["enforce_acl"]:
        docs = [d for d in docs if groups & set(d["acl"])]
    q = _tokens(query)
    scored = sorted(((len(q & _tokens(d["text"] + " " + d["title"])), d["id"], d) for d in docs), key=lambda x: (-x[0], x[1]))
    return [{"id": d["id"], "title": d["title"], "score": s, "acl": d["acl"]} for s, _i, d in scored if s > 0][:k]


def rag_run_tests(cfg: dict[str, Any]) -> dict[str, Any]:
    out = []
    for t in RAG_TESTS:
        got = [d["id"] for d in rag_retrieve(cfg, t["role"], t["query"])]
        leaked = sorted(set(got) & set(t["forbidden"]))
        missing = bool(t["expected_any"]) and not (set(got) & set(t["expected_any"]))
        out.append({**t, "retrieved": got, "leaked": leaked, "missing_expected": missing, "passed": not leaked and not missing})
    return {"results": out, "passed": all(r["passed"] for r in out), "provenance": "SIMULATED"}


def ai_logging_findings(cfg: dict[str, Any]) -> list[dict[str, str]]:
    for k, opts in AI_LOG_OPTIONS.items():
        if cfg.get(k) not in opts:
            raise DomainError(f"Invalid value for {k}")
    days = cfg.get("retention_days")
    if not isinstance(days, int) or days < 0:
        raise DomainError("retention_days must be a non-negative integer")
    f = []
    if cfg["prompt_logging"] == "full":
        f.append({"id": "AI-01", "finding": "Full prompts are logged, copying any sensitive data users paste.", "fix": "Log redacted prompts or metadata only."})
    if days > 90:
        f.append({"id": "AI-02", "finding": f"Prompt logs kept for {days} days.", "fix": "Keep prompt logs 90 days or less unless a documented need exists."})
    if cfg["log_access"] == "all_staff":
        f.append({"id": "AI-03", "finding": "All staff can read prompt logs.", "fix": "Restrict log access to Security."})
    if cfg["vendor_training_opt_in"]:
        f.append({"id": "AI-04", "finding": "Prompts are shared with the vendor for model training.", "fix": "Opt out of vendor training."})
    return f
