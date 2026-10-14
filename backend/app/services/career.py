"""Learning journey: role choice, Levels 0-5, fundamentals, knowledge checks, lab missions and level unlocks.

    Choose role -> Level n: read fundamentals -> pass the knowledge check -> complete every lab mission
    (Understand -> Inspect -> Act -> Observe -> Validate -> Submit evidence and explanation ->
    server-side competency assessment -> required criteria?
        no  -> skill gaps + remedial lessons -> retry with practice or a new variant
        yes -> record skills and outcome -> next lab)
    -> level complete -> congratulations (pending_promotion) -> Level n+1 unlocked automatically.

Scenario missions reuse the scenario and assessment engines unchanged. Lab missions are assessed from
the server-verified ``LabExerciseResult`` rows the labs record; the demo lab from the demo progress
recorded by the real detector and policy-engine endpoints.
"""
from __future__ import annotations

import hashlib
import random
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..content import career as C
from ..content.curriculum import LESSONS, QUIZZES
from ..labs import get_state, passed_exercises
from ..models import (
    Alert, AssessmentAttempt, EvidenceReference, LabExerciseResult, LearnerProfile, MissionAttempt, ScenarioSession,
    SecurityEvent, SkillRecord, User, utcnow,
)
from . import assessment, detection
from .common import DomainError, audit, iso
from .investigation import primary_case
from .policy_engine import PolicyDefinition, decide, evaluate_policy, explain_entry
from .scenario_defs import get_definition
from .session_lifecycle import start_scenario_session, submit_scenario_session

LESSON_BY_ID = {x["id"]: x for x in LESSONS}
PREVENTED = {"BLOCKED", "DENIED", "FAILURE"}
SKILL_GAP_THRESHOLD = 70
CHECK_PASS_MARK = 0.8  # 4 of 5

# --------------------------------------------------------------------------- questions (options shuffled, answers server-side)


def served_questions(qs: list[dict[str, Any]], salt: str) -> list[dict[str, Any]]:
    """Questions with their options in a stable, shuffled order so the right answer is not always in the same place.

    The order depends only on the salt and the question text, so the same learner sees the same order every time
    and grading stays deterministic. Each returned question keeps its (remapped) ``answer``; callers strip it
    before sending questions to the browser.
    """
    out = []
    for q in qs:
        order = list(range(len(q["options"])))
        random.Random(hashlib.sha256(f"{salt}|{q['q']}".encode()).hexdigest()).shuffle(order)
        out.append({"q": q["q"], "options": [q["options"][i] for i in order], "answer": order.index(q["answer"])})
    return out


def public_questions(qs: list[dict[str, Any]], salt: str) -> list[dict[str, Any]]:
    return [{"q": q["q"], "options": q["options"]} for q in served_questions(qs, salt)]


def level_questions(level: int) -> list[dict[str, Any]]:
    return served_questions(C.LEVEL_CHECKS[level], C.check_id(level))


def mission_questions(mid: str) -> list[dict[str, Any]]:
    return served_questions(C.MISSIONS[mid]["business_problem"]["questions"], mid)


# --------------------------------------------------------------------------- profile and role


def get_profile(db: Session, user: User) -> LearnerProfile:
    p = db.scalar(select(LearnerProfile).where(LearnerProfile.user_id == user.id))
    if p is None:
        try:
            with db.begin_nested():
                p = LearnerProfile(user_id=user.id, onboarding_step="ROLE", onboarding={}, career_level=0)
                db.add(p)
        except IntegrityError:
            p = db.scalar(select(LearnerProfile).where(LearnerProfile.user_id == user.id))
    return p


def _role(p: LearnerProfile) -> dict[str, Any] | None:
    return next((r for r in C.ROLES if r["key"] == p.desired_role), None)


def profile_out(db: Session, user: User, p: LearnerProfile) -> dict[str, Any]:
    lv = C.level_def(p.career_level)
    return {
        "onboarding_complete": p.onboarding_step == "DONE",
        "desired_role": p.desired_role,
        "role": _role(p),
        "career_level": p.career_level,
        "role_title": p.role_title,
        "joined_at": iso(p.joined_at),
        "pending_promotion": p.pending_promotion,
        "level": {k: lv[k] for k in ("level", "title", "summary")} if lv else None,
        "top_level": C.TOP_LEVEL,
    }


def choose_role(db: Session, user: User, role_key: str) -> LearnerProfile:
    if role_key not in C.ROLE_KEYS:
        raise DomainError(f"Unknown role; choose one of {C.ROLE_KEYS}", 422)
    p = get_profile(db, user)
    first = p.onboarding_step != "DONE"
    p.desired_role = role_key
    p.role_title = C.role_title(role_key, p.career_level)
    if first:
        p.onboarding_step = "DONE"
        p.joined_at = utcnow()
    # Keep the Learning Library pathway aligned with the chosen role.
    st = get_state(db, user, "profile", {"pathway": "foundation"})
    st.state = {**(st.state or {}), "pathway": role_key}
    audit(db, user_id=user.id, org_id=user.org_id, action="career.role", target_type="role", target_id=role_key,
          detail={"first_time": first})
    return p


def public_content() -> dict[str, Any]:
    """Content for the public welcome and get-started pages (no answers, nothing user-specific)."""
    return {
        "welcome": C.WELCOME, "platform": C.PLATFORM, "roles": C.ROLES, "phases": C.PHASES,
        "levels": [{"level": lv["level"], "title": lv["title"], "summary": lv["summary"], "icon": lv["icon"],
                    "labs": len(lv["missions"]), "lessons": len(_fundamentals(lv["level"]))} for lv in C.LEVELS],
    }


# --------------------------------------------------------------------------- interactive demo (real detectors and policy engine)


def _demo_progress(p: LearnerProfile) -> dict[str, Any]:
    return dict((p.onboarding or {}).get("demo", {}))


def _set_demo(p: LearnerProfile, **changes: Any) -> dict[str, Any]:
    demo = {**_demo_progress(p), **changes}
    p.onboarding = {**(p.onboarding or {}), "demo": demo}
    return demo


def _reset_demo(p: LearnerProfile) -> None:
    p.onboarding = {**(p.onboarding or {}), "demo": {}}


def _demo_flags(p: LearnerProfile) -> dict[str, bool]:
    return {k: bool(_demo_progress(p).get(k)) for k in C.DEMO["completion"]}


def demo_scan(db: Session, user: User, text: str | None) -> dict[str, Any]:
    p = get_profile(db, user)
    results = detection.scan_text(text if text is not None else C.DEMO["record"])
    _set_demo(p, scanned=True)
    return {
        "provenance": "SIMULATED",
        "findings": [{"detector": r.detector, "match_count": r.match_count, "confidence": r.confidence, "evidence": r.evidence}
                     for r in results.values()],
        "explanation": ("Detectors combine patterns with validators (for example the Luhn checksum for card numbers) and nearby "
                        "keywords. Findings carry masked evidence, so scan results, cases and reports never repeat the full value."),
        "demo": _demo_flags(p),
    }


def demo_classify(db: Session, user: User, label: str) -> dict[str, Any]:
    keys = {lab["key"] for lab in C.DEMO["labels"]}
    if label not in keys:
        raise DomainError(f"Unknown label; choose one of {sorted(keys)}", 422)
    p = get_profile(db, user)
    correct = label == C.DEMO["expected_label"]
    _set_demo(p, label=label, **({"classified": True} if correct else {}))
    return {"label": label, "correct": correct, "feedback": C.DEMO["label_feedback"][label], "demo": _demo_flags(p)}


def demo_transfer(db: Session, user: User, destination: str) -> dict[str, Any]:
    dest = next((d for d in C.DEMO["destinations"] if d["key"] == destination), None)
    if dest is None:
        raise DomainError("Unknown demo destination", 422)
    p = get_profile(db, user)
    label = _demo_progress(p).get("label")
    results = detection.scan_text(C.DEMO["record"])
    ranks = {lab["key"]: lab["rank"] for lab in C.DEMO["labels"]}
    ctx = {
        "action": {"type": "UPLOAD" if dest["kind"] == "SFTP" else "EMAIL"},
        "actor": {"id": "you", "department": "Customer Operations", "role": "Support Agent", "employment_type": "EMPLOYEE", "groups": []},
        "content": {"label": label, "label_rank": ranks.get(label) if label else None, "detected_types": sorted(results),
                    "max_confidence": max((r.confidence for r in results.values()), key=detection.CONFIDENCE_ORDER.get, default=None),
                    "match_count": sum(r.match_count for r in results.values()), "record_count": 1},
        "destination": {k: dest[k] for k in ("kind", "category", "sanctioned", "internal")} | {"id": dest["key"], "domain": ""},
        "context": {"after_hours": False, "device_managed": True},
        "_label_ranks": ranks,
    }
    entry = evaluate_policy("DEMO-DLP", 1, "ENABLED", PolicyDefinition.model_validate(C.DEMO["policy"]), ctx)
    entry["explanation"] = explain_entry(entry)
    decision = decide([entry])
    if decision["outcome"] == "BLOCK":
        _set_demo(p, observed_block=True)
    elif decision["outcome"] == "ALLOW":
        _set_demo(p, observed_allow=True)
    consequence = ("The transfer was stopped before the data left the company. An alert would go to the SOC."
                   if decision["outcome"] == "BLOCK" else
                   "The transfer went through. Legitimate business transfers must keep working — over-blocking is a failure too.")
    return {"provenance": "SIMULATED", "destination": dest, "label_used": label, "decision": decision, "trace": [entry],
            "consequence": consequence, "demo": _demo_flags(p)}


def demo_content() -> dict[str, Any]:
    return {k: v for k, v in C.DEMO.items() if k not in ("expected_label", "label_feedback", "completion")}


# --------------------------------------------------------------------------- levels: fundamentals and knowledge checks


def _fundamentals(level: int) -> list[dict[str, Any]]:
    lv = C.level_def(level)
    items = list(lv["intro_items"])
    items += [{"type": "lesson", "key": x["id"], "title": x["title"]} for x in LESSONS if x["level"] == f"L{level}"]
    return items


def _item_content(item: dict[str, Any]) -> dict[str, Any]:
    if item["type"] == "lesson":
        x = LESSON_BY_ID[item["key"]]
        return {**item, "module": x["module"], "body": x["body"], "practice": x["practice"]}
    if item["type"] == "briefing":
        return {**item, "organization": C.ORGANIZATION}
    return dict(item)


def _read(p: LearnerProfile) -> set[str]:
    return set((p.onboarding or {}).get("read", []))


def _require_unlocked(p: LearnerProfile, level: int) -> dict[str, Any]:
    lv = C.level_def(level)
    if lv is None:
        raise DomainError("Level not found", 404)
    if p.onboarding_step != "DONE":
        raise DomainError("Choose your role to start the journey", 409)
    if level > p.career_level:
        raise DomainError(f"Level {level} is locked. Complete Level {p.career_level} first.", 409)
    return lv


def mark_read(db: Session, user: User, level: int, key: str) -> dict[str, Any]:
    p = get_profile(db, user)
    _require_unlocked(p, level)
    if key not in {i["key"] for i in _fundamentals(level)}:
        raise DomainError("Unknown fundamentals item for this level", 404)
    read = _read(p) | {f"L{level}:{key}"}
    p.onboarding = {**(p.onboarding or {}), "read": sorted(read)}
    return level_detail(db, user, level)


def _check_passed(db: Session, user: User, level: int) -> bool:
    return db.scalar(select(func.count(LabExerciseResult.id)).where(
        LabExerciseResult.user_id == user.id, LabExerciseResult.lab == "knowledge",
        LabExerciseResult.exercise == C.check_id(level), LabExerciseResult.passed.is_(True))) > 0


def answer_level_check(db: Session, user: User, level: int, answers: list[int]) -> dict[str, Any]:
    p = get_profile(db, user)
    _require_unlocked(p, level)
    unread = [i for i in _fundamentals(level) if f"L{level}:{i['key']}" not in _read(p)]
    if unread:
        raise DomainError("Review every fundamentals lesson before the knowledge check", 409)
    qs = level_questions(level)
    if len(answers) != len(qs):
        raise DomainError(f"Expected {len(qs)} answers", 422)
    correct = [a == q["answer"] for a, q in zip(answers, qs)]
    score = sum(correct) / len(qs)
    passed = score >= CHECK_PASS_MARK
    db.add(LabExerciseResult(user_id=user.id, lab="knowledge", exercise=C.check_id(level), passed=passed, provenance="SIMULATED",
                             detail={"score": score, "correct": correct}))
    db.flush()
    nxt = _advance(db, user, p) if passed else None
    return {"score": score, "passed": passed, "correct": correct, "pass_mark": CHECK_PASS_MARK, "next": nxt}


# --------------------------------------------------------------------------- mission catalogue


def _mission(mid: str) -> dict[str, Any]:
    m = C.MISSIONS.get(mid)
    if m is None:
        raise DomainError("Mission not found", 404)
    return m


def _required_items(m: dict[str, Any]) -> list[dict[str, Any]]:
    if m["kind"] == "LAB":
        return [{"key": ex["exercise"], "label": ex["title"], "requirement": "Verified by the lab"} for ex in m["exercises"]]
    if m["kind"] == "DEMO":
        return [{"key": i["key"], "label": i["title"], "requirement": "Completed in the demo lab"} for i in m["items"]]
    d = get_definition(m["scenario_id"])
    crit = {c.key: c for c in d.rubric.criteria}
    out = []
    for rc in m.get("required_criteria", []):
        if "criterion" in rc:
            c = crit[rc["criterion"]]
            req = "full credit" if rc["min_fraction"] >= 1 else f"at least {round(rc['min_fraction'] * 100)}% of its points"
            out.append({"key": rc["criterion"], "label": c.description, "requirement": req})
        else:
            cat = d.rubric.categories[rc["category"]]
            out.append({"key": rc["category"], "label": f"{cat.name} category", "requirement": f"at least {rc['min_percent']}%"})
    return out


def mission_public(mid: str) -> dict[str, Any]:
    """Learner-safe mission view. Comprehension answers are never included."""
    m = _mission(mid)
    bp = m["business_problem"]
    lv = C.level_def(m["level"])
    out: dict[str, Any] = {
        "id": mid, "kind": m["kind"], "level": m["level"], "level_title": lv["title"], "title": m["title"], "assigned_by": m["assigned_by"],
        "business_problem": {**{k: v for k, v in bp.items() if k != "questions"},
                             "questions": public_questions(bp["questions"], mid)},
        "required": _required_items(m), "min_explanation": m.get("min_explanation", 80),
    }
    if m["kind"] == "SCENARIO":
        d = get_definition(m["scenario_id"])
        out.update({"scenario_id": d.id, "scenario_title": d.title, "briefing": d.briefing, "mode": m["mode"],
                    "min_score": m["min_score"], "estimated_minutes": d.estimated_minutes, "hints": m["mode"] == "GUIDED",
                    "execution_mode": "SIMULATED"})
    elif m["kind"] == "LAB":
        out.update({"lab": m["lab"], "route": C.LAB_ROUTES[m["lab"]], "min_score": 100,
                    "exercises": [{k: ex[k] for k in ("exercise", "phase", "title", "steps")} for ex in m["exercises"]]})
    else:
        out.update({"min_score": 100, "demo": demo_content()})
    return out


def _passed_missions(db: Session, user: User) -> set[str]:
    return {mid for mid in db.scalars(select(MissionAttempt.mission_id).where(
        MissionAttempt.user_id == user.id, MissionAttempt.status == "PASSED")).all() if mid in C.MISSIONS}


def _level_complete(db: Session, user: User, level: int, passed: set[str] | None = None) -> bool:
    passed = passed if passed is not None else _passed_missions(db, user)
    return _check_passed(db, user, level) and all(mid in passed for mid in C.level_def(level)["missions"])


def assigned_mission_id(db: Session, user: User, p: LearnerProfile) -> str | None:
    lv = C.level_def(p.career_level)
    if lv is None or p.onboarding_step != "DONE" or not _check_passed(db, user, p.career_level):
        return None
    passed = _passed_missions(db, user)
    return next((mid for mid in lv["missions"] if mid not in passed), None)


def _active_attempt(db: Session, user: User, mid: str) -> MissionAttempt | None:
    return db.scalar(select(MissionAttempt).where(MissionAttempt.user_id == user.id, MissionAttempt.mission_id == mid,
                                                  MissionAttempt.status == "IN_PROGRESS").order_by(MissionAttempt.id.desc()).limit(1))


def _latest_attempt(db: Session, user: User, mid: str) -> MissionAttempt | None:
    return db.scalar(select(MissionAttempt).where(MissionAttempt.user_id == user.id, MissionAttempt.mission_id == mid)
                     .order_by(MissionAttempt.id.desc()).limit(1))


# --------------------------------------------------------------------------- level views


def level_detail(db: Session, user: User, level: int) -> dict[str, Any]:
    p = get_profile(db, user)
    lv = C.level_def(level)
    if lv is None:
        raise DomainError("Level not found", 404)
    unlocked = p.onboarding_step == "DONE" and level <= p.career_level
    read = _read(p)
    passed = _passed_missions(db, user)
    check = _check_passed(db, user, level)
    steps: list[dict[str, Any]] = []
    fundamentals = [_item_content(i) for i in _fundamentals(level)]
    for i in fundamentals:
        steps.append({"type": "learn", "key": i["key"], "title": i["title"], "done": f"L{level}:{i['key']}" in read})
    all_read = all(s["done"] for s in steps)
    steps.append({"type": "check", "key": C.check_id(level), "title": f"Level {level} knowledge check", "done": check})
    first_open_mission = next((mid for mid in lv["missions"] if mid not in passed), None)
    for mid in lv["missions"]:
        m = C.MISSIONS[mid]
        latest = _latest_attempt(db, user, mid)
        steps.append({"type": "mission", "key": mid, "title": m["title"], "kind": m["kind"], "lab": m.get("lab"), "mode": m.get("mode"),
                      "done": mid in passed,
                      "latest_attempt": {"id": latest.id, "status": latest.status, "score": latest.score} if latest else None})
    # Steps are sequential: everything up to the first unfinished step is reachable.
    reachable = unlocked
    for s in steps:
        if s["type"] == "check" and not all_read:
            reachable = False
        if s["type"] == "mission" and (not check or (s["key"] != first_open_mission and not s["done"])):
            s["status"] = "DONE" if s["done"] else "LOCKED"
            continue
        s["status"] = "DONE" if s["done"] else ("CURRENT" if reachable else "LOCKED")
        if not s["done"] and reachable:
            reachable = s["type"] == "learn"  # every lesson is open once the level is unlocked
    first_current = next((s for s in steps if s["status"] == "CURRENT"), None)
    for s in steps:
        if s["status"] == "CURRENT" and s is not first_current:
            s["status"] = "OPEN"
    current = first_current
    done = sum(1 for s in steps if s["done"])
    complete = check and all(mid in passed for mid in lv["missions"])
    status = "COMPLETED" if complete else ("CURRENT" if unlocked else "LOCKED")
    return {
        "level": level, "title": lv["title"], "summary": lv["summary"], "icon": lv["icon"],
        "before_you_start": lv["before_you_start"], "responsibilities": lv["responsibilities"], "challenge": lv["challenge"],
        "rank_title": C.role_title(p.desired_role, level), "status": status, "unlocked": unlocked,
        "fundamentals": fundamentals, "steps": steps, "progress": {"done": done, "total": len(steps)},
        "next_step": current, "check": {"passed": check, "pass_mark": CHECK_PASS_MARK,
                                        "questions": public_questions(C.LEVEL_CHECKS[level], C.check_id(level))},
    }


def _level_summary(db: Session, user: User, level: int) -> dict[str, Any]:
    d = level_detail(db, user, level)
    return {k: d[k] for k in ("level", "title", "summary", "icon", "status", "unlocked", "progress", "rank_title", "next_step")} | {
        "labs": len(C.level_def(level)["missions"])}


# --------------------------------------------------------------------------- starting and retrying missions


def start_mission(db: Session, user: User, mid: str, strategy: str = "ASSIGNED",
                  previous: MissionAttempt | None = None) -> MissionAttempt:
    p = get_profile(db, user)
    if p.onboarding_step != "DONE":
        raise DomainError("Choose your role to start the journey", 409)
    m = _mission(mid)
    if m["level"] > p.career_level:
        raise DomainError(f"This lab belongs to Level {m['level']}, which is still locked", 409)
    if not _check_passed(db, user, m["level"]):
        raise DomainError(f"Pass the Level {m['level']} knowledge check before starting its labs", 409)
    if mid in _passed_missions(db, user):
        raise DomainError("You have already passed this lab", 409)
    lv = C.level_def(m["level"])
    passed = _passed_missions(db, user)
    first_open = next((x for x in lv["missions"] if x not in passed), None)
    if mid != first_open:
        raise DomainError("Labs in a level are taken in order. Finish the current lab first.", 409)
    active = _active_attempt(db, user, mid)
    if active is not None:
        if strategy == "ASSIGNED":
            return active
        active.status = "ABANDONED"
        previous = previous or active
    if m["kind"] != "SCENARIO" and strategy == "NEW_VARIANT":
        raise DomainError("This lab has no variants; retry with practice instead", 422)
    n = (db.scalar(select(func.count(MissionAttempt.id)).where(MissionAttempt.user_id == user.id,
                                                               MissionAttempt.mission_id == mid)) or 0) + 1
    understanding: dict[str, Any] = {}
    if previous is not None and (previous.understanding or {}).get("passed"):
        understanding = {**previous.understanding, "carried_over_from": previous.attempt_number}
    a = MissionAttempt(user_id=user.id, mission_id=mid, attempt_number=n, strategy=strategy, counts=True,
                       status="IN_PROGRESS", understanding=understanding, cited_evidence=[], outcome={})
    if m["kind"] == "SCENARIO":
        prev_session = db.get(ScenarioSession, previous.session_id) if previous is not None and previous.session_id else None
        if strategy == "PRACTICE":
            s = start_scenario_session(db, user, m["scenario_id"], "GUIDED", prev_session.variant if prev_session else None)
        elif strategy == "NEW_VARIANT":
            s = start_scenario_session(db, user, m["scenario_id"], m["mode"], exclude_variant=prev_session.variant if prev_session else None)
        else:
            s = start_scenario_session(db, user, m["scenario_id"], m["mode"])
        a.session_id = s.id
        a.counts = s.mode == m["mode"]
    elif m["kind"] == "DEMO" and previous is not None:
        _reset_demo(p)  # a retry repeats the demo from the start
    db.add(a)
    db.flush()
    audit(db, user_id=user.id, org_id=user.org_id, action="mission.start", target_type="mission_attempt", target_id=a.id,
          detail={"mission": mid, "strategy": strategy, "counts": a.counts})
    return a


def retry(db: Session, user: User, a: MissionAttempt, strategy: str) -> MissionAttempt:
    if a.status == "PASSED":
        raise DomainError("This lab is already passed", 409)
    if a.status == "ABANDONED":
        raise DomainError("This attempt was replaced by a newer one", 409)
    latest = _latest_attempt(db, user, a.mission_id)
    if latest is not None and latest.id != a.id:
        raise DomainError("Retry from the latest attempt of this lab", 409)
    return start_mission(db, user, a.mission_id, strategy, previous=a)


# --------------------------------------------------------------------------- mission view


def _session_observations(db: Session, s: ScenarioSession) -> dict[str, Any]:
    runs = []
    for r in (s.flags or {}).get("runs", []):
        n = r["run_number"]
        events = db.scalar(select(func.count(SecurityEvent.id)).where(SecurityEvent.session_id == s.id, SecurityEvent.run_number == n)) or 0
        prevented = db.scalar(select(func.count(SecurityEvent.id)).where(
            SecurityEvent.session_id == s.id, SecurityEvent.run_number == n, SecurityEvent.result.in_(PREVENTED))) or 0
        alerts = db.scalar(select(func.count(Alert.id)).where(Alert.session_id == s.id, Alert.run_number == n)) or 0
        runs.append({"run_number": n, "mode": r["mode"], "sim_day": r["sim_day"], "events": events,
                     "prevented_events": prevented, "alerts": alerts})
    return {"runs": runs}


def _evidence_options(db: Session, s: ScenarioSession) -> dict[str, Any]:
    case = primary_case(db, s)
    if case is None:
        return {"case_id": None, "case_title": None, "items": []}
    items = [{"id": e.id, "ref_type": e.ref_type, "ref_id": e.ref_id, "label": e.label}
             for e in db.scalars(select(EvidenceReference).where(EvidenceReference.case_id == case.id).order_by(EvidenceReference.id))]
    return {"case_id": case.id, "case_title": case.title, "items": items}


def _phases(db: Session, user: User, a: MissionAttempt, m: dict[str, Any], s: ScenarioSession | None) -> list[dict[str, Any]]:
    items: dict[str, list[dict[str, Any]]] = {k: [] for k in C.PHASE_KEYS}
    und = a.understanding or {}
    items["UNDERSTAND"].append({"key": "understand", "kind": "check", "title": "Answer the business-problem check",
                                "description": "Server-graded; the correct options are never sent to your browser.",
                                "done": bool(und.get("passed")), "steps": ["Read the business problem.", "Answer the questions and click 'Check answers'."]})
    if m["kind"] == "SCENARIO" and s is not None:
        for t in assessment.task_progress(db, s):
            items[t["phase"]].append({"key": t["key"], "kind": "task", "title": t["title"], "description": t["description"],
                                      "done": t["done"], "hints_available": t["hints_available"]})
    elif m["kind"] == "LAB":
        passed = passed_exercises(db, user, m["lab"])
        for ex in m["exercises"]:
            items[ex["phase"]].append({"key": ex["exercise"], "kind": "lab_exercise", "title": ex["title"],
                                       "description": f"Verified server-side by the {m['lab']} lab.", "steps": ex["steps"],
                                       "done": ex["exercise"] in passed, "route": C.LAB_ROUTES[m["lab"]]})
    else:
        flags = _demo_flags(get_profile(db, user))
        for it in m["items"]:
            items[it["phase"]].append({"key": it["key"], "kind": "demo_step", "title": it["title"], "steps": it["steps"],
                                       "description": "Recorded by the demo lab.", "done": flags[it["key"]]})
    min_exp = m.get("min_explanation", 80)
    items["SUBMIT"].append({"key": "submission", "kind": "submission", "title": "Submit your explanation",
                            "description": f"At least {min_exp} characters" + ("; cite case evidence." if m["kind"] == "SCENARIO" else "."),
                            "done": a.submitted_at is not None,
                            "steps": ["Explain what you found, what you did and how you know it worked.", "Click 'Submit for assessment'."]})
    out = []
    for ph in C.PHASES:
        its = items[ph["key"]]
        note = None if its else "Covered inside the lab: every action shows its real result immediately."
        out.append({**ph, "items": its, "done": all(i["done"] for i in its) if its else None, "note": note})
    return out


def attempt_out(db: Session, user: User, a: MissionAttempt) -> dict[str, Any]:
    m = _mission(a.mission_id)
    s = db.get(ScenarioSession, a.session_id) if a.session_id else None
    phases = _phases(db, user, a, m, s)
    work_items = [i for ph in phases if ph["key"] not in ("UNDERSTAND", "SUBMIT") for i in ph["items"]]
    und = a.understanding or {}
    retry_options: list[str] = []
    latest = _latest_attempt(db, user, a.mission_id)
    if a.status in ("NOT_PASSED", "PRACTICE_PASSED", "IN_PROGRESS") and latest is not None and latest.id == a.id:
        retry_options = ["PRACTICE"] + (["NEW_VARIANT"] if m["kind"] == "SCENARIO" else [])
    out: dict[str, Any] = {
        "id": a.id, "mission": mission_public(a.mission_id), "attempt_number": a.attempt_number, "strategy": a.strategy,
        "counts": a.counts, "status": a.status, "started_at": iso(a.started_at), "submitted_at": iso(a.submitted_at),
        "understanding": {"passed": bool(und.get("passed")), "score": und.get("score"), "correct": und.get("correct"),
                          "carried_over_from": und.get("carried_over_from")},
        "phases": phases,
        "readiness": {"understanding_passed": bool(und.get("passed")),
                      "work_done": sum(1 for i in work_items if i["done"]), "work_total": len(work_items),
                      "session_status": s.status if s else None},
        "explanation": a.explanation, "cited_evidence": a.cited_evidence, "score": a.score,
        "outcome": a.outcome or None, "retry_options": retry_options,
        "session": None, "observations": None, "evidence_options": None,
    }
    if s is not None:
        out["session"] = {"id": s.id, "mode": s.mode, "status": s.status, "attempt_number": s.attempt_number,
                          "run_count": s.run_count, "execution_mode": "SIMULATED"}
        out["observations"] = _session_observations(db, s)
        out["evidence_options"] = _evidence_options(db, s)
    if not a.counts and a.status == "IN_PROGRESS":
        out["practice_note"] = ("Practice attempt: guided mode with hints. It is assessed and shows your skill gaps, but the "
                                "lab is only passed by an attempt in independent assessment mode.")
    return out


# --------------------------------------------------------------------------- understanding gate


def answer_understanding(db: Session, user: User, a: MissionAttempt, answers: list[int]) -> dict[str, Any]:
    if a.status != "IN_PROGRESS":
        raise DomainError(f"Attempt is {a.status}", 409)
    _mission(a.mission_id)
    qs = mission_questions(a.mission_id)
    if len(answers) != len(qs):
        raise DomainError(f"Expected {len(qs)} answers", 422)
    correct = [ans == q["answer"] for ans, q in zip(answers, qs)]
    score = sum(correct) / len(qs)
    passed = score >= 0.75
    a.understanding = {"passed": passed or bool((a.understanding or {}).get("passed")), "score": score, "correct": correct,
                       "answered_at": iso(utcnow())}
    return {"score": score, "passed": passed, "correct": correct}


# --------------------------------------------------------------------------- submission and competency assessment


def _lessons(ids: list[str]) -> list[dict[str, Any]]:
    out, seen = [], set()
    for lid in ids:
        if lid in seen or lid not in LESSON_BY_ID:
            continue
        seen.add(lid)
        x = LESSON_BY_ID[lid]
        out.append({"id": lid, "title": x["title"], "module": x["module"], "body": x["body"], "practice": x["practice"],
                    "has_quiz": lid in QUIZZES})
    return out


def _evaluate_scenario(m: dict[str, Any], at: AssessmentAttempt) -> dict[str, Any]:
    crit = {c["key"]: c for c in at.criteria}
    required = []
    unmet_skills: dict[str, list[str]] = {}
    for item, rc in zip(_required_items(m), m.get("required_criteria", [])):
        if "criterion" in rc:
            c = crit[rc["criterion"]]
            frac = c["earned"] / c["points"] if c["points"] else 0
            met = frac + 1e-9 >= rc["min_fraction"]
            actual, why = f"{c['earned']}/{c['points']} points", c["explanation"]
            if not met:
                unmet_skills.setdefault(C.CRITERION_SKILLS[c["key"]], []).append(f"{c['description']}: {why}")
        else:
            cs = at.category_scores[rc["category"]]
            met = cs["percent"] + 1e-9 >= rc["min_percent"]
            actual, why = f"{cs['percent']}%", f"{cs['name']} scored {cs['percent']}%."
            if not met:
                for c in at.criteria:
                    if c["category"] == rc["category"] and c["earned"] < c["points"]:
                        unmet_skills.setdefault(C.CRITERION_SKILLS[c["key"]], []).append(f"{c['description']}: {c['explanation']}")
        required.append({**item, "met": met, "actual": actual, "explanation": why})
    tally: dict[str, list[float]] = {}
    for c in at.criteria:
        t = tally.setdefault(C.CRITERION_SKILLS[c["key"]], [0.0, 0.0])
        t[0] += c["earned"]
        t[1] += c["points"]
    skills = [{"skill": k, "name": C.SKILLS[k]["name"], "proficiency": round(100 * e / p) if p else 0,
               "criteria": [c["key"] for c in at.criteria if C.CRITERION_SKILLS[c["key"]] == k]} for k, (e, p) in tally.items()]
    gaps = []
    for sk in skills:
        because = list(unmet_skills.get(sk["skill"], []))
        if sk["proficiency"] < SKILL_GAP_THRESHOLD:
            because += [f"{c['description']}: {c['explanation']}" for c in at.criteria
                        if C.CRITERION_SKILLS[c["key"]] == sk["skill"] and c["earned"] < c["points"]
                        and f"{c['description']}: {c['explanation']}" not in because]
        if because:
            gaps.append({**sk, "because": because})
    score_ok = at.total_score >= m["min_score"]
    passed = score_ok and not at.critical_failures and all(r["met"] for r in required)
    lesson_ids = [lid for g in gaps for lid in C.SKILLS[g["skill"]]["lessons"]] + [r["lesson_id"] for r in at.recommendations]
    return {
        "kind": "SCENARIO", "score": at.total_score, "min_score": m["min_score"], "score_ok": score_ok,
        "assessment_passed": at.passed, "assessment_attempt_id": at.id,
        "critical_failures": at.critical_failures, "required": required, "passed": passed,
        "category_scores": at.category_scores, "criteria": at.criteria, "missing_tasks": at.missing_tasks,
        "skills": skills, "skill_gaps": gaps, "remedial_lessons": _lessons(lesson_ids)[:6],
        "inputs_digest": at.inputs_digest, "mode_label": "Guided practice result" if at.mode == "GUIDED" else "Independent assessment result",
    }


def _evaluate_lab(db: Session, user: User, m: dict[str, Any]) -> dict[str, Any]:
    rows = {r.exercise: r for r in db.scalars(select(LabExerciseResult).where(
        LabExerciseResult.user_id == user.id, LabExerciseResult.lab == m["lab"], LabExerciseResult.passed.is_(True))
        .order_by(LabExerciseResult.id))}
    required, missing = [], []
    for item, ex in zip(_required_items(m), m["exercises"]):
        r = rows.get(ex["exercise"])
        if r is None:
            missing.append(ex)
        required.append({**item, "met": r is not None, "actual": f"verified {iso(r.created_at)} ({r.provenance})" if r else "not yet verified",
                         "explanation": "Recorded by the lab from a real result." if r else "The lab has not verified this exercise."})
    total = len(m["exercises"])
    score = round(100 * (total - len(missing)) / total, 2)
    skill = C.LAB_SKILLS[m["lab"]]
    skills = [{"skill": skill, "name": C.SKILLS[skill]["name"], "proficiency": round(score), "criteria": [ex["exercise"] for ex in m["exercises"]]}]
    gaps = [{**skills[0], "because": [f"Not verified: {ex['title']}" for ex in missing]}] if missing else []
    evidence = [{"lab": m["lab"], "exercise": e, "provenance": r.provenance, "verified_at": iso(r.created_at)}
                for e, r in rows.items() if e in {ex["exercise"] for ex in m["exercises"]}]
    return {"kind": "LAB", "score": score, "min_score": 100, "score_ok": not missing, "critical_failures": [],
            "required": required, "passed": not missing, "skills": skills, "skill_gaps": gaps,
            "remedial_lessons": _lessons([C.EXERCISE_LESSONS[(m["lab"], ex["exercise"])] for ex in missing]), "lab_evidence": evidence}


def _evaluate_demo(p: LearnerProfile, m: dict[str, Any]) -> dict[str, Any]:
    flags = _demo_flags(p)
    required = [{**item, "met": flags[item["key"]], "actual": "done" if flags[item["key"]] else "not done",
                 "explanation": "Recorded by the demo lab." if flags[item["key"]] else "Not completed yet."} for item in _required_items(m)]
    done = sum(flags.values())
    score = round(100 * done / len(flags), 2)
    skills = [{"skill": "data-classification", "name": C.SKILLS["data-classification"]["name"], "proficiency": round(score),
               "criteria": list(flags)}]
    missing = [i["title"] for i in m["items"] if not flags[i["key"]]]
    gaps = [{**skills[0], "because": [f"Not completed: {t}" for t in missing]}] if missing else []
    return {"kind": "DEMO", "score": score, "min_score": 100, "score_ok": not missing, "critical_failures": [], "required": required,
            "passed": not missing, "skills": skills, "skill_gaps": gaps, "remedial_lessons": _lessons(["M01-L2", "M02-L1"]) if missing else [],
            "lab_evidence": [{"demo_step": k, "done": v} for k, v in flags.items()]}


def _record_skills(db: Session, user: User, a: MissionAttempt, outcome: dict[str, Any]) -> list[dict[str, Any]]:
    recorded = []
    for sk in outcome["skills"]:
        db.add(SkillRecord(user_id=user.id, skill_key=sk["skill"], proficiency=sk["proficiency"], mission_id=a.mission_id,
                           mission_attempt_id=a.id, evidence={"score": outcome["score"], "criteria": sk["criteria"],
                                                              "assessment_attempt_id": outcome.get("assessment_attempt_id")}))
        recorded.append({"skill": sk["skill"], "name": sk["name"], "proficiency": sk["proficiency"]})
    return recorded


def _advance(db: Session, user: User, p: LearnerProfile) -> dict[str, Any]:
    """'More labs in the current level?' If not, unlock the next level(s) automatically."""
    passed = _passed_missions(db, user)
    start = p.career_level
    while _level_complete(db, user, p.career_level, passed) and p.career_level < C.TOP_LEVEL:
        p.career_level += 1  # earlier work can complete more than one level at once
    top_done = p.career_level == C.TOP_LEVEL and _level_complete(db, user, C.TOP_LEVEL, passed)
    if p.career_level > start:
        p.role_title = C.role_title(p.desired_role, p.career_level)
        p.pending_promotion = p.career_level
        audit(db, user_id=user.id, org_id=user.org_id, action="career.level_unlocked", target_type="level", target_id=p.career_level,
              detail={"from": start, "role_title": p.role_title})
        return {"more_missions": False, "level_completed": start, "level_unlocked": p.career_level, "new_title": p.role_title}
    if top_done:
        if p.pending_promotion != C.JOURNEY_COMPLETE and not (p.onboarding or {}).get("journey_complete_seen"):
            p.pending_promotion = C.JOURNEY_COMPLETE
        return {"more_missions": False, "level_completed": C.TOP_LEVEL, "journey_complete": True}
    nxt = assigned_mission_id(db, user, p)
    if nxt is not None:
        return {"more_missions": True, "next_mission": {"id": nxt, "title": C.MISSIONS[nxt]["title"]}}
    return {"more_missions": False}


def submit_attempt(db: Session, user: User, a: MissionAttempt, explanation: str, cited: list[int]) -> MissionAttempt:
    if a.status != "IN_PROGRESS":
        raise DomainError(f"Attempt is {a.status}; nothing to submit", 409)
    if not (a.understanding or {}).get("passed"):
        raise DomainError("Answer the business-problem check before submitting", 409)
    m = _mission(a.mission_id)
    explanation = explanation.strip()
    min_exp = m.get("min_explanation", 80)
    if len(explanation) < min_exp:
        raise DomainError(f"Your explanation needs at least {min_exp} characters: what happened, what you did and how you verified it", 422)
    p = get_profile(db, user)
    if m["kind"] == "SCENARIO":
        s = db.get(ScenarioSession, a.session_id)
        if s is None:
            raise DomainError("The lab session no longer exists; retry the lab", 409)
        if s.status != "ACTIVE":
            raise DomainError(f"The lab workspace is {s.status}; resume it before submitting", 409)
        options = {e["id"]: e for e in _evidence_options(db, s)["items"]}
        if not cited:
            raise DomainError("Cite at least one evidence item from your investigation case", 422)
        if any(i not in options for i in cited):
            raise DomainError("Cited evidence must come from your primary investigation case", 422)
        a.cited_evidence = [{k: options[i][k] for k in ("id", "ref_type", "ref_id", "label")} for i in dict.fromkeys(cited)]
        at = submit_scenario_session(db, s, user)
        a.assessment_attempt_id = at.id
        outcome = _evaluate_scenario(m, at)
    elif m["kind"] == "LAB":
        outcome = _evaluate_lab(db, user, m)
        a.cited_evidence = outcome["lab_evidence"]
    else:
        outcome = _evaluate_demo(p, m)
        a.cited_evidence = outcome["lab_evidence"]
    a.explanation = explanation
    a.submitted_at = utcnow()
    a.score = outcome["score"]
    if outcome["passed"] and a.counts:
        a.status = "PASSED"
        db.flush()
        outcome["skills_recorded"] = _record_skills(db, user, a, outcome)
        outcome["next"] = _advance(db, user, p)
    elif outcome["passed"]:
        a.status = "PRACTICE_PASSED"
        outcome["next"] = {"practice_only": True}
    else:
        a.status = "NOT_PASSED"
    a.outcome = outcome
    audit(db, user_id=user.id, org_id=user.org_id, action="mission.submit", target_type="mission_attempt", target_id=a.id,
          detail={"mission": a.mission_id, "status": a.status, "score": a.score})
    return a


# --------------------------------------------------------------------------- journey overview and celebration


def skills_summary(db: Session, user: User) -> list[dict[str, Any]]:
    latest: dict[str, SkillRecord] = {}
    for r in db.scalars(select(SkillRecord).where(SkillRecord.user_id == user.id).order_by(SkillRecord.id)):
        latest[r.skill_key] = r
    return [{"skill": key, "name": sk["name"], "description": sk["description"],
             "proficiency": latest[key].proficiency if key in latest else None,
             "mission_id": latest[key].mission_id if key in latest else None,
             "recorded_at": iso(latest[key].recorded_at) if key in latest else None} for key, sk in C.SKILLS.items()]


def promotion_out(p: LearnerProfile) -> dict[str, Any] | None:
    if p.pending_promotion is None:
        return None
    if p.pending_promotion == C.JOURNEY_COMPLETE:
        return {"journey_complete": True, "level": None, "completed_level": C.TOP_LEVEL, "title": "Journey complete",
                "new_title": p.role_title, "summary": "You have completed all six levels, from Foundation to Mastery.",
                "responsibilities": [], "challenge": "", "missions": []}
    lv = C.level_def(p.pending_promotion)
    prev = C.level_def(p.pending_promotion - 1)
    return {"journey_complete": False, "level": lv["level"], "completed_level": prev["level"], "completed_title": prev["title"],
            "title": lv["title"], "new_title": p.role_title, "summary": lv["summary"], "responsibilities": lv["responsibilities"],
            "challenge": lv["challenge"],
            "missions": [{"id": mid, "title": C.MISSIONS[mid]["title"], "kind": C.MISSIONS[mid]["kind"]} for mid in lv["missions"]]}


def acknowledge_promotion(p: LearnerProfile) -> None:
    if p.pending_promotion == C.JOURNEY_COMPLETE:
        p.onboarding = {**(p.onboarding or {}), "journey_complete_seen": True}
    p.pending_promotion = None


def journey(db: Session, user: User) -> dict[str, Any]:
    p = get_profile(db, user)
    levels = [_level_summary(db, user, lv["level"]) for lv in C.LEVELS]
    current = next((lv for lv in levels if lv["level"] == p.career_level), levels[0])
    assigned = assigned_mission_id(db, user, p)
    active = _active_attempt(db, user, assigned) if assigned else None
    recent = [r for r in db.scalars(select(MissionAttempt).where(MissionAttempt.user_id == user.id, MissionAttempt.submitted_at.is_not(None))
                                    .order_by(MissionAttempt.id.desc()).limit(10)) if r.mission_id in C.MISSIONS][:6]
    total_steps = sum(lv["progress"]["total"] for lv in levels)
    done_steps = sum(lv["progress"]["done"] for lv in levels)
    complete = all(lv["status"] == "COMPLETED" for lv in levels)
    return {
        "profile": profile_out(db, user, p),
        "levels": levels,
        "current_level": current,
        "next_step": None if complete else current["next_step"] and {**current["next_step"], "level": current["level"],
                                                                      "active_attempt_id": active.id if active else None},
        "overall_progress": {"done": done_steps, "total": total_steps},
        "journey_complete": complete,
        "skills": skills_summary(db, user),
        "recent_outcomes": [{"attempt_id": r.id, "mission_id": r.mission_id, "title": C.MISSIONS[r.mission_id]["title"],
                             "level": C.MISSIONS[r.mission_id]["level"], "status": r.status, "score": r.score,
                             "submitted_at": iso(r.submitted_at)} for r in recent],
        "pending_promotion": promotion_out(p),
        "organization": {"name": C.ORGANIZATION["company"]["name"], "team": C.ORGANIZATION["team"]},
    }
