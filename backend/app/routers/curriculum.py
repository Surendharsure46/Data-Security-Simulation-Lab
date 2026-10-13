"""Learning paths, lesson completion, knowledge checks and the learner dashboard."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..content.curriculum import LESSONS, LEVELS, MODULES, PATHWAYS, QUIZZES
from ..db import get_db
from ..models import (
    AssessmentAttempt, ChangeRecord, LabExerciseResult, LabState, PolicyTestRun, RemediationAction, ScenarioSession, User,
)
from ..security import current_user
from ..services import assessment
from ..services.common import iso

router = APIRouter(prefix="/api", tags=["curriculum"])


class Completion:
    """Evaluates lesson completion for one user from persisted evidence."""

    def __init__(self, db: Session, user: User, earned: set[str] | None = None):
        self.db, self.user = db, user
        # Scenario tasks completed in earlier attempts stay earned after a session reset.
        self.earned: set[str] = set(earned or ())
        self.sessions = list(db.scalars(select(ScenarioSession).where(ScenarioSession.user_id == user.id)))
        self._tasks: dict[int, dict[str, bool]] = {}
        self.labs = {(r.lab, r.exercise) for r in db.scalars(select(LabExerciseResult).where(
            LabExerciseResult.user_id == user.id, LabExerciseResult.passed.is_(True)))}
        sids = [s.id for s in self.sessions]
        self.test_runs = len(db.scalars(select(PolicyTestRun.id).where(PolicyTestRun.session_id.in_(sids))).all()) if sids else 0
        self.change_records = len(db.scalars(select(ChangeRecord.id).where(ChangeRecord.session_id.in_(sids))).all()) if sids else 0
        self.attempts = list(db.scalars(select(AssessmentAttempt).where(AssessmentAttempt.user_id == user.id)))

    def tasks_for(self, s: ScenarioSession) -> dict[str, bool]:
        if s.id not in self._tasks:
            try:
                self._tasks[s.id] = {t["key"]: t["done"] for t in assessment.task_progress(self.db, s)}
            except Exception:  # scenario definition removed
                self._tasks[s.id] = {}
        return self._tasks[s.id]

    def done(self, check: dict[str, Any]) -> bool:
        t = check["type"]
        if t == "scenario_task":
            key = f"{check['scenario']}:{check['task']}"
            if key in self.earned:
                return True
            if any(self.tasks_for(s).get(check["task"]) for s in self.sessions if s.scenario_id == check["scenario"]):
                self.earned.add(key)
                return True
            return False
        if t == "lab_exercise":
            return (check["lab"], check["exercise"]) in self.labs
        if t == "policy_test_suite_run":
            return self.test_runs >= 1
        if t == "policy_test_suite_runs":
            return self.test_runs >= check.get("count", 2)
        if t == "change_record":
            return self.change_records >= 1
        if t == "assessment_passed":
            return any(a.passed and a.mode == check["mode"] and a.scenario_id == check["scenario"] for a in self.attempts)
        return False


def _profile(db: Session, user: User) -> LabState:
    from ..labs import get_state
    return get_state(db, user, "profile", {"pathway": "foundation"})


def remember_completed_tasks(db: Session, user: User) -> None:
    """Persist currently completed scenario tasks before a reset wipes session state."""
    build_curriculum(db, user)


def build_curriculum(db: Session, user: User) -> dict[str, Any]:
    profile = _profile(db, user)
    comp = Completion(db, user, set(profile.state.get("earned_tasks", [])))
    pathway_id = profile.state.get("pathway", "foundation")
    pathway = next((p for p in PATHWAYS if p["id"] == pathway_id), PATHWAYS[0])
    lesson_done = {lesson["id"]: comp.done(lesson["check"]) for lesson in LESSONS}
    if set(profile.state.get("earned_tasks", [])) != comp.earned:
        profile.state = {**profile.state, "earned_tasks": sorted(comp.earned)}
    unlocked: dict[str, bool] = {}
    for lv in LEVELS:
        reqs = lv["unlock"]["requires"]
        ok = all(unlocked.get(r) for r in reqs)
        if ok and reqs:
            prev_done = sum(lesson_done[x["id"]] for x in LESSONS if x["level"] == reqs[-1])
            ok = prev_done >= lv["unlock"]["min_lessons_in_previous"]
        unlocked[lv["id"]] = ok
    modules = {m["id"]: m for m in MODULES}
    lessons_out = []
    for lesson in LESSONS:
        available = unlocked[lesson["level"]] or lesson["id"] in pathway["lessons"]
        if modules[lesson["module"]]["status"] == "PLANNED" and lesson["check"]["type"] != "assessment_passed":
            available = False
        lessons_out.append({k: v for k, v in lesson.items() if k != "check"} | {
            "completed": lesson_done[lesson["id"]], "available": available, "check_type": lesson["check"]["type"],
            "in_pathway": lesson["id"] in pathway["lessons"], "has_quiz": lesson["id"] in QUIZZES})
    levels_out = []
    for lv in LEVELS:
        ls = [x for x in LESSONS if x["level"] == lv["id"]]
        levels_out.append({**lv, "unlocked": unlocked[lv["id"]], "lessons_total": len(ls),
                           "lessons_completed": sum(lesson_done[x["id"]] for x in ls)})
    modules_out = []
    for m in MODULES:
        ls = [x for x in LESSONS if x["module"] == m["id"]]
        modules_out.append({**m, "lessons_total": len(ls), "lessons_completed": sum(lesson_done[x["id"]] for x in ls)})
    pathways_out = [{**p, "completed": sum(lesson_done[x] for x in p["lessons"]), "total": len(p["lessons"]),
                     "selected": p["id"] == pathway["id"]} for p in PATHWAYS]
    return {"levels": levels_out, "modules": modules_out, "lessons": lessons_out, "pathways": pathways_out,
            "selected_pathway": pathway["id"]}


@router.get("/curriculum")
def curriculum(user: User = Depends(current_user), db: Session = Depends(get_db)):
    out = build_curriculum(db, user)
    db.commit()
    return out


class PathwayIn(BaseModel):
    pathway: str


@router.put("/curriculum/pathway")
def set_pathway(body: PathwayIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if body.pathway not in {p["id"] for p in PATHWAYS}:
        raise HTTPException(422, "Unknown pathway")
    st = _profile(db, user)
    st.state = {**st.state, "pathway": body.pathway}
    db.commit()
    return {"pathway": body.pathway}


@router.get("/curriculum/quiz/{lesson_id}")
def get_quiz(lesson_id: str, user: User = Depends(current_user)):
    qs = QUIZZES.get(lesson_id)
    if qs is None:
        raise HTTPException(404, "No knowledge check for this lesson")
    return {"lesson_id": lesson_id, "questions": [{"q": q["q"], "options": q["options"]} for q in qs], "pass_mark": 0.75}


class QuizIn(BaseModel):
    answers: list[int] = Field(max_length=20)


@router.post("/curriculum/quiz/{lesson_id}")
def submit_quiz(lesson_id: str, body: QuizIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    qs = QUIZZES.get(lesson_id)
    if qs is None:
        raise HTTPException(404, "No knowledge check for this lesson")
    if len(body.answers) != len(qs):
        raise HTTPException(422, f"Expected {len(qs)} answers")
    correct = [a == q["answer"] for a, q in zip(body.answers, qs)]
    score = sum(correct) / len(qs)
    passed = score >= 0.75
    db.add(LabExerciseResult(user_id=user.id, lab="knowledge", exercise=lesson_id, passed=passed, provenance="SIMULATED",
                             detail={"score": score, "correct": correct}))
    db.commit()
    # Only per-question correctness is returned, not the correct option, so the check can be retaken meaningfully.
    return {"lesson_id": lesson_id, "score": score, "passed": passed, "correct": correct}


@router.get("/dashboard")
def dashboard(user: User = Depends(current_user), db: Session = Depends(get_db)):
    cur = build_curriculum(db, user)
    sessions = list(db.scalars(select(ScenarioSession).where(ScenarioSession.user_id == user.id)
                               .order_by(ScenarioSession.updated_at.desc()).limit(5)))
    attempts = list(db.scalars(select(AssessmentAttempt).where(AssessmentAttempt.user_id == user.id)
                               .order_by(AssessmentAttempt.id.desc()).limit(10)))
    labs = list(db.scalars(select(LabExerciseResult).where(LabExerciseResult.user_id == user.id)
                           .order_by(LabExerciseResult.id.desc()).limit(10)))
    pathway = next(p for p in cur["pathways"] if p["selected"])
    nxt = next((x for x in cur["lessons"] if x["id"] in pathway["lessons"] and x["available"] and not x["completed"]), None) or \
        next((x for x in cur["lessons"] if x["available"] and not x["completed"]), None)
    recs = attempts[0].recommendations if attempts else []
    proficiency = [{"module": m["id"], "title": m["title"], "completed": m["lessons_completed"], "total": m["lessons_total"],
                    "percent": round(100 * m["lessons_completed"] / m["lessons_total"]) if m["lessons_total"] else 0}
                   for m in cur["modules"]]
    category = attempts[0].category_scores if attempts else {}
    open_remediation = db.scalars(select(RemediationAction.id).join(ScenarioSession, RemediationAction.session_id == ScenarioSession.id)
                                  .where(ScenarioSession.user_id == user.id, RemediationAction.status == "VERIFICATION_FAILED")).all()
    db.commit()
    return {
        "user": {"display_name": user.display_name, "role": user.role},
        "pathway": pathway, "levels": [{k: lv[k] for k in ("id", "title", "unlocked", "lessons_total", "lessons_completed")} for lv in cur["levels"]],
        "next_lesson": nxt, "proficiency": proficiency, "latest_assessment_categories": category,
        "recommendations": recs, "unverified_remediations": len(open_remediation),
        "recent_sessions": [{"id": s.id, "scenario_id": s.scenario_id, "status": s.status, "mode": s.mode,
                             "attempt_number": s.attempt_number, "updated_at": iso(s.updated_at)} for s in sessions],
        "recent_attempts": [{"id": a.id, "session_id": a.session_id, "score": a.total_score, "passed": a.passed, "mode": a.mode,
                             "submitted_at": iso(a.submitted_at)} for a in attempts],
        "recent_labs": [{"lab": r.lab, "exercise": r.exercise, "passed": r.passed, "provenance": r.provenance,
                         "created_at": iso(r.created_at)} for r in labs],
    }
