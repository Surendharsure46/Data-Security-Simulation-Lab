"""Learning journey API: public welcome content, role choice, Levels 0-5, lab missions and level-up celebrations."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import MissionAttempt, User
from ..security import current_user
from ..services import career
from .deps import STAFF_ROLES

router = APIRouter(prefix="/api/career", tags=["career"])


def _attempt(db: Session, attempt_id: int, user: User, *, write: bool) -> MissionAttempt:
    a = db.get(MissionAttempt, attempt_id)
    if a is None:
        raise HTTPException(404, "Lab attempt not found")
    if a.user_id != user.id:
        owner = db.get(User, a.user_id)
        # Staff may read attempts in their own organisation; nobody else learns that the id exists.
        if write or user.role not in STAFF_ROLES or owner is None or owner.org_id != user.org_id:
            raise HTTPException(404, "Lab attempt not found")
    return a


# --------------------------------------------------------------------------- public (welcome and get-started pages)


@router.get("/public")
def public_content():
    """Welcome page, platform overview, roles and level outline. No authentication; contains nothing user-specific."""
    return career.public_content()


# --------------------------------------------------------------------------- profile and role


@router.get("/profile")
def get_profile(user: User = Depends(current_user), db: Session = Depends(get_db)):
    p = career.get_profile(db, user)
    db.commit()
    return career.profile_out(db, user, p)


class RoleIn(BaseModel):
    role: str = Field(max_length=40)


@router.put("/role")
def choose_role(body: RoleIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    p = career.choose_role(db, user, body.role)
    db.commit()
    return career.profile_out(db, user, p)


# --------------------------------------------------------------------------- journey and levels


@router.get("/journey")
def journey(user: User = Depends(current_user), db: Session = Depends(get_db)):
    out = career.journey(db, user)
    db.commit()
    return out


@router.get("/levels/{level}")
def level(level: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    out = career.level_detail(db, user, level)
    db.commit()
    return out


@router.post("/levels/{level}/read/{key}")
def mark_read(level: int, key: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    out = career.mark_read(db, user, level, key)
    db.commit()
    return out


class AnswersIn(BaseModel):
    answers: list[int] = Field(max_length=20)


@router.post("/levels/{level}/check")
def level_check(level: int, body: AnswersIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    out = career.answer_level_check(db, user, level, body.answers)
    db.commit()
    return out


# --------------------------------------------------------------------------- interactive demo lab


class DemoScanIn(BaseModel):
    text: str | None = Field(default=None, max_length=5000)


@router.post("/demo/scan")
def demo_scan(body: DemoScanIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    out = career.demo_scan(db, user, body.text)
    db.commit()
    return out


class DemoClassifyIn(BaseModel):
    label: str = Field(max_length=40)


@router.post("/demo/classify")
def demo_classify(body: DemoClassifyIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    out = career.demo_classify(db, user, body.label)
    db.commit()
    return out


class DemoTransferIn(BaseModel):
    destination: str = Field(max_length=60)


@router.post("/demo/transfer")
def demo_transfer(body: DemoTransferIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    out = career.demo_transfer(db, user, body.destination)
    db.commit()
    return out


# --------------------------------------------------------------------------- lab missions


@router.get("/missions/{mission_id}")
def get_mission(mission_id: str, user: User = Depends(current_user)):
    return career.mission_public(mission_id)


@router.post("/missions/{mission_id}/start", status_code=201)
def start_mission(mission_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    a = career.start_mission(db, user, mission_id)
    db.commit()
    return career.attempt_out(db, user, a)


@router.get("/attempts/{attempt_id}")
def get_attempt(attempt_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return career.attempt_out(db, user, _attempt(db, attempt_id, user, write=False))


@router.post("/attempts/{attempt_id}/understand")
def understand(attempt_id: int, body: AnswersIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    a = _attempt(db, attempt_id, user, write=True)
    out = career.answer_understanding(db, user, a, body.answers)
    db.commit()
    return out


class SubmitIn(BaseModel):
    explanation: str = Field(max_length=6000)
    cited_evidence: list[int] = Field(default_factory=list, max_length=50)


@router.post("/attempts/{attempt_id}/submit")
def submit(attempt_id: int, body: SubmitIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    a = _attempt(db, attempt_id, user, write=True)
    career.submit_attempt(db, user, a, body.explanation, body.cited_evidence)
    db.commit()
    return career.attempt_out(db, user, a)


class RetryIn(BaseModel):
    strategy: Literal["PRACTICE", "NEW_VARIANT"]


@router.post("/attempts/{attempt_id}/retry", status_code=201)
def retry(attempt_id: int, body: RetryIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    a = _attempt(db, attempt_id, user, write=True)
    new = career.retry(db, user, a, body.strategy)
    db.commit()
    return career.attempt_out(db, user, new)


# --------------------------------------------------------------------------- level-up celebration


@router.get("/promotion")
def promotion(user: User = Depends(current_user), db: Session = Depends(get_db)):
    p = career.get_profile(db, user)
    db.commit()
    return {"pending": career.promotion_out(p)}


@router.post("/promotion/acknowledge")
def acknowledge_promotion(user: User = Depends(current_user), db: Session = Depends(get_db)):
    p = career.get_profile(db, user)
    if p.pending_promotion is None:
        raise HTTPException(409, "Nothing to acknowledge")
    career.acknowledge_promotion(p)
    db.commit()
    return career.profile_out(db, user, p)
