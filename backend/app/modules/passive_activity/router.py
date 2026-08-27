from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...database import get_db
from ...models import (
    CommandActivity, PassiveActivity, ProcessInstance, RawActivityEvent,
    RemoteSessionCandidate, TerminalSession,
)
from .raw_events import sync_event_inbox
from .reconstruction import reconstruct
from .service import sync_inbox

router = APIRouter(prefix="/api/passive", tags=["Passive Activity"])


@router.post("/sync")
def sync(db: Session = Depends(get_db)):
    activities = sync_inbox(db)
    raw_events = sync_event_inbox(db)
    return {**activities, "raw_events": raw_events,
            "reconstruction": reconstruct(db)}


@router.post("/reconstruct")
def reconstruct_sessions(db: Session = Depends(get_db)):
    return reconstruct(db)


@router.get("/activities")
def activities(project_id: int | None = None, db: Session = Depends(get_db)):
    query = select(PassiveActivity).order_by(PassiveActivity.id.desc()).limit(100)
    if project_id is not None:
        query = query.where(PassiveActivity.project_id == project_id)
    return list(db.scalars(query))


@router.get("/events")
def events(kind: str | None = None, pid: int | None = None,
           limit: int = 200, db: Session = Depends(get_db)):
    query = select(RawActivityEvent).order_by(RawActivityEvent.id.desc())
    if kind is not None:
        query = query.where(RawActivityEvent.kind == kind)
    if pid is not None:
        query = query.where(RawActivityEvent.pid == pid)
    return list(db.scalars(query.limit(max(1, min(limit, 500)))))


@router.get("/processes")
def processes(pid: int | None = None, limit: int = 200,
              db: Session = Depends(get_db)):
    query = select(ProcessInstance).order_by(ProcessInstance.started_at.desc())
    if pid is not None:
        query = query.where(ProcessInstance.pid == pid)
    return list(db.scalars(query.limit(max(1, min(limit, 500)))))


@router.get("/terminal-sessions")
def terminal_sessions(kind: str | None = None, limit: int = 100,
                      db: Session = Depends(get_db)):
    query = select(TerminalSession).order_by(TerminalSession.started_at.desc())
    if kind is not None:
        query = query.where(TerminalSession.kind == kind)
    return list(db.scalars(query.limit(max(1, min(limit, 500)))))


@router.get("/commands")
def commands(session_id: int | None = None, limit: int = 200,
             db: Session = Depends(get_db)):
    query = select(CommandActivity).order_by(CommandActivity.started_at.desc())
    if session_id is not None:
        query = query.where(CommandActivity.terminal_session_id == session_id)
    return list(db.scalars(query.limit(max(1, min(limit, 500)))))


@router.get("/remote-sessions")
def remote_sessions(limit: int = 100, db: Session = Depends(get_db)):
    query = select(RemoteSessionCandidate).order_by(
        RemoteSessionCandidate.started_at.desc())
    return list(db.scalars(query.limit(max(1, min(limit, 500)))))
