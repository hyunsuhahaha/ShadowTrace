from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...database import get_db
from ...models import PassiveActivity, RawActivityEvent
from .raw_events import sync_event_inbox
from .service import sync_inbox

router = APIRouter(prefix="/api/passive", tags=["Passive Activity"])


@router.post("/sync")
def sync(db: Session = Depends(get_db)):
    activities = sync_inbox(db)
    return {**activities, "raw_events": sync_event_inbox(db)}


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
