from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...database import get_db
from ...models import PassiveActivity
from .service import sync_inbox

router = APIRouter(prefix="/api/passive", tags=["Passive Activity"])


@router.post("/sync")
def sync(db: Session = Depends(get_db)):
    return sync_inbox(db)


@router.get("/activities")
def activities(project_id: int | None = None, db: Session = Depends(get_db)):
    query = select(PassiveActivity).order_by(PassiveActivity.id.desc()).limit(100)
    if project_id is not None:
        query = query.where(PassiveActivity.project_id == project_id)
    return list(db.scalars(query))
