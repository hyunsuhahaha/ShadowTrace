from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session
from ...database import get_db
from ...models import Credential, Note, Project, Service, Target
from ...schemas import NoteIn, NoteOut, NoteUpdate
from ...time import utcnow

router = APIRouter(prefix="/api/notes", tags=["Notes"])


def need(db: Session, model, ident: int):
    row = db.get(model, ident)
    if not row:
        raise HTTPException(404, "Not found")
    return row


def _validate_scope(db: Session, body: NoteIn) -> None:
    need(db, Project, body.project_id)
    target = None
    if body.target_id:
        target = need(db, Target, body.target_id)
        if target.project_id != body.project_id:
            raise HTTPException(400, "Target does not belong to the project")
    if body.service_id:
        service = need(db, Service, body.service_id)
        if not target or service.target_id != target.id:
            raise HTTPException(400, "Service requires its owning target")
    if body.credential_id:
        credential = need(db, Credential, body.credential_id)
        if credential.project_id != body.project_id:
            raise HTTPException(400, "Credential does not belong to the project")


@router.get("", response_model=list[NoteOut])
def list_notes(project_id: int, target_id: int | None = None,
               service_id: int | None = None, credential_id: int | None = None,
               db: Session = Depends(get_db)):
    statement = select(Note).where(Note.project_id == project_id)
    if target_id:
        statement = statement.where(Note.target_id == target_id)
    if service_id:
        statement = statement.where(Note.service_id == service_id)
    if credential_id:
        statement = statement.where(Note.credential_id == credential_id)
    return db.scalars(statement.order_by(Note.id.desc()).limit(2000)).all()


@router.post("", response_model=NoteOut, status_code=201)
def create_note(body: NoteIn, db: Session = Depends(get_db)):
    _validate_scope(db, body)
    row = Note(**body.model_dump())
    db.add(row); db.commit(); db.refresh(row)
    return row


@router.patch("/{ident}", response_model=NoteOut)
def update_note(ident: int, body: NoteUpdate, db: Session = Depends(get_db)):
    row = need(db, Note, ident)
    row.body = body.body
    row.updated_at = utcnow()
    db.commit(); db.refresh(row)
    return row


@router.delete("/{ident}", status_code=204)
def delete_note(ident: int, db: Session = Depends(get_db)):
    row = need(db, Note, ident)
    db.delete(row)
    db.commit()
