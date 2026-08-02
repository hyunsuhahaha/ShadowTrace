from __future__ import annotations
import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete, select
from sqlalchemy.orm import Session
from ...database import get_db
from ...models import (
    Credential, Project, RunbookInstance, RunbookStepCredential,
    RunbookStepInstance, Service, Target,
)
from .engine import recompute
from .support import CredentialIn, condition_met, loads, need

router = APIRouter(prefix="/api/runbooks", tags=["Runbooks"])


@router.get("/credentials")
def credentials(project_id: int, db: Session = Depends(get_db)):
    rows = db.scalars(select(Credential).where(
        Credential.project_id == project_id).order_by(Credential.id.desc())).all()
    return [{
        "id": row.id, "project_id": row.project_id, "target_id": row.target_id,
        "service_id": row.service_id, "username": row.username,
        "secret_kind": row.secret_kind, "secret_hint": row.secret_hint,
        # The stored secret stays local-only; the UI masks it and uses it only
        # to auto-fill command generation on this single-user workstation.
        "secret": row.secret, "has_secret": bool(row.secret),
        "source_kind": row.source_kind, "source_detail": row.source_detail,
        "domain": row.domain, "service_names": loads(row.service_names),
        "notes": row.notes, "created_at": row.created_at,
    } for row in rows]


@router.post("/credentials", status_code=201)
def create_credential(body: CredentialIn, db: Session = Depends(get_db)):
    need(db, Project, body.project_id)
    target = need(db, Target, body.target_id) if body.target_id else None
    service = need(db, Service, body.service_id) if body.service_id else None
    if target and target.project_id != body.project_id:
        raise HTTPException(400, "Target belongs to another project")
    if service and (not target or service.target_id != target.id):
        raise HTTPException(400, "Service requires its owning target")
    names = list(dict.fromkeys(
        value.strip().lower() for value in body.service_names if value.strip()))
    if service and service.name.lower() not in names:
        names.append(service.name.lower())
    row = Credential(
        project_id=body.project_id, target_id=body.target_id,
        service_id=body.service_id, username=body.username.strip(),
        secret_kind=body.secret_kind, secret_hint=body.secret_hint,
        secret=body.secret, source_kind=body.source_kind,
        source_detail=body.source_detail,
        domain=body.domain, service_names=json.dumps(names), notes=body.notes)
    db.add(row); db.flush()
    affected = db.scalars(select(RunbookInstance).where(
        RunbookInstance.project_id == body.project_id)).all()
    for instance_row in affected:
        steps = db.scalars(select(RunbookStepInstance).where(
            RunbookStepInstance.instance_id == instance_row.id).order_by(
            RunbookStepInstance.position)).all()
        recompute(db, instance_row, steps, condition_met)
    db.commit(); db.refresh(row)
    return credentials(body.project_id, db)[0]


@router.delete("/credentials/{ident}", status_code=204)
def delete_credential(ident: int, db: Session = Depends(get_db)):
    credential = need(db, Credential, ident)
    db.execute(delete(RunbookStepCredential).where(
        RunbookStepCredential.credential_id == credential.id))
    db.delete(credential)
    db.commit()


@router.get("/credentials/{ident}/recommendations")
def credential_recommendations(ident: int, db: Session = Depends(get_db)):
    credential = need(db, Credential, ident)
    names = loads(credential.service_names)
    rows = db.scalars(select(Service).join(Target).where(
        Target.project_id == credential.project_id)).all()
    return [{
        "service_id": row.id, "target_id": row.target_id, "name": row.name,
        "port": row.port, "reason": f"credential supports {row.name}",
        "source_service": row.id == credential.service_id,
    } for row in rows if row.name.lower() in names]
