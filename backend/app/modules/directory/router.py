import csv
import io
import json
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy import or_, select
from sqlalchemy.orm import Session
from ...database import get_db
from ...models import (
    DirectoryObject, DirectoryRelation, Evidence, Project, Target,
)
from ...schemas import (
    DirectoryObjectIn, DirectoryObjectOut, DirectoryRelationIn,
    DirectoryRelationOut,
)

router = APIRouter(prefix="/api/directory", tags=["AD Information"])
KINDS = {"domain", "user", "group", "computer", "share", "spn", "session",
         "trust", "credential_source"}


def need(db: Session, model, ident: int):
    row = db.get(model, ident)
    if not row:
        raise HTTPException(404, "Not found")
    return row


def values(body: DirectoryObjectIn) -> dict:
    result = body.model_dump()
    result["attributes"] = json.dumps(result["attributes"], ensure_ascii=False)
    result["tags"] = json.dumps(result["tags"], ensure_ascii=False)
    return result


@router.get("/objects", response_model=list[DirectoryObjectOut])
def objects(project_id: int, query: str = "", kind: str = "",
            db: Session = Depends(get_db)):
    statement = select(DirectoryObject).where(
        DirectoryObject.project_id == project_id)
    if kind:
        statement = statement.where(DirectoryObject.kind == kind)
    if query:
        needle = f"%{query[:200]}%"
        statement = statement.where(or_(
            DirectoryObject.name.ilike(needle),
            DirectoryObject.domain.ilike(needle),
            DirectoryObject.attributes.ilike(needle)))
    return db.scalars(statement.order_by(
        DirectoryObject.kind, DirectoryObject.name).limit(5000)).all()


@router.post("/objects", response_model=DirectoryObjectOut, status_code=201)
def create_object(body: DirectoryObjectIn, db: Session = Depends(get_db)):
    need(db, Project, body.project_id)
    if body.target_id:
        target = need(db, Target, body.target_id)
        if target.project_id != body.project_id:
            raise HTTPException(400, "Target does not belong to the project")
    row = DirectoryObject(**values(body))
    db.add(row); db.commit(); db.refresh(row)
    return row


@router.put("/objects/{ident:int}", response_model=DirectoryObjectOut)
def update_object(ident: int, body: DirectoryObjectIn,
                  db: Session = Depends(get_db)):
    row = need(db, DirectoryObject, ident)
    if row.project_id != body.project_id:
        raise HTTPException(400, "Project cannot be changed")
    for key, value in values(body).items():
        setattr(row, key, value)
    db.commit(); db.refresh(row)
    return row


@router.post("/objects/import", response_model=list[DirectoryObjectOut])
async def import_objects(project_id: int, file: UploadFile = File(...),
                         db: Session = Depends(get_db)):
    need(db, Project, project_id)
    content = await file.read(5 * 1024 * 1024 + 1)
    if len(content) > 5 * 1024 * 1024:
        raise HTTPException(413, "Import exceeds 5 MiB")
    try:
        text = content.decode("utf-8-sig")
        if (file.filename or "").lower().endswith(".json"):
            records = json.loads(text)
        else:
            records = list(csv.DictReader(io.StringIO(text)))
        if not isinstance(records, list) or len(records) > 5000:
            raise ValueError("Import must contain at most 5000 objects")
        created = []
        for item in records:
            kind = str(item.get("kind", "")).lower()
            if kind not in KINDS or not item.get("name"):
                raise ValueError("Each object needs a supported kind and name")
            attributes = item.get("attributes", {})
            if isinstance(attributes, str):
                attributes = json.loads(attributes or "{}")
            row = DirectoryObject(
                project_id=project_id, kind=kind,
                name=str(item["name"])[:300],
                domain=str(item.get("domain", ""))[:253],
                attributes=json.dumps(attributes, ensure_ascii=False),
                notes=str(item.get("notes", ""))[:50000],
                tags=json.dumps(item.get("tags", []), ensure_ascii=False),
                source=f"import:{(file.filename or 'data')[:100]}")
            db.add(row); created.append(row)
        db.commit()
        for row in created:
            db.refresh(row)
        return created
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        db.rollback()
        raise HTTPException(400, f"Invalid directory import: {exc}")


@router.get("/relations", response_model=list[DirectoryRelationOut])
def relations(project_id: int, db: Session = Depends(get_db)):
    return db.scalars(select(DirectoryRelation).where(
        DirectoryRelation.project_id == project_id).order_by(
        DirectoryRelation.id.desc()).limit(5000)).all()


@router.post("/relations", response_model=DirectoryRelationOut, status_code=201)
def create_relation(body: DirectoryRelationIn,
                    db: Session = Depends(get_db)):
    source = need(db, DirectoryObject, body.source_id)
    target = need(db, DirectoryObject, body.target_id)
    if source.project_id != body.project_id or target.project_id != body.project_id:
        raise HTTPException(400, "Objects must belong to the project")
    if body.evidence_id:
        evidence = need(db, Evidence, body.evidence_id)
        if evidence.project_id != body.project_id:
            raise HTTPException(400, "Evidence must belong to the project")
    row = DirectoryRelation(**body.model_dump())
    db.add(row); db.commit(); db.refresh(row)
    return row
