from __future__ import annotations
import hashlib
import io
import json
import zipfile
from pathlib import Path
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session
from ...config import WORKSPACE_DIR
from ...database import get_db
from ...models import Evidence, Project, Service, Target
from ...schemas import EvidenceOut, EvidenceUpdate
from ..scan_center.service import _safe

router = APIRouter(prefix="/api/evidence", tags=["Evidence"])
MAX_FILE = 50 * 1024 * 1024
KINDS = {"screenshot", "command_output", "http", "nmap", "flag",
         "attachment", "markdown"}


def need(db: Session, model, ident: int):
    row = db.get(model, ident)
    if not row:
        raise HTTPException(404, "Not found")
    return row


@router.get("", response_model=list[EvidenceOut])
def evidence(target_id: int | None = None, project_id: int | None = None,
             db: Session = Depends(get_db)):
    statement = select(Evidence).order_by(Evidence.id.desc())
    if target_id:
        statement = statement.where(Evidence.target_id == target_id)
    if project_id:
        statement = statement.where(Evidence.project_id == project_id)
    return db.scalars(statement.limit(1000)).all()


def validate_links(db: Session, project_id: int, target_id: int,
                   service_id: int | None):
    target = need(db, Target, target_id)
    if target.project_id != project_id:
        raise HTTPException(400, "Target does not belong to the project")
    if service_id:
        service = need(db, Service, service_id)
        if service.target_id != target.id:
            raise HTTPException(400, "Service does not belong to the target")
    return need(db, Project, project_id), target


@router.post("/upload", response_model=EvidenceOut, status_code=201)
async def upload_evidence(
    project_id: int = Form(...), target_id: int = Form(...),
    title: str = Form(...), kind: str = Form("attachment"),
    description: str = Form(""), service_id: int | None = Form(None),
    source_type: str = Form("upload"), source_id: int | None = Form(None),
    sensitivity: str = Form("normal"), include_report: bool = Form(False),
    file: UploadFile = File(...), db: Session = Depends(get_db),
):
    project, target = validate_links(db, project_id, target_id, service_id)
    if not title.strip():
        raise HTTPException(400, "Evidence title is required")
    if kind not in KINDS or sensitivity not in ("normal", "sensitive", "secret"):
        raise HTTPException(400, "Invalid evidence classification")
    content = await file.read(MAX_FILE + 1)
    if len(content) > MAX_FILE:
        raise HTTPException(413, "Evidence file exceeds 50 MiB")
    digest = hashlib.sha256(content).hexdigest()
    duplicate = db.scalar(select(Evidence).where(
        Evidence.project_id == project_id, Evidence.sha256 == digest))
    row = Evidence(project_id=project_id, target_id=target_id,
        service_id=service_id, title=title[:200], description=description[:20000],
        kind=kind, source_type=source_type[:40], source_id=source_id,
        original_name=Path(file.filename or "evidence.bin").name[:255],
        sha256=digest, size=len(content), sensitivity=sensitivity,
        include_report=include_report, duplicate_of=duplicate.id if duplicate else None)
    db.add(row); db.flush()
    folder = (WORKSPACE_DIR / "projects" / _safe(project.name) / "targets" /
              _safe(target.ip) / "evidence" / str(row.id))
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / _safe(row.original_name)
    path.write_bytes(content)
    row.file_path = str(path)
    db.commit(); db.refresh(row)
    return row


@router.post("/notes", response_model=EvidenceOut, status_code=201)
def create_note(project_id: int, target_id: int, body: EvidenceUpdate,
                db: Session = Depends(get_db)):
    validate_links(db, project_id, target_id, body.service_id)
    values = body.model_dump(exclude={"tags"})
    row = Evidence(project_id=project_id, target_id=target_id,
                   kind="markdown", source_type="note",
                   tags=json.dumps(body.tags, ensure_ascii=False), **values)
    db.add(row); db.commit(); db.refresh(row)
    return row


@router.patch("/{ident}", response_model=EvidenceOut)
def update_evidence(ident: int, body: EvidenceUpdate,
                    db: Session = Depends(get_db)):
    row = need(db, Evidence, ident)
    validate_links(db, row.project_id, row.target_id, body.service_id)
    for key, value in body.model_dump(exclude={"tags"}).items():
        setattr(row, key, value)
    row.tags = json.dumps(body.tags, ensure_ascii=False)
    db.commit(); db.refresh(row)
    return row


@router.get("/{ident}/file")
def evidence_file(ident: int, db: Session = Depends(get_db)):
    row = need(db, Evidence, ident)
    path = Path(row.file_path)
    if not row.file_path or not path.is_file():
        raise HTTPException(410, "Evidence file is no longer available")
    return FileResponse(path, filename=row.original_name,
                        media_type="application/octet-stream")


@router.post("/export")
def export_evidence(ids: list[int], db: Session = Depends(get_db)):
    if not ids or len(ids) > 500:
        raise HTTPException(400, "Select between 1 and 500 evidence records")
    rows = db.scalars(select(Evidence).where(Evidence.id.in_(ids))).all()
    output = io.BytesIO()
    manifest = []
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for row in rows:
            manifest.append({
                "id": row.id, "title": row.title, "kind": row.kind,
                "sha256": row.sha256, "source_type": row.source_type,
                "source_id": row.source_id, "sensitivity": row.sensitivity,
            })
            if row.file_path and (path := Path(row.file_path)).is_file():
                archive.write(path, f"{row.id}-{_safe(row.original_name)}")
            elif row.markdown:
                archive.writestr(f"{row.id}-note.md", row.markdown)
        archive.writestr("manifest.json",
                         json.dumps(manifest, ensure_ascii=False, indent=2))
    return Response(output.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition":
                             'attachment; filename="evidence-export.zip"'})
