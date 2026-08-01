import sqlite3
import zipfile
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import or_, select
from sqlalchemy.orm import Session
from ...config import DB_PATH, STATE_DIR, WORKSPACE_DIR
from ...database import get_db
from ...models import (
    AuditEvent, Credential, DirectoryObject, Evidence, ExploitModification,
    ExploitResearch, ExploitSource, Project, Report,
    ScanJob, Service, Target,
)
from ...time import utcnow

router = APIRouter(prefix="/api/operations", tags=["Operations"])


@router.get("/search")
def search(query: str, project_id: int | None = None,
           db: Session = Depends(get_db)):
    query = query.strip()[:200]
    if not query:
        return []
    needle = f"%{query}%"
    results = []
    targets = select(Target).where(or_(
        Target.name.ilike(needle), Target.ip.ilike(needle),
        Target.hostname.ilike(needle), Target.notes.ilike(needle)))
    if project_id:
        targets = targets.where(Target.project_id == project_id)
    for row in db.scalars(targets.limit(50)):
        results.append({"type": "target", "id": row.id, "title": row.name,
                        "subtitle": f"{row.ip} {row.hostname}", "path": "#"})
    services = select(Service).join(Target).where(or_(
        Service.name.ilike(needle), Service.product.ilike(needle),
        Service.version.ilike(needle), Service.notes.ilike(needle)))
    if project_id:
        services = services.where(Target.project_id == project_id)
    for row in db.scalars(services.limit(50)):
        results.append({"type": "service", "id": row.id,
                        "title": f"{row.port}/{row.protocol} {row.name}",
                        "subtitle": f"{row.product} {row.version}",
                        "path": "#enumeration"})
    evidence = select(Evidence).where(or_(
        Evidence.title.ilike(needle), Evidence.description.ilike(needle),
        Evidence.tags.ilike(needle), Evidence.markdown.ilike(needle)))
    if project_id:
        evidence = evidence.where(Evidence.project_id == project_id)
    for row in db.scalars(evidence.limit(50)):
        results.append({"type": "evidence", "id": row.id, "title": row.title,
                        "subtitle": row.kind, "path": "#evidence"})
    directory = select(DirectoryObject).where(or_(
        DirectoryObject.name.ilike(needle),
        DirectoryObject.attributes.ilike(needle),
        DirectoryObject.notes.ilike(needle)))
    if project_id:
        directory = directory.where(DirectoryObject.project_id == project_id)
    for row in db.scalars(directory.limit(50)):
        results.append({"type": "directory", "id": row.id, "title": row.name,
                        "subtitle": f"{row.kind} {row.domain}",
                        "path": "#directory"})
    reports = select(Report).where(or_(
        Report.title.ilike(needle), Report.markdown.ilike(needle)))
    if project_id:
        reports = reports.where(Report.project_id == project_id)
    for row in db.scalars(reports.limit(50)):
        results.append({"type": "report", "id": row.id, "title": row.title,
                        "subtitle": row.template, "path": "#reports"})
    research = select(ExploitResearch).where(or_(
        ExploitResearch.cve.ilike(needle),
        ExploitResearch.exploit_db_id.ilike(needle),
        ExploitResearch.title.ilike(needle),
        ExploitResearch.service_name.ilike(needle),
        ExploitResearch.discovered_version.ilike(needle),
        ExploitResearch.notes.ilike(needle),
        ExploitResearch.execution_command.ilike(needle)))
    if project_id:
        research = research.where(ExploitResearch.project_id == project_id)
    for row in db.scalars(research.limit(50)):
        results.append({
            "type": "exploit_research", "id": row.id, "title": row.title,
            "subtitle": f"{row.cve} {row.service_name} {row.discovered_version}",
            "path": "#exploit-research",
        })
    modifications = select(ExploitModification).join(ExploitResearch).where(
        or_(ExploitModification.variable_name.ilike(needle),
            ExploitModification.reason.ilike(needle)))
    if project_id:
        modifications = modifications.where(
            ExploitResearch.project_id == project_id)
    for row in db.scalars(modifications.limit(30)):
        results.append({
            "type": "exploit_modification", "id": row.id,
            "title": row.variable_name, "subtitle": row.reason,
            "path": "#exploit-research",
        })
    sources = select(ExploitSource).join(ExploitResearch).where(or_(
        ExploitSource.title.ilike(needle), ExploitSource.source_url.ilike(needle),
        ExploitSource.exploit_db_id.ilike(needle)))
    if project_id:
        sources = sources.where(ExploitResearch.project_id == project_id)
    for row in db.scalars(sources.limit(30)):
        results.append({
            "type": "exploit_source", "id": row.id, "title": row.title,
            "subtitle": row.source_url, "path": "#exploit-research",
        })
    # Credentials are searchable by identity and provenance so the acquisition
    # chain is reconstructable for the report; the stored secret is never
    # surfaced in results.
    creds = select(Credential).where(or_(
        Credential.username.ilike(needle), Credential.domain.ilike(needle),
        Credential.source_detail.ilike(needle), Credential.notes.ilike(needle),
        Credential.service_names.ilike(needle)))
    if project_id:
        creds = creds.where(Credential.project_id == project_id)
    for row in db.scalars(creds.limit(30)):
        identity = f"{row.domain}\\{row.username}" if row.domain else row.username
        provenance = f"{row.source_kind}: {row.source_detail}" if row.source_detail \
            else row.source_kind
        results.append({
            "type": "credential", "id": row.id, "title": identity,
            "subtitle": provenance, "path": "#enumeration",
        })
    return results[:200]


@router.get("/audit")
def audit(limit: int = 200, db: Session = Depends(get_db)):
    limit = max(1, min(limit, 2000))
    rows = db.scalars(select(AuditEvent).order_by(
        AuditEvent.id.desc()).limit(limit)).all()
    return [{"id": row.id, "method": row.method, "path": row.path,
             "status_code": row.status_code,
             "occurred_at": row.occurred_at} for row in rows]


@router.post("/backups")
def create_backup():
    backup_dir = STATE_DIR / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
    database_copy = backup_dir / f"{stamp}-workspace.db"
    archive = backup_dir / f"{stamp}-backup.zip"
    source = sqlite3.connect(DB_PATH)
    destination = sqlite3.connect(database_copy)
    try:
        source.backup(destination)
    finally:
        destination.close(); source.close()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output:
        output.write(database_copy, "workspace.db")
        if WORKSPACE_DIR.is_dir():
            for path in WORKSPACE_DIR.rglob("*"):
                if path.is_file() and not path.is_symlink():
                    output.write(path, Path("artifacts") / path.relative_to(WORKSPACE_DIR))
    database_copy.unlink()
    return {"name": archive.name, "size": archive.stat().st_size}


@router.get("/backups/{name}")
def download_backup(name: str):
    if not name.endswith("-backup.zip") or Path(name).name != name:
        raise HTTPException(400, "Invalid backup name")
    path = STATE_DIR / "backups" / name
    if not path.is_file():
        raise HTTPException(404, "Backup not found")
    return FileResponse(path, filename=name, media_type="application/zip")
