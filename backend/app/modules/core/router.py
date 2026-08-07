import json
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy import delete as sql_delete, select
from sqlalchemy.orm import Session

from ...config import WORKSPACE_DIR
from ...database import Base, get_db
from ...models import Project, Service, ServiceObservation, Target
from ...product_policy import public_policy
from ...schemas import (
    MetasploitLockIn,
    ProjectIn,
    ProjectOut,
    ServiceOut,
    ServiceUpdate,
    TargetEnsureIn,
    TargetHostnameIn,
    TargetIn,
    TargetOut,
)
from ...templates import catalog
from ...time import utcnow
from ..hosts import remove_entries as remove_host_entries
from ..scan_center.service import import_xml as import_scan_xml
from .support import need, safe_part

router = APIRouter()
REPOSITORY_DIR = Path(__file__).resolve().parents[4]


def _release_hostnames(db: Session, hostnames: set[str]) -> None:
    """Remove hostnames from /etc/hosts unless another target still claims
    one (a rare same-hostname reuse across projects). Best-effort: a write
    failure here must never roll back the DB delete that already committed."""
    stale = {h for h in hostnames if h}
    if not stale:
        return
    still_used = set(db.scalars(
        select(Target.hostname).where(Target.hostname.in_(stale))))
    to_remove = stale - still_used
    if not to_remove:
        return
    try:
        remove_host_entries(list(to_remove))
    except HTTPException:
        pass


@router.get("/api/product/capabilities")
def product_capabilities():
    """Expose the immutable OSCP+ product boundary to every client."""
    return public_policy()


@router.get("/api/projects", response_model=list[ProjectOut])
def projects(db: Session = Depends(get_db)):
    return db.scalars(select(Project)).all()


@router.post("/api/projects", response_model=ProjectOut, status_code=201)
def create_project(body: ProjectIn, db: Session = Depends(get_db)):
    row = Project(**body.model_dump())
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


@router.put("/api/projects/{ident}", response_model=ProjectOut)
def update_project(ident: int, body: ProjectIn, db: Session = Depends(get_db)):
    row = need(db, Project, ident)
    for key, value in body.model_dump().items():
        setattr(row, key, value)
    db.commit()
    return row


@router.put("/api/projects/{ident}/metasploit-lock", response_model=ProjectOut)
def set_metasploit_lock(
    ident: int, body: MetasploitLockIn, db: Session = Depends(get_db)
):
    project = need(db, Project, ident)
    if body.target_id is not None:
        target = need(db, Target, body.target_id)
        if target.project_id != ident:
            raise HTTPException(400, "Target does not belong to this project")
    project.metasploit_target_id = body.target_id
    project.metasploit_locked_at = utcnow() if body.target_id is not None else None
    db.commit()
    db.refresh(project)
    return project


@router.delete("/api/projects/{ident}", status_code=204)
def delete_project(ident: int, db: Session = Depends(get_db)):
    project = need(db, Project, ident)
    tables = Base.metadata.tables
    target_ids = list(db.scalars(select(tables["targets"].c.id).where(
        tables["targets"].c.project_id == ident)))
    service_ids = list(db.scalars(select(tables["services"].c.id).where(
        tables["services"].c.target_id.in_(target_ids)))) if target_ids else []
    scan_ids = list(db.scalars(select(tables["scan_jobs"].c.id).where(
        tables["scan_jobs"].c.project_id == ident)))
    request_ids = list(db.scalars(select(tables["http_requests"].c.id).where(
        tables["http_requests"].c.project_id == ident)))
    research_ids = list(db.scalars(select(tables["exploit_research"].c.id).where(
        tables["exploit_research"].c.project_id == ident)))
    runbook_instance_ids = list(db.scalars(select(
        tables["runbook_instances"].c.id
    ).where(tables["runbook_instances"].c.project_id == ident)))
    runbook_step_ids = list(db.scalars(select(
        tables["runbook_step_instances"].c.id
    ).where(tables["runbook_step_instances"].c.instance_id.in_(
        runbook_instance_ids)))) if runbook_instance_ids else []
    credential_ids = list(db.scalars(select(tables["credentials"].c.id).where(
        tables["credentials"].c.project_id == ident)))
    finding_ids = list(db.scalars(select(tables["findings"].c.id).where(
        tables["findings"].c.project_id == ident)))
    evidence_ids = list(db.scalars(select(tables["evidence"].c.id).where(
        tables["evidence"].c.project_id == ident)))
    freed_hostnames = set(db.scalars(select(tables["targets"].c.hostname).where(
        tables["targets"].c.id.in_(target_ids),
        tables["targets"].c.hostname != "",
    ))) if target_ids else set()

    active = db.scalar(select(tables["scan_jobs"].c.id).where(
        tables["scan_jobs"].c.project_id == ident,
        tables["scan_jobs"].c.status.in_(["queued", "running", "processing"]),
    ))
    if active:
        raise HTTPException(409, "실행 중인 스캔을 중단한 뒤 프로젝트를 삭제하세요.")

    def remove(table_name: str, column: str, values: list[int]):
        if values:
            table = tables[table_name]
            db.execute(sql_delete(table).where(table.c[column].in_(values)))

    remove("runbook_step_evidence", "step_id", runbook_step_ids)
    remove("runbook_step_executions", "step_id", runbook_step_ids)
    remove("runbook_step_credentials", "step_id", runbook_step_ids)
    remove("finding_evidence", "finding_id", finding_ids)
    remove("finding_assets", "finding_id", finding_ids)
    remove("finding_retests", "finding_id", finding_ids)
    remove("findings", "id", finding_ids)
    remove("runbook_observations", "step_id", runbook_step_ids)
    remove("runbook_activity_events", "instance_id", runbook_instance_ids)
    remove("runbook_step_instances", "id", runbook_step_ids)
    remove("runbook_instances", "id", runbook_instance_ids)
    remove("runbook_recommendation_dismissals", "service_id", service_ids)
    remove("credentials", "id", credential_ids)
    remove("evidence_image_edits", "evidence_id", evidence_ids)
    remove("exploit_local_runs", "research_id", research_ids)
    remove("exploit_execution_records", "research_id", research_ids)
    remove("exploit_modifications", "research_id", research_ids)
    remove("exploit_sources", "research_id", research_ids)
    remove("http_exchanges", "request_id", request_ids)
    remove("scan_artifacts", "scan_job_id", scan_ids)
    remove("host_observations", "scan_job_id", scan_ids)
    remove("service_observations", "scan_job_id", scan_ids)
    db.execute(sql_delete(tables["directory_relations"]).where(
        tables["directory_relations"].c.project_id == ident))
    for table_name in [
        "evidence", "exploit_research", "http_requests", "directory_objects",
        "tunnels", "reports", "scan_jobs", "remote_executions",
    ]:
        db.execute(sql_delete(tables[table_name]).where(
            tables[table_name].c.project_id == ident))
    for table_name in ["executions", "interactive_sessions"]:
        remove(table_name, "target_id", target_ids)
    remove("services", "id", service_ids)
    remove("targets", "id", target_ids)
    db.delete(project)
    db.commit()
    _release_hostnames(db, freed_hostnames)


@router.get("/api/targets", response_model=list[TargetOut])
def targets(project_id: int | None = None, db: Session = Depends(get_db)):
    statement = select(Target)
    if project_id:
        statement = statement.where(Target.project_id == project_id)
    return db.scalars(statement).all()


@router.post("/api/targets", response_model=TargetOut, status_code=201)
def create_target(body: TargetIn, db: Session = Depends(get_db)):
    need(db, Project, body.project_id)
    row = Target(**body.model_dump())
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


@router.post("/api/targets/ensure", response_model=TargetOut)
def ensure_target(body: TargetEnsureIn, db: Session = Depends(get_db)):
    existing = db.scalar(select(Target).where(Target.ip == body.ip))
    if existing:
        return existing
    project = db.scalar(select(Project).where(Project.name == body.ip))
    if not project:
        project = Project(name=body.ip, description="")
        db.add(project)
        db.flush()
    row = Target(
        project_id=project.id, name=body.name or body.ip, ip=body.ip,
        hostname="", os_guess="", vpn="tun0", notes="",
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


@router.put("/api/targets/{ident}", response_model=TargetOut)
def update_target(ident: int, body: TargetIn, db: Session = Depends(get_db)):
    row = need(db, Target, ident)
    for key, value in body.model_dump().items():
        setattr(row, key, value)
    row.updated_at = utcnow()
    db.commit()
    return row


@router.patch("/api/targets/{ident}/hostname", response_model=TargetOut)
def set_target_hostname(ident: int, body: TargetHostnameIn, db: Session = Depends(get_db)):
    """Confirm a hostname discovered through means the app doesn't automate
    (SMB/LDAP enumeration, the HTB machine page, etc.) without touching the
    rest of the target's fields the way a full PUT would."""
    row = need(db, Target, ident)
    old_hostname = row.hostname.strip()
    row.hostname = body.hostname.strip()
    row.updated_at = utcnow()
    db.commit()
    if old_hostname and old_hostname != row.hostname:
        _release_hostnames(db, {old_hostname})
    return row


@router.delete("/api/targets/{ident}", status_code=204)
def delete_target(ident: int, db: Session = Depends(get_db)):
    row = need(db, Target, ident)
    hostname = row.hostname.strip()
    db.delete(row)
    db.commit()
    if hostname:
        _release_hostnames(db, {hostname})


@router.get("/api/targets/{ident}/services", response_model=list[ServiceOut])
def services(ident: int, db: Session = Depends(get_db)):
    need(db, Target, ident)
    return db.scalars(select(Service).where(Service.target_id == ident)).all()


@router.get("/api/projects/{ident}/services", response_model=list[ServiceOut])
def project_services(ident: int, db: Session = Depends(get_db)):
    """All services across every target in a project, for cross-target tool
    lookups (e.g. the command palette pointing a search to whichever port
    actually has a matching service, not just the currently selected one)."""
    need(db, Project, ident)
    target_ids = db.scalars(
        select(Target.id).where(Target.project_id == ident)).all()
    if not target_ids:
        return []
    return db.scalars(
        select(Service).where(Service.target_id.in_(target_ids))).all()


@router.patch("/api/services/{ident}", response_model=ServiceOut)
def update_service(
    ident: int, body: ServiceUpdate, db: Session = Depends(get_db)
):
    row = need(db, Service, ident)
    if body.product is not None:
        row.product = body.product.strip()
    if body.version is not None:
        row.version = body.version.strip()
    row.notes = body.notes
    row.tags = json.dumps(list(dict.fromkeys(
        tag.strip() for tag in body.tags if tag.strip()
    )), ensure_ascii=False)
    db.commit()
    db.refresh(row)
    return row


@router.post("/api/targets/{ident}/nmap")
async def import_nmap(
    ident: int, file: UploadFile = File(...), db: Session = Depends(get_db)
):
    target = need(db, Target, ident)
    project = need(db, Project, target.project_id)
    try:
        content = await file.read(10 * 1024 * 1024 + 1)
        job = import_scan_xml(db, target, project, content, file.filename or "nmap.xml")
    except Exception as exc:
        raise HTTPException(400, f"Invalid Nmap XML: {exc}") from exc
    count = len(db.scalars(select(ServiceObservation).where(
        ServiceObservation.scan_job_id == job.id
    )).all())
    return {"scan_id": job.id, "hosts": 1, "services": count}


@router.get("/api/services/{ident}/commands")
def commands(ident: int, db: Session = Depends(get_db)):
    service = need(db, Service, ident)
    target = need(db, Target, service.target_id)
    project = need(db, Project, target.project_id)
    target_dir = (WORKSPACE_DIR / "projects" / safe_part(project.name) /
                  "targets" / safe_part(target.ip))
    variables = {
        "host": target.ip, "port": str(service.port),
        "protocol": service.protocol,
        "scheme": "https" if service.name == "https" else "http",
        "output_dir": str(target_dir / "outputs"),
        "repo_dir": str(REPOSITORY_DIR),
    }
    result = []
    for item in catalog.commands_for(
        service.name, service.port, service.protocol,
        product=service.product, cpe=json.loads(service.cpe or "[]"), tls=service.tls,
    ):
        try:
            preview = catalog.render(
                item["id"], variables, item.get("execution_mode", "captured")
            )[1]
        except ValueError:
            preview = item["command"]
        result.append({**item, "preview": preview})
    return result


@router.get("/api/targets/{ident}/identity-commands")
def target_identity_commands(ident: int, db: Session = Depends(get_db)):
    target = need(db, Target, ident)
    project = need(db, Project, target.project_id)
    target_dir = (WORKSPACE_DIR / "projects" / safe_part(project.name) /
                  "targets" / safe_part(target.ip))
    variables = {"host": target.ip, "output_dir": str(target_dir / "outputs"),
                 "repo_dir": str(REPOSITORY_DIR)}
    result = []
    for template_id in ("target-hostname-redirect", "target-hostname-ntlm",
                        "target-hostname-identity", "target-os-identity"):
        item = catalog.items.get(template_id)
        if not item:
            raise HTTPException(500, "Target identity command is not configured")
        try:
            preview = catalog.render(item["id"], variables)[1]
        except ValueError as exc:
            raise HTTPException(500, str(exc)) from exc
        result.append({**item, "preview": preview, "target_level": True})
    return result
