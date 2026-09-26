import json
import shlex
import shutil
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy import delete as sql_delete, select
from sqlalchemy.orm import Session

from ...config import WORKSPACE_DIR
from ...database import Base, get_db
from ...models import (AssessmentAsset, AssessmentAssetSubject, Evidence, Finding, Project, ProjectRoe,
                       ProjectRoeEvent, RunbookInstance,
                       RunbookStepSubject, Service, ServiceObservation, Target)
from ...product_policy import public_policy
from ...schemas import (
    ASSET_SUBJECT_SPECS, AssessmentAssetIn, AssessmentAssetOut,
    AssessmentAssetSubjectIn, AssessmentAssetSubjectOut,
    ProjectRoeDecisionIn, ProjectRoeDraftIn,
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


def _normalize_hostname(value: str) -> str:
    """Accept either a bare hostname or a pasted URL and reduce it to just
    the host part, so a manually-entered 'http://foo.htb/' ends up stored
    the same way the auto-detected flow would ('foo.htb'), not as a literal
    URL that later gets its own scheme prefixed a second time."""
    candidate = value.strip()
    if not candidate:
        return ""
    if "://" not in candidate:
        candidate = f"//{candidate}"
    return urlsplit(candidate).hostname or ""


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
    db.flush()
    db.add(ProjectRoe(project_id=row.id))
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


def _roe_dict(row: ProjectRoe) -> dict:
    return {"project_id": row.project_id, "status": row.status,
            "included_targets": json.loads(row.included_targets or "[]"),
            "excluded_targets": json.loads(row.excluded_targets or "[]"),
            "asset_ids": json.loads(row.asset_ids or "[]"),
            "allowed_actions": json.loads(row.allowed_actions or "[]"),
            "valid_from": row.valid_from, "valid_until": row.valid_until,
            "notes": row.notes, "approved_by": row.approved_by,
            "approval_reason": row.approval_reason, "revision": row.revision,
            "updated_at": row.updated_at}


def _roe_event(db: Session, row: ProjectRoe, action: str, actor: str) -> None:
    db.add(ProjectRoeEvent(project_id=row.project_id, revision=row.revision,
                           action=action, actor=actor,
                           snapshot=json.dumps(_roe_dict(row), default=str, ensure_ascii=False)))


@router.get("/api/projects/{ident}/roe")
def get_project_roe(ident: int, db: Session = Depends(get_db)):
    need(db, Project, ident)
    row = need(db, ProjectRoe, ident)
    return _roe_dict(row)


@router.get("/api/projects/{ident}/roe/history")
def project_roe_history(ident: int, db: Session = Depends(get_db)):
    need(db, Project, ident)
    rows = db.scalars(select(ProjectRoeEvent).where(
        ProjectRoeEvent.project_id == ident).order_by(ProjectRoeEvent.id.desc())).all()
    return [{"id": row.id, "revision": row.revision, "action": row.action,
             "actor": row.actor, "snapshot": json.loads(row.snapshot),
             "occurred_at": row.occurred_at} for row in rows]


@router.put("/api/projects/{ident}/roe")
def update_project_roe(ident: int, body: ProjectRoeDraftIn,
                       db: Session = Depends(get_db)):
    row = need(db, ProjectRoe, ident)
    if body.asset_ids:
        owned = set(db.scalars(select(AssessmentAsset.id).where(
            AssessmentAsset.project_id == ident,
            AssessmentAsset.id.in_(body.asset_ids))))
        if owned != set(body.asset_ids):
            raise HTTPException(400, "RoE references an asset from another project")
    row.included_targets = json.dumps(list(dict.fromkeys(body.included_targets)))
    row.excluded_targets = json.dumps(list(dict.fromkeys(body.excluded_targets)))
    row.asset_ids = json.dumps(list(dict.fromkeys(body.asset_ids)))
    row.allowed_actions = json.dumps(list(dict.fromkeys(body.allowed_actions)))
    row.valid_from, row.valid_until, row.notes = body.valid_from, body.valid_until, body.notes
    row.status, row.approved_by, row.approval_reason = "draft", "", ""
    row.revision += 1
    row.updated_at = utcnow()
    _roe_event(db, row, "revised", "local")
    db.commit(); db.refresh(row)
    return _roe_dict(row)


@router.post("/api/projects/{ident}/roe/approve")
def approve_project_roe(ident: int, body: ProjectRoeDecisionIn,
                        db: Session = Depends(get_db)):
    row = need(db, ProjectRoe, ident)
    if not row.valid_from or not row.valid_until or not json.loads(row.allowed_actions):
        raise HTTPException(409, "RoE requires an approved window and allowed actions")
    if not json.loads(row.included_targets) and not json.loads(row.asset_ids):
        raise HTTPException(409, "RoE requires targets or assets in scope")
    row.status, row.approved_by, row.approval_reason = (
        "approved", body.actor.strip(), body.reason.strip())
    row.updated_at = utcnow()
    _roe_event(db, row, "approved", body.actor.strip())
    db.commit(); db.refresh(row)
    return _roe_dict(row)


@router.post("/api/projects/{ident}/roe/revoke")
def revoke_project_roe(ident: int, body: ProjectRoeDecisionIn,
                       db: Session = Depends(get_db)):
    row = need(db, ProjectRoe, ident)
    row.status, row.approved_by, row.approval_reason = (
        "revoked", body.actor.strip(), body.reason.strip())
    row.updated_at = utcnow()
    _roe_event(db, row, "revoked", body.actor.strip())
    db.commit(); db.refresh(row)
    return _roe_dict(row)


@router.get("/api/assessment-assets", response_model=list[AssessmentAssetOut])
def assessment_assets(project_id: int, db: Session = Depends(get_db)):
    need(db, Project, project_id)
    return db.scalars(select(AssessmentAsset).where(
        AssessmentAsset.project_id == project_id).order_by(AssessmentAsset.id)).all()


@router.post("/api/assessment-assets", response_model=AssessmentAssetOut, status_code=201)
def create_assessment_asset(body: AssessmentAssetIn, db: Session = Depends(get_db)):
    need(db, Project, body.project_id)
    row = AssessmentAsset(project_id=body.project_id, kind=body.kind,
                          name=body.name.strip(), locator=body.locator.strip(),
                          details=json.dumps(body.details, ensure_ascii=False),
                          scope_status=body.scope_status)
    db.add(row); db.commit(); db.refresh(row)
    return row


@router.put("/api/assessment-assets/{ident}", response_model=AssessmentAssetOut)
def update_assessment_asset(ident: int, body: AssessmentAssetIn,
                            db: Session = Depends(get_db)):
    row = need(db, AssessmentAsset, ident)
    if row.project_id != body.project_id:
        raise HTTPException(400, "Asset cannot move between projects")
    if row.kind != body.kind and db.scalar(select(AssessmentAssetSubject.id).where(
            AssessmentAssetSubject.asset_id == ident)) is not None:
        raise HTTPException(409, "Remove assessment subjects before changing asset kind")
    row.kind, row.name, row.locator = body.kind, body.name.strip(), body.locator.strip()
    row.details = json.dumps(body.details, ensure_ascii=False)
    row.scope_status = body.scope_status
    row.updated_at = utcnow()
    db.commit(); db.refresh(row)
    return row


@router.delete("/api/assessment-assets/{ident}", status_code=204)
def delete_assessment_asset(ident: int, db: Session = Depends(get_db)):
    row = need(db, AssessmentAsset, ident)
    linked = any(db.scalar(select(model.id).where(model.asset_id == ident)) is not None
                 for model in (RunbookInstance, Evidence, Finding))
    if linked or db.scalar(select(AssessmentAssetSubject.id).where(
            AssessmentAssetSubject.asset_id == ident)) is not None:
        raise HTTPException(409, "Asset has workflow, subjects, evidence, or findings")
    db.delete(row); db.commit()


@router.get("/api/assessment-asset-subjects", response_model=list[AssessmentAssetSubjectOut])
def assessment_asset_subjects(asset_id: int, db: Session = Depends(get_db)):
    need(db, AssessmentAsset, asset_id)
    return db.scalars(select(AssessmentAssetSubject).where(
        AssessmentAssetSubject.asset_id == asset_id).order_by(
        AssessmentAssetSubject.id)).all()


def _validate_subject_kind(db: Session, body: AssessmentAssetSubjectIn) -> AssessmentAsset:
    asset = need(db, AssessmentAsset, body.asset_id)
    if body.kind not in ASSET_SUBJECT_SPECS[asset.kind]:
        raise HTTPException(400, "Subject kind does not match the assessment asset")
    return asset


@router.post("/api/assessment-asset-subjects", response_model=AssessmentAssetSubjectOut,
             status_code=201)
def create_assessment_asset_subject(body: AssessmentAssetSubjectIn,
                                    db: Session = Depends(get_db)):
    _validate_subject_kind(db, body)
    existing = db.scalar(select(AssessmentAssetSubject.id).where(
        AssessmentAssetSubject.asset_id == body.asset_id,
        AssessmentAssetSubject.kind == body.kind,
        AssessmentAssetSubject.identifier == body.identifier.strip()))
    if existing is not None:
        raise HTTPException(409, "Assessment subject already exists")
    row = AssessmentAssetSubject(asset_id=body.asset_id, kind=body.kind,
        label=body.label.strip(), identifier=body.identifier.strip(),
        attributes=json.dumps(body.attributes, ensure_ascii=False),
        scope_status=body.scope_status)
    db.add(row); db.commit(); db.refresh(row)
    return row


@router.put("/api/assessment-asset-subjects/{ident}",
            response_model=AssessmentAssetSubjectOut)
def update_assessment_asset_subject(ident: int, body: AssessmentAssetSubjectIn,
                                    db: Session = Depends(get_db)):
    row = need(db, AssessmentAssetSubject, ident)
    if row.asset_id != body.asset_id:
        raise HTTPException(400, "Subject cannot move between assets")
    _validate_subject_kind(db, body)
    duplicate = db.scalar(select(AssessmentAssetSubject.id).where(
        AssessmentAssetSubject.asset_id == body.asset_id,
        AssessmentAssetSubject.kind == body.kind,
        AssessmentAssetSubject.identifier == body.identifier.strip(),
        AssessmentAssetSubject.id != ident))
    if duplicate is not None:
        raise HTTPException(409, "Assessment subject already exists")
    row.kind, row.label, row.identifier = body.kind, body.label.strip(), body.identifier.strip()
    row.attributes = json.dumps(body.attributes, ensure_ascii=False)
    row.scope_status = body.scope_status
    row.updated_at = utcnow()
    db.commit(); db.refresh(row)
    return row


@router.delete("/api/assessment-asset-subjects/{ident}", status_code=204)
def delete_assessment_asset_subject(ident: int, db: Session = Depends(get_db)):
    if db.scalar(select(RunbookStepSubject.step_id).where(
            RunbookStepSubject.subject_id == ident)) is not None:
        raise HTTPException(409, "Subject is linked to a Runbook step")
    db.delete(need(db, AssessmentAssetSubject, ident)); db.commit()


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
    asset_ids = list(db.scalars(select(tables["assessment_assets"].c.id).where(
        tables["assessment_assets"].c.project_id == ident)))
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
    active_crack = db.scalar(select(tables["hash_crack_jobs"].c.id).where(
        tables["hash_crack_jobs"].c.project_id == ident,
        tables["hash_crack_jobs"].c.status.in_(["prepared", "running"]),
    ))
    if active_crack:
        raise HTTPException(409, "실행 중인 해시 크랙 작업을 중단한 뒤 프로젝트를 삭제하세요.")
    active_autorecon = db.scalar(select(tables["autorecon_runs"].c.id).where(
        tables["autorecon_runs"].c.project_id == ident,
        tables["autorecon_runs"].c.status.in_(["queued", "running"]),
    ))
    if active_autorecon:
        raise HTTPException(409, "실행 중인 AutoRecon을 중단한 뒤 프로젝트를 삭제하세요.")

    def remove(table_name: str, column: str, values: list[int]):
        if values:
            table = tables[table_name]
            db.execute(sql_delete(table).where(table.c[column].in_(values)))

    remove("runbook_step_evidence", "step_id", runbook_step_ids)
    remove("runbook_step_executions", "step_id", runbook_step_ids)
    remove("runbook_step_http_exchanges", "step_id", runbook_step_ids)
    remove("runbook_step_remote_executions", "step_id", runbook_step_ids)
    remove("runbook_step_sessions", "step_id", runbook_step_ids)
    remove("runbook_step_subjects", "step_id", runbook_step_ids)
    remove("runbook_step_handoffs", "from_step_id", runbook_step_ids)
    remove("assessment_asset_subjects", "asset_id", asset_ids)
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
        "tunnels", "reports", "scan_jobs", "remote_executions", "hash_crack_jobs",
        "autorecon_runs",
        # graph tables were added after this cascade; without them a deleted
        # project's nodes orphan and resurface when SQLite reuses the id.
        "graph_events", "graph_edges", "graph_nodes", "graph_project_meta",
        "notes", "assessment_assets", "project_roe_events", "project_roe",
    ]:
        db.execute(sql_delete(tables[table_name]).where(
            tables[table_name].c.project_id == ident))
    for table_name in ["executions", "interactive_sessions"]:
        remove(table_name, "target_id", target_ids)
    remove("services", "id", service_ids)
    remove("targets", "id", target_ids)
    project_name = project.name
    db.delete(project)
    db.commit()
    _release_hostnames(db, freed_hostnames)
    project_dir = WORKSPACE_DIR / "projects" / safe_part(project_name)
    shutil.rmtree(project_dir, ignore_errors=True)


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
    if body.project_id is not None:
        # Scoped to an explicit project (graph-first flow): add the target there,
        # de-duplicating within that project. Never auto-create a project.
        project = db.get(Project, body.project_id)
        if project is None:
            raise HTTPException(404, "project not found")
        existing = db.scalar(select(Target).where(
            Target.ip == body.ip, Target.project_id == project.id))
        if existing:
            return existing
    else:
        # Legacy: one project per target IP (auto-created).
        existing = db.scalar(select(Target).where(Target.ip == body.ip))
        if existing:
            return existing
        project = db.scalar(select(Project).where(Project.name == body.ip))
        if not project:
            project = Project(name=body.ip, description="")
            db.add(project)
            db.flush()
            db.add(ProjectRoe(project_id=project.id))
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
    row.hostname = _normalize_hostname(body.hostname)
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


@router.get("/api/tool-catalog")
def tool_catalog():
    """Every command template grouped by category, regardless of what a
    target's Nmap results matched — for the Tools page, where a user goes
    when a service was missed or misclassified (unusual port, WinRM read as
    plain HTTP, etc.) and the per-service panels never appeared."""
    return {"groups": catalog.list_all()}


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
        command_variables = {
            **variables,
            "host": target.hostname
            if target.hostname and item.get("service_key") == "http"
            else target.ip,
        }
        try:
            preview = catalog.render(
                item["id"], command_variables, item.get("execution_mode", "captured")
            )[1]
        except ValueError:
            preview = item["command"]
            for key, value in command_variables.items():
                preview = preview.replace(f"{{{key}}}", shlex.quote(str(value)))
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
