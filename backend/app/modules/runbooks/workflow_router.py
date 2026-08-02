from __future__ import annotations
import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from ...database import get_db
from ...models import (
    Finding, Project, RunbookActivityEvent, RunbookInstance,
    RunbookRecommendationDismissal, RunbookStepInstance, RunbookStepTemplate,
    RunbookTemplate, RunbookTemplateVersion, Service, Target,
)
from ...templates import catalog
from ...time import utcnow
from .engine import recompute, workflow_summary
from .support import (
    ApplyIn, CloneIn, DismissIn, FindingUpdate, ImportIn,
    PublishIn, StepIn, TemplateIn,
    condition_met, event, instance_dict, instance_scope_current, loads,
    need, seconds_since, service_fingerprint, template_dict, version_dict,
)

router = APIRouter(prefix="/api/runbooks", tags=["Runbooks"])


@router.get("/templates")
def templates(db: Session = Depends(get_db)):
    rows = db.scalars(select(RunbookTemplate).where(
        RunbookTemplate.archived.is_(False)).order_by(RunbookTemplate.name)).all()
    return [template_dict(db, row) for row in rows]


@router.post("/templates", status_code=201)
def create_template(body: TemplateIn, db: Session = Depends(get_db)):
    row = RunbookTemplate(
        name=body.name.strip(), description=body.description,
        tags=json.dumps(body.tags, ensure_ascii=False),
        service_names=json.dumps(
            list(dict.fromkeys(value.strip().lower() for value in body.service_names
                               if value.strip()))),
        ports=json.dumps(body.ports))
    db.add(row); db.commit(); db.refresh(row)
    return template_dict(db, row)


@router.put("/templates/{ident}")
def update_template(ident: int, body: TemplateIn, db: Session = Depends(get_db)):
    row = need(db, RunbookTemplate, ident)
    if row.builtin_key:
        raise HTTPException(409, "기본 Runbook은 복제한 뒤 수정하세요.")
    row.name = body.name.strip()
    row.description = body.description
    row.tags = json.dumps(body.tags, ensure_ascii=False)
    row.service_names = json.dumps(
        list(dict.fromkeys(value.strip().lower() for value in body.service_names
                           if value.strip())))
    row.ports = json.dumps(body.ports)
    row.updated_at = utcnow()
    db.commit(); db.refresh(row)
    return template_dict(db, row)


@router.post("/templates/{ident}/publish", status_code=201)
def publish(ident: int, body: PublishIn, db: Session = Depends(get_db)):
    template = need(db, RunbookTemplate, ident)
    if template.builtin_key:
        raise HTTPException(409, "기본 Runbook은 복제한 뒤 수정하세요.")
    missing = sorted({
        command for step in body.steps for command in step.command_refs
        if command not in catalog.items
    })
    if missing:
        raise HTTPException(400, f"Unknown command references: {', '.join(missing)}")
    node_keys = [item.node_key or item.guidance.get("stage_id") or f"step-{position}"
                 for position, item in enumerate(body.steps, 1)]
    if len(node_keys) != len(set(node_keys)):
        raise HTTPException(400, "Runbook node keys must be unique")
    referenced = {
        target for item in body.steps for transition in item.transitions
        for target in ([transition.get("target")]
                       if transition.get("target") else transition.get("targets", []))
    }
    unknown_targets = sorted(referenced - set(node_keys))
    if unknown_targets:
        raise HTTPException(400, f"Unknown transition targets: {', '.join(unknown_targets)}")
    number = (db.scalar(select(func.max(RunbookTemplateVersion.version)).where(
        RunbookTemplateVersion.template_id == ident)) or 0) + 1
    version = RunbookTemplateVersion(
        template_id=ident, version=number, name=template.name,
        description=template.description, tags=template.tags,
        service_names=template.service_names, ports=template.ports)
    db.add(version); db.flush()
    for position, item in enumerate(body.steps, 1):
        node_key = item.node_key or item.guidance.get("stage_id") or f"step-{position}"
        db.add(RunbookStepTemplate(
            version_id=version.id, position=position, title=item.title.strip(),
            description=item.description,
            command_refs=json.dumps(list(dict.fromkeys(item.command_refs))),
            expected_observations=json.dumps(
                item.expected_observations, ensure_ascii=False),
            condition=json.dumps(item.condition, ensure_ascii=False),
            guidance=json.dumps(item.guidance, ensure_ascii=False),
            node_key=node_key, node_type=item.node_type,
            transitions=json.dumps(item.transitions, ensure_ascii=False),
            error_policy=json.dumps(item.error_policy, ensure_ascii=False),
            approval=json.dumps(item.approval, ensure_ascii=False)))
    db.commit(); db.refresh(version)
    return version_dict(db, version)


@router.get("/templates/{ident}/versions")
def versions(ident: int, db: Session = Depends(get_db)):
    need(db, RunbookTemplate, ident)
    rows = db.scalars(select(RunbookTemplateVersion).where(
        RunbookTemplateVersion.template_id == ident).order_by(
        RunbookTemplateVersion.version.desc())).all()
    return [version_dict(db, row) for row in rows]


@router.post("/templates/{ident}/clone", status_code=201)
def clone_template(ident: int, body: CloneIn, db: Session = Depends(get_db)):
    source = need(db, RunbookTemplate, ident)
    version = db.scalar(select(RunbookTemplateVersion).where(
        RunbookTemplateVersion.template_id == ident).order_by(
        RunbookTemplateVersion.version.desc()))
    if not version:
        raise HTTPException(409, "Publish the template before cloning")
    created = create_template(TemplateIn(
        name=body.name, description=source.description, tags=loads(source.tags),
        service_names=loads(source.service_names), ports=loads(source.ports)), db)
    source_data = version_dict(db, version)
    published = publish(created["id"], PublishIn(steps=[
        StepIn(**{key: step[key] for key in (
            "title", "description", "command_refs", "expected_observations",
            "condition", "guidance", "node_key", "node_type", "transitions",
            "error_policy", "approval")}) for step in source_data["steps"]
    ]), db)
    return {"template": created, "version": published}


@router.post("/templates/{ident}/archive")
def archive_template(ident: int, db: Session = Depends(get_db)):
    row = need(db, RunbookTemplate, ident)
    if row.builtin_key:
        raise HTTPException(409, "기본 Runbook은 보관할 수 없습니다.")
    row.archived = True
    row.updated_at = utcnow()
    db.commit()
    return {"archived": True}


@router.get("/instances")
def instances(project_id: int | None = None, target_id: int | None = None,
              service_id: int | None = None, db: Session = Depends(get_db)):
    statement = select(RunbookInstance).order_by(RunbookInstance.updated_at.desc())
    if project_id is not None:
        statement = statement.where(RunbookInstance.project_id == project_id)
    if target_id is not None:
        statement = statement.where(RunbookInstance.target_id == target_id)
    if service_id is not None:
        statement = statement.where(RunbookInstance.service_id == service_id)
    return [instance_dict(db, row) for row in db.scalars(statement).all()
            if instance_scope_current(db, row)]


@router.post("/instances", status_code=201)
def apply(body: ApplyIn, db: Session = Depends(get_db)):
    version = need(db, RunbookTemplateVersion, body.version_id)
    target = need(db, Target, body.target_id)
    service = need(db, Service, body.service_id) if body.service_id else None
    if service and service.target_id != target.id:
        raise HTTPException(400, "Service does not belong to the target")
    existing = db.scalar(select(RunbookInstance).where(
        RunbookInstance.target_id == target.id,
        RunbookInstance.service_id == body.service_id,
        RunbookInstance.version_id == version.id))
    if existing:
        # Applying a recommendation is intentionally idempotent.  The UI may
        # ensure the matching runbook while queries are being refreshed, and a
        # duplicate request must select the existing investigation instead of
        # leaving the execution view empty.
        return instance_dict(db, existing, True)
    row = RunbookInstance(
        project_id=target.project_id, target_id=target.id,
        service_id=service.id if service else None, version_id=version.id,
        template_name=version.name, target_name=target.name,
        service_name=service.name if service else "")
    db.add(row); db.flush()
    source_steps = db.scalars(select(RunbookStepTemplate).where(
        RunbookStepTemplate.version_id == version.id).order_by(
        RunbookStepTemplate.position)).all()
    for source in source_steps:
        step = RunbookStepInstance(
            instance_id=row.id, source_step_id=source.id, position=source.position,
            title=source.title, description=source.description,
            command_refs=source.command_refs,
            expected_observations=source.expected_observations,
            condition=source.condition, guidance=source.guidance,
            node_key=source.node_key or f"step-{source.position}",
            node_type=source.node_type, transitions=source.transitions,
            error_policy=source.error_policy, approval=source.approval,
            approval_status=("pending" if source.node_type == "approval"
                             or bool((loads(source.approval) or {}).get("required"))
                             else "not_required"))
        db.add(step)
    db.flush()
    created_steps = db.scalars(select(RunbookStepInstance).where(
        RunbookStepInstance.instance_id == row.id).order_by(
        RunbookStepInstance.position)).all()
    from ..service_intelligence.router import sync_instance_executions
    sync_instance_executions(db, row, created_steps)
    recompute(db, row, created_steps, condition_met)
    event(db, row.id, "instance_created", details={"version": version.version})
    db.commit(); db.refresh(row)
    return instance_dict(db, row, True)


@router.get("/instances/{ident}")
def instance(ident: int, db: Session = Depends(get_db)):
    row = need(db, RunbookInstance, ident)
    if not instance_scope_current(db, row):
        raise HTTPException(410, "Runbook scope belongs to a deleted project")
    steps = db.scalars(select(RunbookStepInstance).where(
        RunbookStepInstance.instance_id == row.id).order_by(
        RunbookStepInstance.position)).all()
    from ..service_intelligence.router import sync_instance_executions
    synced = sync_instance_executions(db, row, steps)
    if recompute(db, row, steps, condition_met) or synced:
        db.commit(); db.refresh(row)
    return instance_dict(db, row, True)


@router.post("/instances/{ident}/recompute")
def recompute_instance(ident: int, db: Session = Depends(get_db)):
    instance = need(db, RunbookInstance, ident)
    steps = db.scalars(select(RunbookStepInstance).where(
        RunbookStepInstance.instance_id == instance.id).order_by(
        RunbookStepInstance.position)).all()
    changed = recompute(db, instance, steps, condition_met)
    if changed:
        event(db, instance.id, "workflow_recomputed", details={
            "active": workflow_summary(steps)["active_node_keys"]})
        instance.updated_at = utcnow()
        db.commit(); db.refresh(instance)
    return instance_dict(db, instance, True)


@router.get("/instances/{ident}/activity")
def activity(ident: int, db: Session = Depends(get_db)):
    need(db, RunbookInstance, ident)
    rows = db.scalars(select(RunbookActivityEvent).where(
        RunbookActivityEvent.instance_id == ident).order_by(
        RunbookActivityEvent.id.desc())).all()
    return [{
        "id": row.id, "step_id": row.step_id, "event_type": row.event_type,
        "details": json.loads(row.details), "occurred_at": row.occurred_at,
    } for row in rows]


@router.get("/recommendations/{service_id}")
def recommendations(service_id: int, db: Session = Depends(get_db)):
    service = need(db, Service, service_id)
    target = need(db, Target, service.target_id)
    result = []
    for template in db.scalars(select(RunbookTemplate).where(
            RunbookTemplate.archived.is_(False))).all():
        names, ports = loads(template.service_names), loads(template.ports)
        reasons = []
        normalized = service.name.lower().strip()
        if normalized in names:
            reasons.append(f"detected-service:{normalized}")
        # Port-only matching is deliberately limited to unidentified services.
        # A detected protocol always wins, including on a non-standard port.
        if normalized in {"", "unknown", "tcpwrapped"} and service.port in ports:
            reasons.append(f"unidentified-port-fallback:{service.port}")
        if not reasons:
            continue
        version = db.scalar(select(RunbookTemplateVersion).where(
            RunbookTemplateVersion.template_id == template.id).order_by(
            RunbookTemplateVersion.version.desc()))
        if not version:
            continue
        fingerprint = service_fingerprint(service)
        dismissed = db.scalar(select(RunbookRecommendationDismissal.id).where(
            RunbookRecommendationDismissal.service_id == service.id,
            RunbookRecommendationDismissal.version_id == version.id,
            RunbookRecommendationDismissal.fingerprint == fingerprint)) is not None
        applied_id = db.scalar(select(RunbookInstance.id).where(
            RunbookInstance.target_id == target.id,
            RunbookInstance.service_id == service.id,
            RunbookInstance.version_id == version.id))
        result.append({
            "template_id": template.id, "template_name": template.name,
            "version_id": version.id, "version": version.version,
            "reasons": reasons, "applied": applied_id is not None,
            "instance_id": applied_id,
            "dismissed": dismissed,
            "fingerprint": fingerprint,
        })
    return result


@router.get("/target-recommendations/{target_id}")
def target_recommendations(target_id: int, db: Session = Depends(get_db)):
    target = need(db, Target, target_id)
    result = []
    for template in db.scalars(select(RunbookTemplate).where(
            RunbookTemplate.archived.is_(False))).all():
        if loads(template.service_names) or loads(template.ports):
            continue
        version = db.scalar(select(RunbookTemplateVersion).where(
            RunbookTemplateVersion.template_id == template.id).order_by(
            RunbookTemplateVersion.version.desc()))
        if not version:
            continue
        applied_id = db.scalar(select(RunbookInstance.id).where(
            RunbookInstance.target_id == target.id,
            RunbookInstance.service_id.is_(None),
            RunbookInstance.version_id == version.id))
        result.append({
            "template_id": template.id, "template_name": template.name,
            "version_id": version.id, "version": version.version,
            "reasons": ["target:baseline"], "applied": applied_id is not None,
            "instance_id": applied_id,
            "fingerprint": None,
        })
    return result


@router.post("/recommendations/{service_id}/dismiss")
def dismiss_recommendation(service_id: int, body: DismissIn,
                           db: Session = Depends(get_db)):
    service = need(db, Service, service_id)
    need(db, RunbookTemplateVersion, body.version_id)
    fingerprint = service_fingerprint(service)
    existing = db.scalar(select(RunbookRecommendationDismissal).where(
        RunbookRecommendationDismissal.service_id == service.id,
        RunbookRecommendationDismissal.version_id == body.version_id,
        RunbookRecommendationDismissal.fingerprint == fingerprint))
    if not existing:
        db.add(RunbookRecommendationDismissal(
            service_id=service.id, version_id=body.version_id,
            fingerprint=fingerprint))
        db.commit()
    return {"dismissed": True, "fingerprint": fingerprint}


@router.get("/templates/{ident}/export")
def export_template(ident: int, db: Session = Depends(get_db)):
    template = need(db, RunbookTemplate, ident)
    version = db.scalar(select(RunbookTemplateVersion).where(
        RunbookTemplateVersion.template_id == ident).order_by(
        RunbookTemplateVersion.version.desc()))
    if not version:
        raise HTTPException(409, "Publish the template before exporting")
    data = version_dict(db, version)
    return {
        "schema_version": 2,
        "template": {
            "name": data["name"], "description": data["description"],
            "tags": data["tags"], "service_names": data["service_names"],
            "ports": data["ports"],
        },
        "steps": [{
            "title": step["title"], "description": step["description"],
            "command_refs": step["command_refs"],
            "expected_observations": step["expected_observations"],
            "condition": step["condition"], "guidance": step["guidance"],
            "node_key": step["node_key"], "node_type": step["node_type"],
            "transitions": step["transitions"],
            "error_policy": step["error_policy"], "approval": step["approval"],
        } for step in data["steps"]],
        "source": {"template_id": template.id, "version": data["version"]},
    }


@router.post("/templates/import", status_code=201)
def import_template(body: ImportIn, db: Session = Depends(get_db)):
    if body.schema_version not in {1, 2}:
        raise HTTPException(400, "Unsupported runbook schema version")
    template = create_template(body.template, db)
    version = publish(template["id"], PublishIn(steps=body.steps), db)
    return {"template": template, "version": version}


@router.get("/findings")
def findings(project_id: int, db: Session = Depends(get_db)):
    rows = db.scalars(select(Finding).where(
        Finding.project_id == project_id).order_by(Finding.id.desc())).all()
    return [{
        "id": row.id, "target_id": row.target_id, "service_id": row.service_id,
        "observation_id": row.observation_id, "title": row.title,
        "description": row.description, "status": row.status,
        "created_at": row.created_at,
    } for row in rows]


@router.patch("/findings/{ident}")
def update_finding(ident: int, body: FindingUpdate,
                   db: Session = Depends(get_db)):
    row = need(db, Finding, ident)
    row.title = body.title.strip()
    row.description = body.description
    row.status = body.status
    db.commit(); db.refresh(row)
    return {
        "id": row.id, "target_id": row.target_id, "service_id": row.service_id,
        "observation_id": row.observation_id, "title": row.title,
        "description": row.description, "status": row.status,
        "created_at": row.created_at,
    }


@router.get("/findings/export")
def export_findings(project_id: int, db: Session = Depends(get_db)):
    project = need(db, Project, project_id)
    rows = db.scalars(select(Finding).where(
        Finding.project_id == project_id).order_by(
        Finding.target_id, Finding.id)).all()
    lines = [f"# {project.name} — Runbook Findings", ""]
    for row in rows:
        target = need(db, Target, row.target_id)
        service = db.get(Service, row.service_id) if row.service_id else None
        lines.extend([
            f"## {row.title}", "",
            f"- Status: `{row.status}`",
            f"- Target: `{target.name}` (`{target.ip}`)",
            f"- Service: `{service.name} {service.port}/{service.protocol}`"
            if service else "- Service: Target-level",
            f"- Source observation: `#{row.observation_id}`", "",
            row.description or "_No description recorded._", "",
        ])
    return {"filename": f"{project.name}-runbook-findings.md",
            "markdown": "\n".join(lines)}


@router.get("/summary")
def summary(project_id: int, db: Session = Depends(get_db),
            stale_minutes: int = 30):
    targets = db.scalars(select(Target).where(Target.project_id == project_id)).all()
    result = []
    for target in targets:
        instances = [row for row in db.scalars(select(RunbookInstance).where(
            RunbookInstance.target_id == target.id)).all()
            if instance_scope_current(db, row)]
        step_rows = []
        for instance in instances:
            step_rows.extend(db.scalars(select(RunbookStepInstance).where(
                RunbookStepInstance.instance_id == instance.id)).all())
        applicable = [step for step in step_rows if step.status != "not_applicable"]
        done = sum(step.status in {"completed", "skipped"} for step in applicable)
        result.append({
            "target_id": target.id, "target_name": target.name,
            "instances": len(instances), "steps": len(applicable), "completed": done,
            "percent": round(done * 100 / len(applicable)) if applicable else None,
            "blocked": sum(step.status == "blocked" for step in step_rows),
            "suspicious": sum(step.status == "suspicious" for step in step_rows),
            "last_activity": max(
                (instance.updated_at for instance in instances), default=None),
            "elapsed_seconds": sum(step.elapsed_seconds + (
                seconds_since(step.timer_started_at)
                if step.timer_started_at else 0) for step in step_rows),
            "stale": bool(instances and all(
                seconds_since(instance.updated_at)
                >= max(1, stale_minutes) * 60 for instance in instances)),
        })
    return result
