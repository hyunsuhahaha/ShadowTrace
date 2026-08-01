from __future__ import annotations
import hashlib
import json
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session
from ...database import get_db
from ...models import (
    Credential, Evidence, Execution, Finding, Project, RunbookActivityEvent, RunbookInstance,
    RunbookObservation, RunbookRecommendationDismissal, RunbookStepCredential, RunbookStepEvidence,
    RunbookStepExecution, RunbookStepInstance, RunbookStepTemplate,
    RunbookTemplate, RunbookTemplateVersion, Service, Target,
)
from ...templates import catalog
from ...time import utcnow
from .engine import (
    approval_required, key_for, recompute, workflow_summary,
)

router = APIRouter(prefix="/api/runbooks", tags=["Runbooks"])
STATUSES = {
    "not_started", "in_progress", "completed", "attempted", "blocked",
    "skipped", "suspicious", "not_applicable",
}
OUTCOMES = {
    "unknown", "confirmed", "not_found", "access_denied", "error",
    "not_applicable", "needs_review", "authentication_required", "partial",
    "ambiguous", "parser_failed",
}
REASON_REQUIRED = {"blocked", "skipped", "not_applicable"}
NODE_TYPES = {
    "command", "manual_check", "decision", "approval", "parallel", "join",
    "evidence", "finding", "sub_runbook", "end",
}
ACTIVATION_LOCKED = {"waiting", "excluded", "awaiting_approval"}


class TemplateIn(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    description: str = Field(default="", max_length=20_000)
    tags: list[str] = Field(default_factory=list, max_length=30)
    service_names: list[str] = Field(default_factory=list, max_length=30)
    ports: list[int] = Field(default_factory=list, max_length=30)

    @field_validator("ports")
    @classmethod
    def valid_ports(cls, values: list[int]) -> list[int]:
        if any(value < 1 or value > 65535 for value in values):
            raise ValueError("Ports must be between 1 and 65535")
        return list(dict.fromkeys(values))


class StepIn(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=20_000)
    command_refs: list[str] = Field(default_factory=list, max_length=20)
    expected_observations: list[str] = Field(default_factory=list, max_length=30)
    condition: dict = Field(default_factory=dict)
    guidance: dict = Field(default_factory=dict)
    node_key: str = Field(default="", max_length=120,
                          pattern=r"^[a-zA-Z0-9_.-]*$")
    node_type: str = Field(default="manual_check")
    transitions: list[dict] = Field(default_factory=list, max_length=30)
    error_policy: dict = Field(default_factory=dict)
    approval: dict = Field(default_factory=dict)

    @field_validator("node_type")
    @classmethod
    def valid_node_type(cls, value: str) -> str:
        if value not in NODE_TYPES:
            raise ValueError("Unsupported runbook node type")
        return value

    @field_validator("transitions")
    @classmethod
    def valid_transitions(cls, value: list[dict]) -> list[dict]:
        allowed_predicates = {
            "all", "any", "not", "always", "outcome", "status",
            "approval_status", "fact_exists", "credential_exists",
        }
        def check_predicate(item: object) -> None:
            if not isinstance(item, dict) or set(item) - allowed_predicates:
                raise ValueError("Unsupported transition predicate")
            for key in ("all", "any"):
                if key in item:
                    if not isinstance(item[key], list):
                        raise ValueError(f"transition.{key} must be a list")
                    for child in item[key]:
                        check_predicate(child)
            if "not" in item:
                check_predicate(item["not"])
        for transition in value:
            if not isinstance(transition, dict):
                raise ValueError("Transition must be an object")
            unknown = set(transition) - {
                "target", "targets", "when", "default", "label", "priority",
            }
            if unknown:
                raise ValueError("Unsupported transition fields")
            targets = transition.get("targets", transition.get("target"))
            if isinstance(targets, str):
                targets = [targets]
            if not isinstance(targets, list) or not targets or not all(
                    isinstance(item, str) and item for item in targets):
                raise ValueError("Transition requires target node keys")
            if not transition.get("default"):
                check_predicate(transition.get("when", {}))
        return value

    @field_validator("error_policy")
    @classmethod
    def valid_error_policy(cls, value: dict) -> dict:
        if not isinstance(value, dict) or set(value) - {"retry", "on_exhausted"}:
            raise ValueError("Unsupported error policy")
        retry = value.get("retry", {})
        if retry and (not isinstance(retry, dict)
                      or set(retry) - {"max_attempts", "backoff_seconds"}):
            raise ValueError("Unsupported retry policy")
        attempts = retry.get("max_attempts", 0) if isinstance(retry, dict) else 0
        if not isinstance(attempts, int) or attempts < 0 or attempts > 10:
            raise ValueError("max_attempts must be between 0 and 10")
        return value

    @field_validator("approval")
    @classmethod
    def valid_approval(cls, value: dict) -> dict:
        if not isinstance(value, dict) or set(value) - {
                "required", "reason", "role", "timeout_minutes"}:
            raise ValueError("Unsupported approval policy")
        return value

    @field_validator("condition")
    @classmethod
    def valid_condition(cls, value: dict) -> dict:
        if not value:
            return {}
        kind = value.get("kind")
        if kind not in {
                "current_service_is", "service_exists",
                "credential_exists", "step_status"}:
            raise ValueError("Unsupported condition kind")
        if kind in {"current_service_is", "service_exists", "credential_exists"}:
            if not isinstance(value.get("service_name"), str) or not value["service_name"].strip():
                raise ValueError("Condition requires service_name")
            return {"kind": kind, "service_name": value["service_name"].strip().lower()}
        position, status = value.get("position"), value.get("status")
        if not isinstance(position, int) or position < 1 or status not in STATUSES:
            raise ValueError("step_status requires a valid position and status")
        return {"kind": kind, "position": position, "status": status}

    @field_validator("guidance")
    @classmethod
    def valid_guidance(cls, value: dict) -> dict:
        allowed = {
            "stage_id", "phase", "question", "purpose", "manual_checks",
            "prerequisites", "auth", "safety", "next_steps", "join",
        }
        if not isinstance(value, dict) or set(value) - allowed:
            raise ValueError("Unsupported guidance fields")
        for key in ("stage_id", "phase", "question", "purpose", "auth", "safety"):
            if key in value and not isinstance(value[key], str):
                raise ValueError(f"guidance.{key} must be text")
        for key in ("manual_checks", "prerequisites"):
            if key in value and (not isinstance(value[key], list)
                                 or not all(isinstance(item, str) for item in value[key])):
                raise ValueError(f"guidance.{key} must be a text list")
        if "next_steps" in value and not isinstance(value["next_steps"], dict):
            raise ValueError("guidance.next_steps must be an object")
        return value


class PublishIn(BaseModel):
    steps: list[StepIn] = Field(min_length=1, max_length=500)


class ApplyIn(BaseModel):
    version_id: int
    target_id: int
    service_id: int | None = None


class StepUpdate(BaseModel):
    status: str
    result: str = Field(default="", max_length=100_000)
    notes: str = Field(default="", max_length=100_000)
    status_reason: str = Field(default="", max_length=20_000)
    outcome: str = Field(default="unknown")
    override: bool = False
    override_reason: str = Field(default="", max_length=20_000)


class ApprovalIn(BaseModel):
    decision: str = Field(pattern=r"^(approved|rejected)$")
    reason: str = Field(min_length=1, max_length=20_000)
    actor: str = Field(default="local", min_length=1, max_length=160)


class LinkIn(BaseModel):
    resource_id: int


class CredentialIn(BaseModel):
    project_id: int
    target_id: int | None = None
    service_id: int | None = None
    username: str = Field(min_length=1, max_length=200)
    secret_kind: str = Field(default="password", pattern=r"^(password|hash|token|key|community)$")
    secret_hint: str = Field(default="", max_length=200)
    secret: str = Field(default="", max_length=20_000)
    source_kind: str = Field(default="manual", max_length=40)
    source_detail: str = Field(default="", max_length=20_000)
    domain: str = Field(default="", max_length=253)
    service_names: list[str] = Field(default_factory=list, max_length=30)
    notes: str = Field(default="", max_length=20_000)


class ObservationIn(BaseModel):
    title: str = Field(min_length=1, max_length=240)
    detail: str = Field(default="", max_length=100_000)
    evidence_id: int | None = None


class FindingIn(BaseModel):
    title: str = Field(min_length=1, max_length=240)
    description: str = Field(default="", max_length=100_000)


class FindingUpdate(FindingIn):
    status: str = Field(pattern=r"^(candidate|confirmed|remediated|false_positive)$")


class CloneIn(BaseModel):
    name: str = Field(min_length=1, max_length=160)


class DismissIn(BaseModel):
    version_id: int


class ImportIn(BaseModel):
    schema_version: int
    template: TemplateIn
    steps: list[StepIn] = Field(min_length=1, max_length=500)


def need(db: Session, model, ident: int):
    row = db.get(model, ident)
    if not row:
        raise HTTPException(404, "Not found")
    return row


def loads(value: str):
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return []


def seconds_since(value) -> int:
    if not value:
        return 0
    now = utcnow()
    if value.tzinfo is None:
        now = now.replace(tzinfo=None)
    return max(0, int((now - value).total_seconds()))


def instance_scope_current(db: Session, row: RunbookInstance) -> bool:
    """Reject records that predate the current project generation.

    SQLite can reuse integer primary keys after project deletion. Older builds
    did not purge runbook rows, so a historical instance could otherwise be
    joined to an unrelated project that later received the same numeric ID.
    """
    project = db.get(Project, row.project_id)
    target = db.get(Target, row.target_id)
    if not project or not target or target.project_id != project.id:
        return False
    instance_created = row.created_at
    project_created = project.created_at
    if instance_created.tzinfo is None and project_created.tzinfo is not None:
        project_created = project_created.replace(tzinfo=None)
    elif instance_created.tzinfo is not None and project_created.tzinfo is None:
        instance_created = instance_created.replace(tzinfo=None)
    if instance_created < project_created:
        return False
    if row.service_id is not None:
        service = db.get(Service, row.service_id)
        if not service or service.target_id != target.id:
            return False
    return True


def template_dict(db: Session, row: RunbookTemplate):
    latest = db.scalar(select(RunbookTemplateVersion).where(
        RunbookTemplateVersion.template_id == row.id).order_by(
        RunbookTemplateVersion.version.desc()))
    return {
        "id": row.id, "name": row.name, "description": row.description,
        "tags": loads(row.tags), "service_names": loads(row.service_names),
        "ports": loads(row.ports), "origin": row.origin,
        "builtin_key": row.builtin_key, "archived": row.archived,
        "latest_version": latest.version if latest else None,
        "latest_version_id": latest.id if latest else None,
        "created_at": row.created_at, "updated_at": row.updated_at,
    }


def version_dict(db: Session, row: RunbookTemplateVersion):
    steps = db.scalars(select(RunbookStepTemplate).where(
        RunbookStepTemplate.version_id == row.id).order_by(
        RunbookStepTemplate.position)).all()
    return {
        "id": row.id, "template_id": row.template_id, "version": row.version,
        "name": row.name, "description": row.description, "tags": loads(row.tags),
        "service_names": loads(row.service_names), "ports": loads(row.ports),
        "published_at": row.published_at,
        "steps": [{
            "id": step.id, "position": step.position, "title": step.title,
            "description": step.description,
            "command_refs": loads(step.command_refs),
            "expected_observations": loads(step.expected_observations),
            "condition": loads(step.condition) or {},
            "guidance": loads(step.guidance) or {},
            "node_key": step.node_key or f"step-{step.position}",
            "node_type": step.node_type,
            "transitions": loads(step.transitions) or [],
            "error_policy": loads(step.error_policy) or {},
            "approval": loads(step.approval) or {},
        } for step in steps],
    }


def progress(steps: list[RunbookStepInstance]):
    applicable = [step for step in steps
                  if step.status != "not_applicable"
                  and getattr(step, "_condition_met", True)
                  and step.activation != "excluded"]
    done = sum(step.activation in {"completed", "failed_handled"}
               for step in applicable)
    return {
        "completed": done, "total": len(applicable),
        "percent": round(done * 100 / len(applicable)) if applicable else None,
    }


def instance_dict(db: Session, row: RunbookInstance, include_steps: bool = False):
    steps = db.scalars(select(RunbookStepInstance).where(
        RunbookStepInstance.instance_id == row.id).order_by(
        RunbookStepInstance.position)).all()
    for step in steps:
        step._condition_met = condition_met(db, row, step, steps)
    recompute(db, row, steps, condition_met)
    result = {
        "id": row.id, "project_id": row.project_id, "target_id": row.target_id,
        "service_id": row.service_id, "version_id": row.version_id,
        "template_name": row.template_name, "target_name": row.target_name,
        "service_name": row.service_name, "status": row.status,
        "progress": progress(steps), "created_at": row.created_at,
        "updated_at": row.updated_at,
        "workflow": workflow_summary(steps),
    }
    if include_steps:
        step_ids = [step.id for step in steps]
        evidence = db.execute(select(
            RunbookStepEvidence.step_id, RunbookStepEvidence.evidence_id).where(
            RunbookStepEvidence.step_id.in_(step_ids))).all() if step_ids else []
        executions = db.execute(select(
            RunbookStepExecution.step_id, RunbookStepExecution.execution_id).where(
            RunbookStepExecution.step_id.in_(step_ids))).all() if step_ids else []
        evidence_map: dict[int, list[int]] = {}
        execution_map: dict[int, list[int]] = {}
        for step_id, resource_id in evidence:
            evidence_map.setdefault(step_id, []).append(resource_id)
        for step_id, resource_id in executions:
            execution_map.setdefault(step_id, []).append(resource_id)
        result["steps"] = [{
            "id": step.id, "position": step.position, "title": step.title,
            "description": step.description,
            "command_refs": loads(step.command_refs),
            "expected_observations": loads(step.expected_observations),
            "condition": loads(step.condition) or {},
            "guidance": loads(step.guidance) or {},
            "node_key": key_for(step), "node_type": step.node_type,
            "transitions": loads(step.transitions) or [],
            "error_policy": loads(step.error_policy) or {},
            "approval": loads(step.approval) or {},
            "condition_met": step._condition_met,
            "status": step.status, "result": step.result, "notes": step.notes,
            "outcome": step.outcome, "assessment": loads(step.assessment) or {},
            "activation": step.activation,
            "decision_trace": loads(step.decision_trace) or [],
            "approval_status": step.approval_status,
            "approval_reason": step.approval_reason,
            "approved_by": step.approved_by, "attempts": step.attempts,
            "last_error": step.last_error,
            "status_reason": step.status_reason, "started_at": step.started_at,
            "completed_at": step.completed_at, "updated_at": step.updated_at,
            "timer_started_at": step.timer_started_at,
            "elapsed_seconds": step.elapsed_seconds + (
                seconds_since(step.timer_started_at)
                if step.timer_started_at else 0),
            "evidence_ids": evidence_map.get(step.id, []),
            "execution_ids": execution_map.get(step.id, []),
            "credential_ids": credential_ids(db, step.id),
            "observations": observations(db, step.id),
        } for step in steps]
    return result


def condition_met(db: Session, instance: RunbookInstance, step: RunbookStepInstance,
                  steps: list[RunbookStepInstance]) -> bool:
    condition = loads(step.condition) or {}
    kind = condition.get("kind")
    if not kind:
        return True
    name = condition.get("service_name", "").lower()
    if kind == "current_service_is":
        return bool(instance.service_name and instance.service_name.lower() == name)
    if kind == "service_exists":
        return db.scalar(select(Service.id).join(Target).where(
            Target.project_id == instance.project_id,
            func.lower(Service.name) == name)) is not None
    if kind == "credential_exists":
        rows = db.scalars(select(Credential).where(
            Credential.project_id == instance.project_id)).all()
        return any(name in loads(row.service_names) for row in rows)
    if kind == "step_status":
        return any(item.position == condition.get("position")
                   and item.status == condition.get("status") for item in steps)
    return False


def credential_ids(db: Session, step_id: int):
    return list(db.scalars(select(RunbookStepCredential.credential_id).where(
        RunbookStepCredential.step_id == step_id)).all())


def observations(db: Session, step_id: int):
    rows = db.scalars(select(RunbookObservation).where(
        RunbookObservation.step_id == step_id).order_by(
        RunbookObservation.id.desc())).all()
    return [{
        "id": row.id, "title": row.title, "detail": row.detail,
        "evidence_id": row.evidence_id, "status": row.status,
        "created_at": row.created_at,
    } for row in rows]


def event(db: Session, instance_id: int, event_type: str,
          step_id: int | None = None, details: dict | None = None):
    db.add(RunbookActivityEvent(
        instance_id=instance_id, step_id=step_id, event_type=event_type,
        details=json.dumps(details or {}, ensure_ascii=False)))


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


@router.patch("/steps/{ident}")
def update_step(ident: int, body: StepUpdate, db: Session = Depends(get_db)):
    step = need(db, RunbookStepInstance, ident)
    if body.status not in STATUSES:
        raise HTTPException(400, "Invalid step status")
    if body.outcome not in OUTCOMES:
        raise HTTPException(400, "Invalid investigation outcome")
    if body.status in REASON_REQUIRED and not body.status_reason.strip():
        raise HTTPException(400, "A reason is required for this status")
    instance = need(db, RunbookInstance, step.instance_id)
    steps = db.scalars(select(RunbookStepInstance).where(
        RunbookStepInstance.instance_id == instance.id).order_by(
        RunbookStepInstance.position)).all()
    recompute(db, instance, steps, condition_met)
    execution_states = {"in_progress", "completed", "attempted", "suspicious"}
    if step.activation in ACTIVATION_LOCKED and body.status in execution_states:
        if not body.override or not body.override_reason.strip():
            raise HTTPException(409, {
                "message": "Step is not active",
                "activation": step.activation,
                "hint": "Use an explicit override with a reason if this path must be forced.",
            })
        event(db, instance.id, "path_overridden", step.id, {
            "activation": step.activation, "reason": body.override_reason})
    before = step.status
    step.status = body.status
    step.result = body.result
    step.notes = body.notes
    step.status_reason = body.status_reason
    step.outcome = body.outcome
    now = utcnow()
    if body.status == "in_progress" and not step.started_at:
        step.started_at = now
    step.completed_at = now if body.status in {
        "completed", "skipped", "not_applicable"} else None
    step.updated_at = now
    instance.updated_at = now
    event(db, instance.id, "step_updated", step.id, {
        "from": before, "to": step.status, "outcome": step.outcome})
    recompute(db, instance, steps, condition_met)
    db.commit(); db.refresh(instance)
    return instance_dict(db, instance, True)


@router.post("/steps/{ident}/approval")
def decide_approval(ident: int, body: ApprovalIn,
                    db: Session = Depends(get_db)):
    step = need(db, RunbookStepInstance, ident)
    instance = need(db, RunbookInstance, step.instance_id)
    if not approval_required(step):
        raise HTTPException(409, "This step does not require approval")
    steps = db.scalars(select(RunbookStepInstance).where(
        RunbookStepInstance.instance_id == instance.id).order_by(
        RunbookStepInstance.position)).all()
    recompute(db, instance, steps, condition_met)
    if step.activation not in {"awaiting_approval", "blocked", "ready"}:
        raise HTTPException(409, "Approval is not available for this step")
    previous_approval = step.approval_status
    step.approval_status = body.decision
    step.approval_reason = body.reason.strip()
    step.approved_by = body.actor.strip()
    step.updated_at = utcnow()
    if body.decision == "rejected":
        step.status = "blocked"
        step.status_reason = body.reason.strip()
    elif step.status == "blocked" and previous_approval == "rejected":
        step.status = "not_started"
        step.status_reason = ""
    event(db, instance.id, f"approval_{body.decision}", step.id, {
        "actor": step.approved_by, "reason": step.approval_reason})
    recompute(db, instance, steps, condition_met)
    instance.updated_at = utcnow()
    db.commit(); db.refresh(instance)
    return instance_dict(db, instance, True)


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


@router.post("/steps/{ident}/timer/{action}")
def step_timer(ident: int, action: str, db: Session = Depends(get_db)):
    step, instance = link_scope(db, ident)
    steps = db.scalars(select(RunbookStepInstance).where(
        RunbookStepInstance.instance_id == instance.id).order_by(
        RunbookStepInstance.position)).all()
    recompute(db, instance, steps, condition_met)
    if action == "start" and step.activation in ACTIVATION_LOCKED:
        raise HTTPException(409, "Step is not active")
    now = utcnow()
    if action == "start":
        if not step.timer_started_at:
            step.timer_started_at = now
            if step.status == "not_started":
                step.status = "in_progress"
                step.started_at = now
            event(db, instance.id, "timer_started", step.id)
    elif action == "stop":
        if step.timer_started_at:
            step.elapsed_seconds += max(
                0, seconds_since(step.timer_started_at))
            step.timer_started_at = None
            event(db, instance.id, "timer_stopped", step.id,
                  {"elapsed_seconds": step.elapsed_seconds})
    else:
        raise HTTPException(400, "Timer action must be start or stop")
    step.updated_at = now
    instance.updated_at = now
    recompute(db, instance, steps, condition_met)
    db.commit(); db.refresh(instance)
    return instance_dict(db, instance, True)


def link_scope(db: Session, step_id: int):
    step = need(db, RunbookStepInstance, step_id)
    return step, need(db, RunbookInstance, step.instance_id)


@router.post("/steps/{ident}/evidence", status_code=201)
def attach_evidence(ident: int, body: LinkIn, db: Session = Depends(get_db)):
    step, instance = link_scope(db, ident)
    evidence = need(db, Evidence, body.resource_id)
    if evidence.project_id != instance.project_id:
        raise HTTPException(400, "Evidence belongs to another project")
    if not db.get(RunbookStepEvidence, (step.id, evidence.id)):
        db.add(RunbookStepEvidence(step_id=step.id, evidence_id=evidence.id))
        event(db, instance.id, "evidence_attached", step.id,
              {"evidence_id": evidence.id})
        db.commit()
    return instance_dict(db, instance, True)


@router.post("/steps/{ident}/executions", status_code=201)
def attach_execution(ident: int, body: LinkIn, db: Session = Depends(get_db)):
    step, instance = link_scope(db, ident)
    execution = need(db, Execution, body.resource_id)
    if execution.target_id != instance.target_id:
        raise HTTPException(400, "Execution belongs to another target")
    if not db.get(RunbookStepExecution, (step.id, execution.id)):
        db.add(RunbookStepExecution(step_id=step.id, execution_id=execution.id))
        event(db, instance.id, "execution_attached", step.id,
              {"execution_id": execution.id})
        db.commit()
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


def service_fingerprint(service: Service) -> str:
    value = json.dumps({
        "name": service.name.lower(), "port": service.port,
        "protocol": service.protocol.lower(), "product": service.product,
        "version": service.version, "tags": loads(service.tags),
    }, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(value.encode()).hexdigest()


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


@router.post("/steps/{ident}/credentials", status_code=201)
def attach_credential(ident: int, body: LinkIn, db: Session = Depends(get_db)):
    step, instance = link_scope(db, ident)
    credential = need(db, Credential, body.resource_id)
    if credential.project_id != instance.project_id:
        raise HTTPException(400, "Credential belongs to another project")
    if not db.get(RunbookStepCredential, (step.id, credential.id)):
        db.add(RunbookStepCredential(step_id=step.id, credential_id=credential.id))
        event(db, instance.id, "credential_attached", step.id,
              {"credential_id": credential.id})
        steps = db.scalars(select(RunbookStepInstance).where(
            RunbookStepInstance.instance_id == instance.id).order_by(
            RunbookStepInstance.position)).all()
        recompute(db, instance, steps, condition_met)
        db.commit()
    return instance_dict(db, instance, True)


@router.post("/steps/{ident}/observations", status_code=201)
def create_observation(ident: int, body: ObservationIn,
                       db: Session = Depends(get_db)):
    step, instance = link_scope(db, ident)
    if body.evidence_id:
        evidence = need(db, Evidence, body.evidence_id)
        if evidence.project_id != instance.project_id:
            raise HTTPException(400, "Evidence belongs to another project")
    row = RunbookObservation(
        step_id=step.id, title=body.title.strip(), detail=body.detail,
        evidence_id=body.evidence_id)
    db.add(row); db.flush()
    event(db, instance.id, "observation_created", step.id,
          {"observation_id": row.id})
    db.commit(); db.refresh(row)
    return observations(db, step.id)[0]


@router.post("/observations/{ident}/promote", status_code=201)
def promote_observation(ident: int, body: FindingIn,
                        db: Session = Depends(get_db)):
    observation = need(db, RunbookObservation, ident)
    step = need(db, RunbookStepInstance, observation.step_id)
    instance = need(db, RunbookInstance, step.instance_id)
    existing = db.scalar(select(Finding).where(Finding.observation_id == ident))
    if existing:
        raise HTTPException(409, "Observation is already promoted")
    finding = Finding(
        project_id=instance.project_id, target_id=instance.target_id,
        service_id=instance.service_id, observation_id=observation.id,
        title=body.title.strip(), description=body.description)
    observation.status = "promoted"
    db.add(finding); db.flush()
    event(db, instance.id, "observation_promoted", step.id,
          {"observation_id": observation.id, "finding_id": finding.id})
    db.commit(); db.refresh(finding)
    return {
        "id": finding.id, "project_id": finding.project_id,
        "target_id": finding.target_id, "service_id": finding.service_id,
        "observation_id": finding.observation_id, "title": finding.title,
        "description": finding.description, "status": finding.status,
        "created_at": finding.created_at,
    }


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
