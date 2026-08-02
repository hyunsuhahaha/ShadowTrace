from __future__ import annotations
import hashlib
import json
from fastapi import HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from ...models import (
    Credential, Project, RunbookActivityEvent, RunbookInstance,
    RunbookObservation, RunbookStepCredential, RunbookStepEvidence,
    RunbookStepExecution, RunbookStepInstance, RunbookStepTemplate,
    RunbookTemplate, RunbookTemplateVersion, Service, Target,
)
from ...time import utcnow
from .engine import key_for, recompute, workflow_summary

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


def link_scope(db: Session, step_id: int):
    step = need(db, RunbookStepInstance, step_id)
    return step, need(db, RunbookInstance, step.instance_id)


def service_fingerprint(service: Service) -> str:
    value = json.dumps({
        "name": service.name.lower(), "port": service.port,
        "protocol": service.protocol.lower(), "product": service.product,
        "version": service.version, "tags": loads(service.tags),
    }, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(value.encode()).hexdigest()
