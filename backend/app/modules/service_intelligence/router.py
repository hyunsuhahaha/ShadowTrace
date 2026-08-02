from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...database import get_db
from ...models import (
    Evidence, Execution, ExploitResearch, Finding, Project, Report,
    RunbookInstance, RunbookStepExecution, RunbookStepInstance,
    RunbookTemplate, RunbookTemplateVersion, Service, Target,
)
from ...time import utcnow
from ..runbooks.engine import TERMINAL_STATUSES, recompute
from ..runbooks.support import (
    condition_met, event, instance_dict, instance_scope_current,
)
from .catalog import catalog


router = APIRouter(tags=["Service Intelligence"])


class AssessmentIn(BaseModel):
    execution_id: int


def need(db: Session, model, ident: int):
    row = db.get(model, ident)
    if not row:
        raise HTTPException(404, "Not found")
    return row


def _refs(step: RunbookStepInstance) -> list[str]:
    try:
        value = json.loads(step.command_refs or "[]")
        return [str(item) for item in value] if isinstance(value, list) else []
    except json.JSONDecodeError:
        return []


def _apply_assessment(db: Session, instance: RunbookInstance,
                      step: RunbookStepInstance, execution: Execution,
                      steps: list[RunbookStepInstance], *, automatic: bool) -> bool:
    assessment = catalog.assess(execution)
    current = json.loads(step.assessment or "{}")
    if int(current.get("execution_id") or 0) >= execution.id:
        return False
    next_tokens = set(assessment.get("next", []))
    assessment["next_recommendations"] = []
    for candidate in steps:
        guidance = json.loads(candidate.guidance or "{}")
        if (guidance.get("stage_id") in next_tokens
                or guidance.get("phase") in next_tokens):
            assessment["next_recommendations"].append({
                "step_id": candidate.id, "position": candidate.position,
                "title": candidate.title,
            })
    if not db.get(RunbookStepExecution, {
            "step_id": step.id, "execution_id": execution.id}):
        db.add(RunbookStepExecution(step_id=step.id, execution_id=execution.id))
    step.assessment = json.dumps(assessment, ensure_ascii=False)
    step.outcome = assessment["outcome"]
    step.attempts += 1
    step.last_error = (assessment.get("summary", "")
                       if assessment["outcome"] == "error" else "")
    if step.status == "not_started":
        step.status = "attempted"
        step.started_at = step.started_at or utcnow()
    step.updated_at = utcnow()
    instance.updated_at = utcnow()
    event(db, instance.id,
          "execution_auto_linked" if automatic else "execution_assessed",
          step.id, {"execution_id": execution.id,
                    "outcome": assessment["outcome"],
                    "facts": len(assessment.get("facts", []))})
    return True


def sync_instance_executions(db: Session, instance: RunbookInstance,
                             steps: list[RunbookStepInstance] | None = None) -> bool:
    """Attach the newest matching service execution to untouched runbook steps."""
    if instance.service_id is None:
        return False
    steps = steps or db.scalars(select(RunbookStepInstance).where(
        RunbookStepInstance.instance_id == instance.id).order_by(
        RunbookStepInstance.position)).all()
    executions = db.scalars(select(Execution).where(
        Execution.target_id == instance.target_id,
        Execution.service_id == instance.service_id).order_by(
        Execution.id.desc())).all()
    newest: dict[str, Execution] = {}
    for execution in executions:
        newest.setdefault(execution.template_id, execution)
    changed = False
    for step in steps:
        candidates = [newest[ref] for ref in _refs(step) if ref in newest]
        if not candidates:
            continue
        execution = max(candidates, key=lambda item: item.id)
        current = json.loads(step.assessment or "{}")
        manually_set = (step.status in {"completed", "skipped", "not_applicable"}
                        and not current.get("execution_id"))
        if manually_set:
            continue
        changed |= _apply_assessment(
            db, instance, step, execution, steps, automatic=True)
    if changed:
        recompute(db, instance, steps, condition_met)
    return changed


def sync_execution_to_runbooks(db: Session, execution: Execution) -> int:
    """Propagate a completed command to matching applied runbook instances."""
    instances = db.scalars(select(RunbookInstance).where(
        RunbookInstance.target_id == execution.target_id,
        RunbookInstance.service_id == execution.service_id)).all()
    updated = 0
    for instance in instances:
        steps = db.scalars(select(RunbookStepInstance).where(
            RunbookStepInstance.instance_id == instance.id).order_by(
            RunbookStepInstance.position)).all()
        for step in steps:
            if execution.template_id not in _refs(step):
                continue
            current = json.loads(step.assessment or "{}")
            manually_set = (step.status in {"completed", "skipped", "not_applicable"}
                            and not current.get("execution_id"))
            if not manually_set and _apply_assessment(
                    db, instance, step, execution, steps, automatic=True):
                updated += 1
        recompute(db, instance, steps, condition_met)
    return updated


def _runbooks(db: Session, service: Service, keys: list[str]) -> list[dict]:
    rows = []
    for key in keys:
        template = db.scalar(select(RunbookTemplate).where(
            RunbookTemplate.builtin_key == key, RunbookTemplate.archived.is_(False)))
        if not template:
            continue
        version = db.scalar(select(RunbookTemplateVersion).where(
            RunbookTemplateVersion.template_id == template.id).order_by(
            RunbookTemplateVersion.version.desc()))
        if not version:
            continue
        applied = db.scalar(select(RunbookInstance.id).where(
            RunbookInstance.target_id == service.target_id,
            RunbookInstance.service_id == service.id,
            RunbookInstance.version_id == version.id))
        rows.append({
            "key": key, "name": template.name, "description": template.description,
            "version": version.version, "version_id": version.id,
            "applied": bool(applied), "instance_id": applied,
        })
    return rows


def _resolved_stage_ids(db: Session, service: Service) -> set[str]:
    """Stage ids the user has already resolved via a matching Runbook step.

    Stages without a command (e.g. cross-referencing Exploit Research) can
    never be marked complete by execution output alone; the Runbook step is
    where that manual judgement is actually recorded.
    """
    steps = db.scalars(select(RunbookStepInstance).join(
        RunbookInstance, RunbookStepInstance.instance_id == RunbookInstance.id).where(
        RunbookInstance.target_id == service.target_id,
        RunbookInstance.service_id == service.id)).all()
    resolved: set[str] = set()
    for step in steps:
        if step.status not in TERMINAL_STATUSES:
            continue
        guidance = json.loads(step.guidance or "{}")
        for token in (guidance.get("stage_id"), guidance.get("phase")):
            if token:
                resolved.add(token)
    return resolved


@router.get("/api/services/{service_id}/intelligence")
def service_intelligence(service_id: int, db: Session = Depends(get_db)):
    service = need(db, Service, service_id)
    target = need(db, Target, service.target_id)
    project = need(db, Project, target.project_id)
    related = db.scalars(select(Service).where(
        Service.target_id == target.id, Service.id != service.id)).all()
    executions = db.scalars(select(Execution).where(
        Execution.target_id == target.id, Execution.service_id == service.id).order_by(
        Execution.started_at.desc())).all()
    result = catalog.build(service, related, executions, _resolved_stage_ids(db, service))
    result["service_id"] = service.id
    result["target_id"] = target.id
    result["project_id"] = project.id
    result["runbooks"] = _runbooks(db, service, result.pop("runbook_keys"))
    result["integration_counts"] = {
        "evidence": db.scalar(select(func.count(Evidence.id)).where(
            Evidence.project_id == project.id, Evidence.service_id == service.id)) or 0,
        "finding": db.scalar(select(func.count(Finding.id)).where(
            Finding.project_id == project.id, Finding.service_id == service.id)) or 0,
        "exploit-research": db.scalar(select(func.count(ExploitResearch.id)).where(
            ExploitResearch.project_id == project.id, ExploitResearch.service_id == service.id)) or 0,
        "reports": db.scalar(select(func.count(Report.id)).where(
            Report.project_id == project.id)) or 0,
    }
    return result


@router.get("/api/executions/{execution_id}/intelligence-assessment")
def execution_assessment(execution_id: int, db: Session = Depends(get_db)):
    return catalog.assess(need(db, Execution, execution_id))


@router.post("/api/runbooks/steps/{step_id}/assess-execution")
def assess_step_execution(step_id: int, body: AssessmentIn,
                          db: Session = Depends(get_db)):
    step = need(db, RunbookStepInstance, step_id)
    instance = need(db, RunbookInstance, step.instance_id)
    if not instance_scope_current(db, instance):
        raise HTTPException(410, "Runbook scope belongs to a deleted project")
    execution = need(db, Execution, body.execution_id)
    if execution.target_id != instance.target_id:
        raise HTTPException(400, "Execution belongs to another target")
    if instance.service_id is not None and execution.service_id != instance.service_id:
        raise HTTPException(400, "Execution belongs to another service")
    steps = db.scalars(select(RunbookStepInstance).where(
        RunbookStepInstance.instance_id == instance.id).order_by(
        RunbookStepInstance.position)).all()
    _apply_assessment(db, instance, step, execution, steps, automatic=False)
    recompute(db, instance, steps, condition_met)
    db.commit()
    return instance_dict(db, instance, True)
