from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session
from ...database import get_db
from ...models import (
    Credential, Evidence, Execution, Finding, RunbookInstance,
    RunbookObservation, RunbookStepCredential, RunbookStepEvidence,
    RunbookStepExecution, RunbookStepInstance,
)
from ...time import utcnow
from .engine import approval_required, recompute
from .support import (
    ACTIVATION_LOCKED, ApprovalIn, FindingIn, LinkIn, ObservationIn,
    OUTCOMES, REASON_REQUIRED, STATUSES, StepUpdate, condition_met, event,
    instance_dict, link_scope, need, observations, seconds_since,
)

router = APIRouter(prefix="/api/runbooks", tags=["Runbooks"])


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
