from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session
from ...database import get_db
from ...engagement import require_roe
from ...models import (
    AssessmentAsset, AssessmentAssetSubject, Credential, Evidence, Execution, Finding, HttpExchange,
    HttpRequest, InteractiveSession, RemoteExecution, RunbookInstance, Target,
    RunbookObservation, RunbookStepCredential, RunbookStepEvidence,
    RunbookStepExecution, RunbookStepHandoff, RunbookStepHttpExchange,
    RunbookStepInstance, RunbookStepRemoteExecution, RunbookStepSession,
    RunbookStepSubject,
)
from ...time import utcnow
from .engine import approval_required, recompute
from .support import (
    ACTIVATION_LOCKED, ApprovalIn, FindingIn, HandoffIn, LinkIn, ObservationIn,
    OUTCOMES, REASON_REQUIRED, STATUSES, StepUpdate, condition_met, event,
    instance_dict, link_scope, need, observations, seconds_since,
)

router = APIRouter(prefix="/api/runbooks", tags=["Runbooks"])


@router.get("/handoff-candidates")
def handoff_candidates(project_id: int, exclude_target_id: int,
                       db: Session = Depends(get_db)):
    rows = db.execute(select(RunbookStepInstance, RunbookInstance, Target).join(
        RunbookInstance, RunbookStepInstance.instance_id == RunbookInstance.id).join(
        Target, RunbookInstance.target_id == Target.id).where(
        RunbookInstance.project_id == project_id,
        RunbookInstance.target_id != exclude_target_id).order_by(
        RunbookInstance.id, RunbookStepInstance.position).limit(500)).all()
    return [{"step_id": step.id, "target_id": target.id,
             "target_name": target.name, "title": step.title}
            for step, _, target in rows]


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
    if instance.target_id is not None and body.status in {
            "in_progress", "completed", "attempted", "suspicious"}:
        from ...models import Target
        require_roe(db, instance.project_id, "runbook",
                    target=need(db, Target, instance.target_id))
    if instance.asset_id is not None and body.status in {
            "in_progress", "completed", "attempted", "suspicious"}:
        asset = need(db, AssessmentAsset, instance.asset_id)
        if asset.scope_status != "in_scope":
            raise HTTPException(409, "Asset must be marked in scope before assessment")
        require_roe(db, instance.project_id, "runbook", asset=asset)
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
    if instance.asset_id is not None and evidence.asset_id != instance.asset_id:
        raise HTTPException(400, "Evidence belongs to another asset")
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


@router.post("/steps/{ident}/http-exchanges", status_code=201)
def attach_http_exchange(ident: int, body: LinkIn,
                         db: Session = Depends(get_db)):
    step, instance = link_scope(db, ident)
    exchange = need(db, HttpExchange, body.resource_id)
    request = need(db, HttpRequest, exchange.request_id)
    if request.project_id != instance.project_id or request.target_id != instance.target_id:
        raise HTTPException(400, "HTTP exchange belongs to another Runbook target")
    if not db.get(RunbookStepHttpExchange, (step.id, exchange.id)):
        db.add(RunbookStepHttpExchange(step_id=step.id, exchange_id=exchange.id))
        event(db, instance.id, "http_exchange_attached", step.id,
              {"exchange_id": exchange.id})
        db.commit()
    return instance_dict(db, instance, True)


@router.post("/steps/{ident}/remote-executions", status_code=201)
def attach_remote_execution(ident: int, body: LinkIn,
                            db: Session = Depends(get_db)):
    step, instance = link_scope(db, ident)
    run = need(db, RemoteExecution, body.resource_id)
    if run.project_id != instance.project_id or run.target_id != instance.target_id:
        raise HTTPException(400, "Remote execution belongs to another Runbook target")
    if not db.get(RunbookStepRemoteExecution, (step.id, run.id)):
        db.add(RunbookStepRemoteExecution(step_id=step.id, remote_execution_id=run.id))
        event(db, instance.id, "remote_execution_attached", step.id,
              {"remote_execution_id": run.id})
        db.commit()
    return instance_dict(db, instance, True)


@router.post("/steps/{ident}/sessions", status_code=201)
def attach_session(ident: int, body: LinkIn, db: Session = Depends(get_db)):
    step, instance = link_scope(db, ident)
    session = need(db, InteractiveSession, body.resource_id)
    from ...models import Target
    target = need(db, Target, session.target_id)
    if target.project_id != instance.project_id or session.target_id != instance.target_id:
        raise HTTPException(400, "Session belongs to another Runbook target")
    if not db.get(RunbookStepSession, (step.id, session.id)):
        db.add(RunbookStepSession(step_id=step.id, session_id=session.id))
        event(db, instance.id, "session_attached", step.id,
              {"session_id": session.id})
        db.commit()
    return instance_dict(db, instance, True)


@router.post("/steps/{ident}/subjects", status_code=201)
def attach_subject(ident: int, body: LinkIn, db: Session = Depends(get_db)):
    step, instance = link_scope(db, ident)
    subject = need(db, AssessmentAssetSubject, body.resource_id)
    if instance.asset_id is None or subject.asset_id != instance.asset_id:
        raise HTTPException(400, "Subject belongs to another Runbook asset")
    asset = need(db, AssessmentAsset, instance.asset_id)
    if asset.scope_status != "in_scope":
        raise HTTPException(409, "Runbook asset must be in scope before assessment")
    if subject.scope_status != "in_scope":
        raise HTTPException(409, "Subject must be in scope before assessment")
    if not db.get(RunbookStepSubject, (step.id, subject.id)):
        db.add(RunbookStepSubject(step_id=step.id, subject_id=subject.id))
        event(db, instance.id, "subject_attached", step.id,
              {"subject_id": subject.id})
        db.commit()
    return instance_dict(db, instance, True)


@router.post("/steps/{ident}/handoffs", status_code=201)
def create_handoff(ident: int, body: HandoffIn, db: Session = Depends(get_db)):
    source, source_instance = link_scope(db, ident)
    destination, destination_instance = link_scope(db, body.to_step_id)
    run = need(db, RemoteExecution, body.remote_execution_id)
    if source_instance.project_id != destination_instance.project_id or source.id == destination.id:
        raise HTTPException(400, "Handoff must stay in one project and use distinct steps")
    if (source_instance.target_id is None or destination_instance.target_id is None or
            source_instance.target_id == destination_instance.target_id or
            run.project_id != source_instance.project_id or
            run.target_id != destination_instance.target_id):
        raise HTTPException(400, "Handoff must connect distinct Target Runbooks")
    if run.status != "completed" or run.exit_code != 0 or not run.credential_id or not run.evidence_id:
        raise HTTPException(409, "Handoff requires completed credential access and Evidence")
    credential = need(db, Credential, run.credential_id)
    evidence = need(db, Evidence, run.evidence_id)
    if credential.project_id != source_instance.project_id or evidence.project_id != source_instance.project_id:
        raise HTTPException(400, "Handoff provenance belongs to another project")
    if len(evidence.sha256 or "") != 64:
        raise HTTPException(409, "Handoff Evidence must have a SHA-256 digest")
    if not body.reason.strip():
        raise HTTPException(400, "Handoff reason is required")
    if credential.target_id is not None and credential.target_id != source_instance.target_id:
        raise HTTPException(400, "Credential origin does not match source Target")
    if not db.get(RunbookStepCredential, (source.id, credential.id)):
        raise HTTPException(409, "Link the used Credential to the source step first")
    if not db.get(RunbookStepRemoteExecution, (destination.id, run.id)):
        raise HTTPException(409, "Link the RemoteExecution to the destination step first")
    row = db.get(RunbookStepHandoff, (source.id, destination.id))
    if row is None:
        row = RunbookStepHandoff(from_step_id=source.id, to_step_id=destination.id,
                                 remote_execution_id=run.id, evidence_id=evidence.id,
                                 reason=body.reason.strip())
        db.add(row)
        event(db, source_instance.id, "handoff_created", source.id,
              {"to_step_id": destination.id, "remote_execution_id": run.id,
               "evidence_id": evidence.id})
        db.commit()
    elif row.remote_execution_id != run.id:
        raise HTTPException(409, "Handoff already uses another RemoteExecution")
    return instance_dict(db, source_instance, True)


@router.post("/steps/{ident}/observations", status_code=201)
def create_observation(ident: int, body: ObservationIn,
                       db: Session = Depends(get_db)):
    step, instance = link_scope(db, ident)
    if body.evidence_id:
        evidence = need(db, Evidence, body.evidence_id)
        if evidence.project_id != instance.project_id:
            raise HTTPException(400, "Evidence belongs to another project")
        if instance.asset_id is not None and evidence.asset_id != instance.asset_id:
            raise HTTPException(400, "Evidence belongs to another asset")
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
        asset_id=instance.asset_id,
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
