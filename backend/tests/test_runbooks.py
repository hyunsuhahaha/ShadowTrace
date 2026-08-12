from datetime import timedelta
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.database import Base
from app.models import Evidence, Execution, Project, Service, Target
from app.modules.runbooks.support import (
    ApplyIn, ApprovalIn, CloneIn, CredentialIn, DismissIn, FindingIn, FindingUpdate,
    ImportIn, LinkIn, ObservationIn, PublishIn, StepIn, StepUpdate, TemplateIn,
)
from app.modules.runbooks.workflow_router import (
    apply, archive_template, clone_template,
    create_template, dismiss_recommendation,
    export_findings, export_template, import_template, instance, instances,
    publish, recommendations, summary,
    recompute_instance,
    update_finding, update_template,
)
from app.modules.runbooks.execution_router import (
    attach_credential, attach_evidence, attach_execution, create_observation,
    promote_observation, step_timer, decide_approval, update_step,
)
from app.modules.runbooks.credentials_router import (
    create_credential, credential_recommendations,
)
from app.time import utcnow


def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def scope(db: Session):
    project = Project(name="Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.10")
    db.add(target); db.flush()
    service = Service(target_id=target.id, port=445, name="microsoft-ds")
    db.add(service); db.commit()
    return project, target, service


def test_published_runbook_is_snapshotted_and_progress_is_manual():
    db = database()
    _, target, service = scope(db)
    template = create_template(TemplateIn(
        name="SMB basics", service_names=["microsoft-ds"], ports=[445]), db)
    version = publish(template["id"], PublishIn(steps=[
        StepIn(title="Anonymous access", command_refs=["smb-null-session"],
               expected_observations=["share list"]),
        StepIn(title="Review permissions"),
    ]), db)
    update_template(template["id"], TemplateIn(
        name="Renamed later", service_names=["smb"]), db)

    instance = apply(ApplyIn(
        version_id=version["id"], target_id=target.id, service_id=service.id), db)
    assert instance["template_name"] == "SMB basics"
    assert [step["title"] for step in instance["steps"]] == [
        "Anonymous access", "Review permissions"]
    assert instance["progress"] == {"completed": 0, "total": 2, "percent": 0}

    changed = update_step(instance["steps"][0]["id"], StepUpdate(
        status="completed", result="Anonymous denied"), db)
    assert changed["progress"] == {"completed": 1, "total": 2, "percent": 50}

    with_ignored = update_step(instance["steps"][1]["id"], StepUpdate(
        status="not_applicable", status_reason="No shares"), db)
    assert with_ignored["progress"] == {"completed": 1, "total": 1, "percent": 100}


def test_links_validate_scope_and_recommendations_report_apply_state():
    db = database()
    project, target, service = scope(db)
    template = create_template(TemplateIn(
        name="SMB basics", service_names=["microsoft-ds"]), db)
    version = publish(template["id"], PublishIn(steps=[
        StepIn(title="Check SMB")]), db)

    recommendation = recommendations(service.id, db)[0]
    assert recommendation["version_id"] == version["id"]
    assert recommendation["applied"] is False

    instance = apply(ApplyIn(
        version_id=version["id"], target_id=target.id, service_id=service.id), db)
    step_id = instance["steps"][0]["id"]
    evidence = Evidence(
        project_id=project.id, target_id=target.id, service_id=service.id,
        title="Output", kind="markdown")
    execution = Execution(
        target_id=target.id, service_id=service.id, template_id="smb-null-session",
        command="smbclient", cwd="/tmp", status="completed")
    db.add_all([evidence, execution]); db.commit()
    linked = attach_evidence(step_id, LinkIn(resource_id=evidence.id), db)
    linked = attach_execution(step_id, LinkIn(resource_id=execution.id), db)
    assert linked["steps"][0]["evidence_ids"] == [evidence.id]
    assert linked["steps"][0]["execution_ids"] == [execution.id]
    assert recommendations(service.id, db)[0]["applied"] is True
    # Repeated ensure/apply calls return the same investigation.
    repeated = apply(ApplyIn(
        version_id=version["id"], target_id=target.id, service_id=service.id), db)
    assert repeated["id"] == instance["id"]


def test_runbook_recommendations_prioritize_detected_service_over_port():
    db = database()
    _, target, smb = scope(db)
    wrong = create_template(TemplateIn(
        name="Wrong port gallery entry", service_names=["msrpc"], ports=[445]), db)
    publish(wrong["id"], PublishIn(steps=[StepIn(title="RPC only")]), db)
    right = create_template(TemplateIn(
        name="SMB investigation", service_names=["microsoft-ds"], ports=[445]), db)
    publish(right["id"], PublishIn(steps=[StepIn(title="SMB only")]), db)

    rows = recommendations(smb.id, db)
    assert [row["template_name"] for row in rows] == ["SMB investigation"]
    assert rows[0]["reasons"] == ["detected-service:microsoft-ds"]

    unidentified = Service(target_id=target.id, port=445, name="unknown")
    db.add(unidentified); db.commit()
    fallback = {row["template_name"] for row in recommendations(unidentified.id, db)}
    assert fallback == {"Wrong port gallery entry", "SMB investigation"}


def test_skipped_and_blocked_require_a_reason():
    db = database()
    _, target, _ = scope(db)
    template = create_template(TemplateIn(name="Target checks"), db)
    version = publish(template["id"], PublishIn(
        steps=[StepIn(title="Check")]), db)
    instance = apply(ApplyIn(version_id=version["id"], target_id=target.id), db)
    try:
        update_step(instance["steps"][0]["id"], StepUpdate(status="blocked"), db)
    except HTTPException as exc:
        assert exc.status_code == 400
    else:
        raise AssertionError("blocked without a reason must fail")


def test_instances_quarantine_rows_from_an_older_project_generation():
    db = database()
    project, target, service = scope(db)
    template = create_template(TemplateIn(name="FTP basics"), db)
    version = publish(template["id"], PublishIn(
        steps=[StepIn(title="Anonymous access")]), db)
    run = apply(ApplyIn(
        version_id=version["id"], target_id=target.id,
        service_id=service.id), db)
    assert [row["id"] for row in instances(target_id=target.id, db=db)] == [run["id"]]

    project.created_at = project.created_at + timedelta(days=1)
    db.commit()

    assert instances(target_id=target.id, db=db) == []
    try:
        instance(run["id"], db)
    except HTTPException as exc:
        assert exc.status_code == 410
    else:
        raise AssertionError("stale runbook scope must not be returned")


def test_credential_listing_exposes_the_structured_source_execution_pointer():
    db = database()
    project, target, service = scope(db)
    credential = create_credential(CredentialIn(
        project_id=project.id, target_id=target.id, service_id=service.id,
        username="student", secret_hint="manually recorded"), db)
    assert credential["source_execution_kind"] is None
    assert credential["source_execution_id"] is None


def test_credential_condition_and_recheck_recommendation():
    db = database()
    project, target, service = scope(db)
    second_target = Target(project_id=project.id, name="Other", ip="10.10.10.11")
    db.add(second_target); db.flush()
    second_service = Service(
        target_id=second_target.id, port=445, name="microsoft-ds")
    db.add(second_service); db.commit()
    template = create_template(TemplateIn(name="Conditional SMB"), db)
    version = publish(template["id"], PublishIn(steps=[
        StepIn(title="Reuse credential", condition={
            "kind": "credential_exists", "service_name": "microsoft-ds"}),
    ]), db)
    run = apply(ApplyIn(
        version_id=version["id"], target_id=target.id, service_id=service.id), db)
    assert run["steps"][0]["condition_met"] is False

    credential = create_credential(CredentialIn(
        project_id=project.id, target_id=target.id, service_id=service.id,
        username="student", secret_hint="ends in 42",
        service_names=["microsoft-ds"]), db)
    refreshed = instance(run["id"], db)
    assert refreshed["steps"][0]["condition_met"] is True
    assert {row["service_id"] for row in credential_recommendations(
        credential["id"], db)} == {service.id, second_service.id}
    linked = attach_credential(
        run["steps"][0]["id"], LinkIn(resource_id=credential["id"]), db)
    assert linked["steps"][0]["credential_ids"] == [credential["id"]]


def test_observation_promotion_keeps_finding_separate():
    db = database()
    _, target, service = scope(db)
    template = create_template(TemplateIn(name="Observe"), db)
    version = publish(template["id"], PublishIn(
        steps=[StepIn(title="Inspect")]), db)
    run = apply(ApplyIn(
        version_id=version["id"], target_id=target.id, service_id=service.id), db)
    observation = create_observation(
        run["steps"][0]["id"],
        ObservationIn(title="Guest access", detail="Read-only share exposed"), db)
    finding = promote_observation(
        observation["id"],
        FindingIn(title="Guest share exposure", description="Needs validation"), db)
    assert finding["status"] == "candidate"
    assert finding["observation_id"] == observation["id"]
    assert instance(run["id"], db)["steps"][0]["status"] == "not_started"


def test_template_export_import_and_project_summary():
    db = database()
    project, target, service = scope(db)
    template = create_template(TemplateIn(
        name="Portable", service_names=["microsoft-ds"]), db)
    version = publish(template["id"], PublishIn(
        steps=[StepIn(title="Check", condition={
            "kind": "service_exists", "service_name": "microsoft-ds"})]), db)
    exported = export_template(template["id"], db)
    imported = import_template(ImportIn(**exported), db)
    assert imported["version"]["steps"][0]["condition"]["kind"] == "service_exists"
    run = apply(ApplyIn(
        version_id=version["id"], target_id=target.id, service_id=service.id), db)
    update_step(run["steps"][0]["id"], StepUpdate(
        status="completed", result="Checked"), db)
    row = summary(project.id, db)[0]
    assert row["percent"] == 100
    assert row["completed"] == 1


def test_timer_clone_archive_and_dismissal_lifecycle():
    db = database()
    _, target, service = scope(db)
    template = create_template(TemplateIn(
        name="Operational", service_names=["microsoft-ds"]), db)
    version = publish(template["id"], PublishIn(
        steps=[StepIn(title="Timed")]), db)
    cloned = clone_template(
        template["id"], CloneIn(name="Operational copy"), db)
    assert cloned["version"]["steps"][0]["title"] == "Timed"
    assert archive_template(template["id"], db) == {"archived": True}

    run = apply(ApplyIn(
        version_id=version["id"], target_id=target.id, service_id=service.id), db)
    step_timer(run["steps"][0]["id"], "start", db)
    from app.models import RunbookStepInstance
    step = db.get(RunbookStepInstance, run["steps"][0]["id"])
    step.timer_started_at = utcnow() - timedelta(seconds=65)
    db.commit()
    stopped = step_timer(step.id, "stop", db)
    assert stopped["steps"][0]["elapsed_seconds"] >= 65

    # The archived source no longer recommends, while its clone does.
    recommendation = recommendations(service.id, db)[0]
    dismiss_recommendation(
        service.id, DismissIn(version_id=recommendation["version_id"]), db)
    hidden = recommendations(service.id, db)
    assert hidden and hidden[0]["dismissed"] is True
    service.version = "changed"
    db.commit()
    assert recommendations(service.id, db)


def test_finding_update_and_markdown_export():
    db = database()
    project, target, service = scope(db)
    template = create_template(TemplateIn(name="Finding flow"), db)
    version = publish(template["id"], PublishIn(
        steps=[StepIn(title="Observe")]), db)
    run = apply(ApplyIn(
        version_id=version["id"], target_id=target.id, service_id=service.id), db)
    observation = create_observation(
        run["steps"][0]["id"],
        ObservationIn(title="Share exposed", detail="Guest can read"), db)
    finding = promote_observation(
        observation["id"], FindingIn(
            title="Guest share", description="Initial"), db)
    updated = update_finding(finding["id"], FindingUpdate(
        title="Guest share exposure", description="Confirmed manually",
        status="confirmed"), db)
    assert updated["status"] == "confirmed"
    exported = export_findings(project.id, db)
    assert "Guest share exposure" in exported["markdown"]
    assert target.ip in exported["markdown"]


def test_branch_engine_activates_access_denied_path_and_excludes_other_branch():
    db = database()
    _, target, service = scope(db)
    template = create_template(TemplateIn(name="Branching SMB"), db)
    version = publish(template["id"], PublishIn(steps=[
        StepIn(title="Identify", node_key="identity", node_type="command",
               transitions=[{"when": {"outcome": "confirmed"},
                             "target": "anonymous"}]),
        StepIn(title="Anonymous", node_key="anonymous", node_type="command",
               transitions=[
                   {"when": {"outcome": "confirmed"}, "target": "permissions"},
                   {"when": {"outcome": "access_denied"}, "target": "authenticated"},
                   {"default": True, "target": "manual-review"},
               ]),
        StepIn(title="Permissions", node_key="permissions"),
        StepIn(title="Authenticated", node_key="authenticated",
               node_type="approval", approval={
                   "required": True, "reason": "Credential use"}),
        StepIn(title="Manual review", node_key="manual-review"),
    ]), db)
    run = apply(ApplyIn(
        version_id=version["id"], target_id=target.id, service_id=service.id), db)
    states = {step["node_key"]: step["activation"] for step in run["steps"]}
    assert states == {
        "identity": "ready", "anonymous": "waiting", "permissions": "waiting",
        "authenticated": "waiting", "manual-review": "waiting",
    }

    try:
        update_step(next(step["id"] for step in run["steps"]
                         if step["node_key"] == "authenticated"), StepUpdate(
            status="completed", outcome="confirmed"), db)
    except HTTPException as exc:
        assert exc.status_code == 409
    else:
        raise AssertionError("inactive branch must not run without override")

    run = update_step(run["steps"][0]["id"], StepUpdate(
        status="completed", outcome="confirmed"), db)
    anonymous = next(step for step in run["steps"]
                     if step["node_key"] == "anonymous")
    assert anonymous["activation"] == "ready"
    run = update_step(anonymous["id"], StepUpdate(
        status="attempted", outcome="access_denied",
        result="NT_STATUS_ACCESS_DENIED"), db)
    states = {step["node_key"]: step["activation"] for step in run["steps"]}
    assert states["authenticated"] == "awaiting_approval"
    assert states["permissions"] == "excluded"
    assert states["manual-review"] == "excluded"
    target_step = next(step for step in run["steps"]
                       if step["node_key"] == "authenticated")
    assert target_step["decision_trace"][0]["sources"] == ["anonymous"]
    approved = decide_approval(target_step["id"], ApprovalIn(
        decision="approved", reason="Lab credential approved", actor="student"), db)
    approved_step = next(step for step in approved["steps"]
                         if step["node_key"] == "authenticated")
    assert approved_step["activation"] == "ready"
    assert approved_step["approved_by"] == "student"


def test_branch_engine_retries_technical_failure_then_uses_recovery_path():
    from app.models import RunbookStepInstance
    db = database()
    _, target, service = scope(db)
    template = create_template(TemplateIn(name="Retry flow"), db)
    version = publish(template["id"], PublishIn(steps=[
        StepIn(title="Probe", node_key="probe", node_type="command",
               error_policy={"retry": {"max_attempts": 2}},
               transitions=[{"default": True, "target": "recovery"}]),
        StepIn(title="Recovery", node_key="recovery"),
    ]), db)
    run = apply(ApplyIn(
        version_id=version["id"], target_id=target.id, service_id=service.id), db)
    step = db.get(RunbookStepInstance, run["steps"][0]["id"])
    step.status = "attempted"; step.outcome = "error"; step.attempts = 1
    db.commit()
    first = recompute_instance(run["id"], db)
    assert first["steps"][0]["activation"] == "retry_ready"
    assert first["steps"][1]["activation"] == "waiting"
    step.attempts = 2
    db.commit()
    exhausted = recompute_instance(run["id"], db)
    assert exhausted["steps"][0]["activation"] == "failed_handled"
    assert exhausted["steps"][1]["activation"] == "ready"
    assert exhausted["steps"][0]["decision_trace"][0]["used_default"] is True


def test_graph_export_preserves_executable_transitions():
    db = database()
    _, _, _ = scope(db)
    template = create_template(TemplateIn(name="Portable graph"), db)
    publish(template["id"], PublishIn(steps=[
        StepIn(title="Start", node_key="start", node_type="decision",
               transitions=[{"default": True, "target": "end"}]),
        StepIn(title="End", node_key="end", node_type="end"),
    ]), db)
    exported = export_template(template["id"], db)
    assert exported["schema_version"] == 2
    assert exported["steps"][0]["transitions"][0]["target"] == "end"
