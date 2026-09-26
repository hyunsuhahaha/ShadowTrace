from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.database import Base
from app.models import (
    Project, RunbookStepTemplate, RunbookTemplate, RunbookTemplateVersion,
    Service, Target,
)
from app.modules.runbooks.builtins import ensure_builtin_runbooks
from app.modules.runbooks.support import CloneIn, TemplateIn
from app.modules.runbooks.workflow_router import (
    apply, archive_template, clone_template, recommendations,
    target_recommendations, update_template,
)
from app.modules.runbooks.support import ApplyIn, StepUpdate
from app.modules.runbooks.execution_router import update_step
from app.modules.graph import service as graph_service
import json


def database() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def scope(db: Session):
    project = Project(name="Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.10")
    db.add(target); db.flush()
    service = Service(
        target_id=target.id, port=21, protocol="tcp", name="ftp")
    db.add(service); db.commit()
    return target, service


def test_builtin_catalog_installs_idempotently_and_recommends():
    db = database()
    target, service = scope(db)

    installed = ensure_builtin_runbooks(db)
    assert installed >= 18
    assert ensure_builtin_runbooks(db) == 0
    assert db.scalar(select(RunbookTemplate).where(
        RunbookTemplate.builtin_key == "ftp-baseline"))
    assert recommendations(service.id, db)[0]["template_name"] == "FTP 기본 열거"
    assert target_recommendations(target.id, db)[0]["template_name"] == "Target 기본 식별"

    for key in (
        "ftp-baseline", "http-baseline", "smb-baseline", "database-baseline",
        "unknown-service-baseline", "msrpc-baseline",
    ):
        template = db.scalar(select(RunbookTemplate).where(
            RunbookTemplate.builtin_key == key))
        version = db.scalar(select(RunbookTemplateVersion).where(
            RunbookTemplateVersion.template_id == template.id).order_by(
                RunbookTemplateVersion.version.desc()))
        steps = db.scalars(select(RunbookStepTemplate).where(
            RunbookStepTemplate.version_id == version.id)).all()
        assert all(step.node_key for step in steps)
        assert any(step.transitions != "[]" for step in steps)

    smb = db.scalar(select(RunbookTemplate).where(
        RunbookTemplate.builtin_key == "smb-baseline"))
    smb_version = db.scalar(select(RunbookTemplateVersion).where(
        RunbookTemplateVersion.template_id == smb.id).order_by(
            RunbookTemplateVersion.version.desc()))
    smb_steps = db.scalars(select(RunbookStepTemplate).where(
        RunbookStepTemplate.version_id == smb_version.id)).all()
    credential = next(step for step in smb_steps
                      if step.node_key == "authenticated")
    assert credential.node_type == "approval"
    assert '"required": true' in credential.approval


def test_practitioner_workflows_project_all_review_branches_into_graph():
    db = database()
    target, service = scope(db)
    assert ensure_builtin_runbooks(db) == 30
    for key, expected in (("assessment-lifecycle", 9),
                          ("web-application-review", 14),
                          ("post-access-review", 7),
                          ("api-security-review", 12)):
        template = db.scalar(select(RunbookTemplate).where(
            RunbookTemplate.builtin_key == key))
        version = db.scalar(select(RunbookTemplateVersion).where(
            RunbookTemplateVersion.template_id == template.id))
        detail = apply(ApplyIn(version_id=version.id, target_id=target.id,
                               service_id=service.id if key in {
                                   "web-application-review", "api-security-review"}
                               else None), db)
        assert len(detail["steps"]) == expected
        assert len({step["node_key"] for step in detail["steps"]}) == expected
    graph_service.sync_from_project(db, target.project_id)
    nodes = db.query(graph_service.GraphNode).filter_by(
        project_id=target.project_id).all()
    steps = [node for node in nodes if node.source_ref and
             json.loads(node.source_ref).get("kind") == "runbook_step"]
    assert len(steps) == 42
    edges = db.query(graph_service.GraphEdge).filter_by(relation="precedes").all()
    assert len(edges) >= 50
    assert graph_service.get_attack_paths(db, target.project_id) == []


def test_web_review_opens_all_categories_and_waits_for_every_decision():
    db = database()
    target, service = scope(db)
    ensure_builtin_runbooks(db)
    template = db.scalar(select(RunbookTemplate).where(
        RunbookTemplate.builtin_key == "web-application-review"))
    version = db.scalar(select(RunbookTemplateVersion).where(
        RunbookTemplateVersion.template_id == template.id))
    detail = apply(ApplyIn(version_id=version.id, target_id=target.id,
                           service_id=service.id), db)
    by_key = {step["node_key"]: step for step in detail["steps"]}
    assert by_key["map"]["activation"] == "ready"
    assert all(by_key[key]["activation"] == "waiting" for key in (
        "info", "config", "identity", "authn", "authz", "session",
        "input", "error", "crypto", "logic", "client", "api"))

    detail = update_step(by_key["map"]["id"], StepUpdate(
        status="completed", outcome="confirmed"), db)
    by_key = {step["node_key"]: step for step in detail["steps"]}
    categories = [key for key in by_key if key not in {"map", "review"}]
    assert len(categories) == 12
    assert all(by_key[key]["activation"] == "ready" for key in categories)
    assert by_key["review"]["activation"] == "waiting"

    for key in categories:
        detail = update_step(by_key[key]["id"], StepUpdate(
            status="completed", outcome="not_found"), db)
    by_key = {step["node_key"]: step for step in detail["steps"]}
    assert by_key["review"]["activation"] == "ready"
    assert len(by_key["review"]["decision_trace"][0]["sources"]) == 12

    graph_service.sync_from_project(db, target.project_id)
    assert graph_service.get_attack_paths(db, target.project_id) == []


def test_builtin_is_read_only_but_clone_is_user_owned():
    db = database()
    scope(db)
    ensure_builtin_runbooks(db)
    builtin = db.scalar(select(RunbookTemplate).where(
        RunbookTemplate.builtin_key == "ftp-baseline"))

    for action in (
        lambda: update_template(builtin.id, TemplateIn(name="changed"), db),
        lambda: archive_template(builtin.id, db),
    ):
        try:
            action()
        except HTTPException as exc:
            assert exc.status_code == 409
        else:
            raise AssertionError("built-in template mutation must be rejected")

    cloned = clone_template(builtin.id, CloneIn(name="내 FTP 절차"), db)
    assert cloned["template"]["origin"] == "user"
    assert cloned["template"]["builtin_key"] is None
