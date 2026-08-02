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
    archive_template, clone_template, recommendations,
    target_recommendations, update_template,
)


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
