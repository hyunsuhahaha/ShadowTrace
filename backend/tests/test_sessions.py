import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.database import Base
from app.models import Project, Service, Target
from app.schemas import InteractiveSessionIn
from types import SimpleNamespace

import app.modules.sessions.router as sessions_router
from app.modules.sessions.router import create_interactive_session


def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def target(db, tmp_path, monkeypatch):
    monkeypatch.setattr(sessions_router, "WORKSPACE_DIR", tmp_path)
    project = Project(name="Lab", description="")
    db.add(project); db.flush()
    row = Target(project_id=project.id, name="Box", ip="10.10.10.60")
    db.add(row); db.commit()
    return row


def test_responder_is_blocked_while_an_instance_is_already_running(tmp_path, monkeypatch):
    db = database()
    box = target(db, tmp_path, monkeypatch)
    monkeypatch.setattr(sessions_router.subprocess, "run", lambda *a, **k:
        SimpleNamespace(returncode=0, stdout="144448\n"))

    with pytest.raises(HTTPException) as exc:
        create_interactive_session(InteractiveSessionIn(
            target_id=box.id, template_id="responder-listener",
            variables={"interface": "tun0"}), db=db)

    assert exc.value.status_code == 409
    assert "144448" in exc.value.detail


def test_responder_is_allowed_when_nothing_is_running(tmp_path, monkeypatch):
    db = database()
    box = target(db, tmp_path, monkeypatch)
    monkeypatch.setattr(sessions_router.subprocess, "run", lambda *a, **k:
        SimpleNamespace(returncode=1, stdout=""))

    row = create_interactive_session(InteractiveSessionIn(
        target_id=box.id, template_id="responder-listener",
        variables={"interface": "tun0"}), db=db)

    assert row.template_id == "responder-listener"
    assert row.command == "sudo responder -I tun0"


def test_the_running_process_check_only_applies_to_responder(tmp_path, monkeypatch):
    db = database()
    box = target(db, tmp_path, monkeypatch)
    service = Service(target_id=box.id, port=21, protocol="tcp", state="open",
                       name="ftp", product="", version="", extra_info="", scripts="{}",
                       notes="", tags="[]")
    db.add(service); db.commit()
    called = {"count": 0}

    def fake_run(*args, **kwargs):
        called["count"] += 1
        return SimpleNamespace(returncode=0, stdout="9999\n")

    monkeypatch.setattr(sessions_router.subprocess, "run", fake_run)

    row = create_interactive_session(InteractiveSessionIn(
        target_id=box.id, service_id=service.id, template_id="ftp-client",
        variables={}), db=db)

    assert row.template_id == "ftp-client"
    assert called["count"] == 0
