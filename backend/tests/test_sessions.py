import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from pydantic import ValidationError

from app.database import Base
from app.models import Project, Service, Target
from app.schemas import InteractiveSessionIn, ManualTerminalIn
from types import SimpleNamespace

import app.modules.sessions.router as sessions_router
from app.modules.sessions.router import (
    create_interactive_session, create_manual_terminal, responder_captures,
)


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
    assert row.command == "sudo responder -I tun0 -v"


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


def test_responder_captures_reads_this_targets_log_and_dedupes_repeat_hashes(
        tmp_path, monkeypatch):
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    monkeypatch.setattr(sessions_router, "RESPONDER_LOGS_DIR", logs_dir)
    (logs_dir / "SMB-NTLMv2-SSP-10.129.95.234.txt").write_text(
        "Administrator::RESPONDER:aaa:bbb:ccc\n"
        "Administrator::RESPONDER:ddd:eee:fff\n",  # CaptureMultipleHashFromSameHost repeat
        encoding="utf-8")
    (logs_dir / "FTP-Cleartext-ClearText-10.129.95.234.txt").write_text(
        "bob:hunter2\n", encoding="utf-8")
    (logs_dir / "SMB-NTLMv2-SSP-10.129.1.1.txt").write_text(
        "svc::OTHERBOX:aaa:bbb:ccc\n", encoding="utf-8")  # a different target — must not appear
    db = database()
    project = Project(name="Lab", description="")
    db.add(project); db.flush()
    box = Target(project_id=project.id, name="Box", ip="10.129.95.234")
    db.add(box); db.commit()

    results = responder_captures(box.id, db)

    assert len(results) == 2
    smb = next(r for r in results if r["label"] == "SMB-NTLMv2-SSP-10.129.95.234")
    assert smb["username"] == "Administrator"
    assert smb["cleartext"] is False
    assert smb["value"] == "Administrator::RESPONDER:aaa:bbb:ccc"
    ftp = next(r for r in results if r["cleartext"] is True)
    assert ftp["username"] == "bob"
    assert ftp["value"] == "hunter2"


def test_responder_captures_is_empty_when_nothing_was_captured_for_this_target(
        tmp_path, monkeypatch):
    monkeypatch.setattr(sessions_router, "RESPONDER_LOGS_DIR", tmp_path / "missing")
    db = database()
    project = Project(name="Lab", description="")
    db.add(project); db.flush()
    box = Target(project_id=project.id, name="Box", ip="10.129.95.234")
    db.add(box); db.commit()

    assert responder_captures(box.id, db) == []


def test_manual_terminal_rejects_a_command_with_an_inline_secret_flag():
    with pytest.raises(ValidationError):
        ManualTerminalIn(target_id=1, service_id=1,
                         command="evil-winrm -i 10.10.10.60 -u admin -p secret")
    with pytest.raises(ValidationError):
        ManualTerminalIn(target_id=1, service_id=1,
                         command="evil-winrm -i 10.10.10.60 -u admin -H aad3b435")


def test_manual_terminal_defaults_to_a_bare_shell_when_no_command_is_given(
        tmp_path, monkeypatch):
    db = database()
    box = target(db, tmp_path, monkeypatch)
    service = Service(target_id=box.id, port=5985, protocol="tcp", state="open",
                       name="http", product="", version="", extra_info="", scripts="{}",
                       notes="", tags="[]")
    db.add(service); db.commit()

    row = create_manual_terminal(
        ManualTerminalIn(target_id=box.id, service_id=service.id), db=db)

    assert row.command == "/bin/bash --noprofile --norc"


def test_manual_terminal_runs_the_given_safe_command_for_a_desktop_launch(
        tmp_path, monkeypatch):
    # evil-winrm without -p prompts "Enter Password:" itself once the
    # terminal opens, so this is the one command a desktop launch is safe
    # to run directly — no secret ever reaches this row or its argv.
    db = database()
    box = target(db, tmp_path, monkeypatch)
    service = Service(target_id=box.id, port=5985, protocol="tcp", state="open",
                       name="http", product="", version="", extra_info="", scripts="{}",
                       notes="", tags="[]")
    db.add(service); db.commit()
    monkeypatch.setattr(sessions_router.shutil, "which", lambda _: "/usr/bin/evil-winrm")

    row = create_manual_terminal(ManualTerminalIn(
        target_id=box.id, service_id=service.id,
        command="evil-winrm -i 10.10.10.60 -u admin"), db=db)

    assert row.command == "evil-winrm -i 10.10.10.60 -u admin"


def test_manual_terminal_rejects_an_uninstalled_command(tmp_path, monkeypatch):
    db = database()
    box = target(db, tmp_path, monkeypatch)
    service = Service(target_id=box.id, port=5985, protocol="tcp", state="open",
                       name="http", product="", version="", extra_info="", scripts="{}",
                       notes="", tags="[]")
    db.add(service); db.commit()
    monkeypatch.setattr(sessions_router.shutil, "which", lambda _: None)

    with pytest.raises(HTTPException) as exc:
        create_manual_terminal(ManualTerminalIn(
            target_id=box.id, service_id=service.id, command="totally-not-a-tool -x"), db=db)
    assert exc.value.status_code == 409
