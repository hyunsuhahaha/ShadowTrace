import asyncio
import hashlib
import sys

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.database import Base
from app.models import Execution, Project, Service, Target
from app.schemas import ExecutionDeriveIn, ExecutionIn
from fastapi import HTTPException

import app.executor as executor_module
import app.modules.executions.router as executions_router
from app.modules.executions.router import (
    _output_path, delete_execution, derive_output, execute, execution_output_file,
)


def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def test_output_path_defaults_to_a_timestamped_template_name(tmp_path):
    path = _output_path(tmp_path, "", "ldap-anonymous-users")
    assert path.parent == tmp_path
    assert path.name.endswith("_ldap-anonymous-users.txt")


def test_output_path_uses_the_requested_filename(tmp_path):
    path = _output_path(tmp_path, "hello", "ldap-anonymous-users")
    assert path == tmp_path / "hello.txt"


def test_output_path_does_not_double_up_a_supplied_txt_extension(tmp_path):
    path = _output_path(tmp_path, "hello.txt", "ldap-anonymous-users")
    assert path == tmp_path / "hello.txt"


def test_output_path_sanitizes_unsafe_characters(tmp_path):
    path = _output_path(tmp_path, "../../etc/passwd", "ldap-anonymous-users")
    assert path.parent == tmp_path
    assert path.name == "etc_passwd.txt"


def test_output_path_avoids_overwriting_an_existing_file(tmp_path):
    (tmp_path / "hello.txt").write_text("previous run")
    path = _output_path(tmp_path, "hello", "ldap-anonymous-users")
    assert path == tmp_path / "hello-2.txt"
    path.write_text("second run")
    third = _output_path(tmp_path, "hello", "ldap-anonymous-users")
    assert third == tmp_path / "hello-3.txt"


def test_derive_output_writes_a_file_and_registers_evidence(tmp_path, monkeypatch):
    monkeypatch.setattr(executions_router, "WORKSPACE_DIR", tmp_path)
    db = database()
    project = Project(name="Forest", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="DC", ip="10.10.10.161")
    db.add(target); db.flush()
    execution = Execution(
        target_id=target.id, template_id="ldap-anonymous-users",
        command="nxc ldap 10.10.10.161 -u '' -p '' --users", cwd=".",
        status="completed",
        stdout="LDAP 10.10.10.161 389 FOREST sebastien\n"
               "LDAP 10.10.10.161 389 FOREST svc-alfresco\n")
    db.add(execution); db.commit()

    row = derive_output(execution.id, ExecutionDeriveIn(
        content="sebastien\nsvc-alfresco", filename="users"), db=db)

    assert row.kind == "command_output"
    assert row.source_type == "execution"
    assert row.source_id == execution.id
    assert row.original_name == "users.txt"
    saved = tmp_path / "projects" / "Forest" / "targets" / "10.10.10.161" / "outputs" / "users.txt"
    assert saved.is_file()
    assert saved.read_text() == "sebastien\nsvc-alfresco"
    assert row.file_path == str(saved)
    assert row.sha256 == hashlib.sha256(b"sebastien\nsvc-alfresco").hexdigest()


def test_derive_output_rejects_an_empty_filename():
    with pytest.raises(ValidationError):
        ExecutionDeriveIn(content="sebastien", filename="")


def test_execution_output_file_reads_a_file_the_command_wrote_itself(
        tmp_path, monkeypatch):
    monkeypatch.setattr(executions_router, "WORKSPACE_DIR", tmp_path)
    db = database()
    project = Project(name="Forest", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="DC", ip="10.10.10.161")
    db.add(target); db.flush()
    execution = Execution(
        target_id=target.id, template_id="ad-asreproast-impacket",
        command="impacket-GetNPUsers htb.local/ -usersfile users.txt",
        cwd=".", status="completed")
    db.add(execution); db.commit()
    output_dir = tmp_path / "projects" / "Forest" / "targets" / "10.10.10.161" / "outputs"
    output_dir.mkdir(parents=True)
    (output_dir / "asrep-hashes.txt").write_text(
        "$krb5asrep$23$svc-alfresco@HTB.LOCAL:deadbeef...\n")

    result = execution_output_file(execution.id, "asrep-hashes.txt", db=db)
    assert result["content"].startswith("$krb5asrep$23$svc-alfresco@HTB.LOCAL")


def test_execution_output_file_404s_for_a_missing_or_traversal_name(
        tmp_path, monkeypatch):
    monkeypatch.setattr(executions_router, "WORKSPACE_DIR", tmp_path)
    db = database()
    project = Project(name="Forest", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="DC", ip="10.10.10.161")
    db.add(target); db.flush()
    execution = Execution(
        target_id=target.id, template_id="ad-asreproast-impacket",
        command="impacket-GetNPUsers htb.local/ -usersfile users.txt",
        cwd=".", status="completed")
    db.add(execution); db.commit()

    with pytest.raises(HTTPException) as missing:
        execution_output_file(execution.id, "asrep-hashes.txt", db=db)
    assert missing.value.status_code == 404

    (tmp_path / "secret.txt").write_text("outside the target folder")
    with pytest.raises(HTTPException) as traversal:
        execution_output_file(execution.id, "../../secret.txt", db=db)
    assert traversal.value.status_code == 404


def test_delete_execution_removes_the_row_and_its_output_file(tmp_path):
    db = database()
    project = Project(name="Forest", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="DC", ip="10.10.10.161")
    db.add(target); db.flush()
    output = tmp_path / "smb-enum.txt"
    output.write_text("results")
    execution = Execution(
        target_id=target.id, template_id="smb-enum", command="enum4linux",
        cwd=".", status="completed", output_path=str(output))
    db.add(execution); db.commit()

    delete_execution(execution.id, db=db)

    assert db.get(Execution, execution.id) is None
    assert not output.exists()


def test_delete_execution_blocks_a_still_running_command():
    db = database()
    project = Project(name="Forest", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="DC", ip="10.10.10.161")
    db.add(target); db.flush()
    execution = Execution(
        target_id=target.id, template_id="smb-enum", command="enum4linux",
        cwd=".", status="running")
    db.add(execution); db.commit()

    with pytest.raises(HTTPException) as exc:
        delete_execution(execution.id, db=db)
    assert exc.value.status_code == 409
    assert db.get(Execution, execution.id) is not None


def test_execute_prefers_the_confirmed_hostname_for_http_templates_only(
        tmp_path, monkeypatch):
    # Vhost-routed sites often refuse or redirect bare-IP requests, so HTTP
    # commands should address the confirmed hostname once one exists. Other
    # protocols (SMB here) keep hitting the IP — a hostname mismatch is far
    # less likely to change their response, and DNS may not even be set up
    # for them.
    monkeypatch.setattr(executions_router, "WORKSPACE_DIR", tmp_path)
    monkeypatch.setattr(executions_router.shutil, "which", lambda _: "/usr/bin/true")
    async def noop(*args, **kwargs):
        pass
    monkeypatch.setattr(executions_router, "run_execution", noop)
    db = database()
    project = Project(name="Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.10", hostname="unika.htb")
    db.add(target); db.flush()
    http_service = Service(
        target_id=target.id, port=80, protocol="tcp", state="open", name="http",
        product="", version="", extra_info="", scripts="{}", notes="", tags="[]")
    smb_service = Service(
        target_id=target.id, port=445, protocol="tcp", state="open", name="microsoft-ds",
        product="", version="", extra_info="", scripts="{}", notes="", tags="[]")
    db.add(http_service); db.add(smb_service); db.commit()

    http_row = asyncio.run(execute(ExecutionIn(
        target_id=target.id, service_id=http_service.id, template_id="http-headers",
        variables={}, run_as_root=False), db=db))
    assert "unika.htb" in http_row.command
    assert "10.10.10.10" not in http_row.command

    smb_row = asyncio.run(execute(ExecutionIn(
        target_id=target.id, service_id=smb_service.id, template_id="smb-enum",
        variables={}, run_as_root=False), db=db))
    assert "10.10.10.10" in smb_row.command
    assert "unika.htb" not in smb_row.command


def test_execute_falls_back_to_ip_for_http_templates_without_a_confirmed_hostname(
        tmp_path, monkeypatch):
    monkeypatch.setattr(executions_router, "WORKSPACE_DIR", tmp_path)
    monkeypatch.setattr(executions_router.shutil, "which", lambda _: "/usr/bin/true")
    async def noop(*args, **kwargs):
        pass
    monkeypatch.setattr(executions_router, "run_execution", noop)
    db = database()
    project = Project(name="Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.10")
    db.add(target); db.flush()
    http_service = Service(
        target_id=target.id, port=80, protocol="tcp", state="open", name="http",
        product="", version="", extra_info="", scripts="{}", notes="", tags="[]")
    db.add(http_service); db.commit()

    row = asyncio.run(execute(ExecutionIn(
        target_id=target.id, service_id=http_service.id, template_id="http-headers",
        variables={}, run_as_root=False), db=db))
    assert "10.10.10.10" in row.command


def test_run_execution_survives_a_long_stretch_without_a_newline(tmp_path, monkeypatch):
    # ffuf/gobuster/feroxbuster redraw an in-place progress counter with \r
    # (no \n) between actual result lines; under connection errors or a slow
    # target this run can outlast the default 64KiB asyncio StreamReader
    # limit before the next real line lands, which used to surface as
    # "Separator is not found, and chunk exceed the limit" and mark a
    # perfectly healthy fuzzing run as failed.
    engine = create_engine(f"sqlite:///{tmp_path / 'exec.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(executor_module, "SessionLocal", factory)
    with factory() as db:
        project = Project(name="Lab", description="")
        db.add(project); db.flush()
        target = Target(project_id=project.id, name="Box", ip="10.10.10.10")
        db.add(target); db.flush()
        execution = Execution(
            target_id=target.id, template_id="http-param-fuzz", command="ffuf ...",
            cwd=str(tmp_path), status="queued")
        db.add(execution); db.commit()
        execution_id = execution.id

    spam_script = tmp_path / "spam.py"
    spam_script.write_text(
        "import sys\n"
        "sys.stdout.write('\\r' * (200 * 1024))\n"
        "sys.stdout.write('done\\n')\n",
        encoding="utf-8",
    )

    async def exercise():
        await executor_module.run_execution(
            execution_id, [sys.executable, str(spam_script)],
            tmp_path, tmp_path / "out.txt",
        )

    asyncio.run(exercise())

    with factory() as db:
        row = db.get(Execution, execution_id)
        assert row.status != "failed", row.error
        assert row.exit_code == 0
        assert "done" in row.stdout
