import asyncio
import hashlib
import json
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.database import Base
from app.models import (Evidence, Execution, Finding, FindingEvidence, GraphEdge, GraphNode,
                        Project, Service, Target)
from app.schemas import ExecutionDeriveIn, ExecutionIn, FtpTreePromoteIn
from fastapi import HTTPException

import app.executor as executor_module
import app.modules.executions.router as executions_router
from app.modules.executions.router import (
    _ftp_tree_connection_args, delete_execution,
    derive_output, execute, execution_output_file, promote_ftp_file,
)
from app.modules.executions.service import (
    _validated_override, output_path_for as _output_path,
)
from app.modules.graph import service as graph_service


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
    monkeypatch.setattr(executions_router.execution_service, "WORKSPACE_DIR", tmp_path)
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
    monkeypatch.setattr(executions_router.execution_service, "WORKSPACE_DIR", tmp_path)
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
    monkeypatch.setattr(executions_router.execution_service, "WORKSPACE_DIR", tmp_path)
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


def test_execute_stores_the_graph_node_it_was_run_to_follow_up_on(tmp_path, monkeypatch):
    monkeypatch.setattr(executions_router.execution_service, "WORKSPACE_DIR", tmp_path)
    monkeypatch.setattr(executions_router.execution_service.shutil, "which", lambda _: "/usr/bin/true")
    async def noop(*args, **kwargs):
        pass
    monkeypatch.setattr(executions_router.execution_service, "run_execution", noop)
    db = database()
    project = Project(name="Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.11")
    db.add(target); db.flush()
    service = Service(
        target_id=target.id, port=445, protocol="tcp", state="open", name="microsoft-ds",
        product="", version="", extra_info="", scripts="{}", notes="", tags="[]")
    db.add(service); db.commit()

    row = asyncio.run(execute(ExecutionIn(
        target_id=target.id, service_id=service.id, template_id="smb-enum",
        variables={}, run_as_root=False,
        graph_node_id="01ABCXYZFINDINGNODE0000001"), db=db))

    assert row.graph_parent_node_id == "01ABCXYZFINDINGNODE0000001"


def test_execute_prefers_the_confirmed_hostname_for_http_templates_only(
        tmp_path, monkeypatch):
    # Vhost-routed sites often refuse or redirect bare-IP requests, so HTTP
    # commands should address the confirmed hostname once one exists. Other
    # protocols (SMB here) keep hitting the IP — a hostname mismatch is far
    # less likely to change their response, and DNS may not even be set up
    # for them.
    monkeypatch.setattr(executions_router.execution_service, "WORKSPACE_DIR", tmp_path)
    monkeypatch.setattr(executions_router.execution_service.shutil, "which", lambda _: "/usr/bin/true")
    async def noop(*args, **kwargs):
        pass
    monkeypatch.setattr(executions_router.execution_service, "run_execution", noop)
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
    monkeypatch.setattr(executions_router.execution_service, "WORKSPACE_DIR", tmp_path)
    monkeypatch.setattr(executions_router.execution_service.shutil, "which", lambda _: "/usr/bin/true")
    async def noop(*args, **kwargs):
        pass
    monkeypatch.setattr(executions_router.execution_service, "run_execution", noop)
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


def test_execute_runs_a_valid_operator_argv_edit(tmp_path, monkeypatch):
    monkeypatch.setattr(executions_router.execution_service, "WORKSPACE_DIR", tmp_path)
    monkeypatch.setattr(executions_router.execution_service.shutil, "which", lambda _: "/usr/bin/true")
    async def noop(*args, **kwargs):
        pass
    monkeypatch.setattr(executions_router.execution_service, "run_execution", noop)
    db = database()
    project = Project(name="Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.10")
    db.add(target); db.flush()
    service = Service(target_id=target.id, port=21, protocol="tcp", state="open",
        name="ftp", product="", version="", extra_info="", scripts="{}",
        notes="", tags="[]")
    db.add(service); db.commit()
    output = (tmp_path / "projects" / "Lab" / "targets" / "10.10.10.10" /
        "outputs" / "service-21-identity.xml")
    command = f"nmap -Pn -sV --version-all --version-trace -p21 -oX {output} 10.10.10.10"

    row = asyncio.run(execute(ExecutionIn(
        target_id=target.id, service_id=service.id, template_id="service-version",
        variables={}, run_as_root=False, command_override=command), db=db))

    assert row.command == command


@pytest.mark.parametrize("command,detail", [
    ("curl -Pn -sV -p21 10.10.10.10", "ENGINE CHANGED"),
    ("nmap -Pn -sV -p22 10.10.10.10", "SERVICE CHANGED"),
    ("nmap -Pn -sV -p21 10.10.10.20", "TARGET CHANGED"),
    ("nmap -Pn -sV -p21 10.10.10.10 | tee out", "Shell operators"),
])
def test_operator_argv_edit_cannot_leave_its_bound_context(command, detail):
    service = Service(port=21, protocol="tcp")
    with pytest.raises(HTTPException) as exc:
        _validated_override(command,
            ["nmap", "-Pn", "-sV", "-p21", "10.10.10.10"],
            "10.10.10.10", service)
    assert detail in exc.value.detail


def test_operator_argv_edit_cannot_rebind_a_generated_output_path():
    service = Service(port=21, protocol="tcp")
    base = ["nmap", "-p21", "-oX",
        "/targets/10.10.10.10/outputs/service-21.xml", "10.10.10.10"]
    edited = "nmap -p21 -oX /targets/10.10.10.20/outputs/service-21.xml 10.10.10.10"
    with pytest.raises(HTTPException) as exc:
        _validated_override(edited, base, "10.10.10.10", service)
    assert "TARGET CHANGED" in exc.value.detail


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


def test_ftp_tree_connection_args_recovers_host_port_username_password():
    command = ("/repo/.venv/bin/python -m app.ftp_tree --host 10.129.7.93 --port 21 "
              "--username anonymous --password anonymous@")
    assert _ftp_tree_connection_args(command) == {
        "host": "10.129.7.93", "port": "21",
        "username": "anonymous", "password": "anonymous@"}


class _FakeFTP:
    """Records connect()/login() calls and returns fixed bytes from
    retrbinary() (or raises, for the failure test) -- ftp_tree.py's own
    walker only lists, so promote_ftp_file has to open its own fresh
    connection to actually fetch a file's bytes."""
    instances: list["_FakeFTP"] = []

    def __init__(self, *, content: bytes = b"loot", error: Exception | None = None):
        self.connected = None
        self.logged_in = None
        self.content = content
        self.error = error
        _FakeFTP.instances.append(self)

    def connect(self, host, port, timeout=10):
        self.connected = (host, port)

    def login(self, username, password):
        self.logged_in = (username, password)

    def retrbinary(self, cmd, callback):
        self.retr_cmd = cmd
        if self.error:
            raise self.error
        callback(self.content)

    def quit(self):
        pass


def _ftp_tree_execution(db, tmp_path, monkeypatch, command=None):
    monkeypatch.setattr(executions_router.execution_service, "WORKSPACE_DIR", tmp_path)
    project = Project(name="Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.129.7.93")
    db.add(target); db.flush()
    execution = Execution(
        target_id=target.id, template_id="ftp-directory-tree",
        command=command or ("python -m app.ftp_tree --host 10.129.7.93 --port 21 "
                            "--username anonymous --password anonymous@"),
        cwd=".", status="completed")
    db.add(execution); db.commit()
    return project, target, execution


def test_promote_ftp_file_reconnects_and_registers_a_draft_finding(tmp_path, monkeypatch):
    db = database()
    _project, _target, execution = _ftp_tree_execution(db, tmp_path, monkeypatch)
    _FakeFTP.instances = []
    monkeypatch.setattr(executions_router.ftplib, "FTP", lambda: _FakeFTP(content=b"loot"))

    result = promote_ftp_file(execution.id, FtpTreePromoteIn(path="backup.zip"), db=db)

    ftp = _FakeFTP.instances[0]
    assert ftp.connected == ("10.129.7.93", 21)
    assert ftp.logged_in == ("anonymous", "anonymous@")
    assert ftp.retr_cmd == "RETR backup.zip"
    finding = db.get(Finding, result["finding_id"])
    assert finding is not None and finding.status == "Draft"
    evidence = db.get(Evidence, result["evidence_id"])
    assert evidence.kind == "attachment" and evidence.original_name == "backup.zip"
    assert Path(evidence.file_path).read_bytes() == b"loot"
    link = db.query(FindingEvidence).filter_by(finding_id=finding.id).one()
    assert link.evidence_id == evidence.id and link.is_primary is True


def test_promote_ftp_file_attaches_to_the_given_technique_node(tmp_path, monkeypatch):
    db = database()
    project, _target, execution = _ftp_tree_execution(db, tmp_path, monkeypatch)
    monkeypatch.setattr(executions_router.ftplib, "FTP", lambda: _FakeFTP(content=b"loot"))
    technique = graph_service.create_node(db, project.id, "technique", label="폴더·파일 트리 조회")
    db.commit()

    result = promote_ftp_file(execution.id, FtpTreePromoteIn(
        path="backup.zip", graph_node_id=technique.id), db=db)

    finding_node = db.query(GraphNode).filter_by(
        project_id=project.id, type="finding").one()
    assert json.loads(finding_node.source_ref) == {
        "module": "findings", "kind": "finding", "id": result["finding_id"]}
    assert json.loads(finding_node.meta)["evidenceCount"] == 1
    edge = db.query(GraphEdge).filter_by(source=technique.id, target=finding_node.id).one()
    assert edge.relation == "yielded"


def test_promote_ftp_file_rejects_an_execution_that_is_not_an_ftp_tree(tmp_path, monkeypatch):
    db = database()
    monkeypatch.setattr(executions_router.execution_service, "WORKSPACE_DIR", tmp_path)
    project = Project(name="Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.129.7.93")
    db.add(target); db.flush()
    execution = Execution(
        target_id=target.id, template_id="ftp-anon", command="nxc ftp 10.129.7.93",
        cwd=".", status="completed")
    db.add(execution); db.commit()

    with pytest.raises(HTTPException) as exc:
        promote_ftp_file(execution.id, FtpTreePromoteIn(path="backup.zip"), db=db)
    assert exc.value.status_code == 422


def test_promote_ftp_file_surfaces_a_failed_download_instead_of_a_500(tmp_path, monkeypatch):
    # Reproduces the live failure: a typo'd path (or a file that's been
    # removed since the tree ran) gets "550 Failed to open file" from the
    # server -- this should read as a clear error, not crash.
    import ftplib as ftplib_module
    db = database()
    _project, _target, execution = _ftp_tree_execution(db, tmp_path, monkeypatch)
    monkeypatch.setattr(executions_router.ftplib, "FTP",
        lambda: _FakeFTP(error=ftplib_module.error_perm("550 Failed to open file.")))

    with pytest.raises(HTTPException) as exc:
        promote_ftp_file(execution.id, FtpTreePromoteIn(path="bazkup.zip"), db=db)
    assert exc.value.status_code == 502
    assert "550" in str(exc.value.detail)
