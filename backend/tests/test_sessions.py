import pytest
from fastapi import BackgroundTasks, HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from pydantic import ValidationError

from app.database import Base
from app.models import Credential, InteractiveSession, Project, Service, Target
from app.schemas import DesktopLaunchIn, InteractiveSessionIn, ManualTerminalIn
from types import SimpleNamespace

from app.schemas import PromoteDownloadIn

import app.modules.sessions.router as sessions_router
from app.modules.sessions.router import (
    _detect_ftp_downloads, create_interactive_session, create_manual_terminal,
    interactive_session_ftp_downloads, promote_download, responder_captures,
    launch_interactive_session_in_desktop, retry_interactive_session,
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


def test_responder_command_override_replaces_the_template_default(tmp_path, monkeypatch):
    db = database()
    box = target(db, tmp_path, monkeypatch)
    monkeypatch.setattr(sessions_router.subprocess, "run", lambda *a, **k:
        SimpleNamespace(returncode=1, stdout=""))

    row = create_interactive_session(InteractiveSessionIn(
        target_id=box.id, template_id="responder-listener",
        variables={"interface": "tun0"},
        command_override="responder -I tun0 -A -v"), db=db)

    # run_as_root still wraps whatever argv the operator ended up with
    assert row.command == "sudo responder -I tun0 -A -v"


def test_responder_command_override_still_goes_through_the_single_instance_guard(
        tmp_path, monkeypatch):
    db = database()
    box = target(db, tmp_path, monkeypatch)
    monkeypatch.setattr(sessions_router.subprocess, "run", lambda *a, **k:
        SimpleNamespace(returncode=0, stdout="144448\n"))

    with pytest.raises(HTTPException) as exc:
        create_interactive_session(InteractiveSessionIn(
            target_id=box.id, template_id="responder-listener",
            variables={"interface": "tun0"},
            command_override="responder -I tun0 --lm"), db=db)

    assert exc.value.status_code == 409


def test_responder_command_override_rejects_an_empty_command(tmp_path, monkeypatch):
    db = database()
    box = target(db, tmp_path, monkeypatch)
    monkeypatch.setattr(sessions_router.subprocess, "run", lambda *a, **k:
        SimpleNamespace(returncode=1, stdout=""))

    with pytest.raises(HTTPException) as exc:
        create_interactive_session(InteractiveSessionIn(
            target_id=box.id, template_id="responder-listener",
            variables={"interface": "tun0"}, command_override="   "), db=db)

    assert exc.value.status_code == 400


def test_command_override_is_ignored_for_templates_other_than_responder(tmp_path, monkeypatch):
    # Scoped deliberately narrow -- letting an arbitrary template's launch
    # be swapped out for an operator-typed command would bypass every other
    # template's own tool-not-installed / variable-substitution checks.
    db = database()
    box = target(db, tmp_path, monkeypatch)
    monkeypatch.setattr(sessions_router.subprocess, "run", lambda *a, **k:
        SimpleNamespace(returncode=1, stdout=""))

    row = create_interactive_session(InteractiveSessionIn(
        target_id=box.id, template_id="smbserver-listener",
        variables={}, command_override="whoami"), db=db)

    assert "impacket-smbserver" in row.command
    assert "whoami" not in row.command


def test_smbserver_is_blocked_while_an_instance_is_already_running(tmp_path, monkeypatch):
    db = database()
    box = target(db, tmp_path, monkeypatch)
    monkeypatch.setattr(sessions_router.subprocess, "run", lambda *a, **k:
        SimpleNamespace(returncode=0, stdout="222333\n"))

    with pytest.raises(HTTPException) as exc:
        create_interactive_session(InteractiveSessionIn(
            target_id=box.id, template_id="smbserver-listener", variables={}), db=db)

    assert exc.value.status_code == 409
    assert "222333" in exc.value.detail


def test_smbserver_is_allowed_when_nothing_is_running_and_gets_its_own_share_dir(
        tmp_path, monkeypatch):
    db = database()
    box = target(db, tmp_path, monkeypatch)
    monkeypatch.setattr(sessions_router.subprocess, "run", lambda *a, **k:
        SimpleNamespace(returncode=1, stdout=""))

    row = create_interactive_session(InteractiveSessionIn(
        target_id=box.id, template_id="smbserver-listener", variables={}), db=db)

    assert row.template_id == "smbserver-listener"
    share_dir = tmp_path / "projects" / "Lab" / "targets" / "10.10.10.60" / "outputs" / "smb-share"
    assert row.command == f"sudo impacket-smbserver share {share_dir} -smb2support"
    assert share_dir.is_dir()  # impacket-smbserver requires the path to pre-exist


def test_failed_interactive_session_can_be_restarted(tmp_path, monkeypatch):
    db = database()
    box = target(db, tmp_path, monkeypatch)
    previous = InteractiveSession(
        target_id=box.id, template_id="responder-listener",
        command="sudo responder -I tun0 -v", cwd=str(tmp_path), status="failed")
    db.add(previous); db.commit()
    monkeypatch.setattr(sessions_router.subprocess, "run", lambda *a, **k:
        SimpleNamespace(returncode=1, stdout=""))

    restarted = retry_interactive_session(previous.id, db)

    assert restarted.id != previous.id
    assert restarted.status == "ready"
    assert restarted.command == previous.command


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


def test_sync_project_responder_captures_creates_one_credential_idempotently(
        tmp_path, monkeypatch):
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    monkeypatch.setattr(sessions_router, "RESPONDER_LOGS_DIR", logs_dir)
    (logs_dir / "SMB-NTLMv2-SSP-10.129.95.234.txt").write_text(
        "Administrator::RESPONDER:aaa:bbb:ccc\n", encoding="utf-8")
    db = database()
    project = Project(name="Lab", description="")
    db.add(project); db.flush()
    db.add(Target(project_id=project.id, name="Box", ip="10.129.95.234"))
    db.commit()

    first = sessions_router.sync_project_responder_captures(project.id, db)
    second = sessions_router.sync_project_responder_captures(project.id, db)

    assert first == {"created": 1}
    assert second == {"created": 0}
    rows = db.query(Credential).all()
    assert len(rows) == 1
    assert rows[0].username == "Administrator"
    assert rows[0].secret_kind == "hash"
    assert rows[0].source_kind == "responder"


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


def test_manual_terminal_opens_a_target_level_shell_without_a_service(
        tmp_path, monkeypatch):
    db = database()
    box = target(db, tmp_path, monkeypatch)

    row = create_manual_terminal(ManualTerminalIn(target_id=box.id), db=db)

    assert row.target_id == box.id
    assert row.service_id is None
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


def test_desktop_launch_passes_the_shell_and_command_as_separate_argv_items(
        tmp_path, monkeypatch):
    # qterminal's -e does not re-parse a single joined string through a
    # shell: a command containing its own quoting (like a shlex-quoted
    # username, e.g. evil-winrm -u 'administrator') breaks apart into
    # garbage when squashed into one argv item, and the shell exits
    # instantly instead of running anything. Reproduced live against a
    # real qterminal/X session -- the fix is passing the shell, its
    # flags, and the command as distinct argv entries.
    db = database()
    box = target(db, tmp_path, monkeypatch)
    service = Service(target_id=box.id, port=5985, protocol="tcp", state="open",
                       name="http", product="", version="", extra_info="", scripts="{}",
                       notes="", tags="[]")
    db.add(service); db.commit()
    row = InteractiveSession(
        target_id=box.id, service_id=service.id, template_id="manual-shell",
        command="evil-winrm -i 10.10.10.60 -u 'administrator'",
        cwd=str(tmp_path), status="ready",
    )
    db.add(row); db.commit()
    monkeypatch.setattr(sessions_router.shutil, "which", lambda _: "/usr/bin/qterminal")
    captured = {}

    def fake_popen(argv, **kwargs):
        captured["argv"] = argv
        return SimpleNamespace(pid=4242)

    monkeypatch.setattr(sessions_router.subprocess, "Popen", fake_popen)

    launch_interactive_session_in_desktop(row.id, BackgroundTasks(), db=db)

    argv = captured["argv"]
    assert argv[-4] == "-e"
    assert argv[-2] == "-lic"
    inner_command = argv[-1]
    assert "evil-winrm -i 10.10.10.60 -u 'administrator'; exec" in inner_command
    # the command itself must be its own argv item, never squashed together
    # with the shell/flags into one pre-quoted string
    assert not any("-lic" in item and "evil-winrm" in item for item in argv[:-1])


def test_desktop_launch_wraps_the_command_in_expect_when_a_secret_needs_typing(
        tmp_path, monkeypatch):
    # evil-winrm's own getpass() refuses a plain piped/redirected stdin
    # (Errno::ENOTTY, reproduced live), so the secret has to reach it
    # through a program that gives it a real pty -- expect's spawn does
    # that. The secret itself must never end up in this argv.
    db = database()
    box = target(db, tmp_path, monkeypatch)
    service = Service(target_id=box.id, port=5985, protocol="tcp", state="open",
                       name="http", product="", version="", extra_info="", scripts="{}",
                       notes="", tags="[]")
    db.add(service); db.commit()
    row = InteractiveSession(
        target_id=box.id, service_id=service.id, template_id="manual-shell",
        command="evil-winrm -i 10.10.10.60 -u 'administrator'",
        cwd=str(tmp_path), status="ready",
    )
    db.add(row); db.commit()
    monkeypatch.setattr(sessions_router.shutil, "which", lambda name:
        "/usr/bin/qterminal" if name == "qterminal" else "/usr/bin/expect")
    monkeypatch.setattr(sessions_router.os, "mkfifo", lambda *a, **k: None)
    monkeypatch.setattr(sessions_router.os, "chown", lambda *a, **k: None)
    monkeypatch.setattr(sessions_router, "_deliver_secret_to_fifo", lambda *a: None)
    captured = {}

    def fake_popen(argv, **kwargs):
        captured["argv"] = argv
        return SimpleNamespace(pid=4242)

    monkeypatch.setattr(sessions_router.subprocess, "Popen", fake_popen)

    launch_interactive_session_in_desktop(
        row.id, BackgroundTasks(), body=DesktopLaunchIn(type_after="hunter2"), db=db)

    inner_command = captured["argv"][-1]
    assert "expect" in inner_command
    assert str(sessions_router.TYPE_RELAY_SCRIPT) in inner_command
    assert "/bin/sh" in inner_command and "-c" in inner_command
    assert "hunter2" not in inner_command


def test_desktop_launch_of_ftp_client_queues_an_automatic_directory_tree(
        tmp_path, monkeypatch):
    # ftp-client sessions can be opened several ways (anonymous-exposure
    # auto-open, typed credentials, or picking the command straight from a
    # catalog/workflow) -- only some of which the frontend wires up to an
    # auto-crawl. This endpoint is the one choke point every path launches
    # a desktop session through, so it's where the auto-crawl belongs.
    db = database()
    box = target(db, tmp_path, monkeypatch)
    service = Service(target_id=box.id, port=21, protocol="tcp", state="open",
                       name="ftp", product="", version="", extra_info="", scripts="{}",
                       notes="", tags="[]")
    db.add(service); db.commit()
    row = InteractiveSession(
        target_id=box.id, service_id=service.id, template_id="ftp-client",
        command="ftp 10.10.10.60 21", cwd=str(tmp_path), status="ready",
    )
    db.add(row); db.commit()
    monkeypatch.setattr(sessions_router.shutil, "which", lambda _: "/usr/bin/qterminal")
    monkeypatch.setattr(sessions_router.subprocess, "Popen",
        lambda argv, **kwargs: SimpleNamespace(pid=4242))
    background_tasks = BackgroundTasks()

    launch_interactive_session_in_desktop(row.id, background_tasks, db=db)

    assert len(background_tasks.tasks) == 1
    task = background_tasks.tasks[0]
    assert task.func is sessions_router._auto_run_ftp_tree
    assert task.args == (box.id, service.id)


def test_desktop_launch_of_a_non_ftp_session_does_not_queue_a_directory_tree(
        tmp_path, monkeypatch):
    db = database()
    box = target(db, tmp_path, monkeypatch)
    service = Service(target_id=box.id, port=5985, protocol="tcp", state="open",
                       name="http", product="", version="", extra_info="", scripts="{}",
                       notes="", tags="[]")
    db.add(service); db.commit()
    row = InteractiveSession(
        target_id=box.id, service_id=service.id, template_id="manual-shell",
        command="/bin/bash --noprofile --norc", cwd=str(tmp_path), status="ready",
    )
    db.add(row); db.commit()
    monkeypatch.setattr(sessions_router.shutil, "which", lambda _: "/usr/bin/qterminal")
    monkeypatch.setattr(sessions_router.subprocess, "Popen",
        lambda argv, **kwargs: SimpleNamespace(pid=4242))
    background_tasks = BackgroundTasks()

    launch_interactive_session_in_desktop(row.id, background_tasks, db=db)

    assert background_tasks.tasks == []


def test_desktop_launch_requires_expect_when_a_secret_needs_typing(tmp_path, monkeypatch):
    db = database()
    box = target(db, tmp_path, monkeypatch)
    service = Service(target_id=box.id, port=5985, protocol="tcp", state="open",
                       name="http", product="", version="", extra_info="", scripts="{}",
                       notes="", tags="[]")
    db.add(service); db.commit()
    row = InteractiveSession(
        target_id=box.id, service_id=service.id, template_id="manual-shell",
        command="evil-winrm -i 10.10.10.60 -u 'administrator'",
        cwd=str(tmp_path), status="ready",
    )
    db.add(row); db.commit()
    monkeypatch.setattr(sessions_router.shutil, "which", lambda name:
        "/usr/bin/qterminal" if name == "qterminal" else None)

    with pytest.raises(HTTPException) as exc:
        launch_interactive_session_in_desktop(
            row.id, BackgroundTasks(), body=DesktopLaunchIn(type_after="hunter2"), db=db)
    assert exc.value.status_code == 409


def test_detect_ftp_downloads_only_counts_transfers_that_actually_completed():
    log = (
        "ftp> get backup.zip\n"
        "local: backup.zip remote: backup.zip\n"
        "229 Entering Extended Passive Mode (|||10888|)\n"
        "150 Opening BINARY mode data connection for backup.zip (2533 bytes).\n"
        "226 Transfer complete.\n"
        "2533 bytes received in 00:00 (3.60 KiB/s)\n"
        "ftp> get notes.txt\n"
        "local: notes.txt remote: notes.txt\n"
        "550 Failed to open file.\n"
        "ftp> get creds.txt\n"
        "local: creds.txt remote: creds.txt\n"
        "226 Transfer complete.\n"
    )
    assert _detect_ftp_downloads(log) == ["backup.zip", "creds.txt"]


def test_promote_download_in_rejects_a_filename_that_tries_to_escape_the_directory():
    with pytest.raises(ValidationError):
        PromoteDownloadIn(filename="../../etc/passwd")


def test_ftp_downloads_endpoint_lists_only_files_still_actually_on_disk(tmp_path, monkeypatch):
    db = database()
    box = target(db, tmp_path, monkeypatch)
    log_path = tmp_path / "session.log"
    log_path.write_text(
        "local: backup.zip remote: backup.zip\n226 Transfer complete.\n"
        "local: gone.txt remote: gone.txt\n226 Transfer complete.\n",
        encoding="utf-8")
    (tmp_path / "backup.zip").write_bytes(b"PK\x03\x04fake-zip-contents")
    row = InteractiveSession(
        target_id=box.id, template_id="ftp-client", command="ftp 10.10.10.60 21",
        cwd=str(tmp_path), log_path=str(log_path), status="stopped")
    db.add(row); db.commit()

    result = interactive_session_ftp_downloads(row.id, db=db)

    assert result == {"files": [{"filename": "backup.zip", "size": 21}]}


def test_promote_download_creates_a_draft_finding_from_a_locally_downloaded_file(
        tmp_path, monkeypatch):
    from app.models import Evidence, Finding, FindingEvidence
    db = database()
    box = target(db, tmp_path, monkeypatch)
    (tmp_path / "backup.zip").write_bytes(b"loot")
    row = InteractiveSession(
        target_id=box.id, template_id="ftp-client", command="ftp 10.10.10.60 21",
        cwd=str(tmp_path), status="stopped")
    db.add(row); db.commit()

    result = promote_download(row.id, PromoteDownloadIn(filename="backup.zip"), db=db)

    finding = db.get(Finding, result["finding_id"])
    assert finding is not None and finding.status == "Draft"
    assert "backup.zip" in finding.title
    evidence = db.get(Evidence, result["evidence_id"])
    assert evidence is not None and evidence.kind == "attachment"
    from pathlib import Path as _Path
    assert _Path(evidence.file_path).read_bytes() == b"loot"
    link = db.query(FindingEvidence).filter_by(finding_id=finding.id).one()
    assert link.evidence_id == evidence.id and link.is_primary is True


def test_promote_download_attaches_the_finding_to_the_given_technique_node(tmp_path, monkeypatch):
    # Same idea as post_exploitation's promote_file test: passing the
    # technique node the download happened in attaches the finding node
    # right there via "yielded" instead of waiting on sync()'s own bare-host
    # fallback -- and its meta must be set up front, not left for a resync a
    # later-dismissed source_ref could skip forever.
    import json
    from app.models import GraphNode
    from app.modules.graph import service as graph_service
    db = database()
    box = target(db, tmp_path, monkeypatch)
    (tmp_path / "backup.zip").write_bytes(b"loot")
    row = InteractiveSession(
        target_id=box.id, template_id="ftp-client", command="ftp 10.10.10.60 21",
        cwd=str(tmp_path), status="stopped")
    db.add(row); db.commit()
    technique = graph_service.create_node(
        db, box.project_id, "technique", label="FTP 수동 접속")
    db.commit()

    result = promote_download(row.id, PromoteDownloadIn(
        filename="backup.zip", graph_node_id=technique.id), db=db)

    finding_node = db.query(GraphNode).filter_by(
        project_id=box.project_id, type="finding").one()
    assert json.loads(finding_node.source_ref) == {
        "module": "findings", "kind": "finding", "id": result["finding_id"]}
    assert json.loads(finding_node.meta)["evidenceCount"] == 1


def test_promote_download_rejects_a_file_that_is_not_actually_there(tmp_path, monkeypatch):
    db = database()
    box = target(db, tmp_path, monkeypatch)
    row = InteractiveSession(
        target_id=box.id, template_id="ftp-client", command="ftp 10.10.10.60 21",
        cwd=str(tmp_path), status="stopped")
    db.add(row); db.commit()

    with pytest.raises(HTTPException) as exc:
        promote_download(row.id, PromoteDownloadIn(filename="never-downloaded.txt"), db=db)
    assert exc.value.status_code == 404
