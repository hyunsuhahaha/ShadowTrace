import json
import os
import time
from pathlib import Path
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from app.database import Base
from app.models import AutoReconRun, Execution, Project, ScanJob, Service, Target
from app.modules.autorecon.service import (
    import_autorecon_run, render_autorecon_command, run_output_dir,
)


def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def _fake_results_tree(base: Path, ip: str) -> None:
    scans = base / ip / "scans"
    (scans / "xml").mkdir(parents=True)
    (scans / "xml" / "_full_tcp_nmap.xml").write_bytes(
        f"""<nmaprun><host><address addr="{ip}"/><ports>
        <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
        </ports></host></nmaprun>""".encode())
    tcp80 = scans / "tcp80"
    tcp80.mkdir()
    (tcp80 / "tcp_80_http_whatweb.txt").write_text("WhatWeb report for http://127.0.0.1:80\n")
    (tcp80 / "tcp_80_http_nikto.txt").write_text("- Nikto v2.5.0\n---------------------------\n")
    # import_autorecon_run skips anything modified within the last
    # _QUIET_PERIOD_SECONDS (still-being-written plugin output) -- backdate
    # these so the fixture reads as "settled" the way a real completed
    # plugin file would by the time a poll (or the final import) reaches it.
    settled = time.time() - 60
    for result_file in tcp80.iterdir():
        os.utime(result_file, (settled, settled))


def test_render_autorecon_command_never_passes_single_target():
    # Confirmed live: without --single-target, output always nests under
    # <output_dir>/<ip>/scans/... for both 1 and N targets -- the importer
    # relies on that uniform layout, so this flag must never appear.
    targets = [Target(project_id=1, name="a", ip="10.10.10.10"),
               Target(project_id=1, name="b", ip="10.10.10.11")]
    argv = render_autorecon_command(targets, Path("/tmp/out"))
    assert argv[0] == "autorecon"
    assert "10.10.10.10" in argv and "10.10.10.11" in argv
    assert "--single-target" not in argv
    assert "--disable-keyboard-control" in argv
    assert "--ignore-plugin-checks" in argv


def test_run_output_dir_is_scoped_by_project_and_run_id():
    project = Project(id=1, name="Lab", description="")
    path = run_output_dir(project, 42)
    assert path.name == "42"
    assert path.parent.name == "autorecon"
    assert "Lab" in str(path)


def test_import_autorecon_run_creates_service_and_per_plugin_executions(tmp_path):
    db = database()
    project = Project(name="Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="127.0.0.1")
    db.add(target); db.flush()
    _fake_results_tree(tmp_path, "127.0.0.1")
    run = AutoReconRun(project_id=project.id, target_ids=json.dumps([target.id]),
                       command="autorecon 127.0.0.1", output_dir=str(tmp_path),
                       status="running")
    db.add(run); db.commit()

    imported = import_autorecon_run(db, run)

    assert imported == 2
    service = db.scalar(select(Service).where(
        Service.target_id == target.id, Service.port == 80))
    assert service is not None and service.name == "http"
    executions = db.scalars(select(Execution).where(
        Execution.target_id == target.id).order_by(Execution.template_id)).all()
    ids = {e.template_id for e in executions}
    assert ids == {"autorecon-nikto", "autorecon-whatweb"}
    for execution in executions:
        assert execution.service_id == service.id
        assert execution.status == "completed"
        assert execution.stdout
        assert Path(execution.output_path).is_file()


def test_import_autorecon_run_skips_a_target_with_no_results_tree(tmp_path):
    db = database()
    project = Project(name="Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.99")
    db.add(target); db.flush()
    run = AutoReconRun(project_id=project.id, target_ids=json.dumps([target.id]),
                       command="autorecon 10.10.10.99", output_dir=str(tmp_path),
                       status="running")
    db.add(run); db.commit()

    imported = import_autorecon_run(db, run)

    assert imported == 0
    assert db.query(Execution).count() == 0


def test_import_autorecon_run_skips_a_result_file_thats_still_being_written(tmp_path):
    # A plugin (feroxbuster in particular) can still be appending to its
    # output file when a poll lands on it -- importing that half-written
    # content would freeze it forever, since a file is never revisited once
    # its output_path has an Execution. Leaving the file at its natural
    # (just-now) mtime, unlike _fake_results_tree's settled fixture, should
    # defer it instead of importing a partial result.
    db = database()
    project = Project(name="Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="127.0.0.1")
    db.add(target); db.flush()
    scans = tmp_path / "127.0.0.1" / "scans"
    (scans / "xml").mkdir(parents=True)
    (scans / "xml" / "_full_tcp_nmap.xml").write_bytes(
        b"""<nmaprun><host><address addr="127.0.0.1"/><ports>
        <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
        </ports></host></nmaprun>""")
    tcp80 = scans / "tcp80"
    tcp80.mkdir()
    (tcp80 / "tcp_80_http_feroxbuster_dirbuster.txt").write_text("still going...\n")
    run = AutoReconRun(project_id=project.id, target_ids=json.dumps([target.id]),
                       command="autorecon 127.0.0.1", output_dir=str(tmp_path),
                       status="running")
    db.add(run); db.commit()

    imported = import_autorecon_run(db, run)

    assert imported == 0
    assert db.query(Execution).count() == 0


def test_import_autorecon_run_is_safe_to_call_repeatedly_without_duplicating(tmp_path):
    # The manager's poll loop calls this every few seconds against the same
    # still-running run -- it must not create a second bookkeeping ScanJob,
    # a second Service/Finding/Evidence pass, or a second Execution for a
    # file it already imported.
    db = database()
    project = Project(name="Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="127.0.0.1")
    db.add(target); db.flush()
    _fake_results_tree(tmp_path, "127.0.0.1")
    run = AutoReconRun(project_id=project.id, target_ids=json.dumps([target.id]),
                       command="autorecon 127.0.0.1", output_dir=str(tmp_path),
                       status="running")
    db.add(run); db.commit()

    first = import_autorecon_run(db, run)
    second = import_autorecon_run(db, run)

    assert first == 2
    assert second == 0
    assert db.query(Execution).count() == 2
    assert db.query(ScanJob).filter_by(source="autorecon").count() == 1
