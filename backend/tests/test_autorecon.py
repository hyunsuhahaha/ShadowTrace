import json
import os
import time
from pathlib import Path
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from app.database import Base
from app.models import AutoReconRun, Execution, Project, ScanArtifact, ScanJob, Service, Target
from app.modules.autorecon.router import _parse_help_options
from app.modules.autorecon.service import (
    import_autorecon_run, render_autorecon_command, run_output_dir,
)


def test_parse_help_options_includes_global_and_plugin_arguments():
    parsed = _parse_help_options("""
options:
  -p, --ports PORTS     Comma separated ports.
  --no-port-dirs        Don't create port directories.
plugin arguments:
  --dirbuster.tool {feroxbuster,ffuf}
                        Tool to use. Default: feroxbuster
""")

    assert [item["flag"] for item in parsed] == [
        "--ports", "--no-port-dirs", "--dirbuster.tool"]
    assert parsed[-1]["description"] == "Tool to use. Default: feroxbuster"


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
    # import_autorecon_run skips anything (including the XML) modified
    # within the last _QUIET_PERIOD_SECONDS (still-being-written) -- backdate
    # these so the fixture reads as "settled" the way real completed AutoRecon
    # output would by the time a poll (or the final import) reaches it.
    settled = time.time() - 60
    os.utime(scans / "xml" / "_full_tcp_nmap.xml", (settled, settled))
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
    assert "--only-scans-dir" not in argv


def test_render_autorecon_command_passes_native_options_through():
    target = Target(project_id=1, name="a", ip="10.10.10.10")
    argv = render_autorecon_command(
        [target], Path("/tmp/out"),
        ["--tags", "safe", "--heartbeat", "15", "--timeout", "120"])
    assert argv == [
        "autorecon", "10.10.10.10", "--disable-keyboard-control",
        "--ignore-plugin-checks", "--tags", "safe", "--heartbeat", "15",
        "--timeout", "120", "-o", "/tmp/out"]


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


def test_import_autorecon_run_uses_quick_xml_while_full_xml_is_truncated(tmp_path):
    # Regression test: a full -p- nmap scan against a real target can take
    # long enough that _full_tcp_nmap.xml is still mid-write (truncated,
    # unclosed tags) well after per-service result files have already
    # settled -- confirmed live, a run sat at imported_count=0 for 4+
    # minutes with real tcp80/ files already on disk. The bug was
    # `except ValueError` around ingest_xml, which never matches
    # xml.etree.ElementTree.ParseError (a SyntaxError subclass) -- so the
    # exception propagated out of this function entirely and the file-import
    # loop below the XML step never ran, every single poll.
    db = database()
    project = Project(name="Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="127.0.0.1")
    db.add(target); db.flush()
    scans = tmp_path / "127.0.0.1" / "scans"
    (scans / "xml").mkdir(parents=True)
    # Deliberately unclosed -- exactly what a parser sees mid-write.
    (scans / "xml" / "_full_tcp_nmap.xml").write_bytes(
        b'<nmaprun><host><address addr="127.0.0.1"/><ports>\n'
        b'<port protocol="tcp" portid="80"><state state="open"/>')
    (scans / "xml" / "_quick_tcp_nmap.xml").write_bytes(
        b'<nmaprun><host><address addr="127.0.0.1"/><ports>'
        b'<port protocol="tcp" portid="80"><state state="open"/>'
        b'<service name="http"/></port></ports></host></nmaprun>')
    settled = time.time() - 60
    os.utime(scans / "xml" / "_full_tcp_nmap.xml", (settled, settled))
    os.utime(scans / "xml" / "_quick_tcp_nmap.xml", (settled, settled))
    tcp80 = scans / "tcp80"
    tcp80.mkdir()
    (tcp80 / "tcp_80_http_whatweb.txt").write_text("WhatWeb report for http://127.0.0.1:80\n")
    os.utime(tcp80 / "tcp_80_http_whatweb.txt", (settled, settled))
    run = AutoReconRun(project_id=project.id, target_ids=json.dumps([target.id]),
                       command="autorecon 127.0.0.1", output_dir=str(tmp_path),
                       status="running")
    db.add(run); db.commit()

    imported = import_autorecon_run(db, run)

    assert imported == 1
    service = db.query(Service).one()
    execution = db.query(Execution).one()
    assert execution.template_id == "autorecon-whatweb"
    assert execution.service_id == service.id


def test_import_autorecon_run_relinks_an_execution_imported_before_service(tmp_path):
    db = database()
    project = Project(name="Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="127.0.0.1")
    db.add(target); db.flush()
    scans = tmp_path / "127.0.0.1" / "scans"
    tcp80 = scans / "tcp80"
    tcp80.mkdir(parents=True)
    result = tcp80 / "tcp_80_http_whatweb.txt"
    result.write_text("WhatWeb report for http://127.0.0.1:80\n")
    settled = time.time() - 60
    os.utime(result, (settled, settled))
    run = AutoReconRun(project_id=project.id, target_ids=json.dumps([target.id]),
                       command="autorecon 127.0.0.1", output_dir=str(tmp_path),
                       status="running")
    db.add(run); db.commit()

    assert import_autorecon_run(db, run) == 1
    execution = db.query(Execution).one()
    assert execution.service_id is None

    xml_dir = scans / "xml"
    xml_dir.mkdir()
    quick_xml = xml_dir / "_quick_tcp_nmap.xml"
    quick_xml.write_bytes(
        b'<nmaprun><host><address addr="127.0.0.1"/><ports>'
        b'<port protocol="tcp" portid="80"><state state="open"/>'
        b'<service name="http"/></port></ports></host></nmaprun>')
    os.utime(quick_xml, (settled, settled))

    assert import_autorecon_run(db, run) == 0
    db.refresh(execution)
    assert execution.service_id == db.query(Service).one().id
    assert execution.template_id == "autorecon-whatweb"


def test_import_autorecon_run_imports_udp_services_and_results(tmp_path):
    db = database()
    project = Project(name="Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="127.0.0.1")
    db.add(target); db.flush()
    scans = tmp_path / "127.0.0.1" / "scans"
    xml_dir = scans / "xml"
    xml_dir.mkdir(parents=True)
    udp_xml = xml_dir / "_top_100_udp_nmap.xml"
    udp_xml.write_bytes(
        b'<nmaprun><host><address addr="127.0.0.1"/><ports>'
        b'<port protocol="udp" portid="161"><state state="open"/>'
        b'<service name="snmp"/></port></ports></host></nmaprun>')
    udp161 = scans / "udp161"
    udp161.mkdir()
    result = udp161 / "udp_161_snmp_snmpwalk.txt"
    result.write_text("SNMPv2-MIB::sysDescr.0 = Linux\n")
    settled = time.time() - 60
    os.utime(udp_xml, (settled, settled))
    os.utime(result, (settled, settled))
    run = AutoReconRun(project_id=project.id, target_ids=json.dumps([target.id]),
                       command="autorecon 127.0.0.1", output_dir=str(tmp_path),
                       status="running")
    db.add(run); db.commit()

    assert import_autorecon_run(db, run) == 1
    service = db.query(Service).one()
    execution = db.query(Execution).one()
    assert (service.protocol, service.port, service.name) == ("udp", 161, "snmp")
    assert execution.service_id == service.id
    assert execution.template_id == "autorecon-snmpwalk"


def test_import_autorecon_run_registers_native_logs_after_completion(tmp_path):
    db = database()
    project = Project(name="Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="127.0.0.1")
    db.add(target); db.flush()
    scans = tmp_path / "127.0.0.1" / "scans"
    scans.mkdir(parents=True)
    commands = scans / "_commands.log"
    commands.write_text("nmap -sV 127.0.0.1\n")
    report = tmp_path / "127.0.0.1" / "report" / "report.md"
    report.parent.mkdir()
    report.write_text("# AutoRecon report\n")
    run = AutoReconRun(project_id=project.id, target_ids=json.dumps([target.id]),
                       command="autorecon 127.0.0.1", output_dir=str(tmp_path),
                       status="completed")
    db.add(run); db.commit()

    import_autorecon_run(db, run)

    paths = {Path(row.path) for row in db.query(ScanArtifact).all()}
    assert {commands, report} <= paths


def test_import_autorecon_run_supports_no_port_dirs_layout(tmp_path):
    db = database()
    project = Project(name="Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="127.0.0.1")
    db.add(target); db.flush()
    scans = tmp_path / "127.0.0.1" / "scans"
    xml_dir = scans / "xml"
    xml_dir.mkdir(parents=True)
    quick = xml_dir / "_quick_tcp_nmap.xml"
    quick.write_bytes(
        b'<nmaprun><host><address addr="127.0.0.1"/><ports>'
        b'<port protocol="tcp" portid="80"><state state="open"/>'
        b'<service name="http"/></port></ports></host></nmaprun>')
    result = scans / "tcp_80_http_whatweb.txt"
    result.write_text("http://127.0.0.1 [200 OK]\n")
    settled = time.time() - 60
    os.utime(quick, (settled, settled)); os.utime(result, (settled, settled))
    run = AutoReconRun(project_id=project.id, target_ids=json.dumps([target.id]),
                       command="autorecon --no-port-dirs 127.0.0.1",
                       output_dir=str(tmp_path), status="running")
    db.add(run); db.commit()

    assert import_autorecon_run(db, run) == 1
    execution = db.query(Execution).one()
    assert execution.service_id == db.query(Service).one().id
    assert execution.template_id == "autorecon-whatweb"
