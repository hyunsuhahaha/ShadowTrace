import json
from pathlib import Path
import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.database import Base
from app.models import Evidence, Execution, Finding, FindingEvidence, Project, ScanArtifact, ScanProfile, Target
from app.models import ScanJob, Service, ServiceObservation
from app.modules.scan_center.router import (
    delete_scan, download_artifact, export_observations, preview, run_scan, update_job,
)
from app.modules.scan_center.service import (
    BUILTIN_PROFILES, compare_jobs, create_chain_job, fan_out_service_executions,
    import_xml, render_scan, seed_profiles,
)
from app.schemas import ScanJobUpdate, ScanPreviewIn

def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)

def test_selected_port_profile_validates_and_renders_argv():
    profile = ScanProfile(name="Detail", kind="selected_ports",
                          arguments="-Pn -sC -sV -p{ports}")
    target = Target(project_id=1, name="box", ip="10.10.10.10")
    command, argv = render_scan(profile, target, "22,80-81")
    assert argv == ["nmap", "-Pn", "-sC", "-sV", "-p22,80-81", "10.10.10.10"]
    assert command.endswith("10.10.10.10")

def test_selected_port_profile_rejects_shell_syntax():
    profile = ScanProfile(name="Detail", kind="selected_ports",
                          arguments="-Pn -p{ports}")
    target = Target(project_id=1, name="box", ip="10.10.10.10")
    try:
        render_scan(profile, target, "80;id")
    except ValueError:
        return
    raise AssertionError("unsafe port input was accepted")

def test_privileged_syn_profile_uses_polkit_without_receiving_a_password():
    profile = ScanProfile(name="SYN", kind="selected_syn_detail",
                          arguments="-Pn -sV -p{ports} -T3")
    target = Target(project_id=1, name="box", ip="10.10.10.10")
    command, argv = render_scan(profile, target, "23,80")
    assert argv[:2] == ["pkexec", "nmap"]
    assert argv[-2:] == ["-T3", "10.10.10.10"]
    assert command.startswith("sudo nmap -Pn -sV")
    assert "password" not in command.lower()

def test_masscan_discovery_profile_is_always_privileged():
    profile = ScanProfile(name="Discovery", kind="masscan_discovery",
                          arguments="-p1-65535 --rate 5000 --open", engine="masscan")
    target = Target(project_id=1, name="box", ip="10.10.10.10")
    command, argv = render_scan(profile, target)
    assert argv[:2] == ["pkexec", "masscan"]
    assert command.startswith("sudo masscan")
    assert argv[-1] == "10.10.10.10"

def test_seed_profiles_adds_and_updates_all_builtin_profiles():
    db = database()
    db.add(ScanProfile(name="Old quick", kind="quick", description="old",
                       arguments="-Pn", builtin=True))
    db.commit()
    seed_profiles(db)
    rows = db.query(ScanProfile).all()
    assert {row.kind for row in rows} == {item[1] for item in BUILTIN_PROFILES}
    assert db.query(ScanProfile).filter_by(kind="quick").one().name == "Top TCP services"

def test_top_ports_are_user_selected_and_bounded():
    profile = ScanProfile(name="Top UDP", kind="udp_top",
                          arguments="-Pn -sU --top-ports {top_ports} -T3")
    target = Target(project_id=1, name="box", ip="10.10.10.10")
    command, argv = render_scan(profile, target, top_ports=200)
    assert "--top-ports" in argv
    assert "200" in argv
    assert command.startswith("sudo nmap")
    try:
        render_scan(profile, target, top_ports=65536)
    except ValueError:
        return
    raise AssertionError("out-of-range top port count was accepted")

def test_operator_can_edit_scan_flags_without_escaping_bound_context():
    profile = ScanProfile(name="Detail", kind="selected_ports", engine="nmap",
                          arguments="-Pn -sV -p{ports}")
    target = Target(project_id=1, name="box", ip="10.10.10.10")
    command, argv = render_scan(
        profile, target, "22", command_override="nmap -Pn -sV --version-all -p22 10.10.10.10"
    )
    assert command == "nmap -Pn -sV --version-all -p22 10.10.10.10"
    assert argv[-2:] == ["-p22", "10.10.10.10"]
    with pytest.raises(ValueError, match="selected target IP"):
        render_scan(profile, target, "22", command_override="nmap -sV 10.10.10.99")
    with pytest.raises(ValueError, match="must execute nmap"):
        render_scan(profile, target, "22", command_override="bash -c id 10.10.10.10")

def test_preview_renders_for_an_unsaved_target_without_persisting_it():
    db = database()
    profile = ScanProfile(name="Quick", kind="quick", engine="nmap", arguments="-Pn -sV")
    db.add(profile)
    db.commit()
    result = preview(ScanPreviewIn(
        target_ip="10.10.10.99", profile_id=profile.id,
    ), db)
    assert result["command"] == "nmap -Pn -sV 10.10.10.99"
    assert db.query(Target).count() == 0

def test_import_preserves_history_and_compare_reports_facts(tmp_path, monkeypatch):
    import app.modules.scan_center.service as service
    monkeypatch.setattr(service, "WORKSPACE_DIR", tmp_path)
    db = database()
    project = Project(name="Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.10")
    db.add(target); db.commit()
    first = b'<nmaprun><host><address addr="10.10.10.10"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8"/></port></ports></host></nmaprun>'
    second = b'<nmaprun><host><address addr="10.10.10.10"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9"/></port><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>'
    before = import_xml(db, target, project, first, "first.xml")
    after = import_xml(db, target, project, second, "second.xml")
    result = compare_jobs(db, before.id, after.id)
    assert result["added"][0]["port"] == 80
    assert result["changed"][0]["changes"]["version"] == {"before": "8", "after": "9"}
    assert (Path(tmp_path) / "projects" / "Lab" / "targets" /
            "10.10.10.10" / "scans" / str(before.id) / "nmap.xml").exists()


def test_blank_scan_identity_does_not_erase_reviewed_service(tmp_path, monkeypatch):
    import app.modules.scan_center.service as service
    monkeypatch.setattr(service, "WORKSPACE_DIR", tmp_path)
    db = database()
    project = Project(name="Lab", description="")
    db.add(project)
    db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.23")
    db.add(target)
    db.commit()
    identified = b'<nmaprun><host><address addr="10.10.10.23"/><ports><port protocol="tcp" portid="23"><state state="open"/><service name="telnet" product="Linux telnetd" version="0.17"/></port></ports></host></nmaprun>'
    blank = b'<nmaprun><host><address addr="10.10.10.23"/><ports><port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port></ports></host></nmaprun>'

    import_xml(db, target, project, identified, "identified.xml")
    import_xml(db, target, project, blank, "blank.xml")

    saved = db.query(Service).filter_by(target_id=target.id, port=23).one()
    assert (saved.product, saved.version) == ("Linux telnetd", "0.17")

def test_scan_manager_runs_streams_and_parses_xml(tmp_path, monkeypatch):
    import asyncio
    import sys
    from sqlalchemy.orm import sessionmaker
    import app.modules.scan_center.manager as manager_module
    import app.modules.scan_center.service as service
    engine = create_engine(f"sqlite:///{tmp_path / 'runner.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(manager_module, "SessionLocal", factory)
    monkeypatch.setattr(service, "WORKSPACE_DIR", tmp_path)
    with factory() as db:
        project = Project(name="Runner Lab", description="")
        db.add(project); db.flush()
        target = Target(project_id=project.id, name="Box", ip="10.10.10.10")
        db.add(target); db.flush()
        job = ScanJob(project_id=project.id, target_id=target.id,
                      source="executed", status="queued", command="fake")
        db.add(job); db.commit(); scan_id = job.id
    script = tmp_path / "fake_nmap.py"
    script.write_text(
        "import pathlib,sys\n"
        "base=pathlib.Path(sys.argv[sys.argv.index('-oA')+1])\n"
        "base.with_suffix('.xml').write_text('<nmaprun><host><address addr=\"10.10.10.10\"/><ports><port protocol=\"tcp\" portid=\"443\"><state state=\"open\"/><service name=\"https\"/></port></ports></host></nmaprun>')\n"
        "base.with_suffix('.nmap').write_text('normal')\n"
        "base.with_suffix('.gnmap').write_text('grepable')\n"
        "print('scan complete')\n"
        "print('diagnostic', file=sys.stderr)\n", encoding="utf-8")
    async def exercise():
        runner = manager_module.ScanManager(1)
        runner.enqueue(scan_id, [sys.executable, str(script), "10.10.10.10"])
        await runner.tasks[scan_id]
    asyncio.run(exercise())
    with factory() as db:
        finished = db.get(ScanJob, scan_id)
        observations = db.query(ServiceObservation).filter_by(scan_job_id=scan_id).all()
        artifacts = db.query(ScanArtifact).filter_by(scan_job_id=scan_id).all()
        assert finished.status == "completed"
        assert observations[0].port == 443
        assert {artifact.kind for artifact in artifacts} >= {
            "stdout", "stderr", "xml", "normal", "grepable"}

def test_scan_manager_detects_masscan_engine_and_triggers_chained_job(tmp_path, monkeypatch):
    import asyncio
    import sys
    from sqlalchemy.orm import sessionmaker
    import app.modules.scan_center.manager as manager_module
    import app.modules.scan_center.service as service
    engine = create_engine(f"sqlite:///{tmp_path / 'masscan_runner.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(manager_module, "SessionLocal", factory)
    monkeypatch.setattr(service, "WORKSPACE_DIR", tmp_path)
    with factory() as db:
        project = Project(name="Masscan Lab", description="")
        db.add(project); db.flush()
        target = Target(project_id=project.id, name="Box", ip="10.10.10.30")
        db.add(target); db.flush()
        job = ScanJob(project_id=project.id, target_id=target.id,
                      source="executed", status="queued", command="fake")
        db.add(job); db.commit(); scan_id = job.id

    # masscan writes one <host> block per open port; the fake binary is named
    # "masscan" so the manager picks -oX instead of Nmap's -oA.
    masscan_script = tmp_path / "masscan"
    masscan_script.write_text(
        "#!/usr/bin/env python3\n"
        "import pathlib,sys\n"
        "path=pathlib.Path(sys.argv[sys.argv.index('-oX')+1])\n"
        "path.write_text('<nmaprun scanner=\"masscan\">"
        "<host><address addr=\"10.10.10.30\"/><ports><port protocol=\"tcp\" portid=\"22\">"
        "<state state=\"open\"/></port></ports></host>"
        "<host><address addr=\"10.10.10.30\"/><ports><port protocol=\"tcp\" portid=\"80\">"
        "<state state=\"open\"/></port></ports></host>"
        "</nmaprun>')\n"
        "print('scan complete')\n", encoding="utf-8")
    masscan_script.chmod(0o755)

    # Stand in for create_chain_job so the test never spawns a real,
    # privileged nmap/pkexec process; it only exercises the manager's
    # "queue the follow-up job" wiring.
    chain_marker = tmp_path / "chain_ran.txt"
    detail_script = tmp_path / "detail.py"
    detail_script.write_text(
        "import pathlib,sys\n"
        f"pathlib.Path({str(chain_marker)!r}).write_text('ran')\n",
        encoding="utf-8")

    def fake_create_chain_job(db, job):
        if job.id != scan_id:
            return None
        chain_job = ScanJob(project_id=job.project_id, target_id=job.target_id,
                            parent_scan_id=job.id, source="executed",
                            status="queued", command="detail scan")
        db.add(chain_job); db.flush()
        return chain_job.id, [sys.executable, str(detail_script), "10.10.10.30"]
    monkeypatch.setattr(manager_module, "create_chain_job", fake_create_chain_job)

    async def exercise():
        runner = manager_module.ScanManager(2)
        runner.enqueue(scan_id, [str(masscan_script), "10.10.10.30"])
        while runner.tasks:
            await asyncio.gather(*list(runner.tasks.values()), return_exceptions=True)
    asyncio.run(exercise())

    with factory() as db:
        finished = db.get(ScanJob, scan_id)
        observations = db.query(ServiceObservation).filter_by(scan_job_id=scan_id).all()
        artifacts = db.query(ScanArtifact).filter_by(scan_job_id=scan_id).all()
        assert finished.status == "completed"
        assert {o.port for o in observations} == {22, 80}
        xml_artifacts = {a.original_name for a in artifacts if a.kind == "xml"}
        assert xml_artifacts == {"masscan.xml"}
        chained = db.query(ScanJob).filter_by(parent_scan_id=scan_id).one()
        assert chained.status == "completed"
    assert chain_marker.exists()

def test_scan_manager_treats_masscan_finding_zero_open_ports_as_completed(tmp_path, monkeypatch):
    # masscan writes nothing at all to its -oX file (not even an empty
    # <nmaprun/>) when it finds zero open ports, rather than crashing the
    # scan as a parse failure the job should just report zero results.
    import asyncio
    import app.modules.scan_center.manager as manager_module
    import app.modules.scan_center.service as service
    from sqlalchemy.orm import sessionmaker
    engine = create_engine(f"sqlite:///{tmp_path / 'masscan_empty.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(manager_module, "SessionLocal", factory)
    monkeypatch.setattr(service, "WORKSPACE_DIR", tmp_path)
    with factory() as db:
        project = Project(name="Empty Masscan Lab", description="")
        db.add(project); db.flush()
        target = Target(project_id=project.id, name="Box", ip="10.10.10.31")
        db.add(target); db.flush()
        job = ScanJob(project_id=project.id, target_id=target.id,
                      source="executed", status="queued", command="fake")
        db.add(job); db.commit(); scan_id = job.id

    masscan_script = tmp_path / "masscan"
    masscan_script.write_text(
        "#!/usr/bin/env python3\n"
        "import pathlib,sys\n"
        "pathlib.Path(sys.argv[sys.argv.index('-oX')+1]).touch()\n"
        "print('scan complete')\n", encoding="utf-8")
    masscan_script.chmod(0o755)

    async def exercise():
        runner = manager_module.ScanManager(1)
        runner.enqueue(scan_id, [str(masscan_script), "10.10.10.31"])
        await runner.tasks[scan_id]
    asyncio.run(exercise())

    with factory() as db:
        finished = db.get(ScanJob, scan_id)
        assert finished.status == "completed"
        assert finished.error == ""
        assert db.query(ServiceObservation).filter_by(scan_job_id=scan_id).count() == 0

def test_create_chain_job_queues_a_detail_scan_from_discovered_open_tcp_ports(tmp_path, monkeypatch):
    import app.modules.scan_center.service as service
    monkeypatch.setattr(service, "WORKSPACE_DIR", tmp_path)
    db = database()
    seed_profiles(db)
    discovery = db.query(ScanProfile).filter_by(kind="masscan_auto_chain").one()
    project = Project(name="Chain Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.40")
    db.add(target); db.commit()
    job = ScanJob(project_id=project.id, target_id=target.id, profile_id=discovery.id,
                  source="executed", status="completed", command="fake")
    db.add(job); db.flush()
    db.add(ServiceObservation(scan_job_id=job.id, target_id=target.id, port=22,
                              protocol="tcp", state="open"))
    db.add(ServiceObservation(scan_job_id=job.id, target_id=target.id, port=80,
                              protocol="tcp", state="open"))
    db.add(ServiceObservation(scan_job_id=job.id, target_id=target.id, port=53,
                              protocol="udp", state="open"))
    db.commit()

    chain_id, argv = create_chain_job(db, job)
    db.commit()

    chained = db.get(ScanJob, chain_id)
    assert chained.parent_scan_id == job.id
    assert chained.status == "queued"
    detail_profile = db.query(ScanProfile).filter_by(kind="selected_syn_detail").one()
    assert chained.profile_id == detail_profile.id
    assert argv[:2] == ["pkexec", "nmap"]
    assert "-p22,80" in argv

def test_create_chain_job_returns_none_without_chain_kind_or_open_ports(tmp_path, monkeypatch):
    import app.modules.scan_center.service as service
    monkeypatch.setattr(service, "WORKSPACE_DIR", tmp_path)
    db = database()
    seed_profiles(db)
    discovery = db.query(ScanProfile).filter_by(kind="masscan_discovery").one()
    auto_chain = db.query(ScanProfile).filter_by(kind="masscan_auto_chain").one()
    project = Project(name="Chain Lab 2", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.41")
    db.add(target); db.commit()

    no_chain_kind_job = ScanJob(project_id=project.id, target_id=target.id,
                                profile_id=discovery.id, source="executed",
                                status="completed", command="fake")
    db.add(no_chain_kind_job); db.flush()
    db.add(ServiceObservation(scan_job_id=no_chain_kind_job.id, target_id=target.id,
                              port=22, protocol="tcp", state="open"))
    db.commit()
    assert create_chain_job(db, no_chain_kind_job) is None

    no_ports_job = ScanJob(project_id=project.id, target_id=target.id,
                           profile_id=auto_chain.id, source="executed",
                           status="completed", command="fake")
    db.add(no_ports_job); db.commit()
    assert create_chain_job(db, no_ports_job) is None

def test_scan_metadata_exports_and_artifact_download(tmp_path, monkeypatch):
    import app.modules.scan_center.service as service
    monkeypatch.setattr(service, "WORKSPACE_DIR", tmp_path)
    db = database()
    project = Project(name="Export Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.11")
    db.add(target); db.commit()
    xml = b'<nmaprun><host><address addr="10.10.10.11"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>'
    job = import_xml(db, target, project, xml, "source.xml")
    updated = update_job(job.id, ScanJobUpdate(alias="web baseline",
                         tags=["initial", "web", "web"]), db)
    assert updated.alias == "web baseline"
    assert updated.tags == '["initial", "web"]'
    exported = export_observations(job.id, "csv", db)
    assert "port,protocol,state" in exported.body.decode()
    artifact = db.query(ScanArtifact).filter_by(scan_job_id=job.id).one()
    response = download_artifact(job.id, artifact.id, db)
    assert Path(response.path).read_bytes() == xml

def test_delete_scan_removes_artifacts_children_and_the_scan_directory(
        tmp_path, monkeypatch):
    import app.modules.scan_center.service as service
    monkeypatch.setattr(service, "WORKSPACE_DIR", tmp_path)
    db = database()
    project = Project(name="Delete Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.13")
    db.add(target); db.commit()
    xml = b'<nmaprun><host><address addr="10.10.10.13"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>'
    job = import_xml(db, target, project, xml, "source.xml")
    child = ScanJob(project_id=project.id, target_id=target.id,
                    parent_scan_id=job.id, source="executed", status="completed",
                    command="nmap -Pn -sC -sV -p80 10.10.10.13")
    db.add(child); db.commit()
    job_dir = service.scan_directory(project, target, job.id)
    assert job_dir.exists()

    delete_scan(job.id, db)

    assert db.get(ScanJob, job.id) is None
    assert db.get(ScanJob, child.id) is None
    assert not job_dir.exists()
    assert db.query(ScanArtifact).filter_by(scan_job_id=job.id).count() == 0
    assert db.query(ServiceObservation).filter_by(scan_job_id=job.id).count() == 0

def test_delete_scan_blocks_a_still_running_scan():
    db = database()
    project = Project(name="Delete Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.14")
    db.add(target); db.commit()
    job = ScanJob(project_id=project.id, target_id=target.id, source="executed",
                 status="running", command="nmap -Pn -p- 10.10.10.14")
    db.add(job); db.commit()

    with pytest.raises(HTTPException) as exc:
        delete_scan(job.id, db)
    assert exc.value.status_code == 409
    assert db.get(ScanJob, job.id) is not None

def test_scan_manager_broadcasts_to_each_subscriber():
    import asyncio
    from app.modules.scan_center.manager import ScanManager
    async def exercise():
        runner = ScanManager()
        first, second = runner.subscribe(7), runner.subscribe(7)
        await runner._publish(7, {"status": "running"})
        assert await first.get() == {"status": "running"}
        assert await second.get() == {"status": "running"}
    asyncio.run(exercise())


def test_import_auto_captures_evidence_and_positive_nse_candidate(tmp_path, monkeypatch):
    import app.modules.scan_center.service as service
    monkeypatch.setattr(service, "WORKSPACE_DIR", tmp_path)
    db = database()
    project = Project(name="Auto Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.12")
    db.add(target); db.commit()
    xml = b"""<nmaprun><host><address addr="10.10.10.12"/><ports>
      <port protocol="tcp" portid="21"><state state="open"/><service name="ftp"/>
        <script id="ftp-anon" output="Anonymous FTP login allowed"/></port>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/>
        <script id="ssh-hostkey" output="2048 SHA256:abc"/></port>
    </ports></host></nmaprun>"""
    job = import_xml(db, target, project, xml, "auto.xml")

    evidence = db.query(Evidence).filter_by(source_type="scan", source_id=job.id).all()
    findings = db.query(Finding).all()
    assert len(evidence) == 2  # original XML plus the finding-specific excerpt
    assert len(findings) == 1
    assert findings[0].status == "Needs Review"
    assert findings[0].disclosure == "INTERNAL"
    assert db.query(FindingEvidence).filter_by(
        finding_id=findings[0].id, evidence_id=evidence[-1].id).one()
    service.capture_scan_evidence(db, job)
    db.commit()
    assert db.query(Evidence).filter_by(
        source_type="scan", source_id=job.id).count() == 2
    assert db.query(Finding).count() == 1


def test_import_does_not_surface_a_service_for_a_scanned_but_closed_port(
        tmp_path, monkeypatch):
    # Nmap emits a <port> element for every port it scanned, not just ones
    # that answered -- a targeted `-p 80,443` scan against a host with
    # nothing on 443 still yields a <port portid="443"> element, just with
    # state="closed". That must not show up in Service Enumeration as if
    # the port were actually found open.
    import app.modules.scan_center.service as service
    monkeypatch.setattr(service, "WORKSPACE_DIR", tmp_path)
    db = database()
    project = Project(name="Closed Port Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.50")
    db.add(target); db.commit()
    xml = b"""<nmaprun><host><address addr="10.10.10.50"/><ports>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
      <port protocol="tcp" portid="443"><state state="closed"/><service name="https"/></port>
    </ports></host></nmaprun>"""

    job = import_xml(db, target, project, xml, "targeted.xml")

    services = db.query(Service).filter_by(target_id=target.id).all()
    assert {s.port for s in services} == {80}
    observations = db.query(ServiceObservation).filter_by(scan_job_id=job.id).all()
    assert {o.port for o in observations} == {80, 443}


def test_negative_nse_result_does_not_create_candidate(tmp_path, monkeypatch):
    import app.modules.scan_center.service as service
    monkeypatch.setattr(service, "WORKSPACE_DIR", tmp_path)
    db = database()
    project = Project(name="Negative Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.13")
    db.add(target); db.commit()
    xml = b"""<nmaprun><host><address addr="10.10.10.13"/><ports>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https"/>
        <script id="ssl-heartbleed" output="NOT VULNERABLE"/></port>
    </ports></host></nmaprun>"""
    import_xml(db, target, project, xml, "negative.xml")
    assert db.query(Finding).count() == 0


def test_run_scan_persists_the_autorecon_tag_at_creation_so_theres_no_race(monkeypatch):
    # tags has to land in the same INSERT as the job -- fan_out_service_executions
    # only reads job.tags once the (possibly very fast) scan chain finishes, so a
    # follow-up PATCH from the frontend could lose the race entirely.
    import app.modules.scan_center.router as router
    monkeypatch.setattr(router.manager, "enqueue", lambda *a, **k: None)
    db = database()
    seed_profiles(db)
    profile = db.query(ScanProfile).filter_by(kind="quick").one()
    project = Project(name="Tag Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.70")
    db.add(target); db.commit()

    import asyncio
    async def exercise():
        return await run_scan(ScanPreviewIn(
            target_id=target.id, profile_id=profile.id, tags=["autorecon"]), db=db)
    job = asyncio.run(exercise())

    assert json.loads(job.tags) == ["autorecon"]
    assert json.loads(db.get(ScanJob, job.id).tags) == ["autorecon"]


def test_fan_out_skips_a_job_without_the_autorecon_tag(monkeypatch):
    import app.modules.scan_center.service as service
    calls = []
    monkeypatch.setattr(service.execution_service, "start_execution",
                        lambda *a, **k: calls.append((a, k)))
    db = database()
    project = Project(name="Fan-out Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.60")
    db.add(target); db.flush()
    db.add(Service(target_id=target.id, port=80, protocol="tcp", name="http",
                   state="open"))
    job = ScanJob(project_id=project.id, target_id=target.id, source="executed",
                 status="completed", command="fake", tags="[]")
    db.add(job); db.commit()

    assert fan_out_service_executions(db, job) == []
    assert calls == []


def test_fan_out_launches_only_autorecon_tagged_matches_grouped_by_service_folder(monkeypatch):
    import app.modules.scan_center.service as service
    launched_calls = []

    def fake_start_execution(db, target, project, svc, template_id, variables,
                             **kwargs):
        launched_calls.append((template_id, kwargs.get("output_subdir")))
        return Execution(target_id=target.id, service_id=svc.id if svc else None,
                         template_id=template_id, command="x", cwd=".",
                         status="queued")
    monkeypatch.setattr(service.execution_service, "start_execution", fake_start_execution)
    db = database()
    project = Project(name="Fan-out Lab 2", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.61")
    db.add(target); db.flush()
    db.add(Service(target_id=target.id, port=80, protocol="tcp", name="http",
                   state="open"))
    # ssh has zero autorecon-tagged catalog commands today -- nothing should
    # launch for it, proving the tag (not just "any match") gates firing.
    db.add(Service(target_id=target.id, port=22, protocol="tcp", name="ssh",
                   state="open"))
    db.flush()
    job = ScanJob(project_id=project.id, target_id=target.id, source="executed",
                 status="completed", command="fake",
                 tags=json.dumps(["autorecon"]))
    db.add(job); db.commit()

    result = fan_out_service_executions(db, job)

    assert len(result) == len(launched_calls)
    assert launched_calls, "expected at least http-headers/http-whatweb to fire"
    assert all(subdir == "tcp80-http" for _, subdir in launched_calls)
    ids = {template_id for template_id, _ in launched_calls}
    assert {"http-headers", "http-whatweb"} <= ids
    # http-directory-fuzz has an empty match{} on purpose (needs a wordlist
    # a human normally supplies) so it never comes back from commands_for()
    # -- the fan-out has to add it back explicitly.
    assert "http-directory-fuzz" in ids
    assert not any(template_id.startswith("ssh-") for template_id, _ in launched_calls)


def test_fan_out_skips_an_item_whose_variables_cannot_be_resolved_but_keeps_going(monkeypatch):
    import app.modules.scan_center.service as service

    def fake_start_execution(db, target, project, svc, template_id, variables,
                             **kwargs):
        if template_id == "dns-dnsrecon-std":
            raise ValueError("Missing or invalid template variables")
        return Execution(target_id=target.id, service_id=svc.id if svc else None,
                         template_id=template_id, command="x", cwd=".",
                         status="queued")
    monkeypatch.setattr(service.execution_service, "start_execution", fake_start_execution)
    db = database()
    project = Project(name="Fan-out Lab 3", description="")
    db.add(project); db.flush()
    # No hostname confirmed, so {domain} genuinely can't be filled in --
    # dns-dnsrecon-std should be attempted and skipped, not abort the batch.
    target = Target(project_id=project.id, name="Box", ip="10.10.10.62")
    db.add(target); db.flush()
    db.add(Service(target_id=target.id, port=53, protocol="tcp", name="domain",
                   state="open"))
    db.flush()
    job = ScanJob(project_id=project.id, target_id=target.id, source="executed",
                 status="completed", command="fake",
                 tags=json.dumps(["autorecon"]))
    db.add(job); db.commit()

    result = fan_out_service_executions(db, job)

    launched_ids = {execution.template_id for execution in result}
    assert "dns-info" in launched_ids
    assert "dns-dnsrecon-std" not in launched_ids


def test_fan_out_fires_wpscan_only_when_the_service_product_looks_like_wordpress(monkeypatch):
    import app.modules.scan_center.service as service
    launched_ids = []
    monkeypatch.setattr(service.execution_service, "start_execution",
        lambda db, target, project, svc, template_id, variables, **kwargs:
            (launched_ids.append(template_id) or Execution(
                target_id=target.id, service_id=svc.id, template_id=template_id,
                command="x", cwd=".", status="queued")))
    db = database()
    project = Project(name="Fan-out Lab 4", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.63")
    db.add(target); db.flush()
    db.add(Service(target_id=target.id, port=80, protocol="tcp", name="http",
                   product="WordPress 6.4", state="open"))
    db.flush()
    job = ScanJob(project_id=project.id, target_id=target.id, source="executed",
                 status="completed", command="fake",
                 tags=json.dumps(["autorecon"]))
    db.add(job); db.commit()

    fan_out_service_executions(db, job)

    assert "http-wpscan" in launched_ids
