from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.database import Base
from app.models import Project, ScanArtifact, ScanProfile, Target
from app.models import ScanJob, ServiceObservation
from app.modules.scan_center.router import (
    download_artifact, export_observations, update_job,
)
from app.modules.scan_center.service import compare_jobs, import_xml, render_scan
from app.schemas import ScanJobUpdate

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
