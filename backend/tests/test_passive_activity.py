import json
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.database import Base
from app.models import (
    Evidence, Finding, GraphNode, PassiveActivity, Project, ScanJob,
    Service, ServiceObservation, Target,
)
from app.modules.passive_activity import service


def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def test_parse_nmap_text_keeps_facts_and_provenance():
    output = """\x1b[32mNmap scan report for box.local (10.10.11.23)\x1b[0m
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian
80/tcp open  http    Apache httpd
443/tcp filtered https
"""
    host = service.parse_nmap_text(output, "10.10.11.23", 7)[0]
    assert host["hostname"] == "box.local"
    assert [(row["port"], row["state"], row["name"])
            for row in host["services"]] == [
        (22, "open", "ssh"), (80, "open", "http"), (443, "filtered", "https")]
    assert host["services"][0]["product"] == ""
    assert host["services"][0]["detection_evidence"]["activity_id"] == 7
    assert service._redact_argv([
        "nmap", "--script-args", "user=john,password=hunter2,token=abc",
    ])[-1] == "user=john,password=<redacted>,token=<redacted>"


def test_passive_nmap_creates_observations_services_and_graph_without_finding(
        tmp_path, monkeypatch):
    inbox, archive = tmp_path / "inbox", tmp_path / "archive"
    inbox.mkdir()
    monkeypatch.setattr(service, "INBOX", inbox)
    monkeypatch.setattr(service, "ARCHIVE", archive)
    import app.modules.scan_center.service as scan_service
    monkeypatch.setattr(scan_service, "WORKSPACE_DIR", tmp_path / "workspace")
    db = database()
    db.add(Project(name="Lab", description=""))
    db.commit()
    output = b"""Starting Nmap
Nmap scan report for 10.10.11.23
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1
80/tcp open  http    Apache httpd
Nmap done
"""
    (inbox / "capture.out").write_bytes(output)
    metadata = {
        "process_key": "boot:4242:100",
        "pid": 4242,
        "ppid": 4000,
        "uid": 1000,
        "argv": ["nmap", "-sC", "-sV", "10.10.11.23"],
        "cwd": "/home/kali/lab",
        "tty": "/dev/pts/3",
        "started_at": "2026-08-27T12:00:00+00:00",
        "ended_at": "2026-08-27T12:00:05+00:00",
        "exit_code": 0,
        "output_file": "capture.out",
    }
    (inbox / "capture.json").write_text(json.dumps(metadata))

    assert service.sync_inbox(db) == {"processed": 1, "failed": 0}
    activity = db.query(PassiveActivity).one()
    assert activity.status == "observed"
    assert activity.confidence == 85
    assert db.query(Target).filter_by(ip="10.10.11.23").one()
    assert {(row.port, row.name) for row in db.query(Service)} == {(22, "ssh"), (80, "http")}
    assert db.query(ServiceObservation).count() == 2
    assert db.query(ScanJob).filter_by(source="passive").count() == 1
    assert db.query(Evidence).count() == 1
    assert db.query(Finding).count() == 0
    assert {row.type for row in db.query(GraphNode)} >= {"project-root", "host", "service"}
    assert Path(activity.output_path).read_bytes() == output

    (inbox / "capture.json").write_text(json.dumps(metadata))
    assert service.sync_inbox(db) == {"processed": 1, "failed": 0}
    assert db.query(PassiveActivity).count() == 1
    assert db.query(ServiceObservation).count() == 2


def test_ambiguous_project_keeps_activity_unresolved(tmp_path, monkeypatch):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    monkeypatch.setattr(service, "INBOX", inbox)
    monkeypatch.setattr(service, "ARCHIVE", tmp_path / "archive")
    db = database()
    db.add_all([Project(name="One", description=""),
                Project(name="Two", description="")])
    db.commit()
    (inbox / "capture.out").write_text(
        "Nmap scan report for 10.10.11.99\n80/tcp open http\n")
    (inbox / "capture.json").write_text(json.dumps({
        "process_key": "boot:1:1", "pid": 1, "ppid": 0, "uid": 1000,
        "argv": ["nmap", "10.10.11.99"], "cwd": "/tmp", "tty": "/dev/pts/1",
        "started_at": "2026-08-27T12:00:00+00:00",
        "ended_at": "2026-08-27T12:00:01+00:00", "exit_code": 0,
        "output_file": "capture.out",
    }))

    assert service.sync_inbox(db) == {"processed": 1, "failed": 0}
    activity = db.query(PassiveActivity).one()
    assert activity.status == "unresolved"
    assert "exactly one project" in activity.error
    assert db.query(Target).count() == 0
    assert db.query(ScanJob).count() == 0
