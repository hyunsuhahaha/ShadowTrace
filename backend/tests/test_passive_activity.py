import json
import os
from datetime import datetime, timedelta, timezone
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
        "capture_truncated": True,
    }
    (inbox / "capture.json").write_text(json.dumps(metadata))

    assert service.sync_inbox(db) == {"processed": 1, "failed": 0}
    activity = db.query(PassiveActivity).one()
    assert activity.status == "observed"
    assert activity.confidence == 60
    assert "truncation or event loss" in activity.error
    assert db.query(Target).filter_by(ip="10.10.11.23").one()
    assert {(row.port, row.name) for row in db.query(Service)} == {(22, "ssh"), (80, "http")}
    assert db.query(ServiceObservation).count() == 2
    assert db.query(ScanJob).filter_by(source="passive").count() == 1
    assert db.query(Evidence).count() == 1
    assert db.query(Finding).count() == 0
    assert {row.type for row in db.query(GraphNode)} >= {"project-root", "host", "service"}
    assert Path(activity.output_path).read_bytes() == output
    assert not (inbox / "capture.out").exists()

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


def test_passive_nmap_xml_stdout_preserves_structured_service_and_evidence(
        tmp_path, monkeypatch):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    monkeypatch.setattr(service, "INBOX", inbox)
    monkeypatch.setattr(service, "ARCHIVE", tmp_path / "archive")
    import app.modules.scan_center.service as scan_service
    monkeypatch.setattr(scan_service, "WORKSPACE_DIR", tmp_path / "workspace")
    db = database()
    db.autoflush = False
    db.add(Project(name="Lab", description=""))
    db.commit()
    xml = (b'<?xml version="1.0"?><nmaprun><host><address addr="10.10.11.23"/>'
           b'<ports><port protocol="tcp" portid="22"><state state="open"/>'
           b'<service name="ssh" product="OpenSSH" version="9.2"/>'
           b'</port></ports></host></nmaprun>')
    (inbox / "capture.out").write_bytes(xml)
    (inbox / "capture.json").write_text(json.dumps({
        "process_key": "boot:xml:1", "pid": 9, "uid": 1000,
        "argv": ["nmap", "-oX", "-", "10.10.11.23"],
        "output_file": "capture.out",
    }))

    assert service.sync_inbox(db) == {"processed": 1, "failed": 0}
    activity = db.query(PassiveActivity).one()
    assert activity.status == "observed"
    assert activity.parser == "nmap-xml-v1"
    row = db.query(Service).one()
    assert (row.name, row.product, row.version) == ("ssh", "OpenSSH", "9.2")
    artifact = db.query(Evidence).one()
    assert Path(artifact.file_path).read_bytes() == xml
    assert db.query(Finding).count() == 0


def test_malformed_passive_xml_is_unresolved_not_server_error(tmp_path, monkeypatch):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    monkeypatch.setattr(service, "INBOX", inbox)
    monkeypatch.setattr(service, "ARCHIVE", tmp_path / "archive")
    db = database()
    db.add(Project(name="Lab", description=""))
    db.commit()
    (inbox / "capture.out").write_bytes(b"<?xml version='1.0'?><nmaprun><host>")
    (inbox / "capture.json").write_text(json.dumps({
        "process_key": "boot:broken:1", "pid": 10, "uid": 1000,
        "argv": ["nmap", "-oX", "-", "10.10.11.23"],
        "output_file": "capture.out",
    }))

    assert service.sync_inbox(db) == {"processed": 1, "failed": 0}
    activity = db.query(PassiveActivity).one()
    assert activity.status == "unresolved"
    assert activity.parser == "nmap-xml-v1"
    assert "invalid Nmap XML" in activity.error
    assert db.query(ScanJob).count() == 0


def test_declared_nmap_oa_xml_enriches_stdout_observation(tmp_path, monkeypatch):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    monkeypatch.setattr(service, "INBOX", inbox)
    monkeypatch.setattr(service, "ARCHIVE", tmp_path / "archive")
    import app.modules.scan_center.service as scan_service
    monkeypatch.setattr(scan_service, "WORKSPACE_DIR", tmp_path / "workspace")
    db = database()
    db.autoflush = False
    db.add(Project(name="Lab", description=""))
    db.commit()
    start = datetime.now(timezone.utc) - timedelta(seconds=1)
    xml = (b'<nmaprun><host><address addr="10.10.11.23"/><ports>'
           b'<port protocol="tcp" portid="80"><state state="open"/>'
           b'<service name="http" product="Apache" version="2.4"/>'
           b'</port></ports></host></nmaprun>')
    (tmp_path / "scan.xml").write_bytes(xml)
    output = b"Nmap scan report for 10.10.11.23\n80/tcp open http\n"
    (inbox / "capture.out").write_bytes(output)
    (inbox / "capture.json").write_text(json.dumps({
        "process_key": "boot:oa:1", "pid": 11, "uid": os.getuid(),
        "argv": ["nmap", "-oA", "scan", "10.10.11.23"],
        "cwd": str(tmp_path), "started_at": start.isoformat(),
        "ended_at": datetime.now(timezone.utc).isoformat(),
        "output_file": "capture.out",
    }))

    assert service.sync_inbox(db) == {"processed": 1, "failed": 0}
    activity = db.query(PassiveActivity).one()
    assert activity.parser == "nmap-xml-v1"
    row = db.query(Service).one()
    assert (row.product, row.version) == ("Apache", "2.4")
    assert db.query(Evidence).count() == 2
    assert Path(activity.output_path).read_bytes() == xml


def test_declared_nmap_xml_symlink_is_not_read(tmp_path):
    assert service._declared_xml_path(["nmap", "-oA", "scan"], "") is None
    xml = tmp_path / "unrelated.xml"
    xml.write_bytes(b"<nmaprun/>")
    (tmp_path / "scan.xml").symlink_to(xml)
    now = datetime.now(timezone.utc).isoformat()
    assert service._fresh_declared_xml(
        ["nmap", "-oA", "scan", "10.10.11.23"],
        {"cwd": str(tmp_path), "started_at": now, "ended_at": now}) is None
    (tmp_path / "scan.xml").unlink()
    (tmp_path / "scan.xml").write_bytes(b"<nmaprun/>")
    stale = datetime.now(timezone.utc).timestamp() - 3600
    os.utime(tmp_path / "scan.xml", (stale, stale))
    assert service._fresh_declared_xml(
        ["nmap", "-oA", "scan", "10.10.11.23"],
        {"cwd": str(tmp_path), "started_at": now, "ended_at": now}) is None


def test_passive_ffuf_json_becomes_sensitive_evidence_without_finding(
        tmp_path, monkeypatch):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    monkeypatch.setattr(service, "INBOX", inbox)
    monkeypatch.setattr(service, "ARCHIVE", tmp_path / "archive")
    monkeypatch.setattr(service, "WORKSPACE_DIR", tmp_path / "workspace")
    db = database()
    project = Project(name="Lab")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Loopback", ip="127.0.0.1")
    db.add(target); db.commit()
    url = "http://127.0.0.1:8000/FUZZ"
    content = json.dumps({
        "config": {"url": url},
        "results": [{"url": "http://127.0.0.1:8000/docs", "status": 200,
                     "length": 1010, "input": {"FUZZ": "docs"}}],
    }).encode()
    (tmp_path / "ffuf.json").write_bytes(content)
    (inbox / "capture.out").write_bytes(b"docs\n")
    start = datetime.now(timezone.utc) - timedelta(seconds=1)
    metadata = {
        "process_key": "boot:ffuf:1", "pid": 77, "uid": os.getuid(),
        "argv": ["ffuf", "-u", url, "-w", "/tmp/words", "-of", "json",
                 "-o", "ffuf.json"],
        "cwd": str(tmp_path), "started_at": start.isoformat(),
        "ended_at": datetime.now(timezone.utc).isoformat(),
        "output_file": "capture.out", "exit_code": 0,
    }
    (inbox / "capture.json").write_text(json.dumps(metadata))

    assert service.sync_inbox(db) == {"processed": 1, "failed": 0}
    activity = db.query(PassiveActivity).one()
    evidence = db.query(Evidence).one()
    assert (activity.status, activity.parser, activity.target_id) == (
        "observed", "ffuf-json-v1", target.id)
    assert evidence.source_type == "passive_activity"
    assert evidence.source_id == activity.id
    assert evidence.sensitivity == "sensitive"
    assert Path(evidence.file_path).read_bytes() == content
    assert db.query(Finding).count() == 0
    assert db.query(ServiceObservation).count() == 0
    (inbox / "capture.json").write_text(json.dumps(metadata))
    assert service.sync_inbox(db) == {"processed": 1, "failed": 0}
    assert db.query(Evidence).count() == 1


def test_passive_ffuf_rejects_cross_target_json(tmp_path, monkeypatch):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    monkeypatch.setattr(service, "INBOX", inbox)
    monkeypatch.setattr(service, "ARCHIVE", tmp_path / "archive")
    db = database()
    project = Project(name="Lab")
    db.add(project); db.flush()
    db.add(Target(project_id=project.id, name="Loopback", ip="127.0.0.1"))
    db.commit()
    url = "http://127.0.0.1:8000/FUZZ"
    (tmp_path / "ffuf.json").write_text(json.dumps({
        "config": {"url": url},
        "results": [{"url": "http://10.10.11.23/private", "status": 200}],
    }))
    (inbox / "capture.out").write_bytes(b"")
    (inbox / "capture.json").write_text(json.dumps({
        "process_key": "boot:ffuf:2", "pid": 78, "uid": os.getuid(),
        "argv": ["ffuf", "-u", url, "-o", "ffuf.json"],
        "cwd": str(tmp_path),
        "started_at": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
        "ended_at": datetime.now(timezone.utc).isoformat(),
        "output_file": "capture.out", "exit_code": 0,
    }))
    assert service.sync_inbox(db) == {"processed": 1, "failed": 0}
    assert db.query(PassiveActivity).one().status == "unresolved"
    assert db.query(Evidence).count() == 0


def test_passive_curl_declared_output_is_sensitive_evidence(tmp_path, monkeypatch):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    monkeypatch.setattr(service, "INBOX", inbox)
    monkeypatch.setattr(service, "ARCHIVE", tmp_path / "archive")
    monkeypatch.setattr(service, "WORKSPACE_DIR", tmp_path / "workspace")
    db = database()
    project = Project(name="Lab")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Loopback", ip="127.0.0.1")
    db.add(target); db.commit()
    content = b"<html>local test</html>"
    (tmp_path / "body.html").write_bytes(content)
    (inbox / "capture.out").write_bytes(b"")
    metadata = {
        "process_key": "boot:curl:1", "pid": 79, "uid": os.getuid(),
        "argv": ["curl", "-sS", "--output", "body.html",
                 "http://127.0.0.1:8000/docs"],
        "cwd": str(tmp_path),
        "started_at": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
        "ended_at": datetime.now(timezone.utc).isoformat(),
        "output_file": "capture.out", "exit_code": 0,
    }
    (inbox / "capture.json").write_text(json.dumps(metadata))

    assert service.sync_inbox(db) == {"processed": 1, "failed": 0}
    activity = db.query(PassiveActivity).one()
    evidence = db.query(Evidence).one()
    assert (activity.status, activity.parser, activity.target_id) == (
        "observed", "curl-output-v1", target.id)
    assert activity.confidence == 60
    assert evidence.sensitivity == "sensitive"
    assert evidence.source_type == "passive_activity"
    assert evidence.source_id == activity.id
    assert evidence.original_name == "body.html"
    assert Path(evidence.file_path).read_bytes() == content
    assert db.query(Finding).count() == 0
    assert db.query(ServiceObservation).count() == 0
    (inbox / "capture.json").write_text(json.dumps(metadata))
    assert service.sync_inbox(db) == {"processed": 1, "failed": 0}
    assert db.query(Evidence).count() == 1


def test_passive_curl_rejects_redirect_or_multiple_urls(tmp_path, monkeypatch):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    monkeypatch.setattr(service, "INBOX", inbox)
    monkeypatch.setattr(service, "ARCHIVE", tmp_path / "archive")
    db = database()
    project = Project(name="Lab")
    db.add(project); db.flush()
    db.add(Target(project_id=project.id, name="Loopback", ip="127.0.0.1"))
    db.commit()
    (tmp_path / "body.html").write_bytes(b"response")
    (inbox / "capture.out").write_bytes(b"")
    for index, extra in enumerate((["-L"], ["http://10.10.11.23/"]), 1):
        (inbox / f"capture-{index}.out").write_bytes(b"")
        (inbox / f"capture-{index}.json").write_text(json.dumps({
            "process_key": f"boot:curl:reject:{index}", "pid": 80 + index,
            "uid": os.getuid(),
            "argv": ["curl", "-s", "-o", "body.html",
                     "http://127.0.0.1:8000/docs", *extra],
            "cwd": str(tmp_path),
            "started_at": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
            "ended_at": datetime.now(timezone.utc).isoformat(),
            "output_file": f"capture-{index}.out", "exit_code": 0,
        }))
    assert service.sync_inbox(db) == {"processed": 2, "failed": 0}
    assert {row.status for row in db.query(PassiveActivity)} == {"unresolved"}
    assert db.query(Evidence).count() == 0
