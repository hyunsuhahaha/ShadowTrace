import asyncio
import base64
import json
import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from app.database import Base
from app.models import HttpExchange, HttpRequest, Project, Target
from app.schemas import ProxyCaptureIn
from app.modules.web_proxy.router import capture, captures, download_ca_cert
import app.modules.web_proxy.router as router_module
import app.modules.web_proxy.manager as manager_module
import pytest
from fastapi import HTTPException


def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def seed(db):
    project = Project(name="Proxy Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.129.219.134")
    db.add(target); db.flush()
    db.commit()
    return project, target


def payload(project, target, **overrides):
    base = dict(
        project_id=project.id, target_id=target.id, method="POST",
        url="http://10.129.219.134/login.php",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        cookies={"PHPSESSID": "abc123"}, body="",
        status_code=200, response_headers={"Content-Type": "text/html"},
        response_cookies={}, response_body="", duration_ms=42,
    )
    base.update(overrides)
    return ProxyCaptureIn(**base)


def test_capture_reuses_the_same_request_and_appends_new_exchanges():
    db = database()
    project, target = seed(db)

    first = capture(payload(project, target), db)
    second = capture(payload(project, target), db)

    requests = db.query(HttpRequest).filter_by(target_id=target.id).all()
    assert len(requests) == 1
    assert json.loads(requests[0].tags) == ["proxy-capture"]
    assert requests[0].folder == "Proxy Capture"
    exchanges = db.query(HttpExchange).filter_by(request_id=requests[0].id).all()
    assert len(exchanges) == 2
    assert {first["id"], second["id"]} == {row.id for row in exchanges}


def test_capture_does_not_merge_into_a_manually_created_request():
    db = database()
    project, target = seed(db)
    manual = HttpRequest(
        project_id=project.id, target_id=target.id, name="Manual login",
        method="POST", url="http://10.129.219.134/login.php")
    db.add(manual); db.commit()

    capture(payload(project, target), db)

    requests = db.query(HttpRequest).filter_by(target_id=target.id).all()
    assert len(requests) == 2
    tagged = [row for row in requests if json.loads(row.tags or "[]") == ["proxy-capture"]]
    assert len(tagged) == 1
    assert manual.body == ""  # the manual request was left untouched


def test_captures_lists_only_proxy_tagged_requests():
    db = database()
    project, target = seed(db)
    db.add(HttpRequest(project_id=project.id, target_id=target.id,
                       name="Manual", method="GET", url="http://10.129.219.134/"))
    db.commit()
    capture(payload(project, target), db)

    result = captures(target.id, db)

    assert len(result) == 1
    assert json.loads(result[0].tags) == ["proxy-capture"]


def test_captures_flags_a_detected_cloud_storage_response():
    db = database()
    project, target = seed(db)
    capture(payload(project, target,
        url="http://s3.the-three.htb/",
        response_headers={"Server": "AmazonS3", "x-amz-request-id": "ABC123"},
        response_body=base64.b64encode(
            b"<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>",
        ).decode(),
    ), db)

    result = captures(target.id, db)

    assert result[0].has_response is True
    assert result[0].cloud_fingerprint["provider"] == "aws-s3"
    assert result[0].cloud_fingerprint["error_code"] == "AccessDenied"


def test_captures_hides_the_fingerprint_when_nothing_is_detected():
    db = database()
    project, target = seed(db)
    capture(payload(project, target,
        response_headers={"Content-Type": "text/html"},
        response_body=base64.b64encode(b"<html>ordinary page</html>").decode(),
    ), db)

    result = captures(target.id, db)

    assert result[0].has_response is True
    assert result[0].cloud_fingerprint is None


def test_captures_marks_no_response_yet_when_the_request_has_no_exchange():
    db = database()
    project, target = seed(db)
    db.add(HttpRequest(project_id=project.id, target_id=target.id,
                       name="Still loading", folder="Proxy Capture",
                       tags=json.dumps(["proxy-capture"]),
                       method="GET", url="http://s3.the-three.htb/"))
    db.commit()

    result = captures(target.id, db)

    assert result[0].has_response is False
    assert result[0].cloud_fingerprint is None


def test_captures_fingerprints_the_latest_exchange_not_the_first():
    db = database()
    project, target = seed(db)
    # Same URL captured twice (e.g. re-visited in the browser) reuses one
    # HttpRequest row with two exchanges — the row should reflect the most
    # recent response, not whichever came first.
    capture(payload(project, target,
        response_headers={"Content-Type": "text/html"},
        response_body=base64.b64encode(b"<html>ordinary page</html>").decode(),
    ), db)
    capture(payload(project, target,
        response_headers={"Server": "AmazonS3", "x-amz-request-id": "XYZ789"},
        response_body=base64.b64encode(
            b"<Error><Code>AccessDenied</Code></Error>").decode(),
    ), db)

    result = captures(target.id, db)

    assert len(result) == 1
    assert result[0].cloud_fingerprint["provider"] == "aws-s3"


def test_ca_cert_download_404s_before_the_proxy_has_ever_started(tmp_path, monkeypatch):
    monkeypatch.setattr(router_module, "CONFDIR", tmp_path / "never-started")
    with pytest.raises(HTTPException) as excinfo:
        download_ca_cert()
    assert excinfo.value.status_code == 404


def test_ca_cert_download_succeeds_once_the_cert_file_exists(tmp_path, monkeypatch):
    confdir = tmp_path / "confdir"
    confdir.mkdir()
    (confdir / "mitmproxy-ca-cert.pem").write_text("fake cert")
    monkeypatch.setattr(router_module, "CONFDIR", confdir)

    response = download_ca_cert()

    assert response.path.name == "mitmproxy-ca-cert.pem"


def test_proxy_manager_start_stop_lifecycle(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'proxy.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(manager_module, "SessionLocal", factory)
    monkeypatch.setattr(manager_module, "CONFDIR", tmp_path / "confdir")
    with factory() as db:
        project = Project(name="Proxy Lab", description="")
        db.add(project); db.flush()
        target = Target(project_id=project.id, name="Box", ip="10.129.219.134")
        db.add(target); db.commit()
        project_id, target_id = project.id, target.id

    # asyncio.create_subprocess_exec doesn't go through a shell, so the fake
    # binary needs its own shebang + exec bit rather than relying on argv[0]
    # being a script path the way `sys.executable script.py` would work —
    # mitmdump's real argv puts flags (-p, --listen-host, ...) right after
    # the binary, which python itself can't parse.
    fake_mitmdump = tmp_path / "fake_mitmdump"
    fake_mitmdump.write_text(
        f"#!{sys.executable}\nimport time\ntime.sleep(60)\n", encoding="utf-8")
    fake_mitmdump.chmod(0o755)
    monkeypatch.setattr(manager_module, "MITMDUMP_BIN", str(fake_mitmdump))

    async def exercise():
        mgr = manager_module.ProxyManager()
        status = await mgr.start(project_id, target_id, 8123)
        assert status["running"] is True
        assert status["target_ip"] == "10.129.219.134"
        assert mgr.status()["running"] is True
        stopped = await mgr.stop()
        assert stopped["running"] is False

    asyncio.run(exercise())


def test_proxy_manager_rejects_a_non_ip_target(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'proxy.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(manager_module, "SessionLocal", factory)
    with factory() as db:
        project = Project(name="Proxy Lab", description="")
        db.add(project); db.flush()
        target = Target(project_id=project.id, name="Box", ip="appointment.htb")
        db.add(target); db.commit()
        project_id, target_id = project.id, target.id

    async def exercise():
        mgr = manager_module.ProxyManager()
        with pytest.raises(ValueError):
            await mgr.start(project_id, target_id, 8124)

    asyncio.run(exercise())
