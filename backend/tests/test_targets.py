import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.main import (
    anonymous_ftp_command,
    delete_project,
    ensure_target,
    update_service,
)
from app.models import Base, Project, RunbookInstance, ScanJob, Service, Target
from app.modules import hosts
from app.modules.core.router import delete_target, project_services, set_target_hostname
from app.modules.runbooks.support import ApplyIn, PublishIn, StepIn, TemplateIn
from app.modules.runbooks.workflow_router import (
    apply, create_template, instances, publish,
)
from app.schemas import ServiceUpdate, TargetEnsureIn, TargetHostnameIn


@pytest.fixture(autouse=True)
def isolated_hosts_file(tmp_path, monkeypatch):
    path = tmp_path / "hosts"
    path.write_text("127.0.0.1\tlocalhost\n")
    monkeypatch.setattr(hosts, "HOSTS_PATH", path)
    return path


def test_anonymous_ftp_command_logs_in_without_password_prompt():
    assert anonymous_ftp_command("10.129.207.145", 21) == [
        "/usr/bin/env", "FTPANONPASS=IEUser@", "ftp", "-a",
        "10.129.207.145", "21",
    ]


def database(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'targets.db'}")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def test_ensure_target_creates_ip_project_once(tmp_path):
    db = database(tmp_path)
    ip = "198.51.100.241"
    first = ensure_target(TargetEnsureIn(ip=ip), db)
    second = ensure_target(TargetEnsureIn(ip=ip, name="ignored"), db)
    assert first.id == second.id
    assert first.name == ip
    project = db.scalar(select(Project).where(Project.id == first.project_id))
    assert project and project.name == ip
    db.close()


def test_ensure_target_rejects_invalid_ip_before_database_write(tmp_path):
    db = database(tmp_path)
    with pytest.raises(ValidationError):
        TargetEnsureIn(ip="not-an-ip")
    assert db.scalars(select(Project)).all() == []
    db.close()


def test_reviewed_service_identity_is_persisted(tmp_path):
    db = database(tmp_path)
    project = Project(name="Lab", description="")
    db.add(project)
    db.flush()
    target = Target(project_id=project.id, name="Host", ip="198.51.100.10")
    db.add(target)
    db.flush()
    service = Service(
        target_id=target.id, port=23, protocol="tcp", state="open",
        name="telnet", product="", version="", extra_info="", scripts="{}",
        notes="", tags="[]",
    )
    db.add(service)
    db.commit()

    update_service(
        service.id,
        ServiceUpdate(
            product="Linux telnetd", version="0.17",
            notes="Banner reviewed", tags=["reviewed"],
        ),
        db,
    )
    db.expire_all()

    saved = db.get(Service, service.id)
    assert saved
    assert (saved.product, saved.version) == ("Linux telnetd", "0.17")
    db.close()


def test_project_services_spans_every_target_in_the_project(tmp_path):
    db = database(tmp_path)
    project = Project(name="Multi-target", description="")
    db.add(project)
    db.flush()
    other_project = Project(name="Unrelated", description="")
    db.add(other_project)
    db.flush()
    web_target = Target(project_id=project.id, name="Web box", ip="198.51.100.30")
    dc_target = Target(project_id=project.id, name="DC", ip="198.51.100.31")
    other_target = Target(project_id=other_project.id, name="Other", ip="198.51.100.32")
    db.add_all([web_target, dc_target, other_target])
    db.flush()
    db.add_all([
        Service(target_id=web_target.id, port=80, protocol="tcp", state="open",
                name="http", product="", version="", extra_info="", scripts="{}",
                notes="", tags="[]"),
        Service(target_id=dc_target.id, port=53, protocol="tcp", state="open",
                name="domain", product="", version="", extra_info="", scripts="{}",
                notes="", tags="[]"),
        Service(target_id=other_target.id, port=22, protocol="tcp", state="open",
                name="ssh", product="", version="", extra_info="", scripts="{}",
                notes="", tags="[]"),
    ])
    db.commit()

    result = project_services(project.id, db)

    assert {(row.target_id, row.port) for row in result} == {
        (web_target.id, 80), (dc_target.id, 53),
    }
    db.close()


def test_project_services_is_empty_for_a_project_with_no_targets(tmp_path):
    db = database(tmp_path)
    project = Project(name="Empty", description="")
    db.add(project)
    db.commit()

    assert project_services(project.id, db) == []
    db.close()


def test_delete_project_removes_connected_workspace_records(tmp_path):
    db = database(tmp_path)
    project = Project(name="Disposable", description="")
    db.add(project)
    db.flush()
    target = Target(project_id=project.id, name="Host", ip="198.51.100.20")
    db.add(target)
    db.flush()
    service = Service(
        target_id=target.id, port=23, protocol="tcp", state="open",
        name="telnet", product="", version="", extra_info="", scripts="{}",
        notes="", tags="[]",
    )
    db.add(service)
    db.add(ScanJob(
        project_id=project.id, target_id=target.id, source="import",
        status="completed", command="fixture", error="", alias="", tags="[]",
    ))
    db.commit()
    template = create_template(TemplateIn(
        name="Disposable FTP", service_names=["telnet"]), db)
    version = publish(template["id"], PublishIn(
        steps=[StepIn(title="Check service")]), db)
    runbook = apply(ApplyIn(
        version_id=version["id"], target_id=target.id,
        service_id=service.id), db)
    project_id, target_id, service_id = project.id, target.id, service.id

    delete_project(project_id, db)

    assert db.get(Project, project_id) is None
    assert db.get(Target, target_id) is None
    assert db.get(Service, service_id) is None
    assert db.get(RunbookInstance, runbook["id"]) is None
    assert db.scalars(select(ScanJob).where(
        ScanJob.project_id == project_id)).all() == []

    replacement = Project(name="Replacement", description="")
    db.add(replacement); db.flush()
    replacement_target = Target(
        project_id=replacement.id, name="New host", ip="198.51.100.21")
    db.add(replacement_target); db.commit()
    assert replacement_target.id == target_id
    assert instances(target_id=replacement_target.id, db=db) == []
    db.close()


def test_delete_project_releases_its_targets_hostnames(tmp_path):
    db = database(tmp_path)
    project = Project(name="Disposable", description="")
    db.add(project); db.flush()
    target = Target(
        project_id=project.id, name="Host", ip="10.129.1.1", hostname="box.htb")
    db.add(target); db.commit()
    hosts.sync_host(hosts.HostsSync(ip="10.129.1.1", hostname="box.htb"))

    delete_project(project.id, db)

    assert "box.htb" not in hosts.list_synced_hosts()["entries"]


def test_delete_project_keeps_hostname_still_used_by_another_project(tmp_path):
    db = database(tmp_path)
    project = Project(name="Disposable", description="")
    db.add(project); db.flush()
    target = Target(
        project_id=project.id, name="Host", ip="10.129.1.1", hostname="box.htb")
    db.add(target)
    other_project = Project(name="Kept", description="")
    db.add(other_project); db.flush()
    other_target = Target(
        project_id=other_project.id, name="Host", ip="10.129.1.1",
        hostname="box.htb")
    db.add(other_target); db.commit()
    hosts.sync_host(hosts.HostsSync(ip="10.129.1.1", hostname="box.htb"))

    delete_project(project.id, db)

    assert "box.htb" in hosts.list_synced_hosts()["entries"]


def test_delete_target_releases_its_hostname(tmp_path):
    db = database(tmp_path)
    project = Project(name="P", description="")
    db.add(project); db.flush()
    target = Target(
        project_id=project.id, name="Host", ip="10.129.1.1", hostname="box.htb")
    db.add(target); db.commit()
    hosts.sync_host(hosts.HostsSync(ip="10.129.1.1", hostname="box.htb"))

    delete_target(target.id, db)

    assert "box.htb" not in hosts.list_synced_hosts()["entries"]


def test_set_target_hostname_releases_the_previous_hostname(tmp_path):
    db = database(tmp_path)
    project = Project(name="P", description="")
    db.add(project); db.flush()
    target = Target(
        project_id=project.id, name="Host", ip="10.129.1.1", hostname="old.htb")
    db.add(target); db.commit()
    hosts.sync_host(hosts.HostsSync(ip="10.129.1.1", hostname="old.htb"))

    set_target_hostname(target.id, TargetHostnameIn(hostname="new.htb"), db)

    entries = hosts.list_synced_hosts()["entries"]
    assert "old.htb" not in entries


def test_set_target_hostname_accepts_a_pasted_url(tmp_path):
    db = database(tmp_path)
    project = Project(name="P", description="")
    db.add(project); db.flush()
    target = Target(
        project_id=project.id, name="Host", ip="10.129.1.1", hostname="")
    db.add(target); db.commit()

    updated = set_target_hostname(
        target.id, TargetHostnameIn(hostname="http://unika.htb/"), db)

    assert updated.hostname == "unika.htb"
