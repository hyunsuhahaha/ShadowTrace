from types import SimpleNamespace

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.database import Base
from app.models import (
    Execution, Project, RunbookInstance, RunbookStepExecution,
    RunbookStepInstance, Service, Target,
)
from app.modules.service_intelligence.catalog import catalog
from app.modules.service_intelligence.router import sync_instance_executions
from app.templates import catalog as command_catalog


def service(name, port, product="", cpe="[]", protocol="tcp"):
    return {"id": 1, "name": name, "port": port, "protocol": protocol,
            "product": product, "version": "", "extra_info": "",
            "cpe": cpe, "tls": False, "detection_evidence": "{}"}


def keys(row):
    return [item.key for item in catalog.match(row)]


def test_detected_service_wins_over_standard_port():
    assert "ssh" in keys(service("ssh", 21))
    assert "ftp" not in keys(service("ssh", 21))
    assert "ftp" in keys(service("ftp", 2121))


def test_layered_product_protocol_family_and_generic_matching():
    apache = keys(service("http", 8088, "Apache httpd 2.4"))
    assert "generic_tcp" in apache
    assert "web" in apache
    assert "apache_httpd" in apache
    assert keys(service("unknown", 65000)) == ["generic_tcp"]


def test_msrpc_keeps_smb_context_separate():
    related = [service("microsoft-ds", 445)]
    related[0]["id"] = 2
    data = catalog.build(service("msrpc", 135), related)
    command_ids = {command["id"] for stage in data["stages"]
                   for command in stage["commands"]}
    assert "msrpc-enum" in command_ids
    assert "msrpc-bind-check" in command_ids
    assert "smb-enum" not in command_ids
    assert data["related_services"][0]["merge_with_current"] is False


def execution(template_id, stdout, status="completed"):
    return SimpleNamespace(id=7, template_id=template_id, stdout=stdout,
                           stderr="", status=status)


def test_structured_assessment_requires_positive_signal():
    smb = catalog.assess(execution("smb-enum", "Sharename Type Comment\nWork Disk Files"))
    assert smb["outcome"] == "confirmed"
    assert smb["facts"][0]["value"]["name"] == "Work"
    generic = catalog.assess(execution("generic-banner", ""))
    assert generic["outcome"] == "needs_review"
    failed = catalog.assess(execution("ftp-anon", "", "failed"))
    assert failed["outcome"] == "error"


def test_completed_process_does_not_complete_stage_without_rpc_evidence():
    empty = execution("msrpc-enum", "135/tcp open msrpc")
    data = catalog.build(service("msrpc", 135), executions=[empty])
    endpoints = next(stage for stage in data["stages"]
                     if stage["id"] == "rpc-endpoints")
    assert endpoints["state"] == "review"
    assert endpoints["completed"] is False
    assert endpoints["commands"][0]["outcome"] == "needs_review"

    output = ('RPC_ENDPOINT {"interface": "12345678-1234-1234-1234-123456789abc v1.0", '
              '"annotation": "Example", "binding": "ncacn_ip_tcp:host[49664]"}')
    confirmed = catalog.assess(execution("msrpc-enum", output))
    assert confirmed["outcome"] == "confirmed"
    assert confirmed["facts"][0]["value"]["binding"].endswith("[49664]")


def test_rpc_bind_assessment_distinguishes_valid_denial():
    output = ('RPC_BIND_RESULT {"interface": "12345678-1234-1234-1234-123456789abc v1.0", '
              '"annotation": "Example", "binding": "ncacn_ip_tcp:host[49664]", '
              '"outcome": "access_denied", "detail": "rpc_s_access_denied"}')
    assessed = catalog.assess(execution("msrpc-bind-check", output))
    assert assessed["outcome"] == "access_denied"
    assert assessed["facts"][0]["value"]["outcome"] == "access_denied"


def test_existing_execution_is_automatically_linked_to_applied_runbook():
    db = Session(create_engine("sqlite:///:memory:"))
    Base.metadata.create_all(db.get_bind())
    project = Project(name="Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.10")
    db.add(target); db.flush()
    rpc = Service(target_id=target.id, port=135, protocol="tcp", name="msrpc")
    db.add(rpc); db.flush()
    run = RunbookInstance(
        project_id=project.id, target_id=target.id, service_id=rpc.id,
        version_id=1, template_name="RPC", target_name="Box", service_name="msrpc")
    db.add(run); db.flush()
    step = RunbookStepInstance(
        instance_id=run.id, source_step_id=1, position=1, title="Endpoints", node_key="endpoints",
        command_refs='["msrpc-enum"]')
    db.add(step)
    execution_row = Execution(
        target_id=target.id, service_id=rpc.id, template_id="msrpc-enum",
        command="probe", cwd="/tmp", status="completed", exit_code=0,
        stdout=('RPC_ENDPOINT {"interface": "12345678-1234-1234-1234-123456789abc v1.0", '
                '"annotation": "Example", "binding": "ncacn_ip_tcp:host[49664]"}'),
        stderr="")
    db.add(execution_row); db.commit()

    assert sync_instance_executions(db, run, [step]) is True
    db.commit(); db.refresh(step)
    assert step.outcome == "confirmed"
    assert step.status == "attempted"
    assert step.activation == "completed"
    assert db.scalar(select(RunbookStepExecution).where(
        RunbookStepExecution.step_id == step.id,
        RunbookStepExecution.execution_id == execution_row.id))


def test_representative_profiles_have_investigation_questions():
    for row in [service("ftp", 2121), service("msrpc", 135),
                service("microsoft-ds", 445), service("http", 8080),
                service("redis", 6379), service("domain", 53)]:
        data = catalog.build(row)
        assert data["stages"]
        assert all(stage.get("question") and stage.get("purpose")
                   for stage in data["stages"])
        assert data["runbook_keys"]


def test_stage_commands_only_reference_ids_the_service_can_actually_run():
    # A profile (e.g. "database") can be shared by several concrete services
    # (mysql, redis, mongodb, ...). Every command button surfaced for a given
    # service must correspond to a command /services/{id}/commands would
    # actually return for that service, or the button silently no-ops when
    # clicked (App.tsx looks up the id in that list and finds nothing).
    for row in [service("redis", 6379), service("mysql", 3306),
                service("mongodb", 27017), service("postgresql", 5432),
                service("http", 80), service("https", 443)]:
        runnable_ids = {item["id"] for item in command_catalog.commands_for(
            row["name"], row["port"], row["protocol"])}
        data = catalog.build(row)
        for stage in data["stages"]:
            for command in stage["commands"]:
                assert command["id"] in runnable_ids, (
                    f"{row['name']}:{row['port']} stage {stage['id']} exposes "
                    f"{command['id']!r} which is not a runnable command for this service"
                )
