"""End-to-end chain across modules: Nmap import -> runbook recommendation/apply
-> evidence+execution attachment -> finding -> report export. Each existing
test file only exercises one module in isolation; this is the one place that
proves the whole investigation flow a user relies on actually threads
together, matching docs/ROADMAP.md's P0 "scan import -> 추천 -> runbook ->
evidence -> report" integration-test item.
"""
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from app.database import Base
from app.models import Evidence, Execution, Finding, FindingEvidence, Project, Report, Service, Target
from app.modules.scan_center.service import import_xml
from app.modules.runbooks.support import ApplyIn, LinkIn, PublishIn, StepIn, TemplateIn
from app.modules.runbooks.workflow_router import apply, create_template, publish, recommendations
from app.modules.runbooks.execution_router import attach_evidence, attach_execution
from app.modules.reports.router import export_report, render_report


def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def scope(db: Session):
    project = Project(name="Golden Path Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.45")
    db.add(target); db.flush()
    db.commit()
    return project, target


SCAN_XML = (
    b'<nmaprun><host><address addr="10.10.10.45"/><hostnames>'
    b'<hostname name="box.local"/></hostnames><ports>'
    b'<port protocol="tcp" portid="445">'
    b'<state state="open"/>'
    b'<service name="microsoft-ds" product="Samba" version="4.6.2"/>'
    b'</port></ports></host></nmaprun>'
)


def test_scan_import_through_runbook_evidence_and_report_export():
    db = database()
    project, target = scope(db)

    # 1. Nmap XML import creates the Service row and auto-captures the scan
    # itself as Evidence (app/modules/scan_center/service.py:capture_scan_evidence) --
    # nothing pre-seeded, exactly like a real "import this scan" action.
    job = import_xml(db, target, project, SCAN_XML, "scope.xml")
    service = db.scalar(select(Service).where(
        Service.target_id == target.id, Service.port == 445))
    assert service is not None
    assert service.name == "microsoft-ds"
    scan_evidence = db.scalar(select(Evidence).where(
        Evidence.source_type == "scan", Evidence.source_id == job.id))
    assert scan_evidence is not None

    # 2. A published runbook targeting the discovered service is recommended
    # and not yet applied.
    template = create_template(TemplateIn(
        name="SMB basics", service_names=["microsoft-ds"]), db)
    version = publish(template["id"], PublishIn(steps=[
        StepIn(title="Check anonymous access"),
    ]), db)
    before = recommendations(service.id, db)[0]
    assert before["version_id"] == version["id"]
    assert before["applied"] is False

    # 3. Apply the runbook, then attach the scan Evidence and a follow-up
    # Execution to the step -- this is what flips a recommendation to applied.
    instance = apply(ApplyIn(
        version_id=version["id"], target_id=target.id, service_id=service.id), db)
    step_id = instance["steps"][0]["id"]
    execution = Execution(
        target_id=target.id, service_id=service.id, template_id="smb-null-session",
        command="smbclient -N -L //10.10.10.45", cwd="/tmp", status="completed")
    db.add(execution); db.commit()
    attach_evidence(step_id, LinkIn(resource_id=scan_evidence.id), db)
    linked = attach_execution(step_id, LinkIn(resource_id=execution.id), db)
    assert linked["steps"][0]["evidence_ids"] == [scan_evidence.id]
    assert linked["steps"][0]["execution_ids"] == [execution.id]
    assert recommendations(service.id, db)[0]["applied"] is True

    # 4. Promote the observation to a Finding, link the same scan Evidence to
    # it, and confirm a generated report actually contains both -- not just
    # that export didn't crash.
    finding = Finding(
        project_id=project.id, target_id=target.id, service_id=service.id,
        title="Anonymous SMB share access", final_risk="High", cvss_score="7.5",
        status="Confirmed", summary="Null session allowed share enumeration.")
    db.add(finding); db.flush()
    db.add(FindingEvidence(
        finding_id=finding.id, evidence_id=scan_evidence.id,
        caption="Nmap scan confirming microsoft-ds", include_client=True,
        include_internal=True))
    report = Report(
        project_id=project.id, title="Golden Path Assessment",
        markdown="# Assessment\n\nSee findings below.", sensitivity_reviewed=True)
    db.add(report); db.commit()

    html_client = render_report(db, report, "client")
    assert "Anonymous SMB share access" in html_client
    assert "Nmap scan confirming microsoft-ds" in html_client

    exported = export_report(report.id, "html", db)
    assert b"Anonymous SMB share access" in exported.body
    assert b"Nmap scan confirming microsoft-ds" in exported.body
