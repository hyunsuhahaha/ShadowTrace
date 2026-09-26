import json
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.database import Base
from app.models import (Evidence, Finding, FindingEvidence, GraphEdge, GraphNode, Project, Report,
    RunbookInstance, RunbookStepInstance, Target)
from docx import Document
from app.modules.reports.router import (GraphPathCaptureIn, capture_graph_path,
    export_report, render_report, update_report)
from app.schemas import ReportIn


def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def test_graph_path_snapshot_keeps_original_nodes_edges_and_evidence_hash():
    db = database()
    project = Project(name="Path Lab")
    db.add(project); db.flush()
    report = Report(project_id=project.id, title="Client path report", markdown="",
                    sensitivity_reviewed=True)
    proof = Evidence(project_id=project.id, title="Sensitive proof", kind="markdown",
                     sensitivity="sensitive", sha256="a"*64)
    db.add_all([report, proof]); db.flush()
    host = GraphNode(id="path-host", project_id=project.id, type="host",
                     label="Host A", status="succeeded")
    finding = GraphNode(id="path-finding", project_id=project.id, type="finding",
                        label="Confirmed finding", status="succeeded")
    evidence_node = GraphNode(id="path-evidence", project_id=project.id,
        type="evidence", label=f"Evidence #{proof.id}", status="untried",
        source_ref=json.dumps({"kind":"evidence","id":proof.id}))
    db.add_all([host, finding, evidence_node]); db.flush()
    edge = GraphEdge(id="path-edge", project_id=project.id, source=host.id,
                     target=finding.id, relation="enumerated", status="succeeded")
    db.add(edge); db.add(GraphEdge(id="proof-edge", project_id=project.id,
        source=finding.id, target=evidence_node.id, relation="documented-by",
        status="untried")); db.commit()
    captured = capture_graph_path(report.id, GraphPathCaptureIn(
        node_ids=[host.id, finding.id], caption="Access path"), db)
    assert captured.sensitivity_reviewed is False
    frozen = json.loads(captured.graph_path_snapshots)[0]
    assert frozen["nodes"][0]["label"] == "Host A"
    assert frozen["evidence"] == [{"id":proof.id,"label":f"Evidence #{proof.id}",
        "sha256":"a"*64,"sensitivity":"sensitive"}]
    host.label = "Changed later"; edge.status = "untried"; db.commit()
    assert "Changed later" not in render_report_after_review(db, report)
    markdown = export_report(report.id, "markdown", db, "client").body.decode()
    assert "Host A" in markdown and "a"*64 in markdown
    assert "enumerated / succeeded" in markdown
    assert "Sensitive proof" not in markdown


def render_report_after_review(db, report):
    try:
        render_report(db, report, "client")
    except HTTPException as exc:
        assert exc.status_code == 409
    else:
        raise AssertionError("sensitive path evidence exported without review")
    report.sensitivity_reviewed = True
    db.commit()
    return render_report(db, report, "client")


def test_changing_report_evidence_resets_prior_sensitivity_review():
    db = database()
    project = Project(name="Review reset")
    db.add(project); db.flush()
    first = Evidence(project_id=project.id, title="First", kind="markdown",
                     sha256="a" * 64)
    second = Evidence(project_id=project.id, title="Second", kind="markdown",
                      sensitivity="sensitive", sha256="b" * 64)
    db.add_all([first, second]); db.flush()
    report = Report(project_id=project.id, title="Client report", markdown="",
                    evidence_links=json.dumps([{"id": first.id, "caption": ""}]),
                    sensitivity_reviewed=True)
    db.add(report); db.commit()
    changed = update_report(report.id, ReportIn(project_id=project.id,
        title=report.title, template="blank", evidence_links=[{"id": first.id},
        {"id": second.id}], sensitivity_reviewed=True), db)
    assert changed.sensitivity_reviewed is False


def test_selected_runbook_coverage_survives_export_without_raw_notes():
    db = database()
    project = Project(name="Coverage Lab")
    other = Project(name="Other Lab")
    db.add_all([project, other]); db.flush()
    target = Target(project_id=project.id, name="Web", ip="10.0.0.9")
    db.add(target); db.flush()
    run = RunbookInstance(project_id=project.id, target_id=target.id,
        version_id=1, template_name="Web authorization checks", target_name="Web")
    db.add(run); db.flush()
    db.add(RunbookStepInstance(instance_id=run.id, source_step_id=1,
        position=1, title="Cross-account access", status="completed",
        outcome="not_found", result="private response body", notes="secret-token"))
    report = Report(project_id=project.id, title="Client report", markdown="# Methodology",
        runbook_instance_links=json.dumps([run.id]))
    db.add(report); db.commit()

    client = render_report(db, report, "client")
    assert "Testing Coverage" in client
    assert "Cross-account access" in client
    assert "not_found" in client
    assert "private response body" not in client
    assert "secret-token" not in client
    markdown = export_report(report.id, "markdown", db, "client").body.decode()
    assert "Cross-account access" in markdown
    assert "secret-token" not in markdown
    document = Document(__import__("io").BytesIO(
        export_report(report.id, "docx", db, "client").body))
    assert "Cross-account access" in " ".join(
        cell.text for table in document.tables for row in table.rows for cell in row.cells)

    report.runbook_instance_links = "[]"
    assert "Cross-account access" not in render_report(db, report, "client")
    report.project_id = other.id
    report.runbook_instance_links = json.dumps([run.id])
    try:
        render_report(db, report, "client")
    except HTTPException as exc:
        assert exc.status_code == 400
    else:
        raise AssertionError("cross-project Runbook coverage was exported")


def test_report_requires_sensitive_evidence_review_and_exports_pdf():
    db = database()
    project = Project(name="Report Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.13")
    db.add(target); db.flush()
    evidence = Evidence(project_id=project.id, target_id=target.id,
                        title="Proof", kind="flag", sensitivity="sensitive")
    db.add(evidence); db.flush()
    report = Report(project_id=project.id, title="Exam report",
                    markdown="# Finding\n\nUser-authored details.",
                    evidence_links=json.dumps(
                        [{"id": evidence.id, "caption": "Manual proof"}]))
    db.add(report); db.commit()
    try:
        render_report(db, report)
    except HTTPException as exc:
        assert exc.status_code == 409
    else:
        raise AssertionError("sensitive evidence exported without review")
    report.sensitivity_reviewed = True
    db.commit()
    html = export_report(report.id, "html", db)
    assert b"User-authored details" in html.body
    pdf = export_report(report.id, "pdf", db)
    assert pdf.body.startswith(b"%PDF")
    docx = export_report(report.id, "docx", db, "internal")
    assert docx.body.startswith(b"PK")
    parsed = Document(__import__("io").BytesIO(docx.body))
    assert "User-authored details" in "\n".join(
        paragraph.text for paragraph in parsed.paragraphs)

def test_finding_evidence_raw_output_is_internal_only():
    db = database()
    project = Project(name="Profiles"); db.add(project); db.flush()
    target = Target(project_id=project.id, name="Host", ip="10.0.0.9")
    db.add(target); db.flush()
    evidence = Evidence(project_id=project.id, target_id=target.id,
        title="Command proof", kind="command_output", sensitivity="normal",
        markdown="password=do-not-leak")
    finding = Finding(project_id=project.id, target_id=target.id,
        title="Profile boundary", final_risk="High", cvss_score="8.0",
        status="Confirmed")
    report = Report(project_id=project.id, title="Boundary report",
        markdown="# Assessment", sensitivity_reviewed=True)
    db.add_all([evidence, finding, report]); db.flush()
    db.add(FindingEvidence(finding_id=finding.id, evidence_id=evidence.id,
        caption="Sanitized caption", include_client=True, include_internal=True))
    db.commit()
    client = render_report(db, report, "client")
    internal = render_report(db, report, "internal")
    assert "Sanitized caption" in client
    assert "password=do-not-leak" not in client
    assert "password=do-not-leak" in internal
