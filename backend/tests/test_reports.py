import json
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.database import Base
from app.models import Evidence, Finding, FindingEvidence, Project, Report, Target
from docx import Document
from app.modules.reports.router import export_report, render_report


def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


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
