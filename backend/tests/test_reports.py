import json
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.database import Base
from app.models import Evidence, Project, Report, Target
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
