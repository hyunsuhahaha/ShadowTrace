import json
import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.database import Base
from app.models import Evidence, FindingAsset, FindingTemplate, Project, Service, Target
from app.modules.findings.router import (apply_template, calculate_cvss,
    add_retest, create_finding, create_template, get_finding, summary,
    update_template)
from app.schemas import (FindingEvidenceIn, FindingIn, FindingRetestIn,
    FindingTemplateIn)

def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)

def test_cvss31_official_example_and_invalid_vector():
    result = calculate_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert result == {"version": "3.1", "vector": result["vector"],
                      "score": 9.8, "severity": "Critical"}
    with pytest.raises(HTTPException):
        calculate_cvss("CVSS:3.1/AV:N")

def test_template_snapshot_project_isolation_and_client_filtering():
    db = database()
    p1, p2 = Project(name="One"), Project(name="Two")
    db.add_all([p1, p2]); db.flush()
    t1, t2 = Target(project_id=p1.id, name="A", ip="10.0.0.1"), Target(
        project_id=p2.id, name="B", ip="10.0.0.2")
    db.add_all([t1, t2]); db.flush()
    public = Evidence(project_id=p1.id, target_id=t1.id, title="Public",
        kind="command_output", sensitivity="normal")
    secret = Evidence(project_id=p1.id, target_id=t1.id, title="Secret",
        kind="command_output", sensitivity="secret")
    foreign = Evidence(project_id=p2.id, target_id=t2.id, title="Foreign",
        kind="command_output", sensitivity="normal")
    db.add_all([public, secret, foreign]); db.commit()
    template = create_template(FindingTemplateIn(title="Default Credentials",
        severity="Critical", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        description="Original"), db)
    finding = apply_template(template["id"], p1.id, t1.id, None, db)
    update_template(template["id"], FindingTemplateIn(
        title="Changed", description="Changed"), db)
    assert json.loads(db.get(FindingTemplate, template["id"]).tags) == []
    assert json.loads(db.get(__import__("app.models", fromlist=["Finding"]).Finding,
                             finding["id"]).template_snapshot)["title"] == "Default Credentials"
    body = FindingIn(project_id=p1.id, target_id=t1.id, title="Leak test",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        final_risk="Critical", internal_notes="password=secret",
        evidence=[
            FindingEvidenceIn(evidence_id=public.id, include_client=True),
            FindingEvidenceIn(evidence_id=secret.id, include_client=True)])
    made = create_finding(body, db)
    client = get_finding(made["id"], "client", db)
    assert "internal_notes" not in client
    assert [x["title"] for x in client["evidence"]] == ["Public"]
    with pytest.raises(HTTPException):
        create_finding(body.model_copy(update={"evidence": [
            FindingEvidenceIn(evidence_id=foreign.id)]}), db)
    assert summary(p1.id, "client", db)["total"] == 2

def test_manual_risk_override_requires_reason():
    db = database(); project = Project(name="Risk"); db.add(project); db.flush()
    target = Target(project_id=project.id, name="A", ip="10.0.0.1")
    db.add(target); db.commit()
    with pytest.raises(HTTPException) as exc:
        create_finding(FindingIn(project_id=project.id, target_id=target.id,
            title="Override", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            final_risk="High"), db)
    assert exc.value.status_code == 422

def test_retest_history_is_append_only_and_decodes_evidence_ids():
    db = database(); project = Project(name="Retest"); db.add(project); db.flush()
    target = Target(project_id=project.id, name="Host", ip="10.0.0.8")
    db.add(target); db.flush()
    before = Evidence(project_id=project.id, target_id=target.id,
        title="Before", kind="screenshot")
    after = Evidence(project_id=project.id, target_id=target.id,
        title="After", kind="screenshot")
    db.add_all([before, after]); db.commit()
    finding = create_finding(FindingIn(project_id=project.id,
        target_id=target.id, title="Retest me"), db)
    add_retest(finding["id"], FindingRetestIn(tester="analyst",
        result="Remediated", remediated=True,
        before_evidence_ids=[before.id], after_evidence_ids=[after.id]), db)
    result = get_finding(finding["id"], None, db)
    assert result["status"] == "Remediated"
    assert result["retests"][0]["before_evidence_ids"] == [before.id]
    assert result["retests"][0]["after_evidence_ids"] == [after.id]

def test_finding_supports_multiple_targets_and_services():
    db = database(); project = Project(name="Assets"); db.add(project); db.flush()
    first = Target(project_id=project.id, name="One", ip="10.0.0.1")
    second = Target(project_id=project.id, name="Two", ip="10.0.0.2")
    db.add_all([first, second]); db.flush()
    service = Service(target_id=second.id, port=443, protocol="tcp", name="https")
    db.add(service); db.commit()
    finding = create_finding(FindingIn(project_id=project.id,
        target_id=first.id, target_ids=[first.id, second.id],
        service_ids=[service.id], title="Shared weakness"), db)
    assert finding["target_ids"] == [first.id, second.id]
    assert finding["service_ids"] == [service.id]
    assets = db.query(FindingAsset).filter_by(finding_id=finding["id"]).all()
    assert {(item.target_id, item.service_id) for item in assets} == {
        (first.id, None), (second.id, service.id)}
