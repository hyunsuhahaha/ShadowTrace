import json

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.database import Base
from app.models import AssessmentAsset, Evidence, GraphEdge, GraphNode, Project
from app.modules.core.router import create_assessment_asset_subject, delete_assessment_asset, delete_assessment_asset_subject
from app.modules.graph import service as graph
from app.modules.runbooks.execution_router import attach_evidence, attach_subject
from app.modules.runbooks.support import ApplyIn, LinkIn, PublishIn, StepIn, TemplateIn
from app.modules.runbooks.workflow_router import apply, create_template, publish
from app.schemas import ASSET_SUBJECT_SPECS, AssessmentAssetSubjectIn


def test_typed_subjects_cover_all_asset_kinds_and_project_to_graph():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = Session(engine)
    project = Project(name="Scoped subjects")
    db.add(project); db.flush()
    created = []
    for asset_kind, subjects in ASSET_SUBJECT_SPECS.items():
        asset = AssessmentAsset(project_id=project.id, kind=asset_kind,
                                name=f"{asset_kind} fixture", scope_status="in_scope")
        db.add(asset); db.flush()
        subject_kind, fields = next(iter(subjects.items()))
        attributes = {key: ("aa:bb:cc:dd:ee:ff" if key == "bssid"
                            else "abcdef1234567" if key == "commit_sha" else "fixture")
                      for key in fields}
        row = create_assessment_asset_subject(AssessmentAssetSubjectIn(
            asset_id=asset.id, kind=subject_kind, label=f"{asset_kind} detail",
            identifier=f"{asset_kind}-001", attributes=attributes,
            scope_status="in_scope"), db)
        created.append((asset, row))
    graph.sync_from_project(db, project.id)
    nodes = db.scalars(select(GraphNode).where(GraphNode.project_id == project.id)).all()
    assert len([node for node in nodes if '"kind": "asset_subject"' in (node.source_ref or "")]) == 8
    for asset, subject in created:
        asset_node = next(node for node in nodes if json.loads(node.source_ref or "{}").get("kind") == "asset"
                          and json.loads(node.source_ref)["id"] == asset.id)
        detail_node = next(node for node in nodes if json.loads(node.source_ref or "{}").get("kind") == "asset_subject"
                           and json.loads(node.source_ref)["id"] == subject.id)
        assert db.scalar(select(GraphEdge).where(GraphEdge.source == asset_node.id,
            GraphEdge.target == detail_node.id, GraphEdge.relation == "discovered"))
    asset, subject = created[0]
    with pytest.raises(HTTPException) as blocked:
        delete_assessment_asset(asset.id, db)
    assert blocked.value.status_code == 409
    with pytest.raises(HTTPException) as mismatch:
        create_assessment_asset_subject(AssessmentAssetSubjectIn(
            asset_id=asset.id, kind="cloud_account", label="Wrong kind",
            identifier="bad", attributes={"provider":"x","account_id":"x"}), db)
    assert mismatch.value.status_code == 400


def test_subject_attribute_schema_rejects_incomplete_wireless_and_ics_records():
    with pytest.raises(ValidationError):
        AssessmentAssetSubjectIn(asset_id=1, kind="wireless_ap",
            label="AP", identifier="AP 1", attributes={"ssid":"Lab","bssid":"invalid","site":"room"})
    with pytest.raises(ValidationError):
        AssessmentAssetSubjectIn(asset_id=1, kind="ics_device",
            label="Controller", identifier="PLC 1",
            attributes={"device":"PLC 1","process":"line A","segment":"OT"})


def test_subject_step_link_records_specific_assessment_and_evidence_lineage():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = Session(engine)
    project = Project(name="Scoped API review")
    db.add(project); db.flush()
    asset = AssessmentAsset(project_id=project.id, kind="api",
                            name="API", scope_status="in_scope")
    other = AssessmentAsset(project_id=project.id, kind="api",
                            name="Other API", scope_status="in_scope")
    db.add_all([asset, other]); db.flush()
    attrs = {key: "fixture" for key in ASSET_SUBJECT_SPECS["api"]["api_operation"]}
    subject = create_assessment_asset_subject(AssessmentAssetSubjectIn(
        asset_id=asset.id, kind="api_operation", label="Invoice read",
        identifier="GET /invoices/{id}", attributes=attrs,
        scope_status="in_scope"), db)
    foreign = create_assessment_asset_subject(AssessmentAssetSubjectIn(
        asset_id=other.id, kind="api_operation", label="Other operation",
        identifier="GET /other", attributes=attrs, scope_status="in_scope"), db)
    template = create_template(TemplateIn(name="API authorization check"), db)
    version = publish(template["id"], PublishIn(steps=[StepIn(title="Check object access")]), db)
    run = apply(ApplyIn(version_id=version["id"], asset_id=asset.id), db)
    step_id = run["steps"][0]["id"]
    linked = attach_subject(step_id, LinkIn(resource_id=subject.id), db)
    assert linked["steps"][0]["subject_ids"] == [subject.id]
    evidence = Evidence(project_id=project.id, asset_id=asset.id,
                        title="Authorization result", kind="markdown", sha256="c" * 64)
    db.add(evidence); db.commit()
    assert attach_evidence(step_id, LinkIn(resource_id=evidence.id), db)["steps"][0]["evidence_ids"] == [evidence.id]
    graph.sync_from_project(db, project.id)
    nodes = db.scalars(select(GraphNode).where(GraphNode.project_id == project.id)).all()
    detail = next(node for node in nodes if json.loads(node.source_ref or "{}").get("kind") == "asset_subject"
                  and json.loads(node.source_ref)["id"] == subject.id)
    step = next(node for node in nodes if json.loads(node.source_ref or "{}").get("kind") == "runbook_step"
                and json.loads(node.source_ref)["id"] == step_id)
    assert db.scalar(select(GraphEdge).where(GraphEdge.source == detail.id,
        GraphEdge.target == step.id, GraphEdge.relation == "assesses"))
    assert db.scalar(select(GraphEdge).where(GraphEdge.source == step.id,
        GraphEdge.relation == "documented-by"))
    with pytest.raises(HTTPException) as mismatch:
        attach_subject(step_id, LinkIn(resource_id=foreign.id), db)
    assert mismatch.value.status_code == 400
    with pytest.raises(HTTPException) as blocked:
        delete_assessment_asset_subject(subject.id, db)
    assert blocked.value.status_code == 409
