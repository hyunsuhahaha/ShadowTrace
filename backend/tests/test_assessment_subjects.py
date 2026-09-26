import json

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.database import Base
from app.models import AssessmentAsset, GraphEdge, GraphNode, Project
from app.modules.core.router import create_assessment_asset_subject, delete_assessment_asset
from app.modules.graph import service as graph
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
