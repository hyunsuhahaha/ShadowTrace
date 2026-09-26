"""A non-IP assessment must retain its asset, procedure and evidence lineage."""
import json

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.database import Base
from app.models import (AssessmentAsset, Evidence, Finding, GraphEdge, GraphNode, Project,
                        RunbookStepInstance, RunbookTemplate, RunbookTemplateVersion)
from app.modules.core.router import create_assessment_asset, update_assessment_asset
from app.modules.graph import service as graph
from app.modules.runbooks.builtins import ensure_builtin_runbooks
from app.modules.runbooks.execution_router import (
    attach_evidence, create_observation, promote_observation, update_step,
)
from app.modules.runbooks.support import ApplyIn, FindingIn, LinkIn, ObservationIn, StepUpdate
from app.modules.runbooks.workflow_router import apply
from app.schemas import AssessmentAssetIn


@pytest.mark.parametrize("kind,key", [
    ("mobile", "mobile-app-review"), ("cloud", "cloud-account-review"),
    ("kubernetes", "kubernetes-review"), ("source", "source-code-review"),
    ("wireless", "wireless-review"), ("ics", "ics-safety-review"),
])
def test_non_ip_asset_runbook_projects_recorded_work_without_false_success(kind, key):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = Session(engine)
    project = Project(name="Approved lab")
    db.add(project); db.commit()
    asset = create_assessment_asset(AssessmentAssetIn(
        project_id=project.id, kind=kind, name=f"{kind} sample",
        locator="lab-only", details={"version": "1"}), db)
    assert ensure_builtin_runbooks(db) == 30
    template = db.scalar(select(RunbookTemplate).where(RunbookTemplate.builtin_key == key))
    version = db.scalar(select(RunbookTemplateVersion).where(
        RunbookTemplateVersion.template_id == template.id))
    instance = apply(ApplyIn(version_id=version.id, asset_id=asset.id), db)
    assert instance["target_id"] is None
    assert instance["asset_id"] == asset.id
    first = instance["steps"][0]
    with pytest.raises(HTTPException) as exc:
        update_step(first["id"], StepUpdate(status="completed", outcome="confirmed"), db)
    assert exc.value.status_code == 409
    update_assessment_asset(asset.id, AssessmentAssetIn(
        project_id=project.id, kind=kind, name=asset.name, locator=asset.locator,
        details={"version": "1"}, scope_status="in_scope"), db)
    evidence = Evidence(project_id=project.id, asset_id=asset.id, target_id=None,
                        title="private app proof", kind="attachment", sensitivity="secret")
    db.add(evidence); db.commit()
    attach_evidence(first["id"], LinkIn(resource_id=evidence.id), db)
    observation = create_observation(first["id"], ObservationIn(
        title="Review observation", detail="Observed in the approved lab",
        evidence_id=evidence.id), db)
    finding = promote_observation(observation["id"], FindingIn(
        title="Confirmed review result", description="Verified"), db)
    assert db.get(Finding, finding["id"]).asset_id == asset.id
    graph.sync_from_project(db, project.id)
    nodes = {(json.loads(row.source_ref).get("kind"), json.loads(row.source_ref).get("id")): row
             for row in db.scalars(select(GraphNode).where(GraphNode.project_id == project.id))
             if row.source_ref}
    asset_node = nodes[("asset", asset.id)]
    step_node = nodes[("runbook_step", first["id"])]
    evidence_node = nodes[("evidence", evidence.id)]
    finding_node = nodes[("finding", finding["id"])]
    assert evidence_node.label == f"Evidence #{evidence.id}"
    relations = {(edge.source, edge.target, edge.relation) for edge in db.scalars(
        select(GraphEdge).where(GraphEdge.project_id == project.id))}
    assert (asset_node.id, step_node.id, "attempted") in relations
    assert (step_node.id, evidence_node.id, "documented-by") in relations
    assert (step_node.id, finding_node.id, "produced-finding") in relations
    assert graph.get_attack_paths(db, project.id) == []
