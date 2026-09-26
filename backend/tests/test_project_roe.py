from datetime import timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.database import Base
from app.engagement import require_roe
from app.models import AssessmentAsset, GraphNode, ProjectRoeEvent, Target
from app.modules.graph import service as graph
from app.modules.core.router import (approve_project_roe, create_project,
                                     revoke_project_roe, update_project_roe)
from app.schemas import ProjectIn, ProjectRoeDecisionIn, ProjectRoeDraftIn
from app.time import utcnow


def test_project_roe_requires_approved_window_action_and_exact_scope():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = Session(engine)
    project = create_project(ProjectIn(name="RoE lab"), db)
    target = Target(project_id=project.id, name="Allowed", ip="10.20.30.4")
    excluded = Target(project_id=project.id, name="Excluded", ip="10.20.30.9")
    asset = AssessmentAsset(project_id=project.id, kind="source", name="Repository",
                            scope_status="in_scope")
    db.add_all([target, excluded, asset]); db.commit()
    with pytest.raises(HTTPException) as pending:
        require_roe(db, project.id, "scan", target=target)
    assert pending.value.status_code == 409
    draft = ProjectRoeDraftIn(
        included_targets=["10.20.30.0/24"], excluded_targets=["10.20.30.9"],
        asset_ids=[asset.id], allowed_actions=["scan", "runbook"],
        valid_from=utcnow()-timedelta(minutes=1),
        valid_until=utcnow()+timedelta(hours=2), notes="Authorized local lab")
    update_project_roe(project.id, draft, db)
    approve_project_roe(project.id, ProjectRoeDecisionIn(
        actor="Lab owner", reason="Approved scope and time"), db)
    require_roe(db, project.id, "scan", target=target)
    require_roe(db, project.id, "runbook", asset=asset)
    graph.sync_from_project(db, project.id)
    scope_node = db.scalar(select(GraphNode).where(
        GraphNode.project_id == project.id, GraphNode.type == "scope"))
    assert scope_node.status == "in-progress"
    for action, subject in (("command", {"target": target}),
                            ("scan", {"target": excluded})):
        with pytest.raises(HTTPException) as denied:
            require_roe(db, project.id, action, **subject)
        assert denied.value.status_code == 409
    revoke_project_roe(project.id, ProjectRoeDecisionIn(
        actor="Lab owner", reason="Window closed"), db)
    graph.sync_from_project(db, project.id)
    db.refresh(scope_node)
    assert scope_node.status == "blocked"
    with pytest.raises(HTTPException):
        require_roe(db, project.id, "scan", target=target)
    assert [item.action for item in db.scalars(select(ProjectRoeEvent).order_by(
        ProjectRoeEvent.id))] == ["revised", "approved", "revoked"]
