import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.database import Base
from app.models import Project
from app.modules.graph import router as api
from app.modules.graph import service
from app.modules.graph.schemas import EdgeIn, NodeIn


def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def project(db):
    p = Project(name="Lab")
    db.add(p)
    db.flush()
    return p


def test_get_graph_bootstraps_and_returns_root():
    db = database()
    p = project(db)
    out = api.get_graph(p.id, db)
    assert out.root_node_id is not None
    assert any(n.type == "project-root" for n in out.nodes)


def test_create_node_rejects_project_root_type():
    db = database()
    p = project(db)
    api.get_graph(p.id, db)
    with pytest.raises(HTTPException) as exc:
        api.create_node(p.id, NodeIn(type="project-root", label="x"), db)
    assert exc.value.status_code == 422


def test_delete_project_root_is_forbidden():
    db = database()
    p = project(db)
    root_id = api.get_graph(p.id, db).root_node_id
    with pytest.raises(HTTPException) as exc:
        api.delete_node(root_id, db)
    assert exc.value.status_code == 422


def test_create_edge_with_illegal_pair_returns_422():
    db = database()
    p = project(db)
    api.get_graph(p.id, db)
    a = api.create_node(p.id, NodeIn(type="finding", label="f"), db)
    b = api.create_node(p.id, NodeIn(type="host", label="h"), db)
    # attempted is finding -> technique; finding -> host is illegal.
    with pytest.raises(HTTPException) as exc:
        api.create_edge(p.id, EdgeIn(source=a.id, target=b.id,
                                     relation="attempted"), db)
    assert exc.value.status_code == 422


def test_deleting_edge_clears_pinned_canonical_reference():
    db = database()
    p = project(db)
    root_id = api.get_graph(p.id, db).root_node_id
    host = api.create_node(p.id, NodeIn(type="host", label="h"), db)
    edge = api.create_edge(p.id, EdgeIn(source=root_id, target=host.id,
                                        relation="discovered"), db)
    host.pinned_canonical_edge_id = edge.id
    db.commit()
    api.delete_edge(edge.id, db)
    db.refresh(host)
    assert host.pinned_canonical_edge_id is None


def test_sync_endpoint_creates_host_and_service_nodes():
    from app.models import Service, Target
    db = database()
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.5")
    db.add(t); db.flush()
    db.add(Service(target_id=t.id, port=22, protocol="tcp", name="ssh")); db.flush()
    result = api.sync_graph(p.id, db)
    assert result["created"] == {"hosts": 1, "services": 1,
                                 "findings": 0, "credentials": 0}
    out = api.get_graph(p.id, db)
    assert any(n.type == "host" for n in out.nodes)
    assert any(n.type == "service" for n in out.nodes)


def test_attack_paths_endpoint_returns_paths_and_summary():
    db = database()
    p = project(db)
    api.get_graph(p.id, db)
    res = api.get_attack_paths(p.id, db)
    assert res["paths"] == []
    assert res["summary"]["steps"] == 0 and res["summary"]["objectivesReached"] == 0
