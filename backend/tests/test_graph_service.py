import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.database import Base
from app.models import GraphNode, Project
from app.modules.graph import service
from app.modules.graph.service import GraphIntegrityError


def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def project(db, name="Lab"):
    p = Project(name=name)
    db.add(p)
    db.flush()
    return p


def test_ensure_project_root_is_idempotent():
    db = database()
    p = project(db)
    root1 = service.ensure_project_root(db, p.id)
    root2 = service.ensure_project_root(db, p.id)
    assert root1.id == root2.id
    assert root1.type == "project-root"
    roots = db.query(GraphNode).filter_by(type="project-root").all()
    assert len(roots) == 1


def test_create_edge_rejects_illegal_type_pair():
    db = database()
    p = project(db)
    root = service.ensure_project_root(db, p.id)
    cred = service.create_node(db, p.id, "credential", "svc_backup")
    # enumerated is service -> finding only; credential source is illegal.
    with pytest.raises(GraphIntegrityError):
        service.create_edge(db, p.id, cred.id, root.id, "enumerated")


def test_create_edge_rejects_cross_project_endpoints():
    db = database()
    p1, p2 = project(db, "One"), project(db, "Two")
    service.ensure_project_root(db, p1.id)
    r2 = service.ensure_project_root(db, p2.id)
    host1 = service.create_node(db, p1.id, "host", "10.0.0.1")
    with pytest.raises(GraphIntegrityError):
        service.create_edge(db, p1.id, r2.id, host1.id, "discovered")


def test_get_tree_nests_host_and_service_under_root():
    db = database()
    p = project(db)
    root = service.ensure_project_root(db, p.id)
    host = service.create_node(db, p.id, "host", "10.10.11.23")
    svc = service.create_node(db, p.id, "service", "445/SMB")
    service.create_edge(db, p.id, root.id, host.id, "discovered")
    service.create_edge(db, p.id, host.id, svc.id, "discovered")
    tree = service.get_tree(db, p.id)
    assert tree["type"] == "project-root"
    host_node = tree["children"][0]
    assert host_node["label"] == "10.10.11.23"
    assert host_node["children"][0]["label"] == "445/SMB"


def test_attack_paths_surface_succeeded_chain():
    db = database()
    p = project(db)
    service.ensure_project_root(db, p.id)
    svc = service.create_node(db, p.id, "service", "80/HTTP")
    finding = service.create_node(db, p.id, "finding", "Upload RCE")
    technique = service.create_node(db, p.id, "technique", "web shell")
    shell = service.create_node(db, p.id, "credential", "www-data")
    service.create_edge(db, p.id, svc.id, finding.id, "enumerated")
    service.create_edge(db, p.id, finding.id, technique.id, "attempted",
                        status="succeeded")
    service.create_edge(db, p.id, technique.id, shell.id, "yielded",
                        status="succeeded")
    paths = service.get_attack_paths(db, p.id)
    assert paths == [[finding.id, technique.id, shell.id]]
