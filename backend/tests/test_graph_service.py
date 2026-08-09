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


def target_with_services(db, project_id):
    from app.models import Service, Target
    t = Target(project_id=project_id, name="box", ip="10.10.11.23",
               hostname="dc01")
    db.add(t); db.flush()
    db.add_all([
        Service(target_id=t.id, port=445, protocol="tcp", name="smb"),
        Service(target_id=t.id, port=80, protocol="tcp", name="http"),
    ]); db.flush()
    return t


def test_sync_projects_targets_and_services_into_graph():
    db = database()
    p = project(db)
    target_with_services(db, p.id)
    result = service.sync_from_project(db, p.id)
    assert result["created"] == {"hosts": 1, "services": 2}
    tree = service.get_tree(db, p.id)
    host = tree["children"][0]
    assert host["label"] == "10.10.11.23 (dc01)"
    svc_labels = sorted(c["label"] for c in host["children"] if c["kind"] == "node")
    assert svc_labels == ["445/tcp smb", "80/tcp http"]


def test_sync_is_idempotent():
    db = database()
    p = project(db)
    target_with_services(db, p.id)
    service.sync_from_project(db, p.id)
    second = service.sync_from_project(db, p.id)
    assert second["created"] == {"hosts": 0, "services": 0}
    nodes = db.query(GraphNode).filter_by(project_id=p.id).all()
    # 1 project-root + 1 host + 2 services, no duplicates on re-sync
    assert len(nodes) == 4
