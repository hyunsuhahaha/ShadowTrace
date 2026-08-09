import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.database import Base
from app.models import GraphEdge, GraphNode, Project
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
    # enumerated allows service/host -> finding/credential; credential source
    # (and project-root target) are illegal.
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
    assert result["created"] == {"hosts": 1, "services": 2,
                                 "findings": 0, "credentials": 0, "techniques": 0}
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
    assert second["created"] == {"hosts": 0, "services": 0,
                                 "findings": 0, "credentials": 0, "techniques": 0}
    nodes = db.query(GraphNode).filter_by(project_id=p.id).all()
    # 1 project-root + 1 host + 2 services, no duplicates on re-sync
    assert len(nodes) == 4


def test_sync_projects_findings_and_credentials():
    from app.models import Credential, Finding, Service, Target
    db = database()
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.9")
    db.add(t); db.flush()
    svc = Service(target_id=t.id, port=445, protocol="tcp", name="smb")
    db.add(svc); db.flush()
    db.add(Finding(project_id=p.id, target_id=t.id, service_id=svc.id,
                   title="Anonymous SMB", severity="Medium", status="open"))
    db.add(Credential(project_id=p.id, target_id=t.id, service_id=svc.id,
                      username="svc_backup", secret_kind="password",
                      secret_hint="8+ chars", secret="REALSECRET",
                      source_kind="smb"))
    db.flush()
    result = service.sync_from_project(db, p.id)
    assert result["created"] == {"hosts": 1, "services": 1,
                                 "findings": 1, "credentials": 1, "techniques": 0}
    nodes = db.query(GraphNode).filter_by(project_id=p.id).all()
    cred = next(n for n in nodes if n.type == "credential")
    assert cred.label == "svc_backup"
    assert "REALSECRET" not in cred.meta  # secret never copied
    finding = next(n for n in nodes if n.type == "finding")
    assert finding.label == "Anonymous SMB"


def test_sync_projects_executions_as_technique_nodes():
    from app.models import Execution, Service, Target
    db = database()
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.7")
    db.add(t); db.flush()
    svc = Service(target_id=t.id, port=80, protocol="tcp", name="http")
    db.add(svc); db.flush()
    db.add(Execution(target_id=t.id, service_id=svc.id, template_id="feroxbuster",
                     command="feroxbuster -u http://...", cwd="/tmp",
                     status="completed"))
    db.flush()
    result = service.sync_from_project(db, p.id)
    assert result["created"]["techniques"] == 1
    tech = db.query(GraphNode).filter_by(type="technique").one()
    assert tech.label == "feroxbuster"
    # completed command is NOT auto-judged as success (product principle)
    assert tech.status == "in-progress"


def test_sync_tracks_and_clears_execution_activity():
    from app.models import Execution, Target
    db = database()
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.12")
    db.add(t); db.flush()
    execution = Execution(target_id=t.id, template_id="nmap-script",
                          command="nmap --script safe", cwd="/tmp",
                          status="running")
    db.add(execution); db.flush()

    service.sync_from_project(db, p.id)
    tech = db.query(GraphNode).filter_by(type="technique").one()
    activity = json.loads(tech.meta)["activity"]
    assert activity["kind"] == "execution"
    assert activity["status"] == "running"
    assert activity["label"] == "nmap-script"
    assert activity["startedAt"]

    execution.status = "completed"
    service.sync_from_project(db, p.id)
    assert "activity" not in json.loads(tech.meta)


def test_sync_marks_host_while_scan_is_active():
    from app.models import ScanJob, Target
    db = database()
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.13")
    db.add(t); db.flush()
    scan = ScanJob(project_id=p.id, target_id=t.id, status="running",
                   alias="Full TCP")
    db.add(scan); db.flush()

    service.sync_from_project(db, p.id)
    host = db.query(GraphNode).filter_by(type="host").one()
    assert json.loads(host.meta)["activity"]["kind"] == "scan"
    assert json.loads(host.meta)["activity"]["label"] == "Full TCP"

    scan.status = "completed"
    service.sync_from_project(db, p.id)
    assert "activity" not in json.loads(host.meta)


def test_hidden_nodes_are_dropped_from_tree():
    db = database()
    p = project(db)
    root = service.ensure_project_root(db, p.id)
    host = service.create_node(db, p.id, "host", "10.0.0.1")
    svc = service.create_node(db, p.id, "service", "445/smb")
    service.create_edge(db, p.id, root.id, host.id, "discovered")
    service.create_edge(db, p.id, host.id, svc.id, "discovered")
    svc.hidden = True
    db.flush()
    tree = service.get_tree(db, p.id)
    host_node = tree["children"][0]
    labels = [c["label"] for c in host_node["children"] if c["kind"] == "node"]
    assert "445/smb" not in labels


def test_sync_relabels_winrm_port_5985():
    from app.models import Service, Target
    db = database()
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.8")
    db.add(t); db.flush()
    db.add(Service(target_id=t.id, port=5985, protocol="tcp", name="http"))
    db.flush()
    service.sync_from_project(db, p.id)
    svc = db.query(GraphNode).filter_by(type="service").one()
    assert svc.label == "5985/tcp winrm"


def test_sync_retroactively_relabels_existing_default_service_node():
    from app.models import Service, Target
    db = database()
    p = project(db)
    root = service.ensure_project_root(db, p.id)
    t = Target(project_id=p.id, name="b", ip="10.0.0.10")
    db.add(t); db.flush()
    svc = Service(target_id=t.id, port=5985, protocol="tcp", name="http")
    db.add(svc); db.flush()
    # simulate a pre-existing node with the raw nmap label
    host = service.create_node(db, p.id, "host", "10.0.0.10",
                               source_ref='{"id": %d, "kind": "target", "module": "core"}' % t.id)
    service.create_edge(db, p.id, root.id, host.id, "discovered")
    node = service.create_node(db, p.id, "service", "5985/tcp http",
                               source_ref='{"id": %d, "kind": "service", "module": "scans"}' % svc.id)
    service.create_edge(db, p.id, host.id, node.id, "discovered")
    service.sync_from_project(db, p.id)
    db.refresh(node)
    assert node.label == "5985/tcp winrm"


def test_sync_projects_interactive_sessions_as_technique_nodes(monkeypatch):
    import os
    from app.models import InteractiveSession, Service, Target
    db = database()
    monkeypatch.setattr(service, "_operator_address", lambda: "10.10.16.178")
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.11")
    db.add(t); db.flush()
    svc = Service(target_id=t.id, port=445, protocol="tcp", name="smb")
    db.add(svc); db.flush()
    db.add(InteractiveSession(target_id=t.id, service_id=svc.id,
                              template_id="responder-listener", command="responder -I tun0",
                              cwd="/tmp", status="launched", pid=os.getpid()))
    db.flush()
    result = service.sync_from_project(db, p.id)
    assert result["created"]["techniques"] == 1
    tech = db.query(GraphNode).filter_by(type="technique").one()
    assert tech.label == "responder-listener"
    assert json.loads(tech.meta)["activity"]["kind"] == "listener"
    assert json.loads(tech.meta)["activity"]["status"] == "launched"
    operator = db.query(GraphNode).filter_by(type="operator").one()
    assert operator.label == "Kali Operator · 10.10.16.178"
    relations = {(edge.relation, edge.source, edge.target)
                 for edge in db.query(GraphEdge).all()}
    host = db.query(GraphNode).filter_by(type="host").one()
    assert ("runs", operator.id, tech.id) in relations
    assert ("captures-from", tech.id, host.id) in relations
    assert not any(relation == "attempted" and target == tech.id
                   for relation, _, target in relations)


def test_sync_prunes_orphaned_nodes_when_target_deleted():
    from app.models import Service, Target
    db = database()
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.20")
    db.add(t); db.flush()
    db.add(Service(target_id=t.id, port=80, protocol="tcp", name="http")); db.flush()
    service.sync_from_project(db, p.id)
    assert db.query(GraphNode).filter_by(type="host").count() == 1
    assert db.query(GraphNode).filter_by(type="service").count() == 1
    # delete the domain rows, then re-sync -> the projected nodes are pruned
    db.query(Service).delete(); db.query(Target).delete(); db.flush()
    service.sync_from_project(db, p.id)
    assert db.query(GraphNode).filter_by(type="host").count() == 0
    assert db.query(GraphNode).filter_by(type="service").count() == 0


def test_ensure_project_root_refreshes_stale_label():
    db = database()
    p = project(db, name="Responder")
    root = service.ensure_project_root(db, p.id)
    root.label = "10.129.245.191"  # stale (project was briefly IP-named)
    db.flush()
    again = service.ensure_project_root(db, p.id)
    assert again.label == "Responder"
