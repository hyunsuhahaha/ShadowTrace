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


def test_resync_preserves_a_finding_s_one_shot_unlock_marker():
    # Confirmed live: GraphWorkspace.tsx polls /graph/sync every 4s, and this
    # loop was unconditionally overwriting an existing finding node's meta
    # wholesale on every single poll -- extract_archive_entry's unlockedAt
    # (meant to survive for several seconds so the canvas can play its
    # one-shot effect) was getting wiped out almost immediately, well before
    # an operator could ever see it.
    from app.models import Finding, Target
    db = database()
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.10")
    db.add(t); db.flush()
    db.add(Finding(project_id=p.id, target_id=t.id,
                   title="압축 해제: index.php", severity="Informational"))
    db.flush()
    service.sync_from_project(db, p.id)
    finding_node = db.query(GraphNode).filter_by(project_id=p.id, type="finding").one()
    meta = json.loads(finding_node.meta)
    meta["unlockedAt"] = "2026-08-15T02:35:08.525894+00:00"
    finding_node.meta = json.dumps(meta)
    db.flush()

    service.sync_from_project(db, p.id)

    refreshed = db.get(GraphNode, finding_node.id)
    assert json.loads(refreshed.meta)["unlockedAt"] == "2026-08-15T02:35:08.525894+00:00"
    # the sync-owned fields still update normally, this isn't a frozen blob
    assert json.loads(refreshed.meta)["evidenceCount"] == 0


def test_sync_sets_evidence_count_on_host_and_service_nodes():
    from app.models import Evidence, Service, Target
    db = database()
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.9")
    db.add(t); db.flush()
    svc = Service(target_id=t.id, port=445, protocol="tcp", name="smb")
    db.add(svc); db.flush()
    db.add(Evidence(project_id=p.id, target_id=t.id, title="host-level note",
                    kind="markdown", source_type="note"))
    db.add(Evidence(project_id=p.id, target_id=t.id, service_id=svc.id,
                    title="smb banner", kind="command_output", source_type="upload"))
    db.flush()
    service.sync_from_project(db, p.id)
    nodes = db.query(GraphNode).filter_by(project_id=p.id).all()
    host = next(n for n in nodes if n.type == "host")
    svc_node = next(n for n in nodes if n.type == "service")
    assert json.loads(host.meta)["evidenceCount"] == 1
    assert json.loads(svc_node.meta)["evidenceCount"] == 1


def test_service_node_under_a_deleted_host_keeps_refreshing_on_later_syncs():
    # Regression test: deleting a host node (docs/SPEC_GRAPH_TRACKER.md §2.1
    # -- node delete cascades EDGES only, never descendant nodes) used to
    # make sync_from_project skip its whole per-target body, including the
    # nested service loop, whenever the host row stayed dismissed. Any
    # service node synced before the host was deleted then got permanently
    # stuck with stale meta/label forever, instead of continuing to reflect
    # reality the way every other still-live node does.
    from app.models import Evidence, Service, Target
    db = database()
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.31")
    db.add(t); db.flush()
    svc = Service(target_id=t.id, port=445, protocol="tcp", name="smb")
    db.add(svc); db.flush()

    service.sync_from_project(db, p.id)
    host = db.query(GraphNode).filter_by(type="host").one()
    svc_node = db.query(GraphNode).filter_by(type="service").one()
    assert json.loads(svc_node.meta)["evidenceCount"] == 0

    # Delete the host node the same way the API does: dismiss its source_ref
    # so sync won't recreate it, then drop the node and its own edges.
    service.dismiss_source(db, p.id, host.source_ref)
    db.query(GraphEdge).filter(
        (GraphEdge.source == host.id) | (GraphEdge.target == host.id)
    ).delete(synchronize_session=False)
    db.delete(host)
    db.flush()

    db.add(Evidence(project_id=p.id, target_id=t.id, service_id=svc.id,
                    title="smb banner", kind="command_output", source_type="upload"))
    db.flush()
    service.sync_from_project(db, p.id)

    assert not any(node.type == "host" for node in
                  db.query(GraphNode).filter_by(project_id=p.id).all())
    refreshed = db.get(GraphNode, svc_node.id)
    assert refreshed is not None
    assert json.loads(refreshed.meta)["evidenceCount"] == 1


def test_sync_sets_evidence_count_on_credential_via_hash_crack_source():
    from app.models import Credential, Evidence, HashCrackJob, Target
    db = database()
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.9")
    db.add(t); db.flush()
    evidence = Evidence(project_id=p.id, target_id=t.id, title="cracked hashes",
                        kind="command_output", source_type="hash_crack_job")
    db.add(evidence); db.flush()
    job = HashCrackJob(project_id=p.id, target_id=t.id, hash_mode_id="ntlm",
                       hash_mode="1000", status="completed", evidence_id=evidence.id)
    db.add(job); db.flush()
    db.add(Credential(project_id=p.id, target_id=t.id, username="administrator",
                      secret_kind="password", source_kind="hash_crack",
                      source_execution_kind="hash_crack_job",
                      source_execution_id=job.id))
    db.flush()
    service.sync_from_project(db, p.id)
    cred = next(n for n in db.query(GraphNode).filter_by(project_id=p.id).all()
               if n.type == "credential")
    assert json.loads(cred.meta)["evidenceCount"] == 1


def test_sync_credential_evidence_count_is_zero_without_a_traceable_source():
    from app.models import Credential, Target
    db = database()
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.9")
    db.add(t); db.flush()
    db.add(Credential(project_id=p.id, target_id=t.id, username="guest",
                      secret_kind="password", source_kind="manual"))
    db.flush()
    service.sync_from_project(db, p.id)
    cred = next(n for n in db.query(GraphNode).filter_by(project_id=p.id).all()
               if n.type == "credential")
    assert json.loads(cred.meta)["evidenceCount"] == 0


def test_sync_projects_successful_credential_reuse_as_access_lineage():
    from app.models import Credential, RemoteExecution, Target
    db = database()
    p = project(db)
    source = Target(project_id=p.id, name="foothold", ip="10.0.0.10")
    destination = Target(project_id=p.id, name="dc", ip="10.0.0.20")
    db.add_all([source, destination]); db.flush()
    credential = Credential(
        project_id=p.id, target_id=source.id, username="administrator",
        domain="CORP", secret_kind="hash", secret_hint="NTLM …8f3a")
    db.add(credential); db.flush()
    db.add(RemoteExecution(
        project_id=p.id, target_id=destination.id, credential_id=credential.id,
        command_id="windows_config_search", category="config_files",
        connection="wmiexec", request_key="lineage-1", approval_token_hash="x",
        argv_json="[]", command_display="impacket-wmiexec CORP/administrator@10.0.0.20",
        timeout_seconds=30, status="completed", exit_code=0))
    db.flush()

    service.sync_from_project(db, p.id)

    nodes = db.query(GraphNode).filter_by(project_id=p.id).all()
    edges = db.query(GraphEdge).filter_by(project_id=p.id).all()
    credential_node = next(node for node in nodes if node.type == "credential")
    hosts = {json.loads(node.source_ref)["id"]: node for node in nodes
             if node.type == "host"}
    reused = next(edge for edge in edges if edge.relation == "reused-credential")
    lateral = next(edge for edge in edges if edge.relation == "pivoted-to")
    assert reused.source == credential_node.id
    assert reused.target == hosts[destination.id].id
    assert reused.status == "succeeded"
    assert reused.label == "CORP\\administrator · WMIEXEC"
    assert json.loads(reused.meta)["remoteExecutionId"]
    assert lateral.source == hosts[source.id].id
    assert lateral.target == hosts[destination.id].id
    assert lateral.label == "LATERAL · CORP\\administrator"

    service.sync_from_project(db, p.id)
    assert db.query(GraphEdge).filter_by(
        project_id=p.id, relation="reused-credential").count() == 1
    assert db.query(GraphEdge).filter_by(
        project_id=p.id, relation="pivoted-to").count() == 1


def test_sync_points_reused_credential_at_the_specific_service_when_known():
    # Without a matching Service row, reused-credential always landed on
    # the bare host -- correct when nothing narrower is known, but for a
    # target that *was* port-scanned (the common case), "I logged in with
    # this credential" should point at the exact service that was logged
    # into (5985/tcp winrm), not the host in general. pivoted-to stays
    # host-level regardless, since its relation only allows host->host.
    from app.models import Credential, RemoteExecution, Service, Target
    db = database()
    p = project(db)
    t = Target(project_id=p.id, name="dc", ip="10.0.0.30")
    db.add(t); db.flush()
    svc = Service(target_id=t.id, port=5985, protocol="tcp", name="http")
    db.add(svc); db.flush()
    credential = Credential(
        project_id=p.id, target_id=t.id, username="Administrator",
        secret_kind="password", secret="badminton", source_kind="responder")
    db.add(credential); db.flush()
    db.add(RemoteExecution(
        project_id=p.id, target_id=t.id, credential_id=credential.id,
        command_id="windows_file_tree_winrm", category="file_tree",
        connection="winrm", request_key="svc-target-1", approval_token_hash="x",
        argv_json="[]", command_display="evil-winrm -i 10.0.0.30 -u Administrator",
        timeout_seconds=30, status="completed", exit_code=0))
    db.flush()

    service.sync_from_project(db, p.id)

    service_node = db.query(GraphNode).filter_by(project_id=p.id, type="service").one()
    host_node = db.query(GraphNode).filter_by(project_id=p.id, type="host").one()
    reused = db.query(GraphEdge).filter_by(
        project_id=p.id, relation="reused-credential").one()
    assert reused.target == service_node.id
    assert reused.target != host_node.id
    # a lone target has no lateral hop -- no pivoted-to edge to mis-point
    assert db.query(GraphEdge).filter_by(
        project_id=p.id, relation="pivoted-to").count() == 0


def test_sync_upgrades_a_stale_host_level_reused_credential_edge_to_the_service():
    # Reproduces the case where the RemoteExecution completed (and got its
    # host-level reused-credential edge) *before* the target was port-
    # scanned -- once a matching Service shows up on a later sync, the
    # stale host edge must be replaced, not left behind as a duplicate
    # alongside the new service-targeted one.
    from app.models import Credential, RemoteExecution, Service, Target
    db = database()
    p = project(db)
    t = Target(project_id=p.id, name="dc", ip="10.0.0.31")
    db.add(t); db.flush()
    credential = Credential(
        project_id=p.id, target_id=t.id, username="Administrator",
        secret_kind="password", secret="badminton", source_kind="responder")
    db.add(credential); db.flush()
    db.add(RemoteExecution(
        project_id=p.id, target_id=t.id, credential_id=credential.id,
        command_id="windows_file_tree_winrm", category="file_tree",
        connection="winrm", request_key="svc-upgrade-1", approval_token_hash="x",
        argv_json="[]", command_display="evil-winrm -i 10.0.0.31 -u Administrator",
        timeout_seconds=30, status="completed", exit_code=0))
    db.flush()

    service.sync_from_project(db, p.id)
    host_node = db.query(GraphNode).filter_by(project_id=p.id, type="host").one()
    first = db.query(GraphEdge).filter_by(
        project_id=p.id, relation="reused-credential").one()
    assert first.target == host_node.id

    db.add(Service(target_id=t.id, port=5985, protocol="tcp", name="http"))
    db.flush()
    service.sync_from_project(db, p.id)

    edges = db.query(GraphEdge).filter_by(
        project_id=p.id, relation="reused-credential").all()
    assert len(edges) == 1
    service_node = db.query(GraphNode).filter_by(project_id=p.id, type="service").one()
    assert edges[0].target == service_node.id


def test_sync_does_not_claim_lineage_for_failed_authentication():
    from app.models import Credential, RemoteExecution, Target
    db = database()
    p = project(db)
    source = Target(project_id=p.id, name="source", ip="10.0.0.10")
    destination = Target(project_id=p.id, name="destination", ip="10.0.0.20")
    db.add_all([source, destination]); db.flush()
    credential = Credential(project_id=p.id, target_id=source.id,
                            username="alice", secret_kind="password")
    db.add(credential); db.flush()
    db.add(RemoteExecution(
        project_id=p.id, target_id=destination.id, credential_id=credential.id,
        command_id="linux_config_grep", category="config_files", connection="ssh",
        request_key="lineage-failed", approval_token_hash="x", argv_json="[]",
        timeout_seconds=30, status="failed", exit_code=255))
    db.flush()

    service.sync_from_project(db, p.id)

    assert db.query(GraphEdge).filter(GraphEdge.relation.in_([
        "reused-credential", "pivoted-to"])).count() == 0


def test_a_fuzzing_execution_gets_its_own_activity_kind_not_a_generic_scan():
    # ffuf/feroxbuster/gobuster all work through their own wordlist -- the
    # canvas gives that a distinct "fuzz" cue instead of the plain radar
    # sweep every other still-running execution gets. Driven by the
    # template's own catalog `tool` field, not a template-id allowlist, so
    # a new fuzz-shaped template picks this up without a matching edit here.
    from app.models import Execution, Service, Target
    db = database()
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.11")
    db.add(t); db.flush()
    svc = Service(target_id=t.id, port=80, protocol="tcp", name="http")
    db.add(svc); db.flush()
    db.add(Execution(target_id=t.id, service_id=svc.id, template_id="http-directory-fuzz-ext",
                     command="feroxbuster -u http://10.0.0.11/ -w rockyou.txt -x php,txt",
                     cwd="/tmp", status="running"))
    db.add(Execution(target_id=t.id, service_id=svc.id, template_id="http-param-fuzz",
                     command="ffuf -u http://10.0.0.11/?FUZZ=test -w rockyou.txt",
                     cwd="/tmp", status="running"))
    db.add(Execution(target_id=t.id, service_id=svc.id, template_id="http-service-version",
                     command="nmap -sV -p80 10.0.0.11", cwd="/tmp", status="running"))
    db.flush()

    service.sync_from_project(db, p.id)

    techniques = db.query(GraphNode).filter_by(project_id=p.id, type="technique").all()
    kinds = {json.loads(t.meta)["tool"]: json.loads(t.meta).get("activity", {}).get("kind")
             for t in techniques}
    assert kinds["http-directory-fuzz-ext"] == "fuzz"
    assert kinds["http-param-fuzz"] == "fuzz"
    assert kinds["http-service-version"] == "execution"


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


def test_sync_projects_autorecon_artifacts_as_host_techniques():
    from app.models import ScanArtifact, ScanJob, Target
    db = database()
    p = project(db)
    target = Target(project_id=p.id, name="box", ip="10.0.0.70")
    db.add(target); db.flush()
    job = ScanJob(project_id=p.id, target_id=target.id, source="autorecon",
                  status="completed", command="autorecon 10.0.0.70")
    db.add(job); db.flush()
    artifact = ScanArtifact(scan_job_id=job.id, kind="command_output",
                            path="/tmp/_manual_commands.txt", sha256="a" * 64,
                            size=42, original_name="_manual_commands.txt")
    db.add(artifact); db.flush()

    service.sync_from_project(db, p.id)

    node = db.query(GraphNode).filter_by(type="technique").one()
    assert node.label == "AutoRecon · Manual Follow-up Commands"
    assert json.loads(node.meta)["path"] == "/tmp/_manual_commands.txt"
    edge = db.query(GraphEdge).filter_by(target=node.id).one()
    assert db.get(GraphNode, edge.source).type == "host"


def test_sync_projects_autorecon_run_and_pipeline_as_graph_structure():
    from app.models import AutoReconRun, ScanArtifact, ScanJob, Target
    db = database()
    p = project(db)
    target = Target(project_id=p.id, name="box", ip="10.0.0.71")
    db.add(target); db.flush()
    run = AutoReconRun(project_id=p.id, target_ids=json.dumps([target.id]),
                       command="autorecon 10.0.0.71 --tags safe", output_dir="/tmp/ar",
                       status="running", imported_count=3)
    db.add(run)
    job = ScanJob(project_id=p.id, target_id=target.id, source="autorecon",
                  status="completed", command=run.command)
    db.add(job); db.flush()
    db.add(ScanArtifact(scan_job_id=job.id, kind="xml", path="/tmp/nmap.xml",
                        sha256="b" * 64, size=100,
                        original_name="_quick_tcp_nmap.xml"))
    db.flush()

    service.sync_from_project(db, p.id)

    labels = {node.label: node for node in db.query(GraphNode).all()}
    assert "AutoRecon Run #1" in labels
    assert "AutoRecon · Quick TCP Scan" not in labels
    relations = {(edge.relation, edge.source, edge.target)
                 for edge in db.query(GraphEdge).all()}
    assert ("scans", labels["AutoRecon Run #1"].id, labels["10.0.0.71"].id) in relations


def test_sync_projects_removes_existing_autorecon_machine_artifact_nodes():
    from app.models import ScanArtifact, ScanJob, Target
    db = database()
    p = project(db)
    target = Target(project_id=p.id, name="box", ip="10.0.0.72")
    db.add(target); db.flush()
    job = ScanJob(project_id=p.id, target_id=target.id, source="autorecon",
                  status="completed", command="autorecon 10.0.0.72")
    db.add(job); db.flush()
    artifact = ScanArtifact(scan_job_id=job.id, kind="xml", path="/tmp/nmap.xml",
                            sha256="c" * 64, size=100,
                            original_name="tcp_80_http_nmap.xml")
    db.add(artifact); db.flush()
    host = service.create_node(db, p.id, "host", label=target.ip,
                               source_ref=json.dumps({"module": "core", "kind": "target",
                                                      "id": target.id}))
    duplicate = service.create_node(
        db, p.id, "technique", label="AutoRecon · tcp_80_http_nmap.xml",
        source_ref=json.dumps({"module": "scan_center", "kind": "scan_artifact",
                               "id": artifact.id}))
    service.create_edge(db, p.id, host.id, duplicate.id, "attempted")

    service.sync_from_project(db, p.id)

    assert db.get(GraphNode, duplicate.id) is None
    assert db.query(ScanArtifact).filter_by(id=artifact.id).one()


def test_execution_parents_under_the_finding_it_was_run_to_follow_up_on():
    # docs/SPEC_GRAPH_TRACKER.md §6.1 "노드 연결 원칙" -- an execution
    # triggered from a specific finding (e.g. re-running a directory brute
    # force after spotting a vhost) belongs under that finding, not the
    # generic host/service every execution falls back to by default.
    from app.models import Execution, Finding, Target
    db = database()
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.26")
    db.add(t); db.flush()
    finding = Finding(project_id=p.id, target_id=t.id, title="Ftp Anon on 10.0.0.26:21")
    db.add(finding); db.flush()
    service.sync_from_project(db, p.id)
    finding_node = db.query(GraphNode).filter_by(type="finding").one()

    db.add(Execution(target_id=t.id, template_id="ftp-directory-tree",
                     command="python -m app.ftp_tree ...", cwd="/tmp", status="completed",
                     graph_parent_node_id=finding_node.id))
    db.flush()

    service.sync_from_project(db, p.id)

    tech = db.query(GraphNode).filter_by(type="technique").one()
    relations = {(edge.relation, edge.source, edge.target)
                 for edge in db.query(GraphEdge).all()}
    assert ("attempted", finding_node.id, tech.id) in relations
    host = db.query(GraphNode).filter_by(type="host").one()
    assert ("attempted", host.id, tech.id) not in relations


def test_graph_hidden_execution_gets_no_node_of_its_own():
    # ftp-directory-tree auto-fired alongside an ftp-client session already
    # renders inline on that session's own Inspector -- a second graph node
    # for the same crawl would just sit next to it showing nothing new.
    from app.models import Execution, Target
    db = database()
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.28")
    db.add(t); db.flush()
    db.add(Execution(target_id=t.id, template_id="ftp-directory-tree",
                     command="python -m app.ftp_tree ...", cwd="/tmp", status="completed",
                     graph_hidden=True))
    db.flush()

    service.sync_from_project(db, p.id)

    assert db.query(GraphNode).filter_by(type="technique").count() == 0


def test_execution_node_is_pruned_once_it_turns_graph_hidden():
    from app.models import Execution, Target
    db = database()
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.29")
    db.add(t); db.flush()
    ex = Execution(target_id=t.id, template_id="ftp-directory-tree",
                   command="python -m app.ftp_tree ...", cwd="/tmp", status="completed")
    db.add(ex); db.flush()
    service.sync_from_project(db, p.id)
    assert db.query(GraphNode).filter_by(type="technique").count() == 1

    ex.graph_hidden = True
    db.flush()
    service.sync_from_project(db, p.id)

    assert db.query(GraphNode).filter_by(type="technique").count() == 0


def test_execution_falls_back_to_host_when_the_explicit_parent_is_a_credential():
    from app.models import Credential, Execution, Target
    db = database()
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.27")
    db.add(t); db.flush()
    db.add(Credential(project_id=p.id, target_id=t.id, username="bob", secret="hash",
                      secret_kind="hash", service_names="[]", notes=""))
    db.flush()
    service.sync_from_project(db, p.id)
    cred_node = db.query(GraphNode).filter_by(type="credential").one()

    db.add(Execution(target_id=t.id, template_id="feroxbuster",
                     command="feroxbuster ...", cwd="/tmp", status="completed",
                     graph_parent_node_id=cred_node.id))
    db.flush()

    service.sync_from_project(db, p.id)

    tech = db.query(GraphNode).filter_by(type="technique").one()
    host = db.query(GraphNode).filter_by(type="host").one()
    relations = {(edge.relation, edge.source, edge.target)
                 for edge in db.query(GraphEdge).all()}
    assert ("attempted", host.id, tech.id) in relations


def test_technique_node_labels_use_the_catalogs_human_readable_name():
    # "service-version" means nothing to someone reading the graph; the
    # catalog already carries a Korean name for it, so use that instead of
    # leaking the internal template id into the UI.
    from app.models import Execution, Service, Target
    db = database()
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.9")
    db.add(t); db.flush()
    svc = Service(target_id=t.id, port=80, protocol="tcp", name="http")
    db.add(svc); db.flush()
    db.add(Execution(target_id=t.id, service_id=svc.id, template_id="service-version",
                     command="nmap -sV ...", cwd="/tmp", status="completed"))
    db.flush()
    service.sync_from_project(db, p.id)
    tech = db.query(GraphNode).filter_by(type="technique").one()
    assert tech.label == "제품·버전 식별"


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
    db.add(Service(target_id=t.id, port=5985, protocol="tcp", name="http",
                   product="Microsoft HTTPAPI httpd", version="2.0"))
    db.flush()
    service.sync_from_project(db, p.id)
    svc = db.query(GraphNode).filter_by(type="service").one()
    assert svc.label == "5985/tcp winrm"
    assert json.loads(svc.meta) == {"port": 5985, "protocol": "tcp", "name": "winrm",
                                    "product": "Microsoft HTTPAPI httpd", "version": "2.0",
                                    "evidenceCount": 0}


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
    # catalog's human-readable name, not the raw template id
    assert tech.label == "Responder 리스너"
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


def test_manual_shell_session_is_labeled_from_its_own_command_not_the_generic_template_id():
    # Every manually-opened session (reverse shell listener, SSH quick-connect,
    # redis-cli probe, ...) shares the synthetic template_id "manual-shell",
    # which was never a real catalog entry -- the graph used to show the
    # literal string "manual-shell" for all of them regardless of what was
    # actually run.
    from app.models import InteractiveSession, Target
    db = database()
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.29")
    db.add(t); db.flush()
    db.add(InteractiveSession(target_id=t.id, template_id="manual-shell",
                              command="nc -lvnp 4444", cwd="/tmp", status="ready"))
    db.flush()

    service.sync_from_project(db, p.id)

    tech = db.query(GraphNode).filter_by(type="technique").one()
    assert tech.label == "nc -lvnp 4444"


def test_manual_shell_session_label_is_truncated_for_a_long_command():
    from app.models import InteractiveSession, Target
    db = database()
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.30")
    db.add(t); db.flush()
    long_command = "impacket-mssqlclient " + "x" * 60
    db.add(InteractiveSession(target_id=t.id, template_id="manual-shell",
                              command=long_command, cwd="/tmp", status="ready"))
    db.flush()

    service.sync_from_project(db, p.id)

    tech = db.query(GraphNode).filter_by(type="technique").one()
    assert len(tech.label) == 60
    assert tech.label.endswith("...")
    assert tech.label.startswith("impacket-mssqlclient ")


def test_sync_retroactively_relabels_a_manual_shell_node_created_before_this_fix():
    from app.models import InteractiveSession, Target
    db = database()
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.31")
    db.add(t); db.flush()
    session = InteractiveSession(target_id=t.id, template_id="manual-shell",
                                 command="nc -lvnp 4444", cwd="/tmp", status="ready")
    db.add(session); db.flush()
    service.sync_from_project(db, p.id)
    tech = db.query(GraphNode).filter_by(type="technique").one()
    # Simulate a node that was created back when the label was still the
    # generic "manual-shell" string, before this fix existed.
    tech.label = "manual-shell"
    db.commit()

    service.sync_from_project(db, p.id)

    db.refresh(tech)
    assert tech.label == "nc -lvnp 4444"


def test_sync_does_not_overwrite_a_manual_shell_label_the_operator_already_edited():
    from app.models import InteractiveSession, Target
    db = database()
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.32")
    db.add(t); db.flush()
    session = InteractiveSession(target_id=t.id, template_id="manual-shell",
                                 command="nc -lvnp 4444", cwd="/tmp", status="ready")
    db.add(session); db.flush()
    service.sync_from_project(db, p.id)
    tech = db.query(GraphNode).filter_by(type="technique").one()
    tech.label = "웹셸 리버스쉘 (커스텀 이름)"
    db.commit()

    service.sync_from_project(db, p.id)

    db.refresh(tech)
    assert tech.label == "웹셸 리버스쉘 (커스텀 이름)"


def test_listener_log_state_reads_the_sessions_own_log(tmp_path):
    armed = tmp_path / "armed.log"
    armed.write_text("listening on [any] 4444 ...\n")
    assert service._listener_log_state(str(armed)) == "armed"

    connected = tmp_path / "connected.log"
    connected.write_text(
        "listening on [any] 4444 ...\nconnect to [1.2.3.4] from (UNKNOWN) [5.6.7.8] 1111\n")
    assert service._listener_log_state(str(connected)) == "connected"

    unrelated = tmp_path / "unrelated.log"
    unrelated.write_text("Microsoft Windows [Version 10.0.19045.1234]\n")
    assert service._listener_log_state(str(unrelated)) is None

    assert service._listener_log_state("") is None
    assert service._listener_log_state(str(tmp_path / "missing.log")) is None


def test_sync_reads_manual_nc_listener_as_armed_until_the_log_shows_a_connection(
        monkeypatch, tmp_path):
    # openManualShell/openListenerShell (App.tsx) always create the session
    # with no command in the request, then type the real "nc -lvnp ..."
    # command into the resulting bash shell as PTY input -- so the session's
    # own `command` column stays "/bin/bash --noprofile --norc" forever and
    # can't be used to recognize a listener. Only the PTY log (which captures
    # nc's own stdout regardless of how nc was launched) can tell "armed" from
    # "connected".
    import os
    from app.models import InteractiveSession, Target

    db = database()
    monkeypatch.setattr(service, "_operator_address", lambda: "10.10.16.178")
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.13")
    db.add(t); db.flush()

    log = tmp_path / "session_1.log"
    log.write_text("listening on [any] 4444 ...\n")
    db.add(InteractiveSession(target_id=t.id, template_id="manual-shell",
                              command="/bin/bash --noprofile --norc", cwd="/tmp",
                              status="launched", pid=os.getpid(), log_path=str(log)))
    db.flush()

    service.sync_from_project(db, p.id)
    tech = db.query(GraphNode).filter_by(type="technique").one()
    assert json.loads(tech.meta)["activity"]["kind"] == "listener"

    log.write_text(
        "listening on [any] 4444 ...\nconnect to [10.0.0.13] from (UNKNOWN) [10.10.16.178] 51522\n")
    service.sync_from_project(db, p.id)
    db.refresh(tech)
    assert json.loads(tech.meta)["activity"]["kind"] == "shell"


def test_sync_reads_a_non_listener_manual_session_as_a_shell_immediately():
    import os
    from app.models import InteractiveSession, Target

    db = database()
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.14")
    db.add(t); db.flush()
    db.add(InteractiveSession(target_id=t.id, template_id="manual-shell",
                              command="/bin/bash --noprofile --norc", cwd="/tmp",
                              status="launched", pid=os.getpid()))
    db.flush()

    service.sync_from_project(db, p.id)
    tech = db.query(GraphNode).filter_by(type="technique").one()
    assert json.loads(tech.meta)["activity"]["kind"] == "shell"


def test_session_parents_under_the_finding_it_was_opened_from():
    # Same override as executions/hash-crack jobs (SPEC_GRAPH_TRACKER.md §6.1) --
    # e.g. the "익명으로 접속하기" button on an Ftp Anon finding opens the
    # session with graph_node_id set to that finding.
    from app.models import Finding, InteractiveSession, Target
    db = database()
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.29")
    db.add(t); db.flush()
    finding = Finding(project_id=p.id, target_id=t.id, title="Ftp Anon on 10.0.0.29:21")
    db.add(finding); db.flush()
    service.sync_from_project(db, p.id)
    finding_node = db.query(GraphNode).filter_by(type="finding").one()

    db.add(InteractiveSession(target_id=t.id, template_id="ftp-client",
                              command="ftp 10.0.0.29", cwd="/tmp", status="launched",
                              graph_parent_node_id=finding_node.id))
    db.flush()

    service.sync_from_project(db, p.id)

    tech = db.query(GraphNode).filter_by(type="technique").one()
    relations = {(edge.relation, edge.source, edge.target)
                 for edge in db.query(GraphEdge).all()}
    assert ("attempted", finding_node.id, tech.id) in relations
    host = db.query(GraphNode).filter_by(type="host").one()
    assert ("attempted", host.id, tech.id) not in relations


def test_session_falls_back_to_host_when_the_explicit_parent_is_a_technique():
    # Regression test: Inspector.tsx's openSsh/openPsexec/openEvilWinrm quick
    # actions pass the currently selected node's id as graph_node_id, and
    # that node can be a technique (e.g. a completed NetExec check), not just
    # a finding. "attempted" only permits finding/service/host as a source
    # (same rule enforced for Execution and HashCrackJob below) -- without
    # the type guard this used to raise GraphIntegrityError and break sync
    # for the whole project on every subsequent poll.
    from app.models import Execution, InteractiveSession, Target
    db = database()
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.30")
    db.add(t); db.flush()
    db.add(Execution(target_id=t.id, template_id="netexec-check",
                     command="nxc smb 10.0.0.30", cwd="/tmp", status="completed"))
    db.flush()
    service.sync_from_project(db, p.id)
    technique_node = db.query(GraphNode).filter_by(type="technique").one()

    db.add(InteractiveSession(target_id=t.id, template_id="ssh-client",
                              command="ssh admin@10.0.0.30", cwd="/tmp", status="launched",
                              graph_parent_node_id=technique_node.id))
    db.flush()

    service.sync_from_project(db, p.id)

    host = db.query(GraphNode).filter_by(type="host").one()
    sessions_tech = [n for n in db.query(GraphNode).filter_by(type="technique").all()
                     if n.id != technique_node.id]
    assert len(sessions_tech) == 1
    relations = {(edge.relation, edge.source, edge.target)
                 for edge in db.query(GraphEdge).all()}
    assert ("attempted", host.id, sessions_tech[0].id) in relations


def test_sync_links_a_responder_captured_credential_to_the_listener_that_caught_it(monkeypatch):
    # Without this, a Responder-sourced credential only ever got the same
    # generic host->credential "enumerated" edge every other credential
    # gets -- nothing in the graph showed which capture session it actually
    # came from, even though the listener node ("captures-from" a host) was
    # right there.
    import os
    from app.models import Credential, InteractiveSession, Target
    db = database()
    monkeypatch.setattr(service, "_operator_address", lambda: "10.10.16.178")
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.12")
    db.add(t); db.flush()
    db.add(InteractiveSession(target_id=t.id, template_id="responder-listener",
                              command="responder -I tun0", cwd="/tmp",
                              status="launched", pid=os.getpid()))
    db.add(Credential(project_id=p.id, target_id=t.id, username="Administrator",
                      secret="badminton", secret_kind="password",
                      source_kind="responder", source_detail="SMB-NTLMv2-SSP-10.0.0.12",
                      service_names="[]", notes=""))
    db.flush()

    service.sync_from_project(db, p.id)

    tech = db.query(GraphNode).filter_by(type="technique").one()
    cred = db.query(GraphNode).filter_by(type="credential").one()
    relations = {(edge.relation, edge.source, edge.target)
                 for edge in db.query(GraphEdge).all()}
    assert ("yielded", tech.id, cred.id) in relations
    host = db.query(GraphNode).filter_by(type="host").one()
    assert ("enumerated", host.id, cred.id) not in relations

    # a second sync (idempotent re-run) must not duplicate the edge
    service.sync_from_project(db, p.id)
    yielded = [e for e in db.query(GraphEdge).all()
               if e.relation == "yielded" and e.source == tech.id and e.target == cred.id]
    assert len(yielded) == 1


def test_sync_projects_hash_crack_jobs_as_technique_nodes():
    from app.models import HashCrackJob, Target
    db = database()
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.20")
    db.add(t); db.flush()
    db.add(HashCrackJob(project_id=p.id, target_id=t.id, label="DC01 kerberoast",
                        hash_mode_id="13100", hash_mode="16800", hash_type_name="Kerberos TGS-REP",
                        status="running"))
    db.flush()

    result = service.sync_from_project(db, p.id)

    assert result["created"]["techniques"] == 1
    tech = db.query(GraphNode).filter_by(type="technique").one()
    assert tech.label == "DC01 kerberoast"
    assert tech.status == "in-progress"
    activity = json.loads(tech.meta)["activity"]
    assert activity["kind"] == "crack"
    assert activity["status"] == "running"
    host = db.query(GraphNode).filter_by(type="host").one()
    relations = {(edge.relation, edge.source, edge.target)
                 for edge in db.query(GraphEdge).all()}
    assert ("attempted", host.id, tech.id) in relations


def test_hash_crack_job_parents_under_the_finding_its_hash_came_from():
    # A job launched by sending a zip2john hash from a specific finding
    # (e.g. a promoted backup.zip) belongs under that finding, not the bare
    # host every job falls back to by default.
    from app.models import Finding, HashCrackJob, Target
    db = database()
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.24")
    db.add(t); db.flush()
    finding = Finding(project_id=p.id, target_id=t.id, title="파일 다운로드: backup.zip")
    db.add(finding); db.flush()
    service.sync_from_project(db, p.id)
    finding_node = db.query(GraphNode).filter_by(type="finding").one()

    db.add(HashCrackJob(project_id=p.id, target_id=t.id, hash_mode_id="pkzip",
                        hash_mode="17200", hash_type_name="PKZIP", status="running",
                        graph_parent_node_id=finding_node.id))
    db.flush()

    service.sync_from_project(db, p.id)

    tech = db.query(GraphNode).filter_by(type="technique").one()
    relations = {(edge.relation, edge.source, edge.target)
                 for edge in db.query(GraphEdge).all()}
    assert ("attempted", finding_node.id, tech.id) in relations
    host = db.query(GraphNode).filter_by(type="host").one()
    assert ("attempted", host.id, tech.id) not in relations


def test_hash_crack_job_falls_back_to_host_when_the_explicit_parent_is_a_credential():
    # credential is always a structural leaf (SPEC_GRAPH_TRACKER §1.4) and
    # can never be a valid `attempted` source -- even if some future caller
    # passes one, this must not violate the schema.
    from app.models import Credential, HashCrackJob, Target
    db = database()
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.25")
    db.add(t); db.flush()
    db.add(Credential(project_id=p.id, target_id=t.id, username="bob", secret="hash",
                      secret_kind="hash", service_names="[]", notes=""))
    db.flush()
    service.sync_from_project(db, p.id)
    cred_node = db.query(GraphNode).filter_by(type="credential").one()

    db.add(HashCrackJob(project_id=p.id, target_id=t.id, hash_mode_id="ntlm",
                        hash_mode="1000", hash_type_name="NTLM", status="running",
                        graph_parent_node_id=cred_node.id))
    db.flush()

    service.sync_from_project(db, p.id)

    tech = db.query(GraphNode).filter_by(type="technique").one()
    host = db.query(GraphNode).filter_by(type="host").one()
    relations = {(edge.relation, edge.source, edge.target)
                 for edge in db.query(GraphEdge).all()}
    assert ("attempted", host.id, tech.id) in relations


def test_sync_clears_hash_crack_activity_once_the_job_finishes():
    from app.models import HashCrackJob, Target
    db = database()
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.21")
    db.add(t); db.flush()
    job = HashCrackJob(project_id=p.id, target_id=t.id, hash_mode_id="1000",
                       hash_mode="1000", hash_type_name="NTLM", status="running")
    db.add(job); db.flush()

    service.sync_from_project(db, p.id)
    tech = db.query(GraphNode).filter_by(type="technique").one()
    assert "activity" in json.loads(tech.meta)

    job.status, job.cracked_count = "completed", 3
    service.sync_from_project(db, p.id)
    db.refresh(tech)
    assert "activity" not in json.loads(tech.meta)
    # a completed run isn't auto-judged a security success just because
    # something cracked -- same restraint as a completed Execution's exit 0
    assert tech.status == "in-progress"


def test_sync_downgrades_a_hash_crack_job_that_exhausts_its_wordlist_with_no_hits():
    from app.models import HashCrackJob, Target
    db = database()
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.22")
    db.add(t); db.flush()
    job = HashCrackJob(project_id=p.id, target_id=t.id, hash_mode_id="1000",
                       hash_mode="1000", hash_type_name="NTLM", status="running")
    db.add(job); db.flush()
    service.sync_from_project(db, p.id)

    job.status, job.cracked_count = "completed", 0
    service.sync_from_project(db, p.id)

    tech = db.query(GraphNode).filter_by(type="technique").one()
    assert tech.status == "attempt-failed"


def test_hash_crack_job_yields_the_credential_it_cracked():
    from app.models import Credential, HashCrackJob, Target
    db = database()
    p = project(db)
    t = Target(project_id=p.id, name="b", ip="10.0.0.23")
    db.add(t); db.flush()
    job = HashCrackJob(project_id=p.id, target_id=t.id, hash_mode_id="1000",
                       hash_mode="1000", hash_type_name="NTLM", status="completed",
                       cracked_count=1)
    db.add(job); db.flush()
    db.add(Credential(project_id=p.id, target_id=t.id, username="bob", secret="hunter2",
                      secret_kind="password", source_kind="hash_crack",
                      source_execution_kind="hash_crack_job", source_execution_id=job.id,
                      service_names="[]", notes=""))
    db.flush()

    service.sync_from_project(db, p.id)

    tech = db.query(GraphNode).filter_by(type="technique").one()
    cred = db.query(GraphNode).filter_by(type="credential").one()
    relations = {(edge.relation, edge.source, edge.target)
                 for edge in db.query(GraphEdge).all()}
    assert ("yielded", tech.id, cred.id) in relations

    # idempotent re-run must not duplicate the edge
    service.sync_from_project(db, p.id)
    yielded = [e for e in db.query(GraphEdge).all()
               if e.relation == "yielded" and e.source == tech.id and e.target == cred.id]
    assert len(yielded) == 1


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


def test_sync_prunes_projected_nodes_when_target_moves_to_another_project():
    from app.models import Target
    db = database()
    source = project(db, "Source")
    destination = project(db, "Destination")
    target_with_services(db, source.id)
    service.sync_from_project(db, source.id)
    moved = db.query(Target).one()
    moved.project_id = destination.id
    db.flush()

    service.sync_from_project(db, source.id)

    assert db.query(GraphNode).filter_by(project_id=source.id, type="host").count() == 0
    assert db.query(GraphNode).filter_by(project_id=source.id, type="service").count() == 0


def test_ensure_project_root_refreshes_stale_label():
    db = database()
    p = project(db, name="Responder")
    root = service.ensure_project_root(db, p.id)
    root.label = "10.129.245.191"  # stale (project was briefly IP-named)
    db.flush()
    again = service.ensure_project_root(db, p.id)
    assert again.label == "Responder"
