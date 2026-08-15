"""Persistence + integrity layer bridging DB rows and the pure tree engine.

The engine (``engine.py``) knows nothing about SQLAlchemy; this module maps
``GraphNode``/``GraphEdge`` rows into engine records, enforces the schema's
integrity rules (spec 1.4/1.7), and serializes engine output for the API.
"""
from __future__ import annotations

import hashlib
import json
import os
import re

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...models import (Credential, Evidence, Execution, Finding, FindingEvidence, GraphEdge,
                       GraphEvent, GraphNode, GraphProjectMeta, HashCrackJob, InteractiveSession,
                       Project, RemoteExecution, ScanJob, Service, Target)
from ...templates import catalog
from ..vpn import vpn_status


def _catalog_label(template_id: str | None, fallback: str) -> str:
    """Technique nodes are labeled from the catalog's human-readable name
    (e.g. "제품·버전 식별") rather than its raw id ("service-version") --
    the id means nothing to someone reading the graph, not just the person
    who wrote the YAML."""
    item = catalog.items.get(template_id or "")
    return (item or {}).get("name") or template_id or fallback

# Executions are auto-nodified but their security outcome is never auto-judged
# (product principle): a completed command is not a "success". Only technical
# failure/interruption maps to attempt-failed; the user marks real outcomes.
_EXECUTION_STATUS = {
    "queued": "in-progress", "running": "in-progress", "completed": "in-progress",
    "failed": "attempt-failed", "interrupted": "attempt-failed",
}

# nmap reports some services by a generic/misleading name — WinRM's HTTP.sys
# listener shows up as "http" — so relabel well-known ports the way a pentester
# reads them.
_WELL_KNOWN_PORT_NAMES = {5985: "winrm", 5986: "winrm"}

# Which port(s) a RemoteExecution.connection value actually logged into --
# lets the reused-credential edge below point at the specific service a
# credential unlocked instead of always landing on the host in general.
# wmiexec/secretsdump both authenticate over SMB/DCE-RPC, so both map to
# the same SMB port; there's no narrower "service" to point at than that.
_CONNECTION_PORTS = {
    "ssh": {22}, "winrm": {5985, 5986}, "wmiexec": {445, 135}, "secretsdump": {445, 135},
}

_ACTIVE_STATUSES = {"queued", "running", "processing", "launched"}


def _operator_address() -> str:
    match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})/\d+",
                      vpn_status().get("tun0", ""))
    return match.group(1) if match else "tun0 offline"


def _merge_meta(raw: str, patch: dict) -> str:
    """Merge persistent fields (e.g. evidenceCount) into a node's meta JSON
    without disturbing keys owned by other parts of sync (e.g. activity)."""
    try:
        meta = json.loads(raw) if raw else {}
        if not isinstance(meta, dict):
            meta = {}
    except (TypeError, json.JSONDecodeError):
        meta = {}
    meta.update(patch)
    return json.dumps(meta)


# Evidence has no credential_id -- a credential's evidence trail only exists
# where source_execution_kind/id (Credential's structured provenance pointer,
# see docs/DOMAIN_MODEL_GAP_ANALYSIS.md §3.3) points at a row that itself has
# an evidence_id. Only hash-crack promotion sets that pointer today; other
# sources (manual entry, Responder capture, DCSync, ...) correctly report 0
# until they get the same structured provenance.
_CREDENTIAL_EXECUTION_MODELS = {"hash_crack_job": HashCrackJob}


def _credential_evidence_count(db: Session, cred: Credential) -> int:
    model = _CREDENTIAL_EXECUTION_MODELS.get(cred.source_execution_kind or "")
    if not model or not cred.source_execution_id:
        return 0
    run = db.get(model, cred.source_execution_id)
    return 1 if run and run.evidence_id else 0


def _activity_meta(raw: str, activity: dict | None) -> str:
    """Merge ephemeral process activity without disturbing node-owned metadata."""
    try:
        meta = json.loads(raw) if raw else {}
        if not isinstance(meta, dict):
            meta = {}
    except (TypeError, json.JSONDecodeError):
        meta = {}
    if activity is None:
        meta.pop("activity", None)
    else:
        meta["activity"] = activity
    return json.dumps(meta)


def _runtime_activity(kind: str, status: str, label: str,
                      started_at=None) -> dict | None:
    if status not in _ACTIVE_STATUSES:
        return None
    return {"kind": kind, "status": status, "label": label,
            "startedAt": started_at.isoformat() if started_at else None}


def _pid_alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def _service_display_name(service) -> str:
    return _WELL_KNOWN_PORT_NAMES.get(service.port, service.name)
from . import engine
from .ids import new_ulid

NODE_TYPES = {
    "project-root", "operator", "host", "service", "finding", "technique",
    "credential", "memo",
}
NODE_STATUSES = {
    "untried", "in-progress", "attempt-failed", "succeeded", "blocked",
    "not-applicable",
}
EDGE_STATUSES = NODE_STATUSES  # shared vocabulary (spec 1.5)

# relation -> (allowed source types, allowed target types) — spec 1.4.
ALLOWED_RELATIONS: dict[str, tuple[set[str], set[str]]] = {
    "operates": ({"project-root"}, {"operator"}),
    "runs": ({"operator"}, {"technique"}),
    "captures-from": ({"technique"}, {"host"}),
    "discovered": ({"project-root", "host"}, {"host", "service"}),
    "enumerated": ({"service", "host"}, {"finding", "credential"}),
    "attempted": ({"finding", "service", "host"}, {"technique"}),
    # "finding" as a source covers a file pulled back out of another finding
    # (e.g. extracting an entry from a downloaded archive) -- the archive's
    # own finding "yielded" the extracted one, same relationship a technique
    # yielding a finding already has, just one hop further down.
    "yielded": ({"technique", "finding"}, {"credential", "host", "service", "finding"}),
    "pivoted-to": ({"host"}, {"host"}),
    "reused-credential": ({"credential"}, {"host", "service"}),
    "blocked-by": ({"technique", "finding"}, NODE_TYPES),
}


class GraphIntegrityError(ValueError):
    """Raised when a node/edge violates the schema rules (mapped to HTTP 422)."""


# --- engine mapping ---

def _node_data(row: GraphNode) -> engine.NodeData:
    return engine.NodeData(
        id=row.id, type=row.type, status=row.status,
        created_at=row.created_at.isoformat(), label=row.label,
        pinned_canonical_edge_id=row.pinned_canonical_edge_id,
        objective=row.objective,
    )


def _edge_data(row: GraphEdge) -> engine.EdgeData:
    return engine.EdgeData(
        id=row.id, source=row.source, target=row.target, relation=row.relation,
        status=row.status, created_at=row.created_at.isoformat(),
    )


def _load(db: Session, project_id: int) -> tuple[list[GraphNode], list[GraphEdge]]:
    nodes = list(db.scalars(
        select(GraphNode).where(GraphNode.project_id == project_id)))
    edges = list(db.scalars(
        select(GraphEdge).where(GraphEdge.project_id == project_id)))
    return nodes, edges


def record_snapshot(db: Session, project_id: int) -> GraphEvent | None:
    """Append a replay frame only when the observable graph actually changed."""
    nodes, edges = _load(db, project_id)
    project_meta = db.get(GraphProjectMeta, project_id)
    payload = json.dumps({
        "root_node_id": project_meta.root_node_id if project_meta else None,
        "nodes": [{column.name: getattr(node, column.name)
                   for column in GraphNode.__table__.columns
                   if column.name != "project_id"}
                  for node in sorted(nodes, key=lambda item: item.id)],
        "edges": [{column.name: getattr(edge, column.name)
                   for column in GraphEdge.__table__.columns
                   if column.name != "project_id"}
                  for edge in sorted(edges, key=lambda item: item.id)],
    }, default=lambda value: value.isoformat(), sort_keys=True, separators=(",", ":"))
    fingerprint = hashlib.sha256(payload.encode()).hexdigest()
    previous = db.scalar(select(GraphEvent).where(
        GraphEvent.project_id == project_id).order_by(GraphEvent.id.desc()).limit(1))
    if previous and previous.fingerprint == fingerprint:
        return None
    event = GraphEvent(project_id=project_id, kind="graph-snapshot",
                       fingerprint=fingerprint, payload=payload)
    db.add(event)
    db.flush()
    return event


# --- project-root bootstrap (spec 2.1) ---

def ensure_project_root(db: Session, project_id: int) -> GraphNode:
    project = db.get(Project, project_id)
    if project is None:
        raise GraphIntegrityError(f"project {project_id} does not exist")
    meta = db.get(GraphProjectMeta, project_id)
    if meta is not None and meta.root_node_id:
        root = db.get(GraphNode, meta.root_node_id)
        if root is not None:
            # keep the root label in sync with the project name (heals roots
            # created when the project was briefly named after an IP)
            if root.label != project.name:
                root.label = project.name
            return root
    root = GraphNode(id=new_ulid(), project_id=project_id, type="project-root",
                     label=project.name, status="in-progress")
    db.add(root)
    db.flush()
    if meta is None:
        db.add(GraphProjectMeta(project_id=project_id, root_node_id=root.id))
    else:
        meta.root_node_id = root.id
    db.flush()
    return root


# --- mutations ---

def create_node(db: Session, project_id: int, type: str, label: str = "",
                status: str = "untried", **fields) -> GraphNode:
    if type not in NODE_TYPES:
        raise GraphIntegrityError(f"unknown node type: {type}")
    if status not in NODE_STATUSES:
        raise GraphIntegrityError(f"unknown node status: {status}")
    node = GraphNode(id=new_ulid(), project_id=project_id, type=type,
                     label=label, status=status, **fields)
    db.add(node)
    db.flush()
    return node


def create_edge(db: Session, project_id: int, source: str, target: str,
                relation: str, status: str = "untried", label: str = "",
                **fields) -> GraphEdge:
    if relation not in ALLOWED_RELATIONS:
        raise GraphIntegrityError(f"unknown relation: {relation}")
    if status not in EDGE_STATUSES:
        raise GraphIntegrityError(f"unknown edge status: {status}")
    src = db.get(GraphNode, source)
    dst = db.get(GraphNode, target)
    if src is None or dst is None:
        raise GraphIntegrityError("edge endpoints must be existing nodes")
    if src.project_id != project_id or dst.project_id != project_id:
        raise GraphIntegrityError("edge must stay within one project")
    allowed_src, allowed_dst = ALLOWED_RELATIONS[relation]
    if src.type not in allowed_src or dst.type not in allowed_dst:
        raise GraphIntegrityError(
            f"{relation} does not allow {src.type} -> {dst.type}")
    edge = GraphEdge(id=new_ulid(), project_id=project_id, source=source,
                     target=target, relation=relation, status=status,
                     label=label, **fields)
    db.add(edge)
    db.flush()
    return edge


# --- derived views ---

def _serialize_tree(item, node_by_id: dict[str, GraphNode]):
    if isinstance(item, engine.RefLeaf):
        return {"kind": item.kind, "edgeId": item.edge_id,
                "source": item.source, "target": item.target}
    node = node_by_id[item.id]
    return {"kind": "node", "id": item.id, "path": item.path,
            "type": node.type, "label": node.label, "status": node.status,
            "children": [_serialize_tree(c, node_by_id) for c in item.children]}


def _visible(nodes: list[GraphNode], edges: list[GraphEdge]):
    """Drop user-hidden nodes (and any edge touching them) from derived views."""
    kept = {n.id for n in nodes if not n.hidden}
    vnodes = [n for n in nodes if n.id in kept]
    vedges = [e for e in edges if e.source in kept and e.target in kept]
    return vnodes, vedges


def get_tree(db: Session, project_id: int) -> dict:
    root = ensure_project_root(db, project_id)
    nodes, edges = _load(db, project_id)
    vnodes, vedges = _visible(nodes, edges)
    tree = engine.build_tree(
        [_node_data(n) for n in vnodes], [_edge_data(e) for e in vedges], root.id)
    return _serialize_tree(tree, {n.id: n for n in vnodes})


def get_attack_paths(db: Session, project_id: int) -> list[list[str]]:
    nodes, edges = _load(db, project_id)
    _, vedges = _visible(nodes, edges)
    return engine.success_paths([_edge_data(e) for e in vedges])


def get_attack_path_summary(db: Session, project_id: int) -> dict:
    nodes, edges = _load(db, project_id)
    vnodes, vedges = _visible(nodes, edges)
    return engine.attack_path_summary(
        [_node_data(n) for n in vnodes], [_edge_data(e) for e in vedges])


# --- projection sync: existing domain rows -> graph (spec 6.1) ---

def _source_ref(module: str, kind: str, ident: int) -> str:
    return json.dumps({"module": module, "kind": kind, "id": ident},
                      sort_keys=True)


def _index_by_source(nodes: list[GraphNode]) -> dict[tuple[str, int], GraphNode]:
    index: dict[tuple[str, int], GraphNode] = {}
    for node in nodes:
        if not node.source_ref:
            continue
        try:
            ref = json.loads(node.source_ref)
        except ValueError:
            continue
        index[(ref.get("kind"), ref.get("id"))] = node
    return index


def dismiss_source(db: Session, project_id: int, source_ref: str) -> None:
    if not source_ref:
        return
    meta = db.get(GraphProjectMeta, project_id)
    if meta is None:
        return
    try:
        layout = json.loads(meta.layout or "{}")
    except ValueError:
        layout = {}
    dismissed = set(layout.get("dismissedSourceRefs", []))
    dismissed.add(source_ref)
    layout["dismissedSourceRefs"] = sorted(dismissed)
    meta.layout = json.dumps(layout, sort_keys=True)


def _dismissed_sources(db: Session, project_id: int) -> set[tuple[str, int]]:
    meta = db.get(GraphProjectMeta, project_id)
    try:
        refs = json.loads(meta.layout or "{}").get("dismissedSourceRefs", []) if meta else []
    except ValueError:
        refs = []
    dismissed = set()
    for value in refs:
        try:
            ref = json.loads(value)
            dismissed.add((ref.get("kind"), ref.get("id")))
        except (TypeError, ValueError):
            continue
    return dismissed


def sync_from_project(db: Session, project_id: int) -> dict:
    """Project existing domain rows into graph nodes (idempotent, spec 6.1).

    Targets/Services -> host/service nodes; Findings/Credentials -> finding/
    credential nodes attached to their service (or host). Matching is by
    ``source_ref`` so re-running only fills gaps; user edits are left untouched.
    Secrets are never copied — only ``secret_hint``.
    """
    root = ensure_project_root(db, project_id)
    nodes, edges = _load(db, project_id)
    index = _index_by_source(nodes)
    dismissed = _dismissed_sources(db, project_id)

    # Heal orphans: a node projected from a domain row whose row no longer exists
    # (e.g. its target/service was deleted) is stale — drop it and its edges.
    # Manually-created nodes (no source_ref) are never pruned.
    kind_models = {"target": Target, "service": Service, "finding": Finding,
                   "credential": Credential, "execution": Execution,
                   "session": InteractiveSession}
    for key, node in list(index.items()):
        kind, ident = key
        model = kind_models.get(kind)
        row = db.get(model, ident) if model is not None else None
        owner_id = None
        if isinstance(row, (Target, Finding, Credential)):
            owner_id = row.project_id
        elif isinstance(row, (Service, Execution, InteractiveSession)):
            target = db.get(Target, row.target_id)
            owner_id = target.project_id if target else None
        stale_hidden = kind == "execution" and isinstance(row, Execution) and row.graph_hidden
        if model is not None and (row is None or owner_id != project_id or stale_hidden):
            db.query(GraphEdge).filter(
                (GraphEdge.source == node.id) | (GraphEdge.target == node.id)
            ).delete(synchronize_session=False)
            db.delete(node)
            del index[key]
    db.flush()

    created = {"hosts": 0, "services": 0, "findings": 0, "credentials": 0,
               "techniques": 0}
    target_ids: list[int] = []

    def host_for(target_id: int) -> GraphNode | None:
        return index.get(("target", target_id))

    def ensure_edge(source: GraphNode, target: GraphNode, relation: str,
                    label: str = "", status: str | None = None,
                    meta: str | None = None) -> GraphEdge:
        existing = next((edge for edge in edges if edge.source == source.id
                         and edge.target == target.id and edge.relation == relation), None)
        if existing:
            if label:
                existing.label = label
            if status:
                existing.status = status
            if meta is not None:
                existing.meta = meta
            return existing
        edge = create_edge(db, project_id, source.id, target.id, relation,
                           label=label, status=status or "untried", meta=meta or "{}")
        edges.append(edge)
        return edge

    def operator_for() -> GraphNode | None:
        operator = index.get(("operator", project_id))
        if operator is None and ("operator", project_id) in dismissed:
            return None
        address = _operator_address()
        label = f"Kali Operator · {address}"
        meta = json.dumps({"interface": "tun0", "ip": address})
        if operator is None:
            operator = create_node(
                db, project_id, "operator", label=label, status="in-progress",
                source_ref=_source_ref("system", "operator", project_id), meta=meta)
            index[("operator", project_id)] = operator
        else:
            operator.label, operator.meta = label, meta
        ensure_edge(root, operator, "operates")
        return operator

    active_scans = {
        scan.target_id: scan for scan in db.scalars(
            select(ScanJob).where(
                ScanJob.project_id == project_id,
                ScanJob.status.in_(_ACTIVE_STATUSES),
            ).order_by(ScanJob.id)
        )
    }

    for target in db.scalars(
            select(Target).where(Target.project_id == project_id)):
        target_ids.append(target.id)
        host = host_for(target.id)
        if host is None:
            if ("target", target.id) in dismissed:
                continue
            label = target.ip + (f" ({target.hostname})" if target.hostname else "")
            host = create_node(db, project_id, "host", label=label,
                               source_ref=_source_ref("core", "target", target.id))
            create_edge(db, project_id, root.id, host.id, "discovered")
            index[("target", target.id)] = host
            created["hosts"] += 1
        scan = active_scans.get(target.id)
        # Host-level evidence only (service_id is None) -- evidence attached to
        # one of the target's services is counted on that service node instead,
        # so the two counts don't double up on the same underlying row.
        host_evidence_count = db.scalar(select(func.count(Evidence.id)).where(
            Evidence.target_id == target.id, Evidence.service_id.is_(None))) or 0
        host.meta = _activity_meta(
            _merge_meta(host.meta, {"evidenceCount": host_evidence_count}),
            _runtime_activity(
                "scan", scan.status, scan.alias or "NMAP SCAN", scan.started_at,
            ) if scan else None)

        for service in db.scalars(
                select(Service).where(Service.target_id == target.id)):
            raw = f"{service.port}/{service.protocol} {service.name}".strip()
            refined = f"{service.port}/{service.protocol} {_service_display_name(service)}".strip()
            service_evidence_count = db.scalar(select(func.count(Evidence.id)).where(
                Evidence.service_id == service.id)) or 0
            service_meta = json.dumps({"port": service.port, "protocol": service.protocol,
                                       "name": _service_display_name(service),
                                       "product": service.product or "",
                                       "version": service.version or "",
                                       "evidenceCount": service_evidence_count})
            if ("service", service.id) not in index:
                if ("service", service.id) in dismissed:
                    continue
                svc = create_node(db, project_id, "service", label=refined,
                                  source_ref=_source_ref("scans", "service", service.id),
                                  meta=service_meta)
                create_edge(db, project_id, host.id, svc.id, "discovered")
                index[("service", service.id)] = svc
                created["services"] += 1
            else:
                # Retroactively refine a still-default label (e.g. an existing
                # "5985/tcp http" -> "5985/tcp winrm"); leave user edits alone.
                node = index[("service", service.id)]
                if node.label == raw and raw != refined:
                    node.label = refined
                node.meta = service_meta

    # findings + credentials attach to their service, else their host.
    def parent_of(service_id, target_id) -> GraphNode | None:
        if service_id and ("service", service_id) in index:
            return index[("service", service_id)]
        return host_for(target_id) if target_id else None

    for finding in db.scalars(
            select(Finding).where(Finding.project_id == project_id)):
        if ("finding", finding.id) in dismissed:
            continue
        parent = parent_of(finding.service_id, finding.target_id)
        if parent is None:
            continue
        evidence_count = db.scalar(select(func.count(FindingEvidence.id)).where(
            FindingEvidence.finding_id == finding.id)) or 0
        meta = json.dumps({"severity": finding.severity or "",
                           "category": finding.category or "",
                           "evidenceCount": evidence_count})
        if ("finding", finding.id) in index:
            index[("finding", finding.id)].meta = meta
            continue
        node = create_node(db, project_id, "finding", label=finding.title,
                           source_ref=_source_ref("findings", "finding", finding.id),
                           meta=meta)
        create_edge(db, project_id, parent.id, node.id, "enumerated")
        index[("finding", finding.id)] = node
        created["findings"] += 1

    for cred in db.scalars(
            select(Credential).where(Credential.project_id == project_id)):
        if ("credential", cred.id) in dismissed:
            continue
        parent = parent_of(cred.service_id, cred.target_id)
        if parent is None:
            continue
        label = cred.username or (cred.domain and f"{cred.domain}\\") or "credential"
        meta = json.dumps({"username": cred.username or "",
                           "domain": cred.domain or "",
                           "credType": cred.secret_kind or "",
                           "secretHint": cred.secret_hint or "",
                           "sourceKind": cred.source_kind or "",
                           "sourceExecutionKind": cred.source_execution_kind or "",
                           "evidenceCount": _credential_evidence_count(db, cred)})
        provenance = json.dumps({"source": cred.source_kind or "",
                                 "detail": cred.source_detail or ""})
        if ("credential", cred.id) in index:
            index[("credential", cred.id)].meta = meta
            index[("credential", cred.id)].provenance = provenance
            continue
        node = create_node(db, project_id, "credential", label=label,
                           source_ref=_source_ref("core", "credential", cred.id),
                           meta=meta, provenance=provenance)
        create_edge(db, project_id, parent.id, node.id, "enumerated")
        index[("credential", cred.id)] = node
        created["credentials"] += 1

    # A completed remote command with exit 0 is direct evidence that the
    # credential authenticated to the destination. Project two complementary
    # references: credential -> destination (what unlocked it), and source
    # host -> destination (where that credential was acquired). The latter is
    # lateral-access provenance, not proof that packets were routed through the
    # source host; true network pivoting remains represented by Tunnel records.
    successful_access = db.scalars(select(RemoteExecution).where(
        RemoteExecution.project_id == project_id,
        RemoteExecution.credential_id.is_not(None),
        RemoteExecution.status == "completed",
        RemoteExecution.exit_code == 0,
        RemoteExecution.connection.in_(("ssh", "wmiexec", "winrm", "secretsdump")),
    ).order_by(RemoteExecution.id)).all()
    for run in successful_access:
        credential = db.get(Credential, run.credential_id)
        credential_node = index.get(("credential", run.credential_id))
        host_destination = host_for(run.target_id)
        if not credential or not credential_node or not host_destination:
            continue
        # Point at the specific service this connection actually logged
        # into when one's identifiable (e.g. the 5985/tcp winrm node, not
        # just "the host in general") -- pivoted-to below stays host-level
        # regardless, since that relation's schema only allows host->host.
        service_id = db.scalar(select(Service.id).where(
            Service.target_id == run.target_id,
            Service.port.in_(_CONNECTION_PORTS.get(run.connection, ()))))
        destination = index.get(("service", service_id)) or host_destination
        if destination.id != host_destination.id:
            # A prior sync (before a service could be resolved, or before
            # this project was even port-scanned) may have already pointed
            # this same credential->target link at the bare host --
            # ensure_edge only recognizes an existing edge by matching
            # (source, target, relation), so upgrading to the service here
            # would otherwise leave that one behind as a stale duplicate
            # rather than replacing it.
            for stale in db.scalars(select(GraphEdge).where(
                    GraphEdge.source == credential_node.id,
                    GraphEdge.target == host_destination.id,
                    GraphEdge.relation == "reused-credential")):
                db.delete(stale)
        identity = "\\".join(filter(None, (credential.domain, credential.username)))
        identity = identity or "credential"
        meta = json.dumps({
            "remoteExecutionId": run.id,
            "credentialId": credential.id,
            "sourceTargetId": credential.target_id,
            "destinationTargetId": run.target_id,
            "connection": run.connection,
            "confirmedAt": run.ended_at.isoformat() if run.ended_at else None,
        })
        ensure_edge(credential_node, destination, "reused-credential",
                    label=f"{identity} · {run.connection.upper()}",
                    status="succeeded", meta=meta)
        source = host_for(credential.target_id) if credential.target_id else None
        if source and source.id != host_destination.id:
            ensure_edge(source, host_destination, "pivoted-to",
                        label=f"LATERAL · {identity}", status="succeeded", meta=meta)

    # executions auto-nodify into technique nodes (attempted from service/host).
    # Outcome is NOT auto-judged; user marks success. Clutter is managed by the
    # per-node `hidden` flag, not by suppressing the projection.
    if target_ids:
        for ex in db.scalars(
                select(Execution).where(Execution.target_id.in_(target_ids))):
            if ("execution", ex.id) in dismissed:
                continue
            if ex.graph_hidden:
                # Already shown inline on the node that triggered it (e.g. an
                # ftp-client session's own auto-fetched file tree) -- see the
                # orphan-healing pass above for a row that flips this on
                # after it already got a node.
                continue
            # A command run to follow up on a specific finding belongs
            # under that finding, not the generic host/service placement --
            # "attempted" only permits finding/service/host as a source (see
            # docs/SPEC_GRAPH_TRACKER.md §6.1), so an override of any other
            # type (e.g. credential, always a structural leaf) falls back.
            explicit_parent = (
                db.get(GraphNode, ex.graph_parent_node_id)
                if ex.graph_parent_node_id else None)
            if explicit_parent is not None and (
                    explicit_parent.project_id != project_id
                    or explicit_parent.type not in {"finding", "service", "host"}):
                explicit_parent = None
            parent = explicit_parent or parent_of(ex.service_id, ex.target_id)
            if parent is None:
                continue
            activity = _runtime_activity(
                "execution", ex.status, ex.template_id or "COMMAND", ex.started_at)
            existing = index.get(("execution", ex.id))
            runtime = {"tool": ex.template_id or "", "command": ex.command or "",
                       "executionStatus": ex.status, "exitCode": ex.exit_code,
                       "error": ex.error or "",
                       "startedAt": ex.started_at.isoformat() if ex.started_at else None,
                       "endedAt": ex.ended_at.isoformat() if ex.ended_at else None}
            if existing is not None:
                existing.meta = _activity_meta(json.dumps(runtime), activity)
                if (ex.status in {"failed", "interrupted"}
                        and existing.status == "in-progress"):
                    existing.status = "attempt-failed"
                continue
            meta = _activity_meta(json.dumps(runtime), activity)
            provenance = json.dumps({"executionRef": {"module": "executions", "id": ex.id},
                                     "tool": ex.template_id or ""})
            node = create_node(
                db, project_id, "technique",
                label=_catalog_label(ex.template_id, "execution"),
                status=_EXECUTION_STATUS.get(ex.status, "in-progress"),
                source_ref=_source_ref("executions", "execution", ex.id),
                meta=meta, provenance=provenance)
            create_edge(db, project_id, parent.id, node.id, "attempted",
                        status=node.status)
            index[("execution", ex.id)] = node
            created["techniques"] += 1

        # interactive sessions (Responder, reverse shells) -> technique nodes.
        # Low-volume and high-signal; counted under techniques.
        for sess in db.scalars(
                select(InteractiveSession).where(
                    InteractiveSession.target_id.in_(target_ids))):
            if ("session", sess.id) in dismissed:
                continue
            responder = sess.template_id == "responder-listener"
            # A session opened from a specific finding/technique (e.g. "익명으로
            # 접속하기" on an Ftp Anon finding) belongs under that node, not the
            # generic host/service placement every other session falls back to --
            # "attempted" already permits finding/service/host -> technique.
            explicit_parent = (
                db.get(GraphNode, sess.graph_parent_node_id)
                if sess.graph_parent_node_id else None)
            if explicit_parent is not None and explicit_parent.project_id != project_id:
                explicit_parent = None
            parent = (operator_for() if responder
                      else explicit_parent or parent_of(sess.service_id, sess.target_id))
            if parent is None:
                continue
            live_status = sess.status
            if live_status == "launched" and not _pid_alive(sess.pid):
                live_status = "closed"
            activity = _runtime_activity(
                # A live shell reads as "attached", not "still searching" --
                # the canvas gives kind="shell" the same calm breathing-ring
                # treatment a settled desktop session used to get alone,
                # never the scan sweep (GraphCanvas.tsx's signalKindOf).
                "listener" if sess.template_id == "responder-listener" else "shell",
                live_status, "RESPONDER" if sess.template_id == "responder-listener"
                else sess.template_id or "SESSION", sess.started_at)
            existing = index.get(("session", sess.id))
            if existing is not None:
                existing.meta = _activity_meta(existing.meta, activity)
                if (sess.status in {"failed", "interrupted"}
                        and existing.status == "in-progress"):
                    existing.status = "attempt-failed"
                node = existing
            else:
                meta = _activity_meta(json.dumps({
                    "tool": sess.template_id or "session", "command": sess.command or "",
                }), activity)
                provenance = json.dumps({"sessionRef": {"module": "sessions", "id": sess.id},
                                         "tool": sess.template_id or ""})
                node = create_node(
                    db, project_id, "technique",
                    label=_catalog_label(sess.template_id, "session"),
                    status=_EXECUTION_STATUS.get(sess.status, "in-progress"),
                    source_ref=_source_ref("sessions", "session", sess.id),
                    meta=meta, provenance=provenance)
                index[("session", sess.id)] = node
                created["techniques"] += 1
            if responder:
                # Migrate the legacy victim -> Responder projection.
                for edge in list(edges):
                    if edge.target == node.id and edge.relation == "attempted":
                        db.delete(edge)
                        edges.remove(edge)
                ensure_edge(parent, node, "runs")
                host = host_for(sess.target_id)
                if host:
                    ensure_edge(node, host, "captures-from", "AUTH CAPTURE")
                # Credentials this listener caught get a direct line back to
                # it, not just the host they're filed under -- the
                # host->credential "enumerated" edge the credential loop
                # above gives every credential by default doesn't fit here
                # (nothing was scanned or logged into; the listener passively
                # caught an inbound auth attempt), so replace it rather than
                # add a second, redundant edge alongside it. Queried fresh
                # from the DB (not the `edges` list loaded at the top of this
                # function) since the credential loop above creates that
                # edge via create_edge(), not ensure_edge(), so it never
                # made it into `edges` on a project's very first sync.
                for cred in db.scalars(select(Credential).where(
                        Credential.target_id == sess.target_id,
                        Credential.source_kind == "responder")):
                    cred_node = index.get(("credential", cred.id))
                    if cred_node is None:
                        continue
                    if host is not None:
                        for edge in db.scalars(select(GraphEdge).where(
                                GraphEdge.source == host.id, GraphEdge.target == cred_node.id,
                                GraphEdge.relation == "enumerated")):
                            db.delete(edge)
                            if edge in edges:
                                edges.remove(edge)
                    ensure_edge(node, cred_node, "yielded")
            else:
                ensure_edge(parent, node, "attempted")

        # hash-crack jobs -> technique nodes. No service dimension (cracking
        # is local, not against a specific network service), so this parents
        # straight under the host rather than trying parent_of()'s service
        # lookup. Credential can't itself be a valid `attempted` source (it's
        # always a structural leaf, see SPEC_GRAPH_TRACKER §1.4) and a job
        # has no column recording which existing hash it targeted anyway
        # (free-pasted hashes are supported too) -- so the link to whatever
        # this job actually cracked is the same "technique yielded credential"
        # edge Responder's listener already gets, found via the same
        # source_execution_kind/id provenance pointer _credential_evidence_count
        # above already reads.
        for job in db.scalars(
                select(HashCrackJob).where(HashCrackJob.target_id.in_(target_ids))):
            if ("hash_crack_job", job.id) in dismissed:
                continue
            # A job started from a specific finding (e.g. a zip2john'd
            # archive) belongs under that node, not the generic host
            # placement -- "attempted" only permits finding/service/host as
            # a source, so a credential-sourced handoff (not currently
            # possible from the frontend, but not guaranteed to stay that
            # way) falls back to host rather than violating the schema.
            explicit_parent = (
                db.get(GraphNode, job.graph_parent_node_id)
                if job.graph_parent_node_id else None)
            if explicit_parent is not None and (
                    explicit_parent.project_id != project_id
                    or explicit_parent.type not in {"finding", "service", "host"}):
                explicit_parent = None
            parent = explicit_parent or host_for(job.target_id)
            if parent is None:
                continue
            activity = _runtime_activity(
                "crack", job.status, job.hash_type_name or job.label or "HASHCAT", job.started_at)
            existing = index.get(("hash_crack_job", job.id))
            runtime = {"tool": "hashcat", "hashType": job.hash_type_name or "",
                       "crackedCount": job.cracked_count, "hashCount": job.hash_count,
                       "jobStatus": job.status, "exitCode": job.exit_code, "error": job.error or "",
                       "startedAt": job.started_at.isoformat() if job.started_at else None,
                       "endedAt": job.ended_at.isoformat() if job.ended_at else None}
            if existing is not None:
                existing.meta = _activity_meta(json.dumps(runtime), activity)
                if ((job.status in {"failed", "cancelled"}
                     or (job.status == "completed" and job.cracked_count == 0))
                        and existing.status == "in-progress"):
                    existing.status = "attempt-failed"
                node = existing
            else:
                meta = _activity_meta(json.dumps(runtime), activity)
                provenance = json.dumps({"jobRef": {"module": "hash_cracking", "id": job.id},
                                         "tool": "hashcat"})
                status = ("attempt-failed"
                          if job.status in {"failed", "cancelled"} else "in-progress")
                node = create_node(
                    db, project_id, "technique",
                    label=job.label or f"해시 크래킹 · {job.hash_type_name or job.hash_mode}",
                    status=status, source_ref=_source_ref("hash_cracking", "hash_crack_job", job.id),
                    meta=meta, provenance=provenance)
                create_edge(db, project_id, parent.id, node.id, "attempted", status=node.status)
                index[("hash_crack_job", job.id)] = node
                created["techniques"] += 1
            for cred in db.scalars(select(Credential).where(
                    Credential.source_execution_kind == "hash_crack_job",
                    Credential.source_execution_id == job.id)):
                cred_node = index.get(("credential", cred.id))
                if cred_node is not None:
                    ensure_edge(node, cred_node, "yielded")

    return {"rootNodeId": root.id, "created": created}
