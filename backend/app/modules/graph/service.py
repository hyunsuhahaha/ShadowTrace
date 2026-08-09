"""Persistence + integrity layer bridging DB rows and the pure tree engine.

The engine (``engine.py``) knows nothing about SQLAlchemy; this module maps
``GraphNode``/``GraphEdge`` rows into engine records, enforces the schema's
integrity rules (spec 1.4/1.7), and serializes engine output for the API.
"""
from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...models import (Credential, Execution, Finding, GraphEdge, GraphNode,
                       GraphProjectMeta, InteractiveSession, Project, Service,
                       Target)

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


def _service_display_name(service) -> str:
    return _WELL_KNOWN_PORT_NAMES.get(service.port, service.name)
from . import engine
from .ids import new_ulid

NODE_TYPES = {
    "project-root", "host", "service", "finding", "technique", "credential",
}
NODE_STATUSES = {
    "untried", "in-progress", "attempt-failed", "succeeded", "blocked",
    "not-applicable",
}
EDGE_STATUSES = NODE_STATUSES  # shared vocabulary (spec 1.5)

# relation -> (allowed source types, allowed target types) — spec 1.4.
ALLOWED_RELATIONS: dict[str, tuple[set[str], set[str]]] = {
    "discovered": ({"project-root", "host"}, {"host", "service"}),
    "enumerated": ({"service", "host"}, {"finding", "credential"}),
    "attempted": ({"finding", "service", "host"}, {"technique"}),
    "yielded": ({"technique"}, {"credential", "host", "service", "finding"}),
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


# --- project-root bootstrap (spec 2.1) ---

def ensure_project_root(db: Session, project_id: int) -> GraphNode:
    project = db.get(Project, project_id)
    if project is None:
        raise GraphIntegrityError(f"project {project_id} does not exist")
    meta = db.get(GraphProjectMeta, project_id)
    if meta is not None and meta.root_node_id:
        root = db.get(GraphNode, meta.root_node_id)
        if root is not None:
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


def sync_from_project(db: Session, project_id: int) -> dict:
    """Project existing domain rows into graph nodes (idempotent, spec 6.1).

    Targets/Services -> host/service nodes; Findings/Credentials -> finding/
    credential nodes attached to their service (or host). Matching is by
    ``source_ref`` so re-running only fills gaps; user edits are left untouched.
    Secrets are never copied — only ``secret_hint``.
    """
    root = ensure_project_root(db, project_id)
    nodes, _ = _load(db, project_id)
    index = _index_by_source(nodes)
    created = {"hosts": 0, "services": 0, "findings": 0, "credentials": 0,
               "techniques": 0}
    target_ids: list[int] = []

    def host_for(target_id: int) -> GraphNode | None:
        return index.get(("target", target_id))

    for target in db.scalars(
            select(Target).where(Target.project_id == project_id)):
        target_ids.append(target.id)
        host = host_for(target.id)
        if host is None:
            label = target.ip + (f" ({target.hostname})" if target.hostname else "")
            host = create_node(db, project_id, "host", label=label,
                               source_ref=_source_ref("core", "target", target.id))
            create_edge(db, project_id, root.id, host.id, "discovered")
            index[("target", target.id)] = host
            created["hosts"] += 1

        for service in db.scalars(
                select(Service).where(Service.target_id == target.id)):
            raw = f"{service.port}/{service.protocol} {service.name}".strip()
            refined = f"{service.port}/{service.protocol} {_service_display_name(service)}".strip()
            if ("service", service.id) not in index:
                svc = create_node(db, project_id, "service", label=refined,
                                  source_ref=_source_ref("scans", "service", service.id))
                create_edge(db, project_id, host.id, svc.id, "discovered")
                index[("service", service.id)] = svc
                created["services"] += 1
            else:
                # Retroactively refine a still-default label (e.g. an existing
                # "5985/tcp http" -> "5985/tcp winrm"); leave user edits alone.
                node = index[("service", service.id)]
                if node.label == raw and raw != refined:
                    node.label = refined

    # findings + credentials attach to their service, else their host.
    def parent_of(service_id, target_id) -> GraphNode | None:
        if service_id and ("service", service_id) in index:
            return index[("service", service_id)]
        return host_for(target_id) if target_id else None

    for finding in db.scalars(
            select(Finding).where(Finding.project_id == project_id)):
        if ("finding", finding.id) in index:
            continue
        parent = parent_of(finding.service_id, finding.target_id)
        if parent is None:
            continue
        meta = json.dumps({"severity": finding.severity or "",
                           "category": finding.category or ""})
        node = create_node(db, project_id, "finding", label=finding.title,
                           source_ref=_source_ref("findings", "finding", finding.id),
                           meta=meta)
        create_edge(db, project_id, parent.id, node.id, "enumerated")
        index[("finding", finding.id)] = node
        created["findings"] += 1

    for cred in db.scalars(
            select(Credential).where(Credential.project_id == project_id)):
        if ("credential", cred.id) in index:
            continue
        parent = parent_of(cred.service_id, cred.target_id)
        if parent is None:
            continue
        label = cred.username or (cred.domain and f"{cred.domain}\\") or "credential"
        meta = json.dumps({"username": cred.username or "",
                           "credType": cred.secret_kind or "",
                           "secretHint": cred.secret_hint or ""})
        provenance = json.dumps({"source": cred.source_kind or "",
                                 "detail": cred.source_detail or ""})
        node = create_node(db, project_id, "credential", label=label,
                           source_ref=_source_ref("core", "credential", cred.id),
                           meta=meta, provenance=provenance)
        create_edge(db, project_id, parent.id, node.id, "enumerated")
        index[("credential", cred.id)] = node
        created["credentials"] += 1

    # executions auto-nodify into technique nodes (attempted from service/host).
    # Outcome is NOT auto-judged; user marks success. Clutter is managed by the
    # per-node `hidden` flag, not by suppressing the projection.
    if target_ids:
        for ex in db.scalars(
                select(Execution).where(Execution.target_id.in_(target_ids))):
            if ("execution", ex.id) in index:
                continue
            parent = parent_of(ex.service_id, ex.target_id)
            if parent is None:
                continue
            meta = json.dumps({"tool": ex.template_id or "", "command": ex.command or ""})
            provenance = json.dumps({"executionRef": {"module": "executions", "id": ex.id},
                                     "tool": ex.template_id or ""})
            node = create_node(
                db, project_id, "technique", label=ex.template_id or "execution",
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
            if ("session", sess.id) in index:
                continue
            parent = parent_of(sess.service_id, sess.target_id)
            if parent is None:
                continue
            meta = json.dumps({"tool": sess.template_id or "session",
                               "command": sess.command or ""})
            provenance = json.dumps({"sessionRef": {"module": "sessions", "id": sess.id},
                                     "tool": sess.template_id or ""})
            node = create_node(
                db, project_id, "technique", label=sess.template_id or "session",
                status=_EXECUTION_STATUS.get(sess.status, "in-progress"),
                source_ref=_source_ref("sessions", "session", sess.id),
                meta=meta, provenance=provenance)
            create_edge(db, project_id, parent.id, node.id, "attempted",
                        status=node.status)
            index[("session", sess.id)] = node
            created["techniques"] += 1

    return {"rootNodeId": root.id, "created": created}
