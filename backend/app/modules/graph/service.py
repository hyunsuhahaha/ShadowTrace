"""Persistence + integrity layer bridging DB rows and the pure tree engine.

The engine (``engine.py``) knows nothing about SQLAlchemy; this module maps
``GraphNode``/``GraphEdge`` rows into engine records, enforces the schema's
integrity rules (spec 1.4/1.7), and serializes engine output for the API.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...models import GraphEdge, GraphNode, GraphProjectMeta, Project
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
    "enumerated": ({"service"}, {"finding"}),
    "attempted": ({"finding"}, {"technique"}),
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


def get_tree(db: Session, project_id: int) -> dict:
    root = ensure_project_root(db, project_id)
    nodes, edges = _load(db, project_id)
    tree = engine.build_tree(
        [_node_data(n) for n in nodes], [_edge_data(e) for e in edges], root.id)
    return _serialize_tree(tree, {n.id: n for n in nodes})


def get_attack_paths(db: Session, project_id: int) -> list[list[str]]:
    _, edges = _load(db, project_id)
    return engine.success_paths([_edge_data(e) for e in edges])
