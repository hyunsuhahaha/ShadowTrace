"""HTTP surface for the progress graph tracker (spec section 6)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...database import get_db
from ...models import GraphEdge, GraphNode, GraphProjectMeta, Project
from ...time import utcnow
from . import service
from .schemas import (CanonicalPatch, EdgeIn, EdgeOut, EdgePatch, GraphOut,
                      NodeIn, NodeOut, NodePatch)

router = APIRouter(prefix="/api", tags=["Graph"])


def _guard(fn):
    try:
        return fn()
    except service.GraphIntegrityError as exc:
        raise HTTPException(422, str(exc)) from exc


def _require_node(db: Session, node_id: str) -> GraphNode:
    node = db.get(GraphNode, node_id)
    if node is None:
        raise HTTPException(404, "node not found")
    return node


def _require_edge(db: Session, edge_id: str) -> GraphEdge:
    edge = db.get(GraphEdge, edge_id)
    if edge is None:
        raise HTTPException(404, "edge not found")
    return edge


@router.get("/projects/{project_id}/graph", response_model=GraphOut)
def get_graph(project_id: int, db: Session = Depends(get_db)):
    if db.get(Project, project_id) is None:
        raise HTTPException(404, "project not found")
    root = _guard(lambda: service.ensure_project_root(db, project_id))
    db.commit()
    nodes = list(db.scalars(
        select(GraphNode).where(GraphNode.project_id == project_id)))
    edges = list(db.scalars(
        select(GraphEdge).where(GraphEdge.project_id == project_id)))
    return GraphOut(root_node_id=root.id, nodes=nodes, edges=edges)


@router.get("/projects/{project_id}/graph/tree")
def get_tree(project_id: int, db: Session = Depends(get_db)):
    if db.get(Project, project_id) is None:
        raise HTTPException(404, "project not found")
    tree = _guard(lambda: service.get_tree(db, project_id))
    db.commit()
    return tree


@router.get("/projects/{project_id}/graph/attack-paths")
def get_attack_paths(project_id: int, db: Session = Depends(get_db)):
    if db.get(Project, project_id) is None:
        raise HTTPException(404, "project not found")
    return {"paths": service.get_attack_paths(db, project_id),
            "summary": service.get_attack_path_summary(db, project_id)}


@router.post("/projects/{project_id}/graph/sync")
def sync_graph(project_id: int, db: Session = Depends(get_db)):
    if db.get(Project, project_id) is None:
        raise HTTPException(404, "project not found")
    result = _guard(lambda: service.sync_from_project(db, project_id))
    db.commit()
    return result


@router.post("/projects/{project_id}/graph/nodes", response_model=NodeOut)
def create_node(project_id: int, body: NodeIn, db: Session = Depends(get_db)):
    if db.get(Project, project_id) is None:
        raise HTTPException(404, "project not found")
    if body.type == "project-root":
        raise HTTPException(422, "project-root is created automatically")
    node = _guard(lambda: service.create_node(
        db, project_id, body.type, label=body.label, status=body.status,
        notes=body.notes, tags=body.tags, source_ref=body.source_ref,
        meta=body.meta, objective=body.objective,
        objective_kind=body.objective_kind, provenance=body.provenance,
        layer=body.layer))
    db.commit()
    return node


@router.patch("/graph/nodes/{node_id}", response_model=NodeOut)
def patch_node(node_id: str, body: NodePatch, db: Session = Depends(get_db)):
    node = _require_node(db, node_id)
    updates = body.model_dump(exclude_unset=True)
    if "status" in updates and updates["status"] not in service.NODE_STATUSES:
        raise HTTPException(422, f"unknown node status: {updates['status']}")
    for field, value in updates.items():
        setattr(node, field, value)
    node.updated_at = utcnow()
    db.commit()
    return node


@router.patch("/graph/nodes/{node_id}/canonical", response_model=NodeOut)
def set_canonical(node_id: str, body: CanonicalPatch,
                  db: Session = Depends(get_db)):
    node = _require_node(db, node_id)
    edge_id = body.pinned_canonical_edge_id
    if edge_id is not None:
        edge = _require_edge(db, edge_id)
        if edge.target != node_id:
            raise HTTPException(422, "pinned edge must point at this node")
    node.pinned_canonical_edge_id = edge_id
    node.updated_at = utcnow()
    db.commit()
    return node


@router.delete("/graph/nodes/{node_id}")
def delete_node(node_id: str, db: Session = Depends(get_db)):
    node = _require_node(db, node_id)
    if node.type == "project-root":
        raise HTTPException(422, "project-root cannot be deleted")
    db.query(GraphEdge).filter(
        (GraphEdge.source == node_id) | (GraphEdge.target == node_id)).delete(
        synchronize_session=False)
    db.delete(node)
    db.commit()
    return {"ok": True}


@router.post("/projects/{project_id}/graph/edges", response_model=EdgeOut)
def create_edge(project_id: int, body: EdgeIn, db: Session = Depends(get_db)):
    if db.get(Project, project_id) is None:
        raise HTTPException(404, "project not found")
    edge = _guard(lambda: service.create_edge(
        db, project_id, body.source, body.target, body.relation,
        status=body.status, label=body.label, meta=body.meta))
    db.commit()
    return edge


@router.patch("/graph/edges/{edge_id}", response_model=EdgeOut)
def patch_edge(edge_id: str, body: EdgePatch, db: Session = Depends(get_db)):
    edge = _require_edge(db, edge_id)
    updates = body.model_dump(exclude_unset=True)
    if "status" in updates and updates["status"] not in service.EDGE_STATUSES:
        raise HTTPException(422, f"unknown edge status: {updates['status']}")
    for field, value in updates.items():
        setattr(edge, field, value)
    edge.updated_at = utcnow()
    db.commit()
    return edge


@router.delete("/graph/edges/{edge_id}")
def delete_edge(edge_id: str, db: Session = Depends(get_db)):
    edge = _require_edge(db, edge_id)
    # Clear any node pinning this edge as its canonical parent.
    db.query(GraphNode).filter(
        GraphNode.pinned_canonical_edge_id == edge_id).update(
        {GraphNode.pinned_canonical_edge_id: None}, synchronize_session=False)
    db.delete(edge)
    db.commit()
    return {"ok": True}
