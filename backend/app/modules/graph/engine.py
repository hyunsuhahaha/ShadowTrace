"""Pure tree/graph algorithms for the progress graph tracker.

This module has no dependency on the database, FastAPI, or SQLAlchemy. It
operates on lightweight ``NodeData``/``EdgeData`` records so the canonical
placement and tree layout stay deterministic and unit-testable in isolation.
See docs/SPEC_GRAPH_TRACKER.md sections 2 and 3.4.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Relations that form the tree skeleton (spec 1.6). Everything else
# (reused-credential, blocked-by) is cross-cutting and only ever shown as a
# reference, never as a structural parent.
STRUCTURAL_RELATIONS = frozenset(
    {"discovered", "enumerated", "attempted", "yielded", "pivoted-to",
     "operates", "runs"}
)

SUCCESS_STATUS = "succeeded"


@dataclass(frozen=True)
class NodeData:
    id: str
    type: str
    status: str
    created_at: str  # ISO-8601, lexically sortable
    label: str = ""
    pinned_canonical_edge_id: str | None = None
    objective: bool = False


@dataclass(frozen=True)
class EdgeData:
    id: str
    source: str
    target: str
    relation: str
    status: str
    created_at: str  # ISO-8601, lexically sortable


@dataclass
class RefLeaf:
    """A non-canonical connection rendered as a pointer, not a subtree."""

    kind: str  # "ref" | "cycle"
    edge_id: str
    source: str
    target: str


@dataclass
class TreeNode:
    id: str
    path: list[int]
    children: list = field(default_factory=list)  # list[TreeNode | RefLeaf]


def is_structural(edge: EdgeData) -> bool:
    return edge.relation in STRUCTURAL_RELATIONS


def resolve_root(nodes: list[NodeData]) -> str | None:
    """Return the project-root node id, or the earliest node as a fallback.

    A project graph has exactly one synthetic ``project-root`` (spec 2.1). The
    fallback only matters for malformed/legacy graphs that predate it.
    """
    roots = [node for node in nodes if node.type == "project-root"]
    if roots:
        return min(roots, key=lambda node: (node.created_at, node.id)).id
    if not nodes:
        return None
    return min(nodes, key=lambda node: (node.created_at, node.id)).id


def compute_canonical_parents(
    nodes: list[NodeData], edges: list[EdgeData]
) -> dict[str, str | None]:
    """Map each node to the id of its canonical structural parent edge.

    Default rule (spec 2.2): the incoming structural edge with the smallest
    ``(created_at, id)``. A node's ``pinned_canonical_edge_id`` overrides the
    default (spec 3.5). Nodes with no structural parent map to ``None``.
    """
    edge_by_id = {edge.id: edge for edge in edges}
    incoming: dict[str, list[EdgeData]] = {node.id: [] for node in nodes}
    for edge in edges:
        if is_structural(edge) and edge.target in incoming:
            incoming[edge.target].append(edge)

    parents: dict[str, str | None] = {}
    for node in nodes:
        pinned = node.pinned_canonical_edge_id
        if pinned is not None and pinned in edge_by_id:
            parents[node.id] = pinned
            continue
        candidates = incoming[node.id]
        if not candidates:
            parents[node.id] = None
        else:
            best = min(candidates, key=lambda edge: (edge.created_at, edge.id))
            parents[node.id] = best.id
    return parents


def build_tree(
    nodes: list[NodeData], edges: list[EdgeData], root_id: str
) -> TreeNode:
    """Expand the canonical skeleton from ``root_id`` into a reference tree.

    Each node is placed exactly once at its canonical location. Every other
    edge out of a node becomes a leaf: ``ref`` normally, or ``cycle`` when it
    points back to an ancestor on the current path (spec 2.3).
    """
    parent_of = compute_canonical_parents(nodes, edges)
    edge_by_id = {edge.id: edge for edge in edges}

    children_of: dict[str, list[EdgeData]] = {}
    for edge_id in parent_of.values():
        if edge_id is not None:
            edge = edge_by_id[edge_id]
            children_of.setdefault(edge.source, []).append(edge)

    outgoing: dict[str, list[EdgeData]] = {}
    for edge in edges:
        outgoing.setdefault(edge.source, []).append(edge)

    placed: set[str] = set()
    on_path: set[str] = set()

    def walk(node_id: str, path: list[int]) -> TreeNode:
        placed.add(node_id)
        on_path.add(node_id)
        tnode = TreeNode(id=node_id, path=list(path))
        kids = sorted(children_of.get(node_id, []),
                      key=lambda edge: (edge.created_at, edge.id))
        for index, edge in enumerate(kids, start=1):
            tnode.children.append(walk(edge.target, path + [index]))
        refs = [edge for edge in outgoing.get(node_id, [])
                if parent_of.get(edge.target) != edge.id]
        for edge in sorted(refs, key=lambda edge: (edge.created_at, edge.id)):
            kind = "cycle" if edge.target in on_path else "ref"
            tnode.children.append(RefLeaf(kind=kind, edge_id=edge.id,
                                          source=edge.source, target=edge.target))
        on_path.discard(node_id)
        return tnode

    tree = walk(root_id, [1])

    # Detached: nodes whose canonical chain never reached the root. Attach each
    # remaining component under the root as a "미연결" section (spec 2.3),
    # walking the earliest unplaced node first for deterministic output.
    def unplaced() -> list[NodeData]:
        return sorted(
            (node for node in nodes if node.id not in placed and node.id != root_id),
            key=lambda node: (node.created_at, node.id),
        )

    next_index = len(tree.children)
    remaining = unplaced()
    while remaining:
        next_index += 1
        tree.children.append(walk(remaining[0].id, [1, next_index]))
        remaining = unplaced()
    return tree


def success_paths(edges: list[EdgeData]) -> list[list[str]]:
    """Extract compromise chains for the Attack Path view (spec 3.3).

    Returns every maximal path through the subgraph of structural edges whose
    status is ``succeeded``. A chain starts at a node with a succeeded out-edge
    but no succeeded in-edge, and extends while succeeded edges continue.
    """
    succeeded = [edge for edge in edges
                 if is_structural(edge) and edge.status == SUCCESS_STATUS]
    out: dict[str, list[EdgeData]] = {}
    for edge in succeeded:
        out.setdefault(edge.source, []).append(edge)

    targets = {edge.target for edge in succeeded}
    starts = sorted({edge.source for edge in succeeded} - targets)

    paths: list[list[str]] = []

    def walk(node: str, path: list[str]) -> None:
        next_edges = sorted(out.get(node, []),
                            key=lambda edge: (edge.created_at, edge.id))
        # Stop at a tip, or where continuing would revisit a node (cycle).
        continued = [edge for edge in next_edges if edge.target not in path]
        if not continued:
            paths.append(path)
            return
        for edge in continued:
            walk(edge.target, path + [edge.target])

    for start in starts:
        walk(start, [start])
    return paths


def paths_to_objectives(
    nodes: list[NodeData], edges: list[EdgeData]
) -> list[list[str]]:
    """Success paths that reach a user-marked objective node (spec 3.6)."""
    objective_ids = {node.id for node in nodes if node.objective}
    if not objective_ids:
        return []
    return [path for path in success_paths(edges)
            if any(node_id in objective_ids for node_id in path)]


def attack_path_summary(
    nodes: list[NodeData], edges: list[EdgeData]
) -> dict[str, int]:
    """Type counts + step/objective rollup over the success subgraph (spec 3.3)."""
    node_by_id = {node.id: node for node in nodes}
    paths = success_paths(edges)
    reached_ids = {node_id for path in paths for node_id in path}

    summary = {"hosts": 0, "services": 0, "findings": 0, "techniques": 0,
               "credentials": 0, "steps": 0, "objectivesReached": 0}
    plural = {"host": "hosts", "service": "services", "finding": "findings",
              "technique": "techniques", "credential": "credentials"}
    for node_id in reached_ids:
        node = node_by_id.get(node_id)
        if node is None:
            continue
        key = plural.get(node.type)
        if key:
            summary[key] += 1
        if node.objective and node.status == SUCCESS_STATUS:
            summary["objectivesReached"] += 1
    summary["steps"] = len([edge for edge in edges
                            if is_structural(edge) and edge.status == SUCCESS_STATUS])
    return summary
