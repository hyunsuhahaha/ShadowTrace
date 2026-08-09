from app.modules.graph.engine import (
    EdgeData,
    NodeData,
    RefLeaf,
    TreeNode,
    build_tree,
    success_paths,
    compute_canonical_parents,
    resolve_root,
)


def n(id, type="finding", status="untried", created_at="2026-01-01T00:00:00Z",
      pinned=None):
    return NodeData(id=id, type=type, status=status, created_at=created_at,
                    pinned_canonical_edge_id=pinned)


def e(id, source, target, relation="attempted", status="untried",
      created_at="2026-01-01T00:00:00Z"):
    return EdgeData(id=id, source=source, target=target, relation=relation,
                    status=status, created_at=created_at)


def test_earliest_structural_parent_wins():
    nodes = [n("root", type="project-root"), n("a"), n("b"), n("c")]
    edges = [
        e("e2", "b", "c", created_at="2026-01-02T00:00:00Z"),
        e("e1", "a", "c", created_at="2026-01-01T00:00:00Z"),
    ]
    parents = compute_canonical_parents(nodes, edges)
    # c has two structural parents; the earlier edge (e1 via a) is canonical.
    assert parents["c"] == "e1"


def test_non_structural_edge_is_never_a_canonical_parent():
    nodes = [n("cred", type="credential"), n("host", type="host")]
    edges = [e("r1", "cred", "host", relation="reused-credential")]
    parents = compute_canonical_parents(nodes, edges)
    # reused-credential is cross-cutting; host gets no structural parent here.
    assert parents["host"] is None


def test_created_at_tie_breaks_on_edge_id():
    nodes = [n("a"), n("b"), n("c")]
    ts = "2026-01-01T00:00:00Z"
    edges = [
        e("e9", "b", "c", created_at=ts),
        e("e1", "a", "c", created_at=ts),
    ]
    parents = compute_canonical_parents(nodes, edges)
    assert parents["c"] == "e1"


def test_pinned_canonical_edge_overrides_timestamp():
    nodes = [n("a"), n("b"), n("c", pinned="e2")]
    edges = [
        e("e1", "a", "c", created_at="2026-01-01T00:00:00Z"),
        e("e2", "b", "c", created_at="2026-01-09T00:00:00Z"),
    ]
    parents = compute_canonical_parents(nodes, edges)
    # Manual override (spec 3.5) beats the earliest-timestamp default.
    assert parents["c"] == "e2"


def test_root_has_no_parent():
    nodes = [n("root", type="project-root")]
    parents = compute_canonical_parents(nodes, [])
    assert parents["root"] is None


# --- resolve_root ---

def test_resolve_root_returns_project_root_node():
    nodes = [n("h", type="host"), n("root", type="project-root"), n("s")]
    assert resolve_root(nodes) == "root"


def test_resolve_root_falls_back_to_earliest_node_when_no_project_root():
    nodes = [
        n("late", type="host", created_at="2026-03-01T00:00:00Z"),
        n("early", type="host", created_at="2026-01-01T00:00:00Z"),
    ]
    assert resolve_root(nodes) == "early"


# --- build_tree: structure, numbering, ordering ---

def kids_by_id(tree_node):
    return {c.id: c for c in tree_node.children if isinstance(c, TreeNode)}


def test_build_tree_nests_and_numbers_a_simple_chain():
    nodes = [n("root", type="project-root"), n("host", type="host"),
             n("svc", type="service")]
    edges = [e("e1", "root", "host", relation="discovered"),
             e("e2", "host", "svc", relation="discovered")]
    tree = build_tree(nodes, edges, "root")
    assert tree.id == "root" and tree.path == [1]
    host = kids_by_id(tree)["host"]
    assert host.path == [1, 1]
    svc = kids_by_id(host)["svc"]
    assert svc.path == [1, 1, 1]


def test_build_tree_orders_siblings_by_created_at_then_id():
    nodes = [n("root", type="project-root"), n("a"), n("b")]
    edges = [
        e("eb", "root", "b", relation="discovered",
          created_at="2026-01-01T00:00:00Z"),
        e("ea", "root", "a", relation="discovered",
          created_at="2026-02-01T00:00:00Z"),
    ]
    tree = build_tree(nodes, edges, "root")
    ordered_ids = [c.id for c in tree.children if isinstance(c, TreeNode)]
    assert ordered_ids == ["b", "a"]  # b's edge is earlier


def test_multi_parent_node_appears_once_and_second_parent_gets_a_ref():
    # c has a canonical parent (a, earlier) and a second structural parent (b).
    nodes = [n("root", type="project-root"), n("a"), n("b"), n("c")]
    edges = [
        e("er_a", "root", "a", relation="discovered"),
        e("er_b", "root", "b", relation="discovered"),
        e("e1", "a", "c", created_at="2026-01-01T00:00:00Z"),
        e("e2", "b", "c", created_at="2026-02-01T00:00:00Z"),
    ]
    tree = build_tree(nodes, edges, "root")
    a = kids_by_id(tree)["a"]
    b = kids_by_id(tree)["b"]
    # canonical placement under a
    assert "c" in kids_by_id(a)
    # b holds only a reference to c, not a duplicate subtree
    b_refs = [x for x in b.children if isinstance(x, RefLeaf)]
    assert [(r.kind, r.target) for r in b_refs] == [("ref", "c")]
    assert "c" not in kids_by_id(b)


def test_cross_cutting_edge_renders_as_reference_leaf():
    nodes = [n("root", type="project-root"), n("cred", type="credential"),
             n("host2", type="host")]
    edges = [
        e("er_cred", "root", "cred", relation="discovered"),
        e("er_h2", "root", "host2", relation="discovered"),
        e("reuse", "cred", "host2", relation="reused-credential"),
    ]
    tree = build_tree(nodes, edges, "root")
    cred = kids_by_id(tree)["cred"]
    refs = [x for x in cred.children if isinstance(x, RefLeaf)]
    assert [(r.kind, r.target) for r in refs] == [("ref", "host2")]


def test_back_edge_to_ancestor_renders_as_cycle_leaf():
    nodes = [n("root", type="project-root"), n("a"), n("b")]
    edges = [
        e("er", "root", "a", relation="discovered"),
        e("e1", "a", "b", created_at="2026-01-01T00:00:00Z"),
        e("e2", "b", "a", created_at="2026-02-01T00:00:00Z"),
    ]
    tree = build_tree(nodes, edges, "root")
    a = kids_by_id(tree)["a"]
    b = kids_by_id(a)["b"]
    cyc = [x for x in b.children if isinstance(x, RefLeaf)]
    assert [(r.kind, r.target) for r in cyc] == [("cycle", "a")]


def test_detached_nodes_are_attached_under_root():
    nodes = [n("root", type="project-root"), n("lonely", type="host")]
    tree = build_tree(nodes, [], "root")
    assert "lonely" in kids_by_id(tree)


# --- success_paths (Attack Path input) ---

def test_success_path_follows_only_succeeded_structural_edges():
    edges = [
        e("x1", "finding", "exploit", relation="attempted", status="succeeded"),
        e("x2", "exploit", "wwwdata", relation="yielded", status="succeeded"),
        e("x3", "wwwdata", "root_user", relation="attempted", status="untried"),
    ]
    # Chain stops before x3 because that attempt has not succeeded.
    assert success_paths(edges) == [["finding", "exploit", "wwwdata"]]


def test_success_paths_branch_into_separate_chains():
    edges = [
        e("b1", "a", "b", relation="attempted", status="succeeded",
          created_at="2026-01-01T00:00:00Z"),
        e("b2", "a", "c", relation="attempted", status="succeeded",
          created_at="2026-02-01T00:00:00Z"),
    ]
    assert success_paths(edges) == [["a", "b"], ["a", "c"]]


def test_no_succeeded_edges_yields_no_paths():
    edges = [e("z1", "a", "b", relation="attempted", status="attempt-failed")]
    assert success_paths(edges) == []
