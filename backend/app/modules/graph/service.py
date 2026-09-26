"""Persistence + integrity layer bridging DB rows and the pure tree engine.

The engine (``engine.py``) knows nothing about SQLAlchemy; this module maps
``GraphNode``/``GraphEdge`` rows into engine records, enforces the schema's
integrity rules (spec 1.4/1.7), and serializes engine output for the API.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...models import (AssessmentAsset, AssessmentAssetSubject, AutoReconRun, CommandActivity, Credential, Evidence, Execution, Finding, FindingEvidence, GraphEdge,
                       GraphEvent, GraphNode, GraphProjectMeta, HashCrackJob, HttpExchange, HttpRequest, InteractiveSession,
                       PassiveActivity, ProcessInstance, Project, ProjectRoe, RemoteExecution, RunbookInstance,
                       RunbookStepInstance, RunbookStepExecution, RunbookStepHandoff,
                       RunbookStepHttpExchange, RunbookStepRemoteExecution,
                       RunbookStepSession, RunbookStepSubject, RunbookStepEvidence,
                       RunbookObservation,
                       RunbookStepCredential, ScanArtifact, ScanJob,
                       Service, Target)
from ...templates import catalog
from ..vpn import vpn_status


def _catalog_label(template_id: str | None, fallback: str) -> str:
    """Technique nodes are labeled from the catalog's human-readable name
    (e.g. "제품·버전 식별") rather than its raw id ("service-version") --
    the id means nothing to someone reading the graph, not just the person
    who wrote the YAML."""
    item = catalog.items.get(template_id or "")
    return (item or {}).get("name") or template_id or fallback


# Every manually-opened session (a reverse shell listener, an SSH quick-connect,
# a redis-cli/mongo/mysql probe shell, ...) shares the one synthetic
# template_id "manual-shell" -- it was never a real catalog entry, so
# _catalog_label's fallback chain landed on that literal id itself, and the
# graph showed the same generic "manual-shell" label no matter what the
# session's actual command was. Use the command line instead for that one
# id; every other template_id (responder-listener, ftp-client, ...) already
# has its own meaningful id and keeps going through _catalog_label as before.
def _session_label(template_id: str | None, command: str | None) -> str:
    if template_id == "manual-shell" and command:
        return command if len(command) <= 60 else f"{command[:57]}..."
    return _catalog_label(template_id, "session")

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

# A path/param/subdomain fuzzer working through its own wordlist gets a
# distinct canvas activity kind ("fuzz") instead of the generic scan-sweep
# every other execution gets -- driven by the template's own `tool` field
# so a new fuzz-shaped template picks this up automatically without a
# template-id allowlist to keep in sync by hand.
_FUZZ_TOOLS = {"ffuf", "feroxbuster", "gobuster"}


def _is_fuzz_template(template_id: str | None) -> bool:
    return catalog.items.get(template_id or "", {}).get("tool") in _FUZZ_TOOLS


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


# A manual session's own `command` column can't tell a reverse-shell listener
# apart from any other manual shell: every manual-session entry point (the
# reverse-shell panel's "리스너 준비", psexec/wmiexec/smbexec/atexec,
# FloatingCommandSession's free-text box) opens a bare shell first with no
# command in the create request, then types the real command in afterward as
# PTY input (see App.tsx's openManualShell/openListenerShell and
# FloatingCommandSession.tsx) -- so `command` is stuck at the
# "/bin/bash --noprofile --norc" fallback forever, regardless of what actually
# ran inside it.
#
# The session's own PTY log doesn't have that problem: pty_manager.py logs
# every byte read back from the pty, which includes a typed-in subprocess's
# stdout the same as a top-level one. nc -lvnp prints a "listening on" banner
# the moment it binds and a second, distinct line once a peer connects
# ("connect to ... from ...", ncat's "Connection from ...", GNU netcat's
# "Connection received on ..."), so reading the log for those two signals
# works no matter how the nc process was actually launched -- the same way
# _parse_responder_log turns Responder's own capture file into graph state
# instead of trusting the local process's mere existence, which for a
# listener never proves a client actually landed.
_LISTENER_ARMED_RE = re.compile(r"(?i)listening on\b")
_LISTENER_CONNECTED_RE = re.compile(r"(?i)connect(ion)?\s+(to|from|received)")


def _listener_log_state(log_path: str | None) -> str | None:
    """"connected", "armed", or None (not a listener, or no log yet)."""
    if not log_path:
        return None
    path = Path(log_path)
    if not path.is_file():
        return None
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    if _LISTENER_CONNECTED_RE.search(text):
        return "connected"
    if _LISTENER_ARMED_RE.search(text):
        return "armed"
    return None


def _service_display_name(service) -> str:
    return _WELL_KNOWN_PORT_NAMES.get(service.port, service.name)
from . import engine
from .ids import new_ulid

NODE_TYPES = {
    "project-root", "scope", "operator", "host", "asset", "service", "finding", "technique",
    "credential", "evidence", "memo",
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
    "scans": ({"technique"}, {"host"}),
    "discovered": ({"project-root", "host", "asset"}, {"scope", "host", "asset", "service"}),
    "enumerated": ({"service", "host", "asset"}, {"finding", "credential"}),
    "attempted": ({"finding", "service", "host", "asset"}, {"technique"}),
    # "finding" as a source covers a file pulled back out of another finding
    # (e.g. extracting an entry from a downloaded archive) -- the archive's
    # own finding "yielded" the extracted one, same relationship a technique
    # yielding a finding already has, just one hop further down.
    "yielded": ({"technique", "finding"}, {"credential", "host", "service", "finding"}),
    "pivoted-to": ({"host"}, {"host"}),
    "reused-credential": ({"credential"}, {"host", "service"}),
    "blocked-by": ({"technique", "finding"}, NODE_TYPES),
    "precedes": ({"technique"}, {"technique"}),
    "records-execution": ({"technique"}, {"technique"}),
    "handoff": ({"technique"}, {"technique"}),
    "assesses": ({"asset"}, {"technique"}),
    "links-credential": ({"technique"}, {"credential"}),
    "documented-by": ({"technique"}, {"evidence"}),
    "produced-finding": ({"technique"}, {"finding"}),
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


def _command_owner(activity: CommandActivity, targets: list[Target]) -> tuple[int | None, int | None]:
    """Attribute an external command only when its workspace is unambiguous."""
    if activity.kind not in {"command", "pipeline"}:
        # Shell/SSH input and explicit remote argv are unconfirmed candidates,
        # not observed local executions suitable for semantic projection.
        return None, None
    command = activity.command or ""
    try:
        inference = json.loads(activity.inference or "{}")
    except (TypeError, ValueError):
        inference = {}
    endpoint_values = inference.get("network_endpoints", []) if isinstance(inference, dict) else []
    endpoints = ({value for value in endpoint_values if isinstance(value, str)}
                 if isinstance(endpoint_values, list) else set())
    matches = []
    for target in targets:
        try:
            address = ipaddress.ip_address(target.ip)
        except ValueError:
            continue
        if address.is_loopback or address.is_unspecified:
            continue
        if (re.search(r"(?<![\w:.])" + re.escape(target.ip) + r"(?![\w:.])", command)
                or target.ip in endpoints):
            matches.append(target)
    if matches:
        projects = {target.project_id for target in matches}
        if len(projects) == 1:
            return projects.pop(), matches[0].id if len(matches) == 1 else None
        return None, None
    return None, None


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
    commands = list(db.scalars(select(CommandActivity).order_by(CommandActivity.id)))
    targets = list(db.scalars(select(Target))) if commands else []
    command_owners = {command.id: _command_owner(command, targets)
                      for command in commands}
    legacy_process_keys = set(db.scalars(select(PassiveActivity.process_key).where(
        PassiveActivity.project_id == project_id)))
    legacy_process_ids = set(db.scalars(select(ProcessInstance.id).where(
        ProcessInstance.process_key.in_(legacy_process_keys)))) if legacy_process_keys else set()
    duplicate_commands = set()
    for command in commands:
        try:
            process_ids = json.loads(command.process_instance_ids or "[]")
        except (TypeError, ValueError):
            process_ids = []
        if any(process_id in legacy_process_ids for process_id in process_ids):
            duplicate_commands.add(command.id)

    # Heal orphans: a node projected from a domain row whose row no longer exists
    # (e.g. its target/service was deleted) is stale — drop it and its edges.
    # Manually-created nodes (no source_ref) are never pruned.
    kind_models = {"target": Target, "asset": AssessmentAsset,
                   "asset_subject": AssessmentAssetSubject,
                   "project_roe": ProjectRoe,
                   "service": Service, "finding": Finding,
                   "evidence": Evidence, "http_exchange": HttpExchange,
                   "remote_execution": RemoteExecution,
                   "credential": Credential, "execution": Execution,
                   "session": InteractiveSession, "scan_artifact": ScanArtifact,
                   "autorecon_run": AutoReconRun, "autorecon_results": ScanJob,
                   "passive_activity": PassiveActivity, "command_activity": CommandActivity,
                   "runbook_step": RunbookStepInstance}
    for key, node in list(index.items()):
        kind, ident = key
        model = kind_models.get(kind)
        row = db.get(model, ident) if model is not None else None
        owner_id = None
        if isinstance(row, (Target, AssessmentAsset, Finding, Credential, Evidence)):
            owner_id = row.project_id
        elif isinstance(row, (Service, Execution, InteractiveSession)):
            target = db.get(Target, row.target_id)
            owner_id = target.project_id if target else None
        elif isinstance(row, ScanArtifact):
            job = db.get(ScanJob, row.scan_job_id)
            owner_id = job.project_id if job else None
        elif kind == "autorecon_results" and isinstance(row, ScanJob):
            owner_id = row.project_id if row.source == "autorecon" else None
        elif isinstance(row, AutoReconRun):
            owner_id = row.project_id
        elif isinstance(row, PassiveActivity):
            owner_id = row.project_id
        elif isinstance(row, CommandActivity):
            owner_id = command_owners.get(row.id, (None, None))[0]
        elif isinstance(row, RunbookStepInstance):
            instance = db.get(RunbookInstance, row.instance_id)
            owner_id = instance.project_id if instance else None
        elif isinstance(row, ProjectRoe):
            owner_id = row.project_id
        elif isinstance(row, RemoteExecution):
            owner_id = row.project_id
        elif isinstance(row, AssessmentAssetSubject):
            asset = db.get(AssessmentAsset, row.asset_id)
            owner_id = asset.project_id if asset else None
        elif isinstance(row, HttpExchange):
            request = db.get(HttpRequest, row.request_id)
            owner_id = request.project_id if request else None
        stale_hidden = kind == "execution" and isinstance(row, Execution) and row.graph_hidden
        deprecated = kind == "autorecon_run"
        if model is not None and (row is None or owner_id != project_id
                                  or kind == "command_activity" and ident in duplicate_commands
                                  or stale_hidden or deprecated):
            db.query(GraphEdge).filter(
                (GraphEdge.source == node.id) | (GraphEdge.target == node.id)
            ).delete(synchronize_session=False)
            db.delete(node)
            del index[key]
    db.flush()

    created = {"hosts": 0, "assets": 0, "services": 0, "findings": 0, "credentials": 0,
               "techniques": 0, "evidence": 0}
    target_ids: list[int] = []

    def host_for(target_id: int) -> GraphNode | None:
        return index.get(("target", target_id))

    def asset_for(asset_id: int | None) -> GraphNode | None:
        return index.get(("asset", asset_id)) if asset_id is not None else None

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

    roe = db.get(ProjectRoe, project_id)
    if roe and ("project_roe", project_id) not in dismissed:
        scope = index.get(("project_roe", project_id))
        scope_meta = json.dumps({"revision": roe.revision, "status": roe.status,
                                 "validFrom": roe.valid_from.isoformat() if roe.valid_from else None,
                                 "validUntil": roe.valid_until.isoformat() if roe.valid_until else None,
                                 "targetCount": len(json.loads(roe.included_targets or "[]")),
                                 "assetCount": len(json.loads(roe.asset_ids or "[]"))})
        if scope is None:
            scope = create_node(db, project_id, "scope", label="Rules of Engagement",
                                status="in-progress" if roe.status == "approved" else "blocked",
                                source_ref=_source_ref("core", "project_roe", project_id),
                                meta=scope_meta)
            index[("project_roe", project_id)] = scope
        else:
            scope.status = "in-progress" if roe.status == "approved" else "blocked"
            scope.meta = scope_meta
        ensure_edge(root, scope, "discovered", status="untried")

    active_scans = {
        scan.target_id: scan for scan in db.scalars(
            select(ScanJob).where(
                ScanJob.project_id == project_id,
                ScanJob.status.in_(_ACTIVE_STATUSES),
            ).order_by(ScanJob.id)
        )
    }
    autorecon_runs = list(db.scalars(select(AutoReconRun).where(
        AutoReconRun.project_id == project_id)))
    active_autorecon: dict[int, AutoReconRun] = {}
    for run in autorecon_runs:
        if run.status not in _ACTIVE_STATUSES:
            continue
        try:
            run_target_ids = json.loads(run.target_ids or "[]")
        except ValueError:
            continue
        for target_id in run_target_ids:
            active_autorecon[target_id] = run

    for target in db.scalars(
            select(Target).where(Target.project_id == project_id)):
        target_ids.append(target.id)
        host = host_for(target.id)
        # A dismissed (user-deleted) host node must not be recreated, but its
        # services still need to run through the loop below every sync --
        # skipping the whole target body here used to leave any
        # already-synced service node under it permanently stuck with
        # whatever meta/label it had at the moment the host was deleted
        # (per spec §2.1 "노드 삭제 시 관련 엣지 cascade" only edges cascade
        # on delete, not descendant nodes, so those service nodes are still
        # expected to be live and refreshed by every future sync).
        host_dismissed = host is None and ("target", target.id) in dismissed
        if host is None and not host_dismissed:
            label = target.ip + (f" ({target.hostname})" if target.hostname else "")
            host = create_node(db, project_id, "host", label=label,
                               source_ref=_source_ref("core", "target", target.id))
            create_edge(db, project_id, root.id, host.id, "discovered")
            index[("target", target.id)] = host
            created["hosts"] += 1
        if host is not None:
            scan = active_scans.get(target.id)
            autorecon = active_autorecon.get(target.id)
            # Host-level evidence only (service_id is None) -- evidence attached to
            # one of the target's services is counted on that service node instead,
            # so the two counts don't double up on the same underlying row.
            host_evidence_count = db.scalar(select(func.count(Evidence.id)).where(
                Evidence.target_id == target.id, Evidence.service_id.is_(None))) or 0
            host.meta = _activity_meta(
                _merge_meta(host.meta, {"evidenceCount": host_evidence_count}),
                _runtime_activity("scan", autorecon.status, "AUTORECON",
                                  autorecon.started_at) if autorecon else
                (_runtime_activity("scan", scan.status, scan.alias or "NMAP SCAN",
                                   scan.started_at) if scan else None))

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
                # No host to attach a brand-new service to -- same "don't
                # auto-create under a dismissed parent" rule the host itself
                # follows just above.
                if host_dismissed or ("service", service.id) in dismissed:
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

    for asset in db.scalars(select(AssessmentAsset).where(
            AssessmentAsset.project_id == project_id)):
        if ("asset", asset.id) in dismissed:
            continue
        meta = json.dumps({"assetId": asset.id, "kind": asset.kind,
                           "locator": asset.locator, "scopeStatus": asset.scope_status})
        node = index.get(("asset", asset.id))
        if node is None:
            node = create_node(db, project_id, "asset", label=asset.name,
                               status="blocked" if asset.scope_status == "out_of_scope" else "untried",
                               source_ref=_source_ref("core", "asset", asset.id), meta=meta)
            index[("asset", asset.id)] = node
            ensure_edge(root, node, "discovered", status="untried")
            created["assets"] += 1
        else:
            node.meta = meta
            node.label = asset.name
            node.status = "blocked" if asset.scope_status == "out_of_scope" else "untried"
        for subject in db.scalars(select(AssessmentAssetSubject).where(
                AssessmentAssetSubject.asset_id == asset.id).order_by(
                AssessmentAssetSubject.id)):
            if ("asset_subject", subject.id) in dismissed:
                continue
            subject_meta = json.dumps({"subjectId": subject.id, "assetId": asset.id,
                "kind": subject.kind, "identifier": subject.identifier,
                "scopeStatus": subject.scope_status})
            subject_node = index.get(("asset_subject", subject.id))
            if subject_node is None:
                subject_node = create_node(db, project_id, "asset", label=subject.label,
                    status="blocked" if subject.scope_status == "out_of_scope" else "untried",
                    source_ref=_source_ref("core", "asset_subject", subject.id),
                    meta=subject_meta)
                index[("asset_subject", subject.id)] = subject_node
                created["assets"] += 1
            else:
                subject_node.label = subject.label
                subject_node.meta = subject_meta
                subject_node.status = ("blocked" if subject.scope_status == "out_of_scope"
                                       else "untried")
            ensure_edge(node, subject_node, "discovered", status="untried")

    # findings + credentials attach to their service, else their host.
    def parent_of(service_id, target_id) -> GraphNode | None:
        if service_id and ("service", service_id) in index:
            return index[("service", service_id)]
        return host_for(target_id) if target_id else None

    # Runbook steps are first-class workflow nodes. Keep only IDs and state in
    # graph metadata; result, notes and evidence remain in the Runbook API.
    def runbook_status(step: RunbookStepInstance) -> str:
        if step.status == "blocked" or step.activation == "blocked":
            return "blocked"
        if step.status in {"skipped", "not_applicable"} or step.activation == "excluded":
            return "not-applicable"
        if step.outcome == "error":
            return "attempt-failed"
        if step.status == "completed":
            return "succeeded"  # the check finished, not a confirmed vulnerability
        if step.status in {"in_progress", "attempted", "suspicious"}:
            return "in-progress"
        return "untried"

    def activated_sources(step: RunbookStepInstance) -> set[str]:
        try:
            trace = json.loads(step.decision_trace or "[]")
        except (TypeError, ValueError):
            return set()
        return {source for item in trace if isinstance(item, dict)
                and item.get("kind") == "activated_by"
                for source in item.get("sources", [])}

    for instance in db.scalars(select(RunbookInstance).where(
            RunbookInstance.project_id == project_id).order_by(RunbookInstance.id)):
        parent = (asset_for(instance.asset_id) if instance.asset_id is not None
                  else parent_of(instance.service_id, instance.target_id))
        if parent is None:
            continue
        steps = list(db.scalars(select(RunbookStepInstance).where(
            RunbookStepInstance.instance_id == instance.id).order_by(
                RunbookStepInstance.position, RunbookStepInstance.id)))
        by_key = {step.node_key or f"step-{step.position}": step for step in steps}
        transitions: dict[int, list[dict]] = {}
        for step in steps:
            try:
                parsed = json.loads(step.transitions or "[]")
            except (TypeError, ValueError):
                parsed = []
            transitions[step.id] = parsed if isinstance(parsed, list) else []
            if ("runbook_step", step.id) in dismissed:
                continue
            meta = json.dumps({"instanceId": instance.id, "targetId": instance.target_id,
                               "assetId": instance.asset_id,
                               "serviceId": instance.service_id, "position": step.position,
                               "stepStatus": step.status, "outcome": step.outcome,
                               "activation": step.activation,
                               "templateName": instance.template_name})
            node = index.get(("runbook_step", step.id))
            if node is None:
                node = create_node(db, project_id, "technique", label=step.title,
                                   status=runbook_status(step),
                                   source_ref=_source_ref("runbooks", "runbook_step", step.id),
                                   meta=meta)
                index[("runbook_step", step.id)] = node
                created["techniques"] += 1
            else:
                node.meta = meta
                node.status = runbook_status(step)
        if any(transitions.values()):
            incoming: set[int] = set()
            for step in steps:
                source = index.get(("runbook_step", step.id))
                for transition in transitions[step.id]:
                    if not isinstance(transition, dict):
                        continue
                    keys = transition.get("targets", transition.get("target", []))
                    if isinstance(keys, str):
                        keys = [keys]
                    for key in keys if isinstance(keys, list) else []:
                        target_step = by_key.get(key)
                        if target_step is None:
                            continue
                        incoming.add(target_step.id)
                        destination = index.get(("runbook_step", target_step.id))
                        if source and destination:
                            source_key = step.node_key or f"step-{step.position}"
                            ensure_edge(source, destination, "precedes",
                                        label=str(transition.get("label") or ""),
                                        status="untried", meta=json.dumps({
                                            "workflow": "runbook",
                                            "selected": source_key in activated_sources(target_step),
                                            "excluded": target_step.activation == "excluded",
                                        }))
            roots = [step for step in steps if step.id not in incoming]
        else:
            roots = steps[:1]
            for first, second in zip(steps, steps[1:]):
                source = index.get(("runbook_step", first.id))
                destination = index.get(("runbook_step", second.id))
                if source and destination:
                    ensure_edge(source, destination, "precedes", status="untried",
                                meta=json.dumps({"workflow": "runbook",
                                                 "selected": False, "excluded": False}))
        for step in roots:
            node = index.get(("runbook_step", step.id))
            if node:
                ensure_edge(parent, node, "attempted", label=instance.template_name,
                            status="untried")

    for finding in db.scalars(
            select(Finding).where(Finding.project_id == project_id)):
        if ("finding", finding.id) in dismissed:
            continue
        parent = (asset_for(finding.asset_id) if finding.asset_id is not None
                  else parent_of(finding.service_id, finding.target_id))
        if parent is None:
            continue
        evidence_count = db.scalar(select(func.count(FindingEvidence.id)).where(
            FindingEvidence.finding_id == finding.id)) or 0
        meta_fields = {"severity": finding.severity or "",
                       "category": finding.category or "",
                       "evidenceCount": evidence_count}
        if ("finding", finding.id) in index:
            existing = index[("finding", finding.id)]
            # unlockedAt (extract_archive_entry's one-shot canvas cue) is set
            # once at creation and owned by the caller, not by this sync --
            # this loop runs on a 4s poll (GraphWorkspace.tsx), so blindly
            # overwriting meta here wiped it out almost immediately,
            # confirmed live: the unlock effect never had a real chance to
            # render before its own trigger disappeared.
            try:
                old_meta = json.loads(existing.meta or "{}")
            except (TypeError, json.JSONDecodeError):
                old_meta = {}
            if "unlockedAt" in old_meta:
                meta_fields["unlockedAt"] = old_meta["unlockedAt"]
            existing.meta = json.dumps(meta_fields)
            continue
        meta = json.dumps(meta_fields)
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

    # The host is the running scan's visual center. Once the process reaches a
    # terminal state, one result-browser node per target exposes AutoRecon's
    # native scans/exploit/loot/report tree without inventing a process node.
    for run in autorecon_runs:
        if run.status not in {"completed", "failed", "stopped", "interrupted"}:
            continue
        try:
            run_target_ids = json.loads(run.target_ids or "[]")
        except ValueError:
            continue
        for target_id in run_target_ids:
            host = host_for(target_id)
            if host is None:
                continue
            job = db.scalar(select(ScanJob).where(
                ScanJob.project_id == project_id, ScanJob.target_id == target_id,
                ScanJob.source == "autorecon", ScanJob.command == run.command))
            if job is None or ("autorecon_results", job.id) in dismissed:
                continue
            runtime = {"tool": "autorecon-results", "runId": run.id,
                       "scanJobId": job.id, "outputDir": run.output_dir,
                       "importedCount": run.imported_count,
                       "executionStatus": run.status,
                       "directories": ["scans", "exploit", "loot", "report"]}
            meta = json.dumps(runtime)
            existing = index.get(("autorecon_results", job.id))
            if existing is not None:
                existing.meta = meta
                continue
            node = create_node(
                db, project_id, "technique", label=f"AutoRecon 결과물 #{run.id}",
                status="succeeded" if run.status == "completed" else "attempt-failed",
                source_ref=_source_ref("autorecon", "autorecon_results", job.id),
                meta=meta, provenance=json.dumps({"source": "autorecon",
                                                  "outputDir": run.output_dir}))
            ensure_edge(host, node, "attempted", label="AUTORECON RESULTS",
                        status=node.status)
            index[("autorecon_results", job.id)] = node
            created["techniques"] += 1

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
                "fuzz" if _is_fuzz_template(ex.template_id) else "execution",
                ex.status, ex.template_id or "COMMAND", ex.started_at)
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

        # Native files live in the completed AutoRecon result-browser node.
        # Remove legacy per-file nodes while retaining every ScanArtifact row.
        artifact_rows = db.execute(
            select(ScanArtifact, ScanJob).join(
                ScanJob, ScanJob.id == ScanArtifact.scan_job_id).where(
                ScanJob.source == "autorecon", ScanJob.target_id.in_(target_ids)))
        for artifact, job in artifact_rows:
            existing = index.get(("scan_artifact", artifact.id))
            if existing is not None:
                db.query(GraphEdge).filter(
                    (GraphEdge.source == existing.id)
                    | (GraphEdge.target == existing.id)
                ).delete(synchronize_session=False)
                db.delete(existing)
                del index[("scan_artifact", artifact.id)]

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
            if explicit_parent is not None and (
                    explicit_parent.project_id != project_id
                    or explicit_parent.type not in {"finding", "service", "host"}):
                explicit_parent = None
            parent = (operator_for() if responder
                      else explicit_parent or parent_of(sess.service_id, sess.target_id))
            if parent is None:
                continue
            live_status = sess.status
            if live_status == "launched" and not _pid_alive(sess.pid):
                live_status = "closed"
            # A manual session is armed-not-connected if its own command line
            # is a listener (nc's own log banner, see _listener_log_state
            # above) and hasn't shown a peer connecting yet -- that gets the
            # same "listener" pulse as Responder. Once a client lands (or the
            # session was never a listener at all) it reads as "attached",
            # the calm breathing-ring kind="shell" treatment (GraphCanvas.tsx's
            # signalKindOf), never the scan sweep.
            armed_listener = (
                not responder and _listener_log_state(sess.log_path) == "armed")
            activity = _runtime_activity(
                "listener" if responder or armed_listener else "shell",
                live_status, "RESPONDER" if responder
                else sess.template_id or "SESSION", sess.started_at)
            existing = index.get(("session", sess.id))
            if existing is not None:
                existing.meta = _activity_meta(existing.meta, activity)
                if (sess.status in {"failed", "interrupted"}
                        and existing.status == "in-progress"):
                    existing.status = "attempt-failed"
                # Retroactively refine a node created before this label logic
                # existed (still stuck on the raw "manual-shell" id) -- same
                # "still-default label" refresh the service loop above does,
                # never touches a label the operator has actually edited.
                if existing.label == "manual-shell" and sess.command:
                    existing.label = _session_label(sess.template_id, sess.command)
                node = existing
            else:
                meta = _activity_meta(json.dumps({
                    "tool": sess.template_id or "session", "command": sess.command or "",
                }), activity)
                provenance = json.dumps({"sessionRef": {"module": "sessions", "id": sess.id},
                                         "tool": sess.template_id or ""})
                node = create_node(
                    db, project_id, "technique",
                    label=_session_label(sess.template_id, sess.command),
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

    # External terminal observations live in the same graph as in-app runs.
    # A target association requires a unique literal IP or observed connection;
    # the mere existence of one project is not ownership evidence.
    for activity in commands:
        owner_id, target_id = command_owners[activity.id]
        if (owner_id != project_id or activity.id in duplicate_commands
                or ("command_activity", activity.id) in dismissed):
            continue
        parent = host_for(target_id) if target_id is not None else operator_for()
        if parent is None:
            continue
        visible_command = "[민감 입력]" if activity.sensitive else activity.command.strip()
        label = (visible_command.splitlines()[0] if visible_command else "터미널 활동")[:100]
        meta = json.dumps({
            "command": visible_command, "source": "passive", "kind": activity.kind,
            "startedAt": activity.started_at.isoformat(),
            "endedAt": activity.ended_at.isoformat() if activity.ended_at else None,
            "confidence": activity.confidence, "lossState": activity.loss_state,
            "terminalSessionId": activity.terminal_session_id,
        }, ensure_ascii=False)
        existing = index.get(("command_activity", activity.id))
        if existing is not None:
            existing.meta = meta
            if activity.ended_at and existing.status == "in-progress":
                existing.status = "untried"
            continue
        node = create_node(db, project_id, "technique", label=label,
                           status="untried" if activity.ended_at else "in-progress",
                           source_ref=_source_ref("passive_activity", "command_activity", activity.id),
                           meta=meta)
        ensure_edge(parent, node, "attempted" if parent.type == "host" else "runs")
        index[("command_activity", activity.id)] = node
        created["techniques"] += 1

    # Legacy passive Nmap captures carry an explicit project/target binding.
    for activity in db.scalars(select(PassiveActivity).where(
            PassiveActivity.project_id == project_id).order_by(PassiveActivity.id)):
        if ("passive_activity", activity.id) in dismissed:
            continue
        parent = host_for(activity.target_id) if activity.target_id else operator_for()
        if parent is None:
            continue
        existing = index.get(("passive_activity", activity.id))
        meta = json.dumps({"command": activity.command, "source": "passive",
                           "tool": activity.tool, "startedAt": activity.started_at.isoformat(),
                           "endedAt": activity.ended_at.isoformat() if activity.ended_at else None,
                           "exitCode": activity.exit_code, "captureStatus": activity.status,
                           "confidence": activity.confidence}, ensure_ascii=False)
        if existing is not None:
            existing.meta = meta
            if activity.ended_at and existing.status == "in-progress":
                existing.status = "untried"
            continue
        node = create_node(db, project_id, "technique",
                           label=(activity.command.strip() or activity.tool or "수집된 활동")[:100],
                           status="untried" if activity.ended_at else "in-progress",
                           source_ref=_source_ref("passive_activity", "passive_activity", activity.id),
                           meta=meta)
        ensure_edge(parent, node, "attempted" if parent.type == "host" else "runs")
        index[("passive_activity", activity.id)] = node
        created["techniques"] += 1

    # Explicit Runbook links connect the operator's planned check to the
    # actual saved execution, credential, or evidence. These relationships
    # do not claim the check succeeded or that a credential was obtained here.
    runbook_step_ids = [ident for kind, ident in index if kind == "runbook_step"]
    desired_links: set[tuple[str, str, str]] = set()
    linked_evidence_ids: set[int] = set()
    linked_http_exchange_ids: set[int] = set()
    linked_remote_execution_ids: set[int] = set()
    if runbook_step_ids:
        for link in db.scalars(select(RunbookStepSubject).where(
                RunbookStepSubject.step_id.in_(runbook_step_ids))):
            subject = index.get(("asset_subject", link.subject_id))
            step_node = index.get(("runbook_step", link.step_id))
            if subject and step_node:
                ensure_edge(subject, step_node, "assesses", status="untried")
                desired_links.add((subject.id, step_node.id, "assesses"))
        for link in db.scalars(select(RunbookStepExecution).where(
                RunbookStepExecution.step_id.in_(runbook_step_ids))):
            source = index.get(("runbook_step", link.step_id))
            target = index.get(("execution", link.execution_id))
            if source and target:
                ensure_edge(source, target, "records-execution", status="untried")
                desired_links.add((source.id, target.id, "records-execution"))
        for link in db.scalars(select(RunbookStepHttpExchange).where(
                RunbookStepHttpExchange.step_id.in_(runbook_step_ids))):
            source = index.get(("runbook_step", link.step_id))
            row = db.get(HttpExchange, link.exchange_id)
            request = db.get(HttpRequest, row.request_id) if row else None
            if not source or not row or not request or request.project_id != project_id:
                continue
            linked_http_exchange_ids.add(row.id)
            if ("http_exchange", row.id) in dismissed:
                continue
            node = index.get(("http_exchange", row.id))
            meta = json.dumps({"exchangeId": row.id, "requestId": request.id,
                               "targetId": request.target_id,
                               "statusCode": row.status_code,
                               "reviewStatus": row.review_status})
            if node is None:
                node = create_node(db, project_id, "technique",
                                   label=f"HTTP Exchange #{row.id}", status="untried",
                                   source_ref=_source_ref("web_testing", "http_exchange", row.id),
                                   meta=meta)
                index[("http_exchange", row.id)] = node
                created["techniques"] += 1
            else:
                node.meta = meta
            ensure_edge(source, node, "records-execution", status="untried")
            desired_links.add((source.id, node.id, "records-execution"))
        for link in db.scalars(select(RunbookStepRemoteExecution).where(
                RunbookStepRemoteExecution.step_id.in_(runbook_step_ids))):
            source = index.get(("runbook_step", link.step_id))
            run = db.get(RemoteExecution, link.remote_execution_id)
            if not source or not run or run.project_id != project_id:
                continue
            linked_remote_execution_ids.add(run.id)
            if ("remote_execution", run.id) in dismissed:
                continue
            node = index.get(("remote_execution", run.id))
            meta = json.dumps({"remoteExecutionId": run.id, "targetId": run.target_id,
                               "status": run.status, "exitCode": run.exit_code,
                               "evidenceId": run.evidence_id})
            if node is None:
                node = create_node(db, project_id, "technique",
                                   label=f"RemoteExecution #{run.id}", status="untried",
                                   source_ref=_source_ref("post_exploitation", "remote_execution", run.id),
                                   meta=meta)
                index[("remote_execution", run.id)] = node
                created["techniques"] += 1
            else:
                node.meta = meta
            ensure_edge(source, node, "records-execution", status="untried")
            desired_links.add((source.id, node.id, "records-execution"))
        for link in db.scalars(select(RunbookStepSession).where(
                RunbookStepSession.step_id.in_(runbook_step_ids))):
            source = index.get(("runbook_step", link.step_id))
            session = index.get(("session", link.session_id))
            if source and session:
                ensure_edge(source, session, "records-execution", status="untried")
                desired_links.add((source.id, session.id, "records-execution"))
        for handoff in db.scalars(select(RunbookStepHandoff).where(
                RunbookStepHandoff.from_step_id.in_(runbook_step_ids))):
            source = index.get(("runbook_step", handoff.from_step_id))
            destination = index.get(("runbook_step", handoff.to_step_id))
            run = db.get(RemoteExecution, handoff.remote_execution_id)
            if not source or not destination or not run or run.project_id != project_id:
                continue
            if run.status != "completed" or run.exit_code != 0 or run.evidence_id != handoff.evidence_id:
                continue
            ensure_edge(source, destination, "handoff", status="untried",
                        label="확인된 원격 접근",
                        meta=json.dumps({"remoteExecutionId": run.id,
                                         "evidenceId": handoff.evidence_id}))
            desired_links.add((source.id, destination.id, "handoff"))
        for link in db.scalars(select(RunbookStepCredential).where(
                RunbookStepCredential.step_id.in_(runbook_step_ids))):
            source = index.get(("runbook_step", link.step_id))
            target = index.get(("credential", link.credential_id))
            if source and target:
                ensure_edge(source, target, "links-credential", status="untried")
                desired_links.add((source.id, target.id, "links-credential"))
        for link in db.scalars(select(RunbookStepEvidence).where(
                RunbookStepEvidence.step_id.in_(runbook_step_ids))):
            source = index.get(("runbook_step", link.step_id))
            row = db.get(Evidence, link.evidence_id)
            if not source or not row or row.project_id != project_id:
                continue
            linked_evidence_ids.add(row.id)
            if ("evidence", row.id) in dismissed:
                continue
            node = index.get(("evidence", row.id))
            meta = json.dumps({"evidenceId": row.id, "targetId": row.target_id,
                               "assetId": row.asset_id,
                               "kind": row.kind, "sensitivity": row.sensitivity})
            if node is None:
                node = create_node(db, project_id, "evidence",
                                   label=(f"Evidence #{row.id}" if row.sensitivity in {"sensitive", "secret"}
                                          else row.title), status="untried",
                                   source_ref=_source_ref("evidence", "evidence", row.id),
                                   meta=meta)
                index[("evidence", row.id)] = node
                created["evidence"] += 1
            else:
                node.meta = meta
                if row.sensitivity in {"sensitive", "secret"}:
                    node.label = f"Evidence #{row.id}"
            ensure_edge(source, node, "documented-by", status="untried")
            desired_links.add((source.id, node.id, "documented-by"))
        for observation, finding in db.execute(select(RunbookObservation, Finding).join(
                Finding, Finding.observation_id == RunbookObservation.id).where(
                    RunbookObservation.step_id.in_(runbook_step_ids),
                    Finding.project_id == project_id)):
            source = index.get(("runbook_step", observation.step_id))
            target = index.get(("finding", finding.id))
            if source and target:
                ensure_edge(source, target, "produced-finding", status="untried")
                desired_links.add((source.id, target.id, "produced-finding"))
    for key, node in list(index.items()):
        if (key[0] == "evidence" and key[1] not in linked_evidence_ids or
                key[0] == "http_exchange" and key[1] not in linked_http_exchange_ids or
                key[0] == "remote_execution" and key[1] not in linked_remote_execution_ids):
            db.query(GraphEdge).filter(
                (GraphEdge.source == node.id) | (GraphEdge.target == node.id)
            ).delete(synchronize_session=False)
            db.delete(node)
            del index[key]
    for edge in db.scalars(select(GraphEdge).where(
            GraphEdge.project_id == project_id,
            GraphEdge.relation.in_(("records-execution", "handoff", "assesses", "links-credential",
                                   "documented-by", "produced-finding")))):
        if (edge.source, edge.target, edge.relation) not in desired_links:
            db.delete(edge)

    return {"rootNodeId": root.id, "created": created}
