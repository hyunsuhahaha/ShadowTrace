import { lazy, Suspense, useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../api";
import { parseLinkExtractResults } from "../../serviceIntel";
import { setPendingServiceNav } from "../../pendingServiceNav";
import { consumePendingGraphFocus } from "../../pendingGraphFocus";

// Existing workspaces embedded (their own chrome hidden) so the graph is the
// primary interface: service node -> Enumeration, root node -> Scan Center.
const EmbeddedEnumeration = lazy(() => import("../../App"));
const EmbeddedScanCenter = lazy(() => import("../../ScanCenter"));
const EmbeddedHashCracking = lazy(() => import("../../HashCrackingWorkspace"));
const EmbeddedPostExploitation = lazy(() => import("../../PostExploitationWorkspace"));
const EmbeddedReports = lazy(() => import("../../ReportWorkspace"));

// Vertical slice: nmap-derived host/service nodes -> API -> Graph + Outline.
// Graph renders on Canvas 2D (renderer boundary from spec 3.4; the Pixi/WebGL
// swap is M4 and isolated to <GraphCanvas>). No new dependencies in this slice.

type NodeType = "project-root" | "operator" | "host" | "service" | "finding"
  | "technique" | "credential";
type GraphNode = {
  id: string; type: NodeType; status: string; label: string; objective: boolean;
  source_ref: string; hidden: boolean; meta?: string; created_at?: string; updated_at?: string;
  notes?: string; tags?: string; pinned?: boolean;
};
type DeepLink = { label: string; open: () => void };
type GraphEdge = {
  id: string; source: string; target: string; relation: string; status: string;
};
type GraphOut = { root_node_id: string | null; nodes: GraphNode[]; edges: GraphEdge[] };
type GraphFilter = { query: string; type: "all" | NodeType; status: string;
  focusDepth: number; pinnedOnly: boolean };
type GraphRequestDraft = {
  projectId: number; targetId: number; serviceId: number; url: string;
};
type CredentialHandoff = {
  id: number; project_id: number; target_id?: number; secret: string;
  secret_hint?: string; source_kind?: string;
};
export type NodeActivity = {
  kind: "scan" | "execution" | "listener";
  status: "queued" | "running" | "processing" | "launched";
  label: string; startedAt?: string | null;
};

type TreeRef = { kind: "ref" | "cycle"; edgeId: string; source: string; target: string };
type TreeNode = {
  kind: "node"; id: string; path: number[]; type: NodeType; label: string;
  status: string; children: TreeItem[];
};
type TreeItem = TreeNode | TreeRef;

const STATUS_COLOR: Record<string, string> = {
  untried: "#8b8b93", "in-progress": "#f5a524", "attempt-failed": "#e5484d",
  succeeded: "#30a46c", blocked: "#8e4ec6", "not-applicable": "#5a5a60",
};
const STATUS_LABEL: Record<string, string> = {
  untried: "미시도", "in-progress": "진행중", "attempt-failed": "실패",
  succeeded: "성공", blocked: "차단", "not-applicable": "N/A",
};
const STATUS_REASON: Record<string, string> = {
  untried: "준비됨", "in-progress": "실행 중",
  "attempt-failed": "실패 후 재시도 가능", succeeded: "완료",
  blocked: "선행 정보 부족", "not-applicable": "적용 불가",
};
const LINK_KIND_LABEL: Record<string, string> = {
  page: "페이지", asset: "정적 리소스", absolute: "절대경로", anchor: "앵커",
};
const LINK_KIND_ORDER = ["page", "absolute", "asset", "anchor"];
const EXECUTION_STATUS_LABEL: Record<string, string> = {
  queued: "대기", running: "실행 중", completed: "완료", failed: "실패",
  interrupted: "중단됨",
};
const GLYPH: Record<NodeType, string> = {
  "project-root": "◎", operator: "⌁", host: "▣", service: "◉", finding: "◇",
  technique: "⚡", credential: "🔑",
};
const color = (s: string) => STATUS_COLOR[s] ?? "#8b8b93";

function nodeMeta(node: Pick<GraphNode, "meta">): Record<string, any> {
  try { return JSON.parse(node.meta || "{}"); } catch { return {}; }
}

export function nodeStatusReason(node: Pick<GraphNode, "status" | "type" | "meta">): string {
  const meta = nodeMeta(node);
  if (node.type === "technique" && node.status === "in-progress"
      && ["completed", "closed"].includes(meta.executionStatus)) return "사용자 검토 대기";
  return STATUS_REASON[node.status] ?? node.status;
}

export function nodeSummary(node: Pick<GraphNode, "type" | "status" | "label" | "meta">): string {
  const meta = nodeMeta(node);
  if (node.type === "service")
    return [node.label, meta.product, meta.version].filter(Boolean).join(" · ");
  if (node.type === "technique") {
    const started = meta.startedAt ? Date.parse(meta.startedAt) : NaN;
    const ended = meta.endedAt ? Date.parse(meta.endedAt) : NaN;
    const duration = Number.isFinite(started) && Number.isFinite(ended)
      ? `${Math.max(0, Math.round((ended - started) / 1000))}s` : "";
    if (meta.error || meta.executionStatus === "failed")
      return [meta.error || "failed", meta.exitCode == null ? "" : `exit ${meta.exitCode}`]
        .filter(Boolean).join(" · ");
    return [meta.tool || node.label, meta.executionStatus || nodeStatusReason(node), duration]
      .filter(Boolean).join(" · ");
  }
  if (node.type === "credential")
    return [meta.username || node.label, meta.credType || "credential", "captured"]
      .filter(Boolean).join(" · ");
  if (node.type === "finding")
    return [node.label, meta.severity, `evidence ${meta.evidenceCount || 0}`]
      .filter(Boolean).join(" · ");
  return node.label;
}

type ActivityKind = "live" | "service" | "task" | "credential" | "finding" | "target";
type ActivityItem = { nodeId: string; at: string; text: string; kind: ActivityKind;
  status: string; reason: string };
type ActivityPanelState = { x?: number; y?: number; width: number; height: number; collapsed: boolean };
const ACTIVITY_PANEL_KEY = "oscp-graph-activity-panel";
const defaultActivityPanel: ActivityPanelState = {
  width: 380, height: 340, collapsed: false,
};

export function clampActivityPanel(x: number, y: number, width: number, height: number,
  boundsWidth: number, boundsHeight: number) {
  const resizeHandleClearance = 28;
  return { x: Math.max(0, Math.min(x, Math.max(0, boundsWidth - width - resizeHandleClearance))),
    y: Math.max(0, Math.min(y, Math.max(0, boundsHeight - height - resizeHandleClearance))) };
}

function readActivityPanel(): ActivityPanelState {
  try {
    const saved = JSON.parse(localStorage.getItem(ACTIVITY_PANEL_KEY) || "null");
    if (saved && Number.isFinite(saved.width) && Number.isFinite(saved.height))
      return { x: Number.isFinite(saved.x) ? saved.x : undefined,
        y: Number.isFinite(saved.y) ? saved.y : undefined,
        width: Math.max(360, saved.width), height: Math.max(260, saved.height),
        collapsed: !!saved.collapsed };
  } catch { /* use the compact default */ }
  return defaultActivityPanel;
}
export function buildActivityFeed(data: GraphOut): ActivityItem[] {
  const active = data.nodes.flatMap((node) => {
    const activity = getNodeActivity(node);
    return activity?.startedAt ? [{ nodeId: node.id, at: activity.startedAt,
      text: `${activity.label} ${activity.kind === "listener" ? "listening"
        : activity.status === "launched" ? "connected" : "started"}`,
      kind: "live" as const, status: "in-progress", reason: "실행 중" }] : [];
  });
  const activeIds = new Set(active.map((item) => item.nodeId));
  const created = data.nodes.flatMap((node) => node.created_at && !activeIds.has(node.id) ? [{ nodeId: node.id,
    at: node.created_at, text: node.type === "service" ? `${nodeSummary(node)} discovered`
      : node.type === "credential" ? `${nodeSummary(node)} captured`
      : node.type === "finding" ? `${nodeSummary(node)} identified`
      : node.type === "technique" ? nodeSummary(node) : `${node.label} discovered`,
    kind: (node.type === "technique" ? "task" : node.type === "project-root"
      || node.type === "host" || node.type === "operator" ? "target" : node.type) as ActivityKind,
    status: node.status, reason: nodeStatusReason(node) }] : []);
  return [...active, ...created].sort((a, b) => Date.parse(b.at) - Date.parse(a.at)).slice(0, 100);
}

type ActivityStatusFilter = "all" | "running" | "review" | "failed" | "complete";
export function filterActivityFeed(items: ActivityItem[], query: string,
  kind: "all" | ActivityKind, status: ActivityStatusFilter = "all"): ActivityItem[] {
  const needle = query.trim().toLocaleLowerCase();
  return items.filter((item) => (kind === "all" || item.kind === kind)
    && (status === "all" || status === "running" && item.kind === "live"
      || status === "review" && item.reason === "사용자 검토 대기"
      || status === "failed" && item.status === "attempt-failed"
      || status === "complete" && item.status === "succeeded")
    && (!needle || `${item.text} ${item.kind} ${item.reason}`.toLocaleLowerCase().includes(needle)));
}

export function filterGraph(data: GraphOut, filter: GraphFilter,
  selected: string | null): GraphOut {
  const allowed = new Set(data.nodes.map((node) => node.id));
  if (filter.focusDepth > 0 && selected) {
    allowed.clear(); allowed.add(selected);
    let frontier = new Set([selected]);
    for (let depth = 0; depth < filter.focusDepth; depth++) {
      const next = new Set<string>();
      data.edges.forEach((edge) => {
        if (frontier.has(edge.source)) next.add(edge.target);
        if (frontier.has(edge.target)) next.add(edge.source);
      });
      next.forEach((id) => allowed.add(id)); frontier = next;
    }
  }
  const needle = filter.query.trim().toLocaleLowerCase();
  const nodes = data.nodes.filter((node) => allowed.has(node.id)
    && (filter.type === "all" || node.type === filter.type)
    && (filter.status === "all" || node.status === filter.status)
    && (!filter.pinnedOnly || node.pinned)
    && (!needle || `${node.label} ${nodeSummary(node)} ${node.notes || ""} ${node.tags || ""}`
      .toLocaleLowerCase().includes(needle)));
  const ids = new Set(nodes.map((node) => node.id));
  return { root_node_id: data.root_node_id, nodes,
    edges: data.edges.filter((edge) => ids.has(edge.source) && ids.has(edge.target)) };
}

export function getNodeActivity(node: Pick<GraphNode, "meta">): NodeActivity | null {
  if (!node.meta) return null;
  try {
    const value = JSON.parse(node.meta).activity;
    if (!value || !["scan", "execution", "listener"].includes(value.kind)
      || !["queued", "running", "processing", "launched"].includes(value.status)) return null;
    return { kind: value.kind, status: value.status,
      label: typeof value.label === "string" ? value.label : "TASK",
      startedAt: typeof value.startedAt === "string" ? value.startedAt : null };
  } catch { return null; }
}

export function isCrackableCredential(node: Pick<GraphNode, "type" | "meta">): boolean {
  if (node.type !== "credential") return false;
  try { return JSON.parse(node.meta || "{}").credType === "hash"; }
  catch { return false; }
}

function useActiveProjectId(): number | null {
  const [id, setId] = useState<number | null>(() => {
    const raw = Number(localStorage.getItem("oscp-workspace-project"));
    return raw > 0 ? raw : null;
  });
  useEffect(() => {
    const change = (e: Event) => setId((e as CustomEvent<number>).detail);
    addEventListener("oscp-project-change", change);
    return () => removeEventListener("oscp-project-change", change);
  }, []);
  return id;
}

export default function GraphWorkspace() {
  const projectId = useActiveProjectId();
  const queryClient = useQueryClient();
  const [view, setView] = useState<"graph" | "tree" | "outline">(() =>
    (localStorage.getItem("oscp-graph-view") as "graph" | "tree" | "outline") || "graph");
  useEffect(() => { localStorage.setItem("oscp-graph-view", view); }, [view]);
  const [selected, setSelected] = useState<string | null>(() =>
    localStorage.getItem("oscp-graph-selected"));
  useEffect(() => {
    if (selected) localStorage.setItem("oscp-graph-selected", selected);
    else localStorage.removeItem("oscp-graph-selected");
  }, [selected]);
  const [filter, setFilter] = useState<GraphFilter>({ query: "", type: "all",
    status: "all", focusDepth: 0, pinnedOnly: false });
  const [queueOpen, setQueueOpen] = useState(false);
  const [contextMenu, setContextMenu] = useState<{ id: string; x: number; y: number } | null>(null);
  const [showHidden, setShowHidden] = useState(false);
  const [focus, setFocus] = useState<{ id: string; nonce: number } | null>(null);
  const [addOpen, setAddOpen] = useState(false);
  const [webRequest, setWebRequest] = useState<GraphRequestDraft | null>(null);
  const [hashPanel, setHashPanel] = useState<CredentialHandoff | null>(null);
  const [postPanel, setPostPanel] = useState<CredentialHandoff | null>(null);
  const [reportPanel, setReportPanel] = useState(false);
  const [paneWidth, setPaneWidth] = useState(() => {
    const saved = Number(localStorage.getItem("oscp-graph-pane"));
    return saved >= 320 ? saved : 640;
  });
  useEffect(() => {
    localStorage.setItem("oscp-graph-pane", String(paneWidth));
  }, [paneWidth]);
  // A scan (or other workspace) finished producing rows -> re-sync the graph so
  // the new services/findings appear as nodes. Structural sharing keeps the
  // reference stable when nothing changed, so this won't reflow spuriously.
  useEffect(() => {
    const refresh = () =>
      queryClient.invalidateQueries({ queryKey: ["graph", projectId] });
    addEventListener("oscp-graph-refresh", refresh);
    return () => removeEventListener("oscp-graph-refresh", refresh);
  }, [queryClient, projectId]);
  const dragRef = useRef<{ startX: number; startWidth: number } | null>(null);
  const onSplitDown = (e: React.PointerEvent) => {
    dragRef.current = { startX: e.clientX, startWidth: paneWidth };
    e.currentTarget.setPointerCapture(e.pointerId);
  };
  const onSplitMove = (e: React.PointerEvent) => {
    if (!dragRef.current) return;
    const delta = dragRef.current.startX - e.clientX;  // drag left => wider pane
    setPaneWidth(Math.max(320,
      Math.min(window.innerWidth - 380, dragRef.current.startWidth + delta)));
  };
  const onSplitUp = (e: React.PointerEvent) => {
    dragRef.current = null;
    e.currentTarget.releasePointerCapture(e.pointerId);
  };

  const createProject = useMutation({
    mutationFn: () => api<{ id: number }>("/projects", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: `OSCP Practice ${Date.now().toString().slice(-4)}`,
        description: "Local lab workspace",
      }),
    }),
    onSuccess: (project) => {
      localStorage.setItem("oscp-workspace-project", String(project.id));
      dispatchEvent(new CustomEvent("oscp-project-change", { detail: project.id }));
      queryClient.invalidateQueries({ queryKey: ["projects"] });
    },
  });

  const invalidateGraph = () => {
    queryClient.invalidateQueries({ queryKey: ["graph", projectId] });
    queryClient.invalidateQueries({ queryKey: ["graphTree", projectId] });
  };
  const setHidden = useMutation({
    mutationFn: (v: { id: string; hidden: boolean }) =>
      api(`/graph/nodes/${v.id}`, {
        method: "PATCH", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hidden: v.hidden }),
      }),
    onSuccess: invalidateGraph,
  });
  const setStatus = useMutation({
    mutationFn: (v: { id: string; status: string }) =>
      api(`/graph/nodes/${v.id}`, {
        method: "PATCH", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: v.status }),
      }),
    onSuccess: invalidateGraph,
  });
  const setDetails = useMutation({
    mutationFn: (v: { id: string; notes?: string; pinned?: boolean }) =>
      api(`/graph/nodes/${v.id}`, { method: "PATCH",
        headers: { "Content-Type": "application/json" }, body: JSON.stringify(v) }),
    onSuccess: invalidateGraph,
  });
  // Manual recording: create a node and connect it to the selected one. This is
  // how artifacts the DB never captured (a stolen hash, an observed LFI) get
  // into the graph.
  const addNode = useMutation({
    mutationFn: async (v: {
      sourceId: string; type: string; label: string; relation: string; status: string;
    }) => {
      const node = await api<{ id: string }>(`/projects/${projectId}/graph/nodes`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type: v.type, label: v.label, status: v.status }),
      });
      await api(`/projects/${projectId}/graph/edges`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ source: v.sourceId, target: node.id,
          relation: v.relation, status: v.status }),
      });
    },
    onSuccess: invalidateGraph,
  });

  const graph = useQuery({
    queryKey: ["graph", projectId],
    enabled: !!projectId,
    queryFn: async () => {
      // idempotent projection of existing nmap targets/services (spec 6.1)
      await api(`/projects/${projectId}/graph/sync`, { method: "POST" });
      return api<GraphOut>(`/projects/${projectId}/graph`);
    },
    refetchInterval: (query) =>
      query.state.data?.nodes.some((node) => getNodeActivity(node)) ? 2000 : false,
  });
  const tree = useQuery({
    queryKey: ["graphTree", projectId, graph.dataUpdatedAt],
    enabled: !!projectId && graph.isSuccess,
    queryFn: () => api<TreeNode>(`/projects/${projectId}/graph/tree`),
  });

  const nodeById = useMemo(() => {
    const map = new Map<string, GraphNode>();
    graph.data?.nodes.forEach((n) => map.set(n.id, n));
    return map;
  }, [graph.data]);
  useEffect(() => {
    if (selected && graph.data && !nodeById.has(selected)) setSelected(null);
  }, [graph.data, nodeById, selected]);

  // Reverse bridge: focus the node a specialized workspace pointed us at.
  useEffect(() => {
    if (!graph.data) return;
    const resolve = (kind: string, id: number): string | undefined => {
      for (const n of graph.data!.nodes) {
        if (!n.source_ref) continue;
        try {
          const r = JSON.parse(n.source_ref);
          if (r.kind === kind && r.id === id) return n.id;
        } catch { /* ignore */ }
      }
      return undefined;
    };
    const apply = () => {
      const req = consumePendingGraphFocus();
      if (!req) return;
      const nodeId = resolve(req.kind, req.id);
      if (!nodeId) return;
      setView("graph");
      setSelected(nodeId);
      setFocus({ id: nodeId, nonce: Date.now() });
    };
    apply();
    const onEvent = () => apply();
    addEventListener("oscp-graph-focus", onEvent);
    return () => removeEventListener("oscp-graph-focus", onEvent);
  }, [graph.data]);

  // Resolve a service node to the {targetId, serviceId} the Enumeration
  // workspace needs (targetId comes from the parent host node).
  const serviceHandoff = (id: string | null): { targetId: number; serviceId: number } | null => {
    if (!id) return null;
    const node = nodeById.get(id);
    if (!node || node.type !== "service" || !node.source_ref) return null;
    let ref: { kind: string; id: number };
    try { ref = JSON.parse(node.source_ref); } catch { return null; }
    if (ref.kind !== "service") return null;
    const edge = graph.data?.edges.find(
      (e) => e.target === id && e.relation === "discovered");
    const host = edge ? nodeById.get(edge.source) : undefined;
    if (!host?.source_ref) return null;
    try {
      const h = JSON.parse(host.source_ref);
      if (h.kind === "target") return { targetId: h.id, serviceId: ref.id };
    } catch { /* ignore */ }
    return null;
  };
  const executionHandoff = (id: string | null): { targetId: number; serviceId?: number } | null => {
    if (!id) return null;
    const node = nodeById.get(id);
    if (!node?.source_ref) return null;
    let kind: string;
    try {
      kind = JSON.parse(node.source_ref).kind;
      if (!["execution", "session"].includes(kind)) return null;
    } catch { return null; }
    if (kind === "session") {
      const capture = graph.data?.edges.find((item) =>
        item.source === id && item.relation === "captures-from");
      const host = capture ? nodeById.get(capture.target) : undefined;
      if (!host?.source_ref) return null;
      try {
        const ref = JSON.parse(host.source_ref);
        return ref.kind === "target" ? { targetId: ref.id } : null;
      } catch { return null; }
    }
    const edge = graph.data?.edges.find((item) =>
      item.target === id && item.relation === "attempted");
    if (!edge) return null;
    const service = serviceHandoff(edge.source);
    if (service) return service;
    const parent = nodeById.get(edge.source);
    if (!parent?.source_ref) return null;
    try {
      const ref = JSON.parse(parent.source_ref);
      return ref.kind === "target" ? { targetId: ref.id } : null;
    } catch { return null; }
  };

  // Scope the embedded Enumeration workspace to the selected service node.
  const selectedType = selected ? nodeById.get(selected)?.type : undefined;
  useEffect(() => {
    const h = serviceHandoff(selected);
    if (h) {
      setPendingServiceNav(h);
      dispatchEvent(new CustomEvent("oscp-service-nav"));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected, selectedType]);

  // Two-way bridge: a graph node deep-links into the specialized workspace that
  // owns its underlying domain entity (via source_ref). This is what makes the
  // graph a hub rather than a sibling view.
  const deepLinks = (id: string): DeepLink[] => {
    const node = nodeById.get(id);
    if (!node?.source_ref) return [];
    let ref: { module: string; kind: string; id: number };
    try { ref = JSON.parse(node.source_ref); } catch { return []; }
    const credentialHandoff = async () => {
      if (!projectId) return null;
      const rows = await api<CredentialHandoff[]>(
        `/runbooks/credentials?project_id=${projectId}`);
      return rows.find((item) => item.id === ref.id) || null;
    };
    if (ref.kind === "service" || ref.kind === "target") return [];
    if (ref.kind === "finding") return [{ label: "Finding 작업 패널 열기 →", open: () => {
      setHashPanel(null); setPostPanel(null); setWebRequest(null); setReportPanel(true);
    } }];
    if (ref.kind === "credential") {
      if (!isCrackableCredential(node))
        return [{ label: "Post-Exploitation 패널 열기 →", open: async () => {
          const credential = await credentialHandoff();
          if (credential) { setHashPanel(null); setWebRequest(null); setReportPanel(false); setPostPanel(credential); }
        } }];
      return [{
        label: "Hash Cracking 패널 열기 →",
        open: async () => {
          const credential = await credentialHandoff();
          if (!credential) return;
          setPostPanel(null); setWebRequest(null); setReportPanel(false); setHashPanel(credential);
        },
      }, {
        label: "Post-Exploitation 패널 열기 →",
        open: async () => {
          const credential = await credentialHandoff();
          if (credential) { setHashPanel(null); setWebRequest(null); setReportPanel(false); setPostPanel(credential); }
        },
      }];
    }
    return [];
  };

  const noProject = !projectId;
  if (!noProject && graph.isLoading) return <Empty text="그래프 동기화 중…" />;
  if (!noProject && graph.isError)
    return <Empty text={`불러오기 실패: ${(graph.error as Error).message}`} />;

  // Graph-first onboarding: even with no project (or before any scan), show a
  // graph with a single root node the user can click to start scanning.
  const SYNTHETIC: GraphOut = {
    root_node_id: "start",
    nodes: [{ id: "start", type: "project-root", status: "in-progress",
      label: "여기서 시작 · 프로젝트 만들기", objective: false, source_ref: "", hidden: false }],
    edges: [],
  };
  const data = noProject ? SYNTHETIC : graph.data!;
  const visibleData = filterGraph(data, filter, selected);
  const hostCount = data.nodes.filter((n) => n.type === "host" && !n.hidden).length;
  const hiddenCount = data.nodes.filter((n) => n.hidden).length;
  const selectedNode = selected
    ? (noProject ? data.nodes.find((n) => n.id === selected) : nodeById.get(selected))
    : undefined;

  return (
    <div style={S.wrap}>
      <div style={S.bar}>
        <div style={S.tabs}>
          <Tab on={view === "graph"} onClick={() => setView("graph")}>그래프</Tab>
          <Tab on={view === "tree"} onClick={() => setView("tree")}>트리</Tab>
          <Tab on={view === "outline"} onClick={() => setView("outline")}>Outline</Tab>
        </div>
        {selectedNode && !noProject && (
          <button onClick={() => setAddOpen(true)} style={S.hiddenChip}
            title={`${selectedNode.label} 아래에 노드 추가`}>
            ＋ 노드 추가
          </button>
        )}
        {hiddenCount > 0 && (
          <button onClick={() => setShowHidden((v) => !v)} style={{
            ...S.hiddenChip,
            ...(showHidden ? { background: "#6aa9ff", color: "#06131f" } : {}),
          }}>
            숨김 {hiddenCount}{showHidden ? " 표시중" : ""}
          </button>
        )}
        <div style={S.legend}>
          {Object.entries(STATUS_REASON).map(([k, v]) => (
            <span key={k} style={{ display: "flex", alignItems: "center", gap: 5 }}>
              <span style={{ width: 9, height: 9, borderRadius: 9, background: color(k) }} />
              {v}
            </span>
          ))}
        </div>
      </div>
      <div style={S.graphTools}>
        <label style={S.graphSearch}><span>⌕</span><input aria-label="그래프 검색"
          style={S.graphSearchInput}
          value={filter.query} placeholder="노드, 서비스, 메모 검색"
          onChange={(event) => setFilter({ ...filter, query: event.target.value })} /></label>
        <select aria-label="노드 유형" value={filter.type}
          style={S.graphControl}
          onChange={(event) => setFilter({ ...filter, type: event.target.value as GraphFilter["type"] })}>
          <option value="all">모든 유형</option>{Object.keys(GLYPH).map((type) =>
            <option key={type} value={type}>{type}</option>)}</select>
        <select aria-label="노드 상태" value={filter.status}
          style={S.graphControl}
          onChange={(event) => setFilter({ ...filter, status: event.target.value })}>
          <option value="all">모든 상태</option>{STATUS_ORDER.map((status) =>
            <option key={status} value={status}>{STATUS_REASON[status]}</option>)}</select>
        <select aria-label="집중 범위" value={filter.focusDepth}
          style={S.graphControl}
          onChange={(event) => setFilter({ ...filter, focusDepth: Number(event.target.value) })}>
          <option value={0}>전체 관계</option><option value={1}>선택 주변 1단계</option>
          <option value={2}>선택 주변 2단계</option><option value={3}>선택 주변 3단계</option></select>
        <button style={{ ...S.graphControl, ...(filter.pinnedOnly ? S.toolActive : {}) }}
          onClick={() => setFilter({ ...filter, pinnedOnly: !filter.pinnedOnly })}>★ 북마크</button>
        <button style={S.graphControl} onClick={() => setFilter({ query: "", type: "all", status: "all",
          focusDepth: 0, pinnedOnly: false })}>필터 초기화</button>
        <button style={S.graphControl} onClick={() => setQueueOpen((value) => !value)}>작업 큐</button>
        <span style={S.filterCount}>{visibleData.nodes.length}/{data.nodes.length} nodes</span>
      </div>
      <div style={S.stage}>
        {view !== "outline" ? (
          <GraphCanvas data={visibleData} hostCount={hostCount} showHidden={showHidden}
            selected={selected} onSelect={setSelected} focus={focus} layoutMode={view}
            onContext={(id, x, y) => setContextMenu({ id, x, y })}
            onActivitySelect={(id) => { setSelected(id); setFocus({ id, nonce: Date.now() }); }} />
        ) : (
          <OutlineView tree={tree.data} onSelect={setSelected} selected={selected} />
        )}
        <div style={S.splitter} onPointerDown={onSplitDown}
          onPointerMove={onSplitMove} onPointerUp={onSplitUp} />
        <div style={{ width: paneWidth, flexShrink: 0, display: "flex",
          minWidth: 0, minHeight: 0 }}>
          {reportPanel ? (
            <div style={S.embedPane}><Suspense fallback={<Empty text="Findings 불러오는 중…" />}>
              <EmbeddedReports embedded initialProjectId={projectId || undefined}
                onBack={() => setReportPanel(false)} />
            </Suspense></div>
          ) : hashPanel ? (
            <div style={S.embedPane}><Suspense fallback={<Empty text="Hash Cracking 불러오는 중…" />}>
              <EmbeddedHashCracking embedded initialProjectId={hashPanel.project_id}
                initialTargetId={hashPanel.target_id} initialHash={hashPanel.secret}
                initialMode={hashPanel.source_kind === "responder"
                  || /NTLMv2/i.test(hashPanel.secret_hint || "") ? "netntlmv2" : undefined}
                onBack={() => setHashPanel(null)} />
            </Suspense></div>
          ) : postPanel ? (
            <div style={S.embedPane}><Suspense fallback={<Empty text="Post-Exploitation 불러오는 중…" />}>
              <EmbeddedPostExploitation embedded initialProjectId={postPanel.project_id}
                initialTargetId={postPanel.target_id} initialCredentialId={postPanel.id}
                onBack={() => setPostPanel(null)} />
            </Suspense></div>
          ) : webRequest ? (
            <GraphRequestPanel draft={webRequest} onBack={() => setWebRequest(null)} />
          ) : noProject ? (
            <OnboardingPane creating={createProject.isPending}
              onCreate={() => createProject.mutate()} />
          ) : selectedNode?.type === "project-root" || selectedNode?.type === "host" ? (
            <div style={S.embedPane}>
              <Suspense fallback={<Empty text="Scan Center 불러오는 중…" />}>
                <EmbeddedScanCenter embedded />
              </Suspense>
            </div>
          ) : selectedNode?.type === "service" ? (
            <div style={S.embedPane}>
              <Suspense fallback={<Empty text="도구 불러오는 중…" />}>
                <EmbeddedEnumeration embedded />
              </Suspense>
            </div>
          ) : (
            <Inspector node={selectedNode} links={selected ? deepLinks(selected) : []}
              executionContext={executionHandoff(selected)}
              onOpenRequest={(draft) => {
                setHashPanel(null); setPostPanel(null); setReportPanel(false); setWebRequest(draft);
              }}
              busy={addNode.isPending}
              onToggleHidden={(id, hidden) => setHidden.mutate({ id, hidden })}
              onSetStatus={(id, status) => setStatus.mutate({ id, status })}
              onSetDetails={(id, details) => setDetails.mutate({ id, ...details })}
              onAddNode={(v) => addNode.mutate(v)} />
          )}
        </div>
      </div>
      {queueOpen && <TaskQueue nodes={data.nodes} onClose={() => setQueueOpen(false)}
        onSelect={(id) => { setSelected(id); setFocus({ id, nonce: Date.now() }); }}
        onStatus={(id, status) => setStatus.mutate({ id, status })}
        onAdd={() => selectedNode && setAddOpen(true)} canAdd={!!selectedNode} />}
      {contextMenu && nodeById.get(contextMenu.id) && <NodeQuickMenu
        node={nodeById.get(contextMenu.id)!} x={contextMenu.x} y={contextMenu.y}
        onClose={() => setContextMenu(null)}
        onOpen={() => { setSelected(contextMenu.id); setContextMenu(null); }}
        onAdd={() => { setSelected(contextMenu.id); setAddOpen(true); setContextMenu(null); }}
        onPin={() => { const node = nodeById.get(contextMenu.id)!;
          setDetails.mutate({ id: node.id, pinned: !node.pinned }); setContextMenu(null); }}
        onHide={() => { setHidden.mutate({ id: contextMenu.id, hidden: true }); setContextMenu(null); }}
        onStatus={(status) => { setStatus.mutate({ id: contextMenu.id, status }); setContextMenu(null); }} />}
      {addOpen && selectedNode && (
        <div style={S.overlay} onClick={() => setAddOpen(false)}>
          <div style={{ width: 380 }} onClick={(e) => e.stopPropagation()}>
            <AddNodeForm source={selectedNode} busy={addNode.isPending}
              onCancel={() => setAddOpen(false)}
              onSubmit={(v) => { addNode.mutate({ sourceId: selectedNode.id, ...v });
                setAddOpen(false); }} />
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------- Graph (Canvas force sim; Pixi swap = M4) ----------------

type Sim = GraphNode & { x: number; y: number; vx: number; vy: number };
type GraphPosition = { x: number; y: number };

export function initialGraphPosition(id: string, index: number, total: number,
  cached: ReadonlyMap<string, GraphPosition>): GraphPosition {
  const previous = cached.get(id);
  if (previous) return previous;
  const angle = (index / Math.max(1, total)) * Math.PI * 2;
  return { x: 400 + Math.cos(angle) * 180, y: 300 + Math.sin(angle) * 140 };
}

export function initialGraphPositionNearParent(id: string, parent?: GraphPosition): GraphPosition | null {
  if (!parent) return null;
  const seed = [...id].reduce((sum, char) => sum + char.charCodeAt(0), 0);
  const angle = (seed % 360) * Math.PI / 180;
  return { x: parent.x + Math.cos(angle) * 74, y: parent.y + Math.sin(angle) * 74 };
}

function GraphCanvas(props: {
  data: GraphOut; hostCount: number; showHidden: boolean;
  selected: string | null; onSelect: (id: string) => void;
  focus: { id: string; nonce: number } | null;
  layoutMode: "graph" | "tree"; onActivitySelect: (id: string) => void;
  onContext: (id: string, x: number, y: number) => void;
}) {
  const { data, hostCount, showHidden } = props;
  // These are read through refs inside the render loop so selection/zoom changes
  // do NOT re-run the effect (which would reseed positions and make the graph
  // "jump" on every click). The sim only re-inits when the node set changes.
  const focusReq = useRef<{ id: string; nonce: number } | null>(null);
  useEffect(() => { focusReq.current = props.focus; }, [props.focus]);
  const selectedRef = useRef(props.selected);
  useEffect(() => { selectedRef.current = props.selected; }, [props.selected]);
  const zoomRef = useRef(1);  // camera zoom (mouse wheel + Ctrl +/-); persists across re-init
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const positions = useRef({ graph: new Map<string, GraphPosition>(),
    tree: new Map<string, GraphPosition>() });
  const activityStarted = useRef(new Map<string, number>());
  const latestNodes = useRef(new Map(data.nodes.map((n) => [n.id, n])));
  const latestEdges = useRef(new Map(data.edges.map((e) => [e.id, e])));
  useEffect(() => {
    latestNodes.current = new Map(data.nodes.map((n) => [n.id, n]));
    latestEdges.current = new Map(data.edges.map((e) => [e.id, e]));
  }, [data]);
  const nodeSet = data.nodes.map((n) => n.id).sort().join("|");
  const edgeSet = data.edges.map((e) => e.id).sort().join("|");
  // adaptive root (decision B): single host => that host is the visual anchor.
  const anchorId = hostCount === 1
    ? (data.nodes.find((n) => n.type === "host")?.id ?? data.root_node_id)
    : data.root_node_id;
  const hideRoot = hostCount === 1;  // single host is the anchor; 0 hosts -> show root

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    let W = 0, H = 0, raf = 0, render = (_now?: number) => {};
    const workspaceKey = `oscp-graph-camera:${data.root_node_id || "start"}:${props.layoutMode}`;
    let restored: { panX?: number; panY?: number; zoom?: number;
      positions?: Record<string, GraphPosition> } = {};
    try { restored = JSON.parse(localStorage.getItem(workspaceKey) || "{}"); } catch { /* defaults */ }
    if (restored.positions) positions.current[props.layoutMode] = new Map(Object.entries(restored.positions));
    if (Number.isFinite(restored.zoom)) zoomRef.current = Math.max(.3, Math.min(4, restored.zoom!));
    let panX = Number.isFinite(restored.panX) ? restored.panX! : 0;
    let panY = Number.isFinite(restored.panY) ? restored.panY! : 0;
    let panning = false, panStart = { x: 0, y: 0 };
    let dragging: Sim | null = null, hover: Sim | null = null;

    const visible = (n: GraphNode) =>
      !(hideRoot && n.type === "project-root") && (showHidden || !n.hidden);
    const cached = positions.current[props.layoutMode];
    const parentByNode = new Map(data.edges.map((edge) => [edge.target, edge.source]));
    const retained = new Set(data.nodes.filter((node) => cached.has(node.id)).map((node) => node.id));
    const nodes: Sim[] = data.nodes.filter(visible).map((n, i) => {
      const parent = cached.get(parentByNode.get(n.id) || "");
      const point = cached.get(n.id) || initialGraphPositionNearParent(n.id, parent)
        || initialGraphPosition(n.id, i, data.nodes.length, cached);
      return { ...n, ...point, vx: 0, vy: 0 };
    });
    const stabilizationEnds = retained.size && retained.size < nodes.length
      ? performance.now() + 700 : 0;
    const index = new Map(nodes.map((n) => [n.id, n]));
    const edges = data.edges.filter((e) => index.has(e.source) && index.has(e.target));
    const structural = new Set(["discovered", "enumerated", "attempted", "yielded",
      "pivoted-to", "operates", "runs"]);
    const depths = new Map<string, number>([[anchorId || "", 0]]);
    for (let pass = 0; pass < nodes.length; pass++) for (const edge of edges) {
      if (!structural.has(edge.relation)) continue;
      const parentDepth = depths.get(edge.source);
      if (parentDepth !== undefined && !depths.has(edge.target)) depths.set(edge.target, parentDepth + 1);
    }
    const levels = new Map<number, Sim[]>();
    nodes.forEach((node) => {
      const depth = depths.get(node.id) ?? 0;
      levels.set(depth, [...(levels.get(depth) || []), node]);
    });
    const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;
    // Three activity languages, one per meaning: green = actively searching
    // (scan output still streaming, outcome unknown), red = armed and
    // waiting on something external (Responder), blue = already connected
    // and settled -- reuses the app's existing anchor/selection blue rather
    // than inventing a fourth hue.
    const signal = "#59f59a";
    const listenerSignal = "#ff4d67";
    const connectedSignal = "#6aa9ff";
    type SignalKind = "scan" | "listener" | "connected";
    const SIGNAL_RGB: Record<SignalKind, string> = {
      scan: "89,245,154", listener: "255,77,103", connected: "106,169,255",
    };
    const signalKindOf = (a: NodeActivity | null): SignalKind | null => !a ? null
      : a.kind === "listener" ? "listener" : a.status === "launched" ? "connected" : "scan";
    const signalHex = (kind: SignalKind) =>
      kind === "listener" ? listenerSignal : kind === "connected" ? connectedSignal : signal;
    const signalRgba = (kind: SignalKind, alpha: number) => `rgba(${SIGNAL_RGB[kind]},${alpha})`;
    const FILL_BG: Record<SignalKind, string> = {
      scan: "#10251a", listener: "#2a1016", connected: "#0e1a2a",
    };
    const BADGE_BG: Record<SignalKind, string> = {
      scan: "rgba(5,18,12,.9)", listener: "rgba(25,5,10,.92)", connected: "rgba(6,14,26,.92)",
    };
    const signalLabel = (a: NodeActivity, kind: SignalKind) => kind === "listener" ? "LISTENING"
      : kind === "connected" ? "CONNECTED" : a.kind === "scan" ? "SCANNING" : a.status.toUpperCase();

    const resize = () => {
      const r = canvas.getBoundingClientRect(); W = r.width; H = r.height;
      const bw = Math.round(W * dpr), bh = Math.round(H * dpr);
      if (canvas.width !== bw || canvas.height !== bh) {
        // Setting the backing size clears the canvas; ResizeObserver fires after
        // the frame's draw but before paint, so repaint now to avoid a blank
        // frame (the "flicker" while dragging the splitter).
        canvas.width = bw; canvas.height = bh;
        render();
      }
    };
    const ro = new ResizeObserver(resize); ro.observe(canvas); resize();

    const tick = () => {
      if (props.layoutMode === "tree") {
        for (const [depth, level] of levels) level.forEach((node, row) => {
          const tx = 90 + depth * 150;
          const ty = H / 2 + (row - (level.length - 1) / 2) * Math.min(105, H / Math.max(2, level.length));
          node.vx += (tx - node.x) * .035; node.vy += (ty - node.y) * .035;
          node.vx *= .78; node.vy *= .78;
          if (node !== dragging) { node.x += node.vx; node.y += node.vy; }
        });
        return;
      }
      for (let i = 0; i < nodes.length; i++)
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i], b = nodes[j];
          let dx = a.x - b.x, dy = a.y - b.y, d2 = dx * dx + dy * dy || 0.01;
          const d = Math.sqrt(d2), f = 6500 / d2;
          a.vx += (dx / d) * f; a.vy += (dy / d) * f;
          b.vx -= (dx / d) * f; b.vy -= (dy / d) * f;
        }
      for (const e of edges) {
        const a = index.get(e.source)!, b = index.get(e.target)!;
        let dx = b.x - a.x, dy = b.y - a.y, d = Math.hypot(dx, dy) || 0.01;
        // Each tier hop gets its own rest length, tapering down with depth:
        // root->1차 needs the most room (every 1차 node's own children fan
        // out from it next), but if every hop kept that same spacing the
        // graph would blow up in size by 3-4 tiers deep.
        const struct = structural.has(e.relation);
        const tier = struct ? Math.max(depths.get(e.source) ?? 1, depths.get(e.target) ?? 1) : 0;
        const rest = !struct ? 230
          : tier <= 1 ? 475 : tier === 2 ? 250 : tier === 3 ? 160 : 120;
        // Spring stiffness has to scale with repulsion (6500, raised from
        // 2600) or the tiered rest lengths above are cosmetic -- a node's
        // pull toward its actual parent loses the tug-of-war against the
        // *sum* of repulsion from every other nearby node, not just one.
        const k = (d - rest) * 0.045;
        a.vx += (dx / d) * k; a.vy += (dy / d) * k;
        b.vx -= (dx / d) * k; b.vy -= (dy / d) * k;
      }
      const cx = W / 2, cy = H / 2;
      for (const n of nodes) {
        if (n.id === anchorId) { n.x = cx; n.y = cy; n.vx = n.vy = 0; continue; }
        if (props.layoutMode === "graph" && stabilizationEnds > performance.now()
            && retained.has(n.id) && n !== dragging) {
          n.vx = n.vy = 0;
          continue;
        }
        // Center gravity only anchors the first tier. The root sits AT the
        // canvas center, so any residual center-pull on 2차+ nodes is a
        // pull toward the root specifically -- not a neutral force. That
        // biased every deeper node onto the root-facing side of its real
        // parent instead of ringing it evenly, which is the graph looking
        // like it caves inward instead of branching outward from the root.
        // Past 1차, only the parent-edge spring + sibling repulsion apply.
        const depth = depths.get(n.id) ?? 1;
        const pull = depth <= 1 ? 0.002 : 0;
        n.vx += (cx - n.x) * pull; n.vy += (cy - n.y) * pull;
        n.vx *= 0.86; n.vy *= 0.86;
        if (n !== dragging) { n.x += n.vx; n.y += n.vy; }
      }
    };

    const draw = (now = performance.now()) => {
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, W, H);
      ctx.translate(panX, panY);
      ctx.scale(zoomRef.current, zoomRef.current);  // camera zoom: sizes AND spacing
      if (props.layoutMode === "graph" && anchorId) {
        const anchor = index.get(anchorId);
        if (anchor) {
          const stages = ["DISCOVERY", "ENUMERATION", "ACCESS", "PRIVILEGE", "EVIDENCE"];
          stages.forEach((stage, i) => {
            const radius = 70 + i * 58;
            ctx.beginPath(); ctx.arc(anchor.x, anchor.y, radius, 0, Math.PI * 2);
            ctx.strokeStyle = `rgba(89,245,154,${.065 - i * .008})`; ctx.lineWidth = 1; ctx.stroke();
            ctx.fillStyle = "rgba(89,245,154,.24)";
            ctx.font = "600 7px ui-monospace,monospace"; ctx.textAlign = "left";
            ctx.textBaseline = "bottom"; ctx.fillText(stage, anchor.x + 8, anchor.y - radius + 10);
          });
        }
      }
      for (const e of edges) {
        const a = index.get(e.source)!, b = index.get(e.target)!;
        const edge = latestEdges.current.get(e.id) ?? e;
        const activeA = getNodeActivity(latestNodes.current.get(a.id) ?? a);
        const activeB = getNodeActivity(latestNodes.current.get(b.id) ?? b);
        const active = activeA || activeB;
        const edgeKind = signalKindOf(active);
        const edgeSignal = edgeKind ? signalHex(edgeKind) : signal;
        const hot = !!hover && (e.source === hover.id || e.target === hover.id);
        const struct = structural.has(e.relation);
        ctx.beginPath(); ctx.moveTo(a.x, a.y);
        if (struct) { ctx.lineTo(b.x, b.y); ctx.setLineDash([]); }
        else {
          ctx.quadraticCurveTo((a.x + b.x) / 2, (a.y + b.y) / 2 - 34, b.x, b.y);
          ctx.setLineDash([4, 5]);
        }
        ctx.strokeStyle = edgeKind ? signalRgba(edgeKind, edgeKind === "scan" ? .42 : .47)
          : hot ? color(edge.status) : struct ? "#33333f" : "#3a2f45";
        ctx.lineWidth = active ? 1.35 : hot ? 2 : 1;
        ctx.globalAlpha = hover && !hot ? 0.25 : 0.9; ctx.stroke();
        ctx.globalAlpha = 1; ctx.setLineDash([]);
        if (active && !reduceMotion) {
          const flow = ((now / 1250) + (e.id.charCodeAt(0) % 7) / 7) % 1;
          const fromA = !!activeA;
          const t = fromA ? flow : 1 - flow;
          ctx.save(); ctx.shadowColor = edgeSignal; ctx.shadowBlur = 10;
          ctx.beginPath(); ctx.arc(a.x + (b.x - a.x) * t,
            a.y + (b.y - a.y) * t, 2.2, 0, Math.PI * 2);
          ctx.fillStyle = edgeSignal; ctx.fill(); ctx.restore();
        }
        if (e.relation === "captures-from") {
          const angle = Math.atan2(b.y - a.y, b.x - a.x);
          const tipX = b.x - Math.cos(angle) * 21, tipY = b.y - Math.sin(angle) * 21;
          ctx.beginPath(); ctx.moveTo(tipX, tipY);
          ctx.lineTo(tipX - Math.cos(angle - .48) * 8, tipY - Math.sin(angle - .48) * 8);
          ctx.lineTo(tipX - Math.cos(angle + .48) * 8, tipY - Math.sin(angle + .48) * 8);
          ctx.closePath(); ctx.fillStyle = "#ff4d67"; ctx.fill();
          ctx.fillStyle = "#ff7188"; ctx.font = "600 8px ui-monospace,monospace";
          ctx.textAlign = "center"; ctx.textBaseline = "bottom";
          ctx.fillText("AUTH CAPTURE", (a.x + b.x) / 2, (a.y + b.y) / 2 - 7);
        }
      }
      for (const n of nodes) {
        const current = latestNodes.current.get(n.id) ?? n;
        const activity = getNodeActivity(current);
        const signalKind = signalKindOf(activity);
        const nodeSignal = signalKind ? signalHex(signalKind) : signal;
        // A command that finished five minutes ago and one still running
        // both land on the same "in-progress" domain status (outcome is
        // never auto-judged -- the user marks success/failure), so without
        // this they're visually identical. Once activity stops animating,
        // a completed-but-unreviewed technique renders hollow instead of
        // filled: same status color, but "done, take a look" not "running now."
        const awaitingReview = !activity && nodeStatusReason(current) === "사용자 검토 대기";
        const isAnchor = n.id === anchorId, isSel = n.id === selectedRef.current;
        const isHost = n.type === "host", isRoot = n.type === "project-root";
        const isOperator = n.type === "operator";
        const r = isRoot ? 40 : isAnchor ? 38 : isHost || isOperator ? 26 : 19;
        ctx.globalAlpha = current.hidden ? 0.3 : 1;   // dim user-hidden nodes
        if (activity && signalKind === "connected") {
          // Settled, not searching: two slow ease-out rings breathing outward,
          // no rotation -- the opposite motion language from the scan sweep,
          // so "already connected" never reads as "still looking."
          if (!activityStarted.current.has(n.id)) activityStarted.current.set(n.id, now);
          const fade = Math.min(1, (now - activityStarted.current.get(n.id)!) / 320);
          ctx.save(); ctx.shadowColor = nodeSignal; ctx.shadowBlur = 14;
          const period = 2600;
          const ringCount = reduceMotion ? 1 : 2;
          for (let i = 0; i < ringCount; i++) {
            const p = reduceMotion ? .4 : ((now % period) / period + i / ringCount) % 1;
            const ease = 1 - Math.pow(1 - p, 3);
            ctx.beginPath(); ctx.arc(n.x, n.y, r + 9 + ease * 41, 0, Math.PI * 2);
            ctx.strokeStyle = signalRgba("connected", (1 - ease) * .5 * fade);
            ctx.lineWidth = 1.3; ctx.stroke();
          }
          ctx.restore();
        } else if (activity) {
          if (!activityStarted.current.has(n.id)) activityStarted.current.set(n.id, now);
          const fade = Math.min(1, (now - activityStarted.current.get(n.id)!) / 320);
          const phase = (now % 2400) / 2400;
          const kind = signalKind!;
          ctx.save(); ctx.shadowColor = nodeSignal; ctx.shadowBlur = 18;
          for (let i = 0; i < (reduceMotion ? 1 : 3); i++) {
            const p = reduceMotion ? .38 : (phase + i / 3) % 1;
            ctx.beginPath(); ctx.arc(n.x, n.y, r + 14 + p * 52, 0, Math.PI * 2);
            const alpha = (reduceMotion ? .38 : (1 - p) * .42) * fade;
            ctx.strokeStyle = signalRgba(kind, kind === "listener" ? alpha * 1.15 : alpha);
            ctx.lineWidth = reduceMotion ? 1.5 : Math.max(.5, 1.8 - p);
            ctx.stroke();
          }
          if (!reduceMotion && activity.status !== "queued") {
            const angle = now / 720;
            ctx.beginPath(); ctx.moveTo(n.x, n.y);
            ctx.arc(n.x, n.y, r + 41, angle - .42, angle);
            ctx.closePath();
            const sweep = ctx.createRadialGradient(n.x, n.y, r, n.x, n.y, r + 41);
            sweep.addColorStop(0, signalRgba(kind, .03));
            sweep.addColorStop(1, signalRgba(kind, kind === "listener" ? .25 : .22));
            ctx.fillStyle = sweep; ctx.fill();
            ctx.beginPath(); ctx.moveTo(n.x, n.y);
            ctx.lineTo(n.x + Math.cos(angle) * (r + 43), n.y + Math.sin(angle) * (r + 43));
            ctx.strokeStyle = kind === "listener"
              ? "rgba(255,116,135,.9)" : "rgba(130,255,181,.8)";
            ctx.lineWidth = 1; ctx.stroke();
          }
          ctx.restore();
        } else activityStarted.current.delete(n.id);
        if (isAnchor) {
          ctx.beginPath(); ctx.arc(n.x, n.y, r + 17, 0, Math.PI * 2);
          ctx.strokeStyle = "rgba(106,169,255,.4)"; ctx.lineWidth = 1.5;
          ctx.setLineDash([3, 4]); ctx.stroke(); ctx.setLineDash([]);
        }
        if (current.objective) {
          ctx.beginPath(); ctx.arc(n.x, n.y, r + 10, 0, Math.PI * 2);
          ctx.strokeStyle = current.status === "succeeded" ? "#f5c518" : "rgba(245,197,24,.5)";
          ctx.lineWidth = 2.5; ctx.stroke();
        }
        ctx.save();
        ctx.shadowColor = activity ? nodeSignal : awaitingReview ? color(current.status)
          : isAnchor ? "#6aa9ff" : color(current.status);
        ctx.shadowBlur = activity ? 28 : isAnchor ? 30 : isSel ? 24 : awaitingReview ? 10 : 12;
        ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
        ctx.fillStyle = awaitingReview ? "rgba(0,0,0,0)" : signalKind ? FILL_BG[signalKind]
          : isOperator ? "#123038" : color(current.status); ctx.fill();
        ctx.restore();
        ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
        ctx.lineWidth = isSel ? 2.5 : isAnchor || isHost ? 2 : awaitingReview ? 1.6 : 1;
        ctx.strokeStyle = activity ? nodeSignal : awaitingReview ? color(current.status)
          : isSel ? "#fff" : isOperator ? "#55d6e8"
          : isAnchor ? "#6aa9ff"
          : isHost ? "rgba(255,255,255,.7)" : "rgba(255,255,255,.35)";
        if (current.hidden) ctx.setLineDash([2, 3]);
        ctx.stroke();
        ctx.setLineDash([]);
        ctx.fillStyle = "#0c0c10"; ctx.textAlign = "center"; ctx.textBaseline = "middle";
        ctx.font = `${Math.round(r * 0.95)}px sans-serif`;
        ctx.fillText(GLYPH[current.type], n.x, n.y + 0.5);
        const alwaysLabel = ["service", "technique", "credential", "finding"].includes(current.type);
        if (alwaysLabel || hover === n || isSel || isHost || isRoot || isOperator || current.hidden || activity) {
          ctx.fillStyle = "#e7e7ee"; ctx.textBaseline = "top";
          ctx.font = isAnchor ? "600 13px sans-serif" : "12px sans-serif";
          ctx.fillText(current.label, n.x, n.y + r + 10);
        }
        if (hover === n || isSel) {
          const detail = nodeSummary(current);
          if (detail !== current.label) {
            ctx.fillStyle = "#899892"; ctx.font = "9px ui-monospace,monospace";
            ctx.fillText(detail.length > 54 ? `${detail.slice(0, 53)}…` : detail,
              n.x, n.y + r + 36);
          }
        }
        if (activity && signalKind) {
          const caption = `${signalLabel(activity, signalKind)}  /  ${activity.label.toUpperCase()}`;
          ctx.font = "600 9px ui-monospace, SFMono-Regular, monospace";
          const width = ctx.measureText(caption).width + 12;
          const y = n.y - r - 40;
          ctx.fillStyle = BADGE_BG[signalKind];
          ctx.fillRect(n.x - width / 2, y - 7, width, 16);
          ctx.strokeStyle = signalRgba(signalKind, signalKind === "scan" ? .5 : .58);
          ctx.lineWidth = 1;
          ctx.strokeRect(n.x - width / 2, y - 7, width, 16);
          ctx.fillStyle = nodeSignal; ctx.textBaseline = "middle";
          ctx.fillText(caption, n.x, y + 1);
        }
        ctx.globalAlpha = 1;
      }
    };

    render = draw;  // let resize() repaint immediately (no blank frame)
    let appliedNonce = 0, focusNode: Sim | null = null, focusFrames = 0;
    const loop = () => {
      tick();
      const req = focusReq.current;
      if (req && req.nonce !== appliedNonce) {
        appliedNonce = req.nonce;
        focusNode = index.get(req.id) ?? null;
        focusFrames = focusNode ? 45 : 0;  // keep centering while it settles
      }
      if (focusNode && focusFrames > 0) {
        const z = zoomRef.current;
        panX = W / 2 - z * focusNode.x; panY = H / 2 - z * focusNode.y; focusFrames--;
      }
      draw(performance.now());
      raf = requestAnimationFrame(loop);
    };
    loop();

    const toWorld = (ev: MouseEvent) => {
      const r = canvas.getBoundingClientRect(), z = zoomRef.current;
      return { x: (ev.clientX - r.left - panX) / z, y: (ev.clientY - r.top - panY) / z };
    };
    const nodeAt = (x: number, y: number) => {  // x,y are world coords
      for (const n of nodes) {
        const rr = n.type === "project-root" ? 30 : n.id === anchorId ? 28 : 18;
        if (Math.hypot(n.x - x, n.y - y) < rr) return n;
      }
      return null;
    };
    const onMove = (ev: MouseEvent) => {
      const p = toWorld(ev);
      if (dragging) { dragging.x = p.x; dragging.y = p.y; dragging.vx = dragging.vy = 0; return; }
      if (panning) { panX = ev.clientX - panStart.x; panY = ev.clientY - panStart.y; return; }
      hover = nodeAt(p.x, p.y); canvas.style.cursor = hover ? "pointer" : "grab";
    };
    const onDown = (ev: MouseEvent) => {
      const p = toWorld(ev), n = nodeAt(p.x, p.y);
      if (n) dragging = n;
      else { panning = true; panStart = { x: ev.clientX - panX, y: ev.clientY - panY }; }
    };
    const onUp = () => { dragging = null; panning = false; };
    const saveWorkspace = () => localStorage.setItem(workspaceKey, JSON.stringify({ panX, panY,
      zoom: zoomRef.current, positions: Object.fromEntries(
        nodes.map((node) => [node.id, { x: node.x, y: node.y }])) }));
    const onClick = (ev: MouseEvent) => {
      const p = toWorld(ev), n = nodeAt(p.x, p.y);
      if (n) props.onSelect(n.id);
    };
    const onContext = (ev: MouseEvent) => {
      const p = toWorld(ev), n = nodeAt(p.x, p.y);
      if (!n) return;
      ev.preventDefault(); props.onContext(n.id, ev.clientX, ev.clientY);
    };
    // Zoom about a screen point (sx,sy), keeping the world point under it fixed.
    const zoomAt = (factor: number, sx: number, sy: number) => {
      const z = zoomRef.current, nz = Math.max(0.3, Math.min(4, z * factor));
      panX = sx - (sx - panX) * (nz / z);
      panY = sy - (sy - panY) * (nz / z);
      zoomRef.current = nz;
    };
    const onWheel = (ev: WheelEvent) => {
      const r = canvas.getBoundingClientRect();
      zoomAt(ev.deltaY < 0 ? 1.1 : 1 / 1.1, ev.clientX - r.left, ev.clientY - r.top);
      ev.preventDefault();  // zoom the graph instead of scrolling the page
    };
    const onKey = (ev: KeyboardEvent) => {  // Ctrl/Cmd +/- zooms about the centre
      if (!ev.ctrlKey && !ev.metaKey) return;
      if (ev.key === "-" || ev.key === "_") { zoomAt(1 / 1.12, W / 2, H / 2); ev.preventDefault(); }
      else if (ev.key === "=" || ev.key === "+") { zoomAt(1.12, W / 2, H / 2); ev.preventDefault(); }
    };
    canvas.addEventListener("mousemove", onMove);
    canvas.addEventListener("mousedown", onDown);
    canvas.addEventListener("click", onClick);
    canvas.addEventListener("contextmenu", onContext);
    canvas.addEventListener("wheel", onWheel, { passive: false });
    addEventListener("mouseup", onUp);
    addEventListener("keydown", onKey);
    addEventListener("beforeunload", saveWorkspace);
    return () => {
      positions.current[props.layoutMode] = new Map(
        nodes.map((n) => [n.id, { x: n.x, y: n.y }]));
      cancelAnimationFrame(raf); ro.disconnect();
      saveWorkspace();
      canvas.removeEventListener("mousemove", onMove);
      canvas.removeEventListener("mousedown", onDown);
      canvas.removeEventListener("click", onClick);
      canvas.removeEventListener("contextmenu", onContext);
      canvas.removeEventListener("wheel", onWheel);
      removeEventListener("mouseup", onUp);
      removeEventListener("keydown", onKey);
      removeEventListener("beforeunload", saveWorkspace);
    };
  }, [nodeSet, edgeSet, anchorId, hideRoot, showHidden, props.layoutMode]);

  const activity = buildActivityFeed(data);

  return (
    <div style={{ position: "relative", flex: 1, minWidth: 0 }}>
      <canvas ref={canvasRef} style={{ display: "block", width: "100%", height: "100%" }} />
      <ActivityStream items={activity} onSelect={props.onActivitySelect} />
      <div style={S.hint}>
        초록 신호 = 실행 중 · 파란 신호 = 연결됨 · 빨간 신호 = 리스너 대기 · 드래그 / 휠로 이동·확대
      </div>
    </div>
  );
}

function ActivityStream({ items, onSelect }: { items: ActivityItem[]; onSelect: (id: string) => void }) {
  const [panel, setPanel] = useState(readActivityPanel);
  const [query, setQuery] = useState("");
  const [kind, setKind] = useState<"all" | ActivityKind>("all");
  const [status, setStatusFilter] = useState<ActivityStatusFilter>("all");
  const [newestFirst, setNewestFirst] = useState(true);
  const ref = useRef<HTMLElement>(null);
  const drag = useRef<{ pointerId: number; dx: number; dy: number } | null>(null);
  const resizeDrag = useRef<{ pointerId: number; startX: number; startY: number;
    width: number; height: number; maxWidth: number; maxHeight: number } | null>(null);
  useEffect(() => {
    localStorage.setItem(ACTIVITY_PANEL_KEY, JSON.stringify(panel));
  }, [panel]);
  useEffect(() => {
    const element = ref.current, parent = element?.parentElement;
    if (!element || !parent) return;
    const keepInside = () => setPanel((current) => {
      if (current.x === undefined || current.y === undefined) return current;
      const next = clampActivityPanel(current.x, current.y, element.offsetWidth,
        element.offsetHeight, parent.clientWidth, parent.clientHeight);
      return next.x === current.x && next.y === current.y ? current : { ...current, ...next };
    });
    const observer = new ResizeObserver(keepInside);
    observer.observe(parent); keepInside();
    return () => observer.disconnect();
  }, []);
  const startDrag = (event: React.PointerEvent<HTMLElement>) => {
    const element = ref.current, parent = element?.parentElement;
    if (!element || !parent) return;
    const rect = element.getBoundingClientRect();
    drag.current = { pointerId: event.pointerId, dx: event.clientX - rect.left,
      dy: event.clientY - rect.top };
    event.currentTarget.setPointerCapture(event.pointerId);
  };
  const moveDrag = (event: React.PointerEvent<HTMLElement>) => {
    const active = drag.current, element = ref.current, parent = element?.parentElement;
    if (!active || !element || !parent) return;
    const bounds = parent.getBoundingClientRect();
    const next = clampActivityPanel(event.clientX - bounds.left - active.dx,
      event.clientY - bounds.top - active.dy, element.offsetWidth, element.offsetHeight,
      bounds.width, bounds.height);
    setPanel((current) => ({ ...current, ...next }));
  };
  const stopDrag = (event: React.PointerEvent<HTMLElement>) => {
    if (!drag.current) return;
    drag.current = null;
    event.currentTarget.releasePointerCapture(event.pointerId);
  };
  const positioned = panel.x === undefined || panel.y === undefined
    ? { right: 14, bottom: 14 } : { left: panel.x, top: panel.y };
  const visible = filterActivityFeed(items, query, kind, status);
  const ordered = newestFirst ? visible : [...visible].reverse();
  const startResize = (event: React.PointerEvent<HTMLDivElement>) => {
    const element = ref.current, parent = element?.parentElement;
    if (!element || !parent) return;
    event.stopPropagation();
    const rect = element.getBoundingClientRect(), bounds = parent.getBoundingClientRect();
    const x = rect.left - bounds.left, y = rect.top - bounds.top;
    setPanel((current) => ({ ...current, x, y }));
    resizeDrag.current = { pointerId: event.pointerId, startX: event.clientX,
      startY: event.clientY, width: rect.width, height: rect.height,
      maxWidth: bounds.width - x - 28, maxHeight: bounds.height - y - 28 };
    event.currentTarget.setPointerCapture(event.pointerId);
  };
  const moveResize = (event: React.PointerEvent<HTMLDivElement>) => {
    const active = resizeDrag.current;
    if (!active) return;
    setPanel((current) => ({ ...current,
      width: Math.max(280, Math.min(active.maxWidth,
        active.width + event.clientX - active.startX)),
      height: Math.max(160, Math.min(active.maxHeight,
        active.height + event.clientY - active.startY)) }));
  };
  const stopResize = (event: React.PointerEvent<HTMLDivElement>) => {
    if (!resizeDrag.current) return;
    resizeDrag.current = null;
    event.currentTarget.releasePointerCapture(event.pointerId);
  };
  return <section ref={ref} style={{ ...S.activityStream, ...positioned,
    minWidth: panel.collapsed ? 184 : 360,
    width: panel.collapsed ? 184 : panel.width,
    height: panel.collapsed ? 34 : panel.height,
  }} aria-label="최근 활동">
    <header style={S.activityHead} onPointerDown={startDrag} onPointerMove={moveDrag}
      onPointerUp={stopDrag} onPointerCancel={stopDrag} title="드래그하여 이동">
      <span>ACTIVITY STREAM</span>
      <span style={S.activityHeadActions}><b>{visible.length}/{items.length}</b>
        <span role="separator" aria-label="Activity Stream 크기 조절"
          title="드래그하여 크기 조절" style={S.activityResizeTop}
          onPointerDown={startResize} onPointerMove={moveResize}
          onPointerUp={stopResize} onPointerCancel={stopResize}>↘</span>
        <button type="button" aria-label={panel.collapsed ? "활동 펼치기" : "활동 접기"}
          title={panel.collapsed ? "펼치기" : "접기"}
          style={S.activityToggle}
          onPointerDown={(event) => event.stopPropagation()}
          onClick={() => setPanel((current) => ({ ...current, collapsed: !current.collapsed }))}>
          {panel.collapsed ? "□" : "—"}
        </button></span>
    </header>
    {!panel.collapsed && <>
      <div style={S.activityTools}>
        <label style={S.activitySearch}>
          <span>⌕</span><input aria-label="활동 검색" value={query}
            style={S.activitySearchInput} onChange={(event) => setQuery(event.target.value)}
            placeholder="서비스, 명령, 결과 검색" />
          {query && <button type="button" aria-label="검색 지우기" style={S.activitySearchClear}
            onClick={() => setQuery("")}>×</button>}
        </label>
        <div style={S.activityFilters} aria-label="활동 필터">
          <select aria-label="활동 유형" value={kind}
            style={S.activityControl}
            onChange={(event) => setKind(event.target.value as "all" | ActivityKind)}>
            <option value="all">모든 유형</option><option value="live">실행 중</option>
            <option value="service">서비스</option><option value="task">작업</option>
            <option value="credential">자격 증명</option><option value="finding">Finding</option>
          </select>
          <select aria-label="활동 상태" value={status}
            style={S.activityControl}
            onChange={(event) => setStatusFilter(event.target.value as ActivityStatusFilter)}>
            <option value="all">모든 상태</option><option value="running">실행 중</option>
            <option value="review">검토 대기</option><option value="failed">실패·재시도</option>
            <option value="complete">완료</option>
          </select>
          <button type="button" onClick={() => setNewestFirst((value) => !value)}
            style={S.activityControl} title="시간 정렬 전환">
            {newestFirst ? "최신순 ↓" : "오래된순 ↑"}</button>
        </div>
      </div>
      <div style={S.activityList}>
        {ordered.length ? ordered.map((item, index) =>
          <button key={`${item.nodeId}-${item.at}-${index}`} style={S.activityRow}
            onClick={() => onSelect(item.nodeId)} title="그래프에서 이 노드로 이동">
            <span style={{ ...S.activityDot, background: color(item.status) }} />
            <span style={S.activityCopy}><b>{item.text}</b>
              <small>{item.kind.toUpperCase()} · {item.reason}</small></span>
            <time style={S.activityTime}>{new Date(item.at).toLocaleTimeString("ko-KR", { hour12: false })}</time>
          </button>) : <div style={S.activityEmpty}>
            {items.length ? "검색 조건에 맞는 활동이 없습니다." : "아직 기록된 활동이 없습니다."}
          </div>}
      </div>
      <div role="separator" aria-label="Activity Stream 크기 조절" title="드래그하여 크기 조절"
        style={S.activityResize} onPointerDown={startResize} onPointerMove={moveResize}
        onPointerUp={stopResize} onPointerCancel={stopResize}>⌟</div>
    </>}
  </section>;
}

// ---------------- Outline (React DOM) ----------------

function OutlineView(props: {
  tree?: TreeNode; selected: string | null; onSelect: (id: string) => void;
}) {
  if (!props.tree) return <Empty text="Outline 불러오는 중…" />;
  return (
    <div style={S.outline}>
      <Row item={props.tree} depth={0} selected={props.selected} onSelect={props.onSelect} />
    </div>
  );
}

function Row(props: {
  item: TreeItem; depth: number; selected: string | null; onSelect: (id: string) => void;
}) {
  const { item, depth } = props;
  const [open, setOpen] = useState(depth < 2);
  if (item.kind !== "node") {
    return (
      <div style={{ ...S.row, color: "#6aa9ff", fontStyle: "italic" }}>
        <span style={{ width: 14 }} />↗ {item.kind === "cycle" ? "순환 → " : "참조 → "}
        {item.target}
      </div>
    );
  }
  const kids = item.children;
  const hasKids = kids.length > 0;
  const c = color(item.status);
  return (
    <div>
      <div style={{ ...S.row, ...(props.selected === item.id ? S.rowSel : {}) }}
        onClick={() => props.onSelect(item.id)}>
        <span style={{ width: 14, cursor: "pointer", color: "#6b6b76" }}
          onClick={(e) => { e.stopPropagation(); setOpen(!open); }}>
          {hasKids ? (open ? "▾" : "▸") : ""}
        </span>
        <span style={{ width: 18, textAlign: "center" }}>{GLYPH[item.type]}</span>
        <span style={{ flex: 1 }}>{item.label}</span>
        <span style={{ fontSize: 10, fontWeight: 700, padding: "1px 7px",
          borderRadius: 20, background: `${c}22`, color: c }}>
          {(STATUS_REASON[item.status] ?? item.status).toUpperCase()}
        </span>
      </div>
      {open && hasKids && (
        <div style={{ paddingLeft: 22, marginLeft: 10, borderLeft: "1px solid #2a2a34" }}>
          {kids.map((child, i) => (
            <Row key={child.kind === "node" ? child.id : `${child.edgeId}-${i}`}
              item={child} depth={depth + 1}
              selected={props.selected} onSelect={props.onSelect} />
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------- shared ----------------

function OnboardingPane(props: { creating: boolean; onCreate: () => void }) {
  return (
    <div style={S.embedPane}>
      <div style={{ padding: 40, maxWidth: 440 }}>
        <h2 style={{ margin: "0 0 8px", fontSize: 18 }}>여기서 시작하세요</h2>
        <p style={{ color: "#9a9aa6", fontSize: 13, lineHeight: 1.6 }}>
          아직 프로젝트가 없습니다. 프로젝트를 만들면 루트 노드가 생기고, 그 노드를 클릭해
          대상 추가 · nmap 스캔을 그래프에서 바로 진행할 수 있습니다.
        </p>
        <button onClick={props.onCreate} disabled={props.creating} style={S.openBtn}>
          {props.creating ? "만드는 중…" : "＋ 새 프로젝트 만들기"}
        </button>
      </div>
    </div>
  );
}

function TaskQueue(props: { nodes: GraphNode[]; onClose: () => void;
  onSelect: (id: string) => void; onStatus: (id: string, status: string) => void;
  onAdd: () => void; canAdd: boolean }) {
  const tasks = props.nodes.filter((node) => node.type === "technique"
    && (!node.source_ref || node.status === "attempt-failed" || node.status === "in-progress"));
  return <aside style={S.taskQueue} aria-label="작업 큐">
    <header><div><span>WORK QUEUE</span><b>{tasks.length}</b></div>
      <button onClick={props.onClose}>×</button></header>
    <button style={S.taskAdd} disabled={!props.canAdd} onClick={props.onAdd}>
      ＋ 선택 노드 아래 작업 추가</button>
    <div style={S.taskList}>{tasks.length ? tasks.map((node) =>
      <article key={node.id} style={S.taskItem}>
        <button onClick={() => props.onSelect(node.id)}><b>{node.label}</b>
          <small>{nodeStatusReason(node)}</small></button>
        <div><button onClick={() => props.onStatus(node.id, "in-progress")}>시작</button>
          <button onClick={() => props.onStatus(node.id, "succeeded")}>완료</button></div>
      </article>) : <div style={S.activityEmpty}>대기 중인 수동 작업이 없습니다.</div>}</div>
  </aside>;
}

function NodeQuickMenu(props: { node: GraphNode; x: number; y: number; onClose: () => void;
  onOpen: () => void; onAdd: () => void; onPin: () => void; onHide: () => void;
  onStatus: (status: string) => void }) {
  return <div style={S.quickMenuBackdrop} onPointerDown={props.onClose}>
    <menu style={{ ...S.quickMenu, left: Math.min(props.x, window.innerWidth - 210),
      top: Math.min(props.y, window.innerHeight - 280) }} onPointerDown={(e) => e.stopPropagation()}>
      <header><b>{props.node.label}</b><small>{nodeStatusReason(props.node)}</small></header>
      <button onClick={props.onOpen}>상세·결과 열기</button>
      <button onClick={props.onAdd}>연결 작업 추가</button>
      <button onClick={props.onPin}>{props.node.pinned ? "★ 북마크 해제" : "☆ 북마크"}</button>
      <button onClick={() => props.onStatus("in-progress")}>실행 중으로 표시</button>
      <button onClick={() => props.onStatus("succeeded")}>완료로 표시</button>
      <button onClick={props.onHide}>그래프에서 숨기기</button>
    </menu>
  </div>;
}

const ADD_TYPES: NodeType[] = ["finding", "technique", "credential", "service", "host"];
const STATUS_ORDER = ["untried", "in-progress", "attempt-failed", "succeeded",
  "blocked", "not-applicable"];
const RELATIONS = ["discovered", "enumerated", "attempted", "yielded",
  "pivoted-to", "reused-credential", "blocked-by"];
const RELATION_DEFAULT: Record<string, string> = {
  "project-root>host": "discovered", "host>service": "discovered",
  "host>finding": "enumerated", "host>technique": "attempted", "host>host": "pivoted-to",
  "service>finding": "enumerated", "service>credential": "enumerated",
  "service>technique": "attempted", "finding>technique": "attempted",
  "technique>credential": "yielded", "technique>host": "yielded",
  "technique>service": "yielded", "technique>finding": "yielded",
  "credential>host": "reused-credential", "credential>service": "reused-credential",
};
const defaultRelation = (src: string, dst: string) =>
  RELATION_DEFAULT[`${src}>${dst}`] ?? "attempted";

type AddForm = { type: string; label: string; relation: string; status: string };

export function Inspector(props: {
  node?: GraphNode; links?: DeepLink[]; busy: boolean;
  executionContext?: { targetId: number; serviceId?: number } | null;
  onOpenRequest?: (draft: GraphRequestDraft) => void;
  onToggleHidden: (id: string, hidden: boolean) => void;
  onSetStatus: (id: string, status: string) => void;
  onSetDetails?: (id: string, details: { notes?: string; pinned?: boolean }) => void;
  onAddNode: (v: AddForm & { sourceId: string }) => void;
}) {
  const n = props.node;
  // node.label is now the catalog's human-readable name (e.g. "Responder
  // 리스너"), not the template id -- template-specific panels below key off
  // the id, which only survives in meta.tool.
  const tool = n ? (nodeMeta(n).tool as string | undefined) : undefined;
  const [adding, setAdding] = useState(false);
  const [notes, setNotes] = useState(n?.notes || "");
  useEffect(() => setNotes(n?.notes || ""), [n?.id, n?.notes]);
  const source = (() => {
    if (!n?.source_ref) return null;
    try {
      const ref = JSON.parse(n.source_ref);
      return Number.isInteger(ref.id) ? { kind: ref.kind as string, id: ref.id as number } : null;
    } catch { return null; }
  })();
  const executionId = source?.kind === "execution" ? source.id : null;
  const sessionId = source?.kind === "session" ? source.id : null;
  const executionOutput = useQuery({
    queryKey: ["executionOutput", executionId],
    enabled: executionId !== null,
    queryFn: () => api<{ stdout?: string; stderr?: string; status: string;
      error?: string; exit_code?: number | null }>(`/executions/${executionId}/output`),
  });
  const targets = useQuery({
    queryKey: ["graphLinkTargets"],
    enabled: (executionId !== null || sessionId !== null) && !!props.executionContext,
    queryFn: () => api<Array<{ id: number; project_id: number; ip: string; hostname?: string }>>("/targets"),
  });
  const services = useQuery({
    queryKey: ["graphLinkServices", props.executionContext?.targetId],
    enabled: executionId !== null && !!props.executionContext?.serviceId,
    queryFn: () => api<Array<{ id: number; port: number; name: string;
      product?: string; tls?: boolean }>>(
      `/targets/${props.executionContext!.targetId}/services`),
  });
  const [evidenceState, setEvidenceState] = useState<"idle" | "saving" | "saved" | "error">("idle");
  const [revealedCapture, setRevealedCapture] = useState<string | null>(null);
  const [captureMessage, setCaptureMessage] = useState("");
  const responderCaptures = useQuery({
    queryKey: ["responderCaptures", props.executionContext?.targetId],
    enabled: sessionId !== null && tool === "responder-listener"
      && !!props.executionContext?.targetId,
    refetchInterval: 4000,
    queryFn: () => api<Array<{ label: string; username: string; value: string;
      cleartext: boolean; captured_at: string }>>(
      `/targets/${props.executionContext!.targetId}/responder-captures`),
  });
  const extractedLinks = parseLinkExtractResults(executionOutput.data?.stdout || "")
    .sort((a, b) => LINK_KIND_ORDER.indexOf(a.kind) - LINK_KIND_ORDER.indexOf(b.kind));
  const target = targets.data?.find((item) => item.id === props.executionContext?.targetId);
  const service = services.data?.find((item) => item.id === props.executionContext?.serviceId);
  const command = (() => {
    try { return JSON.parse(n?.meta || "{}").command || ""; } catch { return ""; }
  })();
  const base = target && service
    ? `${service.tls || /https|ssl/i.test(service.name) ? "https" : "http"}`
      + `://${target.hostname || target.ip}:${service.port}/`
    : "";
  const openInRequest = (url: string) => {
    if (!props.executionContext?.serviceId || !base || !target) return;
    const resolved = new URL(url, base).toString();
    localStorage.setItem("oscp-web-launch", JSON.stringify({
      targetId: props.executionContext.targetId,
      serviceId: props.executionContext.serviceId,
      url: resolved,
    }));
    props.onOpenRequest?.({ projectId: target.project_id,
      targetId: props.executionContext.targetId,
      serviceId: props.executionContext.serviceId, url: resolved });
  };
  const saveEvidence = async () => {
    if (executionId === null || !executionOutput.data?.stdout) return;
    setEvidenceState("saving");
    try {
      await api(`/executions/${executionId}/derive`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          content: executionOutput.data.stdout,
          filename: `link-extract-${executionId}.txt`,
        }),
      });
      setEvidenceState("saved");
    } catch { setEvidenceState("error"); }
  };
  const saveResponderCapture = async (capture: {
    label: string; username: string; value: string; cleartext: boolean;
  }) => {
    if (!target || !props.executionContext) return;
    setCaptureMessage("저장 중…");
    try {
      await api("/runbooks/credentials", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ project_id: target.project_id,
          target_id: props.executionContext.targetId, username: capture.username,
          secret: capture.value, secret_kind: capture.cleartext ? "password" : "hash",
          secret_hint: capture.cleartext ? "Responder 평문 캡처" : "Responder NTLMv2-SSP 캡처",
          source_kind: "responder", source_detail: capture.label, service_names: [] }),
      });
      setCaptureMessage(`${capture.username} 저장 완료`);
    } catch (reason) {
      setCaptureMessage(`저장 실패: ${reason instanceof Error ? reason.message : String(reason)}`);
    }
  };
  if (!n)
    return <aside style={S.inspector}>
      <div style={{ color: "#6b6b76", fontSize: 13 }}>노드를 선택하세요.</div>
    </aside>;
  return (
    <aside style={S.inspector}>
      <div style={S.inspectorTitle}><h3 style={{ margin: 0, fontSize: 15 }}>{n.label}</h3>
        <button title={n.pinned ? "북마크 해제" : "북마크"}
          onClick={() => props.onSetDetails?.(n.id, { pinned: !n.pinned })}>
          {n.pinned ? "★" : "☆"}</button></div>
      <div style={{ color: "#6b6b76", fontSize: 12 }}>
        {GLYPH[n.type]} {n.type}
        {n.objective && <span style={{ color: "#f5c518" }}> · 🎯 목표</span>}
        {n.hidden && <span style={{ color: "#6b6b76" }}> · 숨김</span>}
      </div>
      <div style={{ marginTop: 14 }}>
        <div style={{ color: "#9a9aa6", fontSize: 11, marginBottom: 6 }}>상태</div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
          {STATUS_ORDER.map((s) => (
            <button key={s} onClick={() => props.onSetStatus(n.id, s)} style={{
              fontSize: 11, padding: "4px 8px", borderRadius: 6, cursor: "pointer",
              border: `1px solid ${n.status === s ? color(s) : "#2a2a34"}`,
              background: n.status === s ? `${color(s)}22` : "transparent",
              color: n.status === s ? color(s) : "#9a9aa6",
            }}>{s === n.status ? nodeStatusReason(n) : STATUS_REASON[s] ?? s}</button>
          ))}
        </div>
      </div>
      <section style={S.nodeNotes}>
        <div><span>작업 메모</span><button disabled={notes === (n.notes || "")}
          onClick={() => props.onSetDetails?.(n.id, { notes })}>저장</button></div>
        <textarea value={notes} onChange={(event) => setNotes(event.target.value)}
          placeholder="확인한 내용, 실패 원인, 다음에 볼 항목을 기록하세요." />
      </section>
      {executionId !== null && <section style={S.executionResults} aria-label="실행 결과">
        <div style={S.executionResultsHead}>
          <strong>실행 결과</strong>
          <span>{EXECUTION_STATUS_LABEL[executionOutput.data?.status || ""]
            || STATUS_LABEL[n.status] || executionOutput.data?.status || n.status}
            {executionOutput.data?.exit_code == null ? "" : ` · exit ${executionOutput.data.exit_code}`}</span>
        </div>
        {(target || service) && <div style={S.executionContext}>
          {target && <div style={S.contextFact}><span>대상</span><b>{target.hostname || target.ip}</b></div>}
          {service && <div style={S.contextFact}><span>서비스</span><b>{service.port}/tcp · {service.name}
            {service.product ? ` · ${service.product}` : ""}</b></div>}
        </div>}
        {command && <code style={S.executionCommand}>{command}</code>}
        {executionOutput.isLoading ? <div style={S.resultMessage}>결과 불러오는 중…</div>
          : executionOutput.isError ? <div style={S.resultError}>실행 결과를 불러오지 못했습니다.</div>
          : <div style={S.rawOutput}>
            {executionOutput.data?.error && <div style={S.resultError}>{executionOutput.data.error}</div>}
            {executionOutput.data?.stdout && <details style={S.outputBlock}
              open={n.label !== "http-link-extract"}>
              <summary style={S.outputSummary}>표준 출력</summary>
              <pre style={S.outputPre}>{executionOutput.data.stdout}</pre>
            </details>}
            {executionOutput.data?.stderr && <details style={S.outputBlock} open>
              <summary style={S.outputSummary}>오류 출력</summary>
              <pre style={S.outputPre}>{executionOutput.data.stderr}</pre>
            </details>}
            {!executionOutput.data?.stdout && !executionOutput.data?.stderr
              && !executionOutput.data?.error && <div style={S.resultMessage}>저장된 출력이 없습니다.</div>}
          </div>}
      </section>}
      {executionId !== null && tool === "http-link-extract" && (
        <section style={S.executionResults} aria-label="링크 추출 결과">
          <div style={S.executionResultsHead}>
            <div><strong>발견된 링크</strong> <span>{extractedLinks.length}개</span></div>
            {!!extractedLinks.length && (
              <button style={S.resultAction} disabled={evidenceState === "saving"}
                onClick={() => void saveEvidence()}>
                {evidenceState === "saving" ? "저장 중…" : "Evidence로 저장"}
              </button>
            )}
          </div>
          {evidenceState === "saved" && <div style={S.resultNotice}>Evidence로 저장됨</div>}
          {evidenceState === "error" && <div style={S.resultError}>Evidence 저장 실패</div>}
          {executionOutput.isLoading ? (
            <div style={S.resultMessage}>결과 불러오는 중…</div>
          ) : executionOutput.isError ? (
            <div style={S.resultMessage}>실행 결과를 불러오지 못했습니다.</div>
          ) : extractedLinks.length ? (
            <div style={S.linkList}>
              <div style={{ ...S.linkRow, ...S.linkHeader }}>
                <span>링크</span><span>유형</span><span />
              </div>
              {extractedLinks.map((item) => (
                <div key={`${item.kind}:${item.url}`} style={S.linkRow}>
                  <code style={S.linkCode}>{item.url}</code>
                  <span style={S.linkKind}>{LINK_KIND_LABEL[item.kind] || item.kind}</span>
                  <span>{(item.kind === "page" || item.kind === "absolute") && base && (
                    <button style={S.rowAction} onClick={() => openInRequest(item.url)}>
                      Request 탭에 채우기
                    </button>
                  )}</span>
                </div>
              ))}
            </div>
          ) : (
            <div style={S.resultMessage}>이 실행에서 찾은 링크가 없습니다.</div>
          )}
        </section>
      )}
      {sessionId !== null && tool === "responder-listener" && (
        <section style={S.executionResults} aria-label="Responder 캡처 결과">
          <div style={S.executionResultsHead}>
            <div><strong>캡처된 자격증명</strong>{" "}
              <span>{responderCaptures.data?.length || 0}개</span></div>
            <span style={{ color: "#59f59a" }}>LIVE · 4s</span>
          </div>
          {captureMessage && <div style={S.resultNotice}>{captureMessage}</div>}
          {responderCaptures.isLoading ? <div style={S.resultMessage}>Responder 로그 확인 중…</div>
            : responderCaptures.isError ? <div style={S.resultError}>캡처 로그를 읽지 못했습니다.</div>
            : responderCaptures.data?.length ? <div style={S.captureList}>
              {responderCaptures.data.map((capture) => {
                const key = `${capture.label}:${capture.username}`;
                const shown = revealedCapture === key;
                return <article key={key} style={S.captureCard}>
                  <div style={S.captureHead}><b>{capture.username}</b>
                    <span>{capture.cleartext ? "CLEARTEXT" : "NETNTLMv2"}</span></div>
                  <div style={S.captureMeta}>{capture.label} · {new Date(capture.captured_at).toLocaleString()}</div>
                  <code style={S.captureValue}>{shown ? capture.value : "••••••••••••••••••••••••"}</code>
                  <div style={S.captureActions}>
                    <button onClick={() => setRevealedCapture(shown ? null : key)}>
                      {shown ? "숨기기" : "해시 보기"}</button>
                    <button onClick={() => void navigator.clipboard.writeText(capture.value)}>복사</button>
                    <button onClick={() => void saveResponderCapture(capture)}>Credential 저장</button>
                  </div>
                </article>;
              })}
            </div> : <div style={S.resultMessage}>
              아직 이 대상에서 캡처된 자격증명이 없습니다. 새 캡처는 자동으로 표시됩니다.
            </div>}
        </section>
      )}
      {props.links?.map((link) => (
        <button key={link.label} onClick={link.open} style={S.openBtn}>{link.label}</button>
      ))}
      {adding ? (
        <AddNodeForm source={n} busy={props.busy} onCancel={() => setAdding(false)}
          onSubmit={(v) => { props.onAddNode({ sourceId: n.id, ...v }); setAdding(false); }} />
      ) : (
        <button onClick={() => setAdding(true)} style={S.openBtn}>＋ 연결 노드 추가</button>
      )}
      {n.type !== "project-root" && (
        <button onClick={() => props.onToggleHidden(n.id, !n.hidden)} style={S.hideBtn}>
          {n.hidden ? "복원" : "그래프에서 숨기기"}
        </button>
      )}
    </aside>
  );
}

type GraphExchange = {
  id: number; status_code?: number | null; duration_ms: number; size: number;
  response_headers: string; error?: string;
};

export function GraphRequestPanel(props: {
  draft: GraphRequestDraft; onBack: () => void;
}) {
  const [method, setMethod] = useState("GET");
  const [url, setUrl] = useState(props.draft.url);
  const [headers, setHeaders] = useState("{}");
  const [body, setBody] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [requestId, setRequestId] = useState<number | null>(null);
  const [exchange, setExchange] = useState<GraphExchange | null>(null);
  const [responseBody, setResponseBody] = useState("");
  const [state, setState] = useState<"idle" | "saving" | "sending">("idle");
  const [error, setError] = useState("");
  const [lhost, setLhost] = useState("");
  const urlInput = useRef<HTMLInputElement>(null);
  useEffect(() => {
    let cancelled = false;
    void fetch("/api/vpn/status").then((response) => response.json()).then((data) => {
      const match = /(\d{1,3}\.){3}\d{1,3}/.exec(data.tun0 || "");
      if (match && !cancelled) setLhost(match[0]);
    }).catch(() => undefined);
    return () => { cancelled = true; };
  }, []);
  const insertResponderIp = () => {
    if (!lhost) return;
    const snippet = `\\\\${lhost}\\test`;
    const pageParam = /([?&]page=)([^&]*)/.exec(url);
    if (pageParam) {
      const start = pageParam.index + pageParam[1].length;
      setUrl(url.slice(0, start) + snippet + url.slice(start + pageParam[2].length));
      return;
    }
    const start = urlInput.current?.selectionStart ?? url.length;
    const end = urlInput.current?.selectionEnd ?? url.length;
    setUrl(url.slice(0, start) + snippet + url.slice(end));
    requestAnimationFrame(() => {
      const cursor = start + snippet.length;
      urlInput.current?.focus();
      urlInput.current?.setSelectionRange(cursor, cursor);
    });
  };

  const requestPayload = () => ({
    project_id: props.draft.projectId, target_id: props.draft.targetId,
    service_id: props.draft.serviceId, name: `${method} ${new URL(url).pathname || "/"}`,
    folder: "Graph", tags: ["graph"], method, url, query: {},
    headers: JSON.parse(headers || "{}"), cookies: {}, body, body_mode: "raw",
    tls_verify: true, proxy: "", timeout: 30, follow_redirects: false,
  });
  const save = async (): Promise<number | null> => {
    setState("saving"); setError("");
    try {
      const saved = await api<{ id: number }>(
        requestId ? `/web/requests/${requestId}` : "/web/requests",
        { method: requestId ? "PUT" : "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(requestPayload()) },
      );
      setRequestId(saved.id); setState("idle");
      return saved.id;
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
      setState("idle"); return null;
    }
  };
  const send = async () => {
    if (!confirmed) { setError("허가된 실습 대상을 확인해 주세요."); return; }
    const id = requestId || await save();
    if (!id) return;
    setState("sending"); setError(""); setExchange(null); setResponseBody("");
    try {
      const rows = await api<GraphExchange[]>(`/web/requests/${id}/send`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ variables: {}, repeat: 1, confirmed: true }),
      });
      const result = rows.at(-1) || null;
      setExchange(result);
      if (result && !result.error) {
        const response = await fetch(`/api/web/exchanges/${result.id}/body`);
        setResponseBody(await response.text());
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally { setState("idle"); }
  };
  let responseHeaders = "";
  if (exchange?.response_headers) {
    try { responseHeaders = JSON.stringify(JSON.parse(exchange.response_headers), null, 2); }
    catch { responseHeaders = exchange.response_headers; }
  }

  return <section style={S.requestPanel} aria-label="Graph Web Request">
    <div style={S.requestPanelHead}>
      <div><small style={S.requestEyebrow}>WEB REQUEST</small>
        <h3 style={{ margin: "4px 0 0" }}>그래프에서 요청 검사</h3></div>
      <button style={S.requestBack} onClick={props.onBack}>← 실행 결과</button>
    </div>
    <div style={S.requestLine}>
      <select value={method} onChange={(e) => setMethod(e.target.value)} style={S.requestMethod}>
        {["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
          .map((item) => <option key={item}>{item}</option>)}
      </select>
      <input ref={urlInput} aria-label="Request URL" value={url} onChange={(e) => setUrl(e.target.value)}
        style={S.requestUrl} />
      <button style={S.responderInsert} disabled={!lhost} onClick={insertResponderIp}
        title="URL 커서 위치 또는 page 파라미터에 UNC 경로 삽입">
        {lhost ? `RESPONDER IP · ${lhost}` : "TUN0 확인 중"}
      </button>
      <button style={S.requestSend} disabled={state !== "idle"}
        onClick={() => void send()}>{state === "sending" ? "전송 중" : "SEND"}</button>
    </div>
    <div style={S.requestGrid}>
      <label style={S.requestField}><span>HEADERS · JSON</span>
        <textarea value={headers} onChange={(e) => setHeaders(e.target.value)} rows={7} /></label>
      <label style={S.requestField}><span>BODY</span>
        <textarea value={body} onChange={(e) => setBody(e.target.value)} rows={7} /></label>
    </div>
    <div style={S.requestActions}>
      <label><input type="checkbox" checked={confirmed}
        onChange={(e) => setConfirmed(e.target.checked)} /> 허가된 실습 대상임을 확인</label>
      <span style={{ flex: 1 }} />
      {requestId && <span style={S.requestSaved}>SAVED #{requestId}</span>}
      <button style={S.resultAction} disabled={state !== "idle"}
        onClick={() => void save()}>{state === "saving" ? "저장 중…" : "요청 저장"}</button>
    </div>
    {error && <div style={S.resultError}>{error}</div>}
    <div style={S.responsePanel}>
      <div style={S.responseHead}>
        <span>RESPONSE</span>
        {exchange && <b>{exchange.error ? "ERROR" : `HTTP ${exchange.status_code ?? "—"}`}
          <small>{exchange.duration_ms}ms · {exchange.size} bytes</small></b>}
      </div>
      {exchange?.error ? <div style={S.resultError}>{exchange.error}</div>
        : exchange ? <>
          {responseHeaders && <details><summary>응답 헤더</summary>
            <pre style={S.responsePre}>{responseHeaders}</pre></details>}
          <pre style={S.responsePre}>{responseBody || "(빈 응답)"}</pre>
        </> : <div style={S.requestEmpty}>요청을 전송하면 응답이 여기에 표시됩니다.</div>}
    </div>
  </section>;
}

function AddNodeForm(props: {
  source: GraphNode; busy: boolean;
  onCancel: () => void; onSubmit: (v: AddForm) => void;
}) {
  const [type, setType] = useState<string>("finding");
  const [label, setLabel] = useState("");
  const [status, setStatus] = useState("untried");
  const [relation, setRelation] = useState(() =>
    defaultRelation(props.source.type, "finding"));
  return (
    <div style={{ marginTop: 14, padding: 12, border: "1px solid #2a2a34",
      borderRadius: 8, background: "#12121a" }}>
      <div style={{ fontSize: 11, color: "#9a9aa6", marginBottom: 8 }}>
        「{props.source.label}」 아래에 노드 추가
      </div>
      <input placeholder="라벨 (예: Administrator NTLMv2 해시)" value={label}
        onChange={(e) => setLabel(e.target.value)} style={S.field} />
      <div style={{ display: "flex", gap: 6, marginTop: 8 }}>
        <select value={type} style={{ ...S.field, flex: 1 }}
          onChange={(e) => { setType(e.target.value);
            setRelation(defaultRelation(props.source.type, e.target.value)); }}>
          {ADD_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <select value={relation} onChange={(e) => setRelation(e.target.value)}
          style={{ ...S.field, flex: 1 }}>
          {RELATIONS.map((r) => <option key={r} value={r}>{r}</option>)}
        </select>
      </div>
      <select value={status} onChange={(e) => setStatus(e.target.value)}
        style={{ ...S.field, marginTop: 8, width: "100%" }}>
        {STATUS_ORDER.map((s) => <option key={s} value={s}>{STATUS_LABEL[s] ?? s}</option>)}
      </select>
      <div style={{ display: "flex", gap: 6, marginTop: 10 }}>
        <button disabled={!label.trim() || props.busy}
          style={{ ...S.openBtn, marginTop: 0, flex: 1, opacity: label.trim() ? 1 : 0.5 }}
          onClick={() => props.onSubmit({ type, label: label.trim(), relation, status })}>
          {props.busy ? "추가 중…" : "추가"}
        </button>
        <button style={{ ...S.hideBtn, marginTop: 0, width: "auto", padding: "8px 14px" }}
          onClick={props.onCancel}>취소</button>
      </div>
    </div>
  );
}

function Tab(props: { on: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <div onClick={props.onClick} style={{
      padding: "6px 14px", borderRadius: 7, cursor: "pointer", fontWeight: 500,
      color: props.on ? "#e7e7ee" : "#9a9aa6",
      background: props.on ? "#1c1c24" : "transparent",
    }}>{props.children}</div>
  );
}

function Empty(props: { text: string }) {
  return <div style={{ padding: 40, color: "#9a9aa6" }}>{props.text}</div>;
}

const S: Record<string, React.CSSProperties> = {
  wrap: { display: "flex", flexDirection: "column", height: "100%", minHeight: 0,
    background: "#0e0e12", color: "#e7e7ee" },
  bar: { display: "flex", alignItems: "center", gap: 16, padding: "10px 16px",
    borderBottom: "1px solid #2a2a34" },
  graphTools: { display: "flex", alignItems: "center", gap: 7, padding: "7px 16px",
    borderBottom: "1px solid #24242d", background: "#111117", overflowX: "auto" },
  graphSearch: { flex: "1 1 240px", minWidth: 180, display: "flex", alignItems: "center",
    gap: 7, height: 32, padding: "0 9px", border: "1px solid #30303a", background: "#0b0b10" },
  graphSearchInput: { flex: 1, minWidth: 0, border: 0, outline: 0, background: "transparent",
    color: "#dce5e0", fontSize: 11 },
  graphControl: { height: 32, padding: "0 9px", border: "1px solid #30303a",
    background: "#17171e", color: "#a6aaa8", fontSize: 10, whiteSpace: "nowrap" },
  filterCount: { marginLeft: "auto", color: "#758079", font: "10px ui-monospace,monospace",
    whiteSpace: "nowrap" },
  toolActive: { borderColor: "#537a5e", color: "#71dfa0", background: "#132018" },
  tabs: { display: "flex", flexShrink: 0, gap: 4, background: "#16161c", padding: 4,
    borderRadius: 10, border: "1px solid #2a2a34" },
  legend: { marginLeft: "auto", minWidth: 0, overflowX: "auto", display: "flex",
    flexWrap: "nowrap", gap: 12, color: "#9a9aa6", fontSize: 12 },
  stage: { flex: 1, display: "flex", minHeight: 0 },
  hint: { position: "absolute", left: 16, bottom: 14, color: "#6b6b76", fontSize: 12,
    pointerEvents: "none" },
  activityStream: { position: "absolute", minWidth: 184, minHeight: 34,
    display: "flex", flexDirection: "column", overflow: "hidden",
    border: "1px solid rgba(89,245,154,.22)",
    background: "rgba(8,12,11,.94)", backdropFilter: "blur(8px)", color: "#d8e2dd" },
  activityHead: { flex: "0 0 auto", zIndex: 1, display: "flex",
    justifyContent: "space-between", padding: "8px 10px", borderBottom: "1px solid #223029",
    background: "rgba(8,12,11,.96)", color: "#59f59a", cursor: "move",
    touchAction: "none", userSelect: "none",
    font: "600 9px ui-monospace,monospace", letterSpacing: 1 },
  activityHeadActions: { display: "flex", alignItems: "center", gap: 8 },
  activityToggle: { width: 22, height: 20, padding: 0, border: "1px solid #294036",
    background: "#101a15", color: "#75d99c", cursor: "pointer",
    font: "600 10px ui-monospace,monospace" },
  activityTools: { flex: "0 0 auto", padding: "10px", borderBottom: "1px solid #223029",
    background: "#0b100e" },
  activitySearch: { height: 34, display: "flex", alignItems: "center", gap: 7,
    padding: "0 9px", border: "1px solid #314139", background: "#060a08", color: "#6f8379" },
  activitySearchInput: { flex: 1, minWidth: 0, padding: 0, border: 0, outline: 0,
    background: "transparent", color: "#e0e8e4", fontSize: 11 },
  activitySearchClear: { width: 22, height: 22, padding: 0, border: 0,
    background: "transparent", color: "#84938b", cursor: "pointer", fontSize: 15 },
  activityFilters: { display: "grid", gridTemplateColumns: "1fr 1fr auto", gap: 6, marginTop: 8 },
  activityControl: { minWidth: 0, height: 30, padding: "0 8px", border: "1px solid #314139",
    background: "#0c1410", color: "#aebdb5", cursor: "pointer", fontSize: 10 },
  activityList: { flex: 1, minHeight: 0, overflow: "auto", paddingBottom: 14 },
  activityRow: { width: "100%", display: "grid",
    gridTemplateColumns: "8px minmax(0,1fr) auto", alignItems: "start",
    gap: 9, padding: "10px", border: 0, borderBottom: "1px solid rgba(255,255,255,.055)",
    background: "transparent", color: "#d2ddd7", textAlign: "left", cursor: "pointer",
    font: "12px/1.45 ui-monospace,monospace" },
  activityDot: { width: 7, height: 7, marginTop: 4, borderRadius: "50%" },
  activityCopy: { display: "grid", gap: 4, minWidth: 0 },
  activityTime: { color: "#829087", fontSize: 10, fontVariantNumeric: "tabular-nums" },
  activityEmpty: { padding: 20, color: "#75837c", fontSize: 11, textAlign: "center" },
  activityResize: { position: "absolute", right: 1, bottom: 1, zIndex: 3,
    width: 22, height: 22, display: "grid", placeItems: "center", color: "#68d594",
    background: "#101a15", borderLeft: "1px solid #31533f", borderTop: "1px solid #31533f",
    cursor: "nwse-resize", touchAction: "none", userSelect: "none", fontSize: 14 },
  activityResizeTop: { width: 22, height: 20, display: "grid", placeItems: "center",
    border: "1px solid #294036", background: "#101a15", color: "#75d99c",
    cursor: "nwse-resize", touchAction: "none", fontSize: 11 },
  inspectorTitle: { display: "flex", alignItems: "center", justifyContent: "space-between",
    gap: 10 },
  nodeNotes: { display: "grid", gap: 7, marginTop: 14, padding: 10,
    border: "1px solid #2a2a34", background: "#111117" },
  taskQueue: { position: "fixed", zIndex: 55, right: 24, top: 150, width: 360,
    maxHeight: "calc(100vh - 180px)", overflow: "auto", border: "1px solid #31513e",
    background: "#0b100e", color: "#d8e2dd", boxShadow: "0 18px 50px rgba(0,0,0,.45)" },
  taskAdd: { width: "calc(100% - 20px)", margin: 10, padding: 9,
    border: "1px solid #365743", background: "#14241a", color: "#74dfa0" },
  taskList: { borderTop: "1px solid #26352d" },
  taskItem: { display: "grid", gridTemplateColumns: "1fr auto", gap: 8, padding: 9,
    borderBottom: "1px solid #222e28" },
  quickMenuBackdrop: { position: "fixed", inset: 0, zIndex: 80 },
  quickMenu: { position: "fixed", width: 200, margin: 0, padding: 6,
    border: "1px solid #35453d", background: "#101512", color: "#d8e2dd",
    boxShadow: "0 14px 40px rgba(0,0,0,.55)" },
  outline: { flex: 1, overflow: "auto", padding: 18 },
  row: { display: "flex", alignItems: "center", gap: 8, padding: "5px 8px",
    borderRadius: 7, cursor: "pointer" },
  rowSel: { background: "rgba(106,169,255,.12)",
    boxShadow: "inset 0 0 0 1px rgba(106,169,255,.25)" },
  inspector: { flex: 1, minWidth: 0, background: "#16161c",
    padding: 16, overflow: "auto" },
  executionResults: { marginTop: 18, border: "1px solid #2a2a34",
    borderRadius: 8, overflow: "hidden", background: "#101016" },
  executionResultsHead: { display: "flex", alignItems: "center", gap: 8,
    justifyContent: "space-between", padding: "10px 12px",
    borderBottom: "1px solid #2a2a34", fontSize: 12 },
  resultAction: { border: "1px solid #454552", borderRadius: 6, padding: "5px 8px",
    background: "#22222b", color: "#e7e7ee", fontSize: 10 },
  resultNotice: { padding: "8px 12px", color: "#8ed1a9", fontSize: 10,
    borderBottom: "1px solid #2a2a34" },
  resultError: { padding: "8px 12px", color: "#e3938c", fontSize: 10,
    borderBottom: "1px solid #2a2a34" },
  executionContext: { display: "grid", gridTemplateColumns: "1fr 1.5fr",
    gap: 1, background: "#2a2a34", borderBottom: "1px solid #2a2a34" },
  contextFact: { display: "grid", gap: 4, minWidth: 0, padding: "10px 12px",
    background: "#121219", fontSize: 10 },
  executionCommand: { display: "block", margin: 10, padding: 10, overflow: "auto",
    border: "1px solid #2a2a34", background: "#08080d", color: "#b9d8ca",
    fontSize: 10, whiteSpace: "pre-wrap", overflowWrap: "anywhere" },
  rawOutput: { borderTop: "1px solid #2a2a34" },
  outputBlock: { borderBottom: "1px solid #2a2a34" },
  outputSummary: { padding: "9px 12px", color: "#9a9aa6", fontSize: 10,
    cursor: "pointer" },
  outputPre: { maxHeight: 320, overflow: "auto", margin: 0, padding: 12,
    background: "#08080d", color: "#c8ded4", font: "10px/1.55 ui-monospace,monospace",
    whiteSpace: "pre-wrap", overflowWrap: "anywhere" },
  resultMessage: { padding: 12, color: "#9a9aa6", fontSize: 11 },
  linkList: { maxHeight: 420, overflow: "auto" },
  linkRow: { display: "grid", gridTemplateColumns: "minmax(0, 1fr) 80px auto",
    alignItems: "center", gap: 10, padding: "9px 12px",
    borderBottom: "1px solid #22222b" },
  linkHeader: { position: "sticky", top: 0, zIndex: 1, background: "#15151c",
    color: "#9a9aa6", fontSize: 10 },
  linkCode: { minWidth: 0, overflowWrap: "anywhere", color: "#d7dedb", fontSize: 11 },
  linkKind: { color: "#9a9aa6", fontSize: 10, whiteSpace: "nowrap" },
  rowAction: { border: "1px solid #454552", borderRadius: 5, padding: "4px 7px",
    background: "#22222b", color: "#e7e7ee", fontSize: 9, whiteSpace: "nowrap" },
  captureList: { display: "grid", gap: 8, padding: 10 },
  captureCard: { padding: 11, border: "1px solid #2d493a", borderRadius: 6,
    background: "#0b120e" },
  captureHead: { display: "flex", justifyContent: "space-between", gap: 8,
    color: "#dce8e1", fontSize: 11 },
  captureMeta: { marginTop: 4, color: "#72847a", fontSize: 9 },
  captureValue: { display: "block", marginTop: 10, padding: 9, maxHeight: 120,
    overflow: "auto", overflowWrap: "anywhere", whiteSpace: "pre-wrap",
    border: "1px solid #24352c", background: "#060a08", color: "#67e89b",
    font: "9px/1.45 ui-monospace,monospace" },
  captureActions: { display: "flex", flexWrap: "wrap", gap: 6, marginTop: 8 },
  requestPanel: { flex: 1, minWidth: 0, overflow: "auto", padding: 18,
    background: "#101317", color: "#dce8e1" },
  requestPanelHead: { display: "flex", justifyContent: "space-between",
    alignItems: "center", paddingBottom: 16, borderBottom: "1px solid #29332e" },
  requestEyebrow: { color: "#59f59a", font: "9px ui-monospace,monospace",
    letterSpacing: 2 },
  requestBack: { border: 0, background: "transparent", color: "#8fa099",
    cursor: "pointer", fontSize: 11 },
  requestLine: { display: "flex", gap: 0, marginTop: 18,
    border: "1px solid #365345", background: "#090d0b" },
  requestMethod: { width: 92, border: 0, borderRight: "1px solid #365345",
    background: "#132219", color: "#59f59a", padding: "11px 10px",
    font: "600 11px ui-monospace,monospace" },
  requestUrl: { minWidth: 0, flex: 1, border: 0, outline: 0, padding: "11px 12px",
    background: "transparent", color: "#dce8e1", font: "11px ui-monospace,monospace" },
  requestSend: { width: 76, border: 0, borderLeft: "1px solid #365345",
    background: "#173824", color: "#72f7a8", cursor: "pointer",
    font: "700 10px ui-monospace,monospace", letterSpacing: 1 },
  responderInsert: { maxWidth: 190, border: 0, borderLeft: "1px solid #61303a",
    padding: "0 12px", background: "#281118", color: "#ff7188", cursor: "pointer",
    font: "600 9px ui-monospace,monospace", whiteSpace: "nowrap" },
  requestGrid: { display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(220px,1fr))",
    gap: 10, marginTop: 12 },
  requestField: { display: "grid", gap: 6, color: "#789086",
    font: "9px ui-monospace,monospace", letterSpacing: 1 },
  requestActions: { display: "flex", alignItems: "center", flexWrap: "wrap",
    gap: 10, marginTop: 12, color: "#8fa099", fontSize: 10 },
  requestSaved: { color: "#59f59a", font: "9px ui-monospace,monospace" },
  responsePanel: { marginTop: 18, border: "1px solid #29332e", background: "#090d0b" },
  responseHead: { display: "flex", justifyContent: "space-between", padding: "10px 12px",
    borderBottom: "1px solid #29332e", color: "#59f59a",
    font: "9px ui-monospace,monospace" },
  responsePre: { maxHeight: 360, overflow: "auto", margin: 0, padding: 12,
    color: "#bcd0c5", whiteSpace: "pre-wrap", overflowWrap: "anywhere",
    font: "10px/1.55 ui-monospace,monospace" },
  requestEmpty: { padding: 32, textAlign: "center", color: "#617069", fontSize: 11 },
  embedPane: { flex: 1, minWidth: 0, overflow: "auto", minHeight: 0,
    background: "#0e0e12" },
  splitter: { width: 6, flexShrink: 0, cursor: "col-resize", background: "#2a2a34",
    borderLeft: "1px solid #0e0e12", borderRight: "1px solid #0e0e12",
    touchAction: "none" },
  openBtn: { marginTop: 18, width: "100%", padding: "9px 12px", borderRadius: 8,
    border: "1px solid #6aa9ff55", background: "#6aa9ff14", color: "#6aa9ff",
    fontWeight: 600, cursor: "pointer" },
  hideBtn: { marginTop: 10, width: "100%", padding: "8px 12px", borderRadius: 8,
    border: "1px solid #2a2a34", background: "transparent", color: "#9a9aa6",
    fontWeight: 500, cursor: "pointer" },
  hiddenChip: { padding: "5px 12px", borderRadius: 8, border: "1px solid #2a2a34",
    background: "#16161c", color: "#9a9aa6", fontSize: 12, fontWeight: 600,
    cursor: "pointer" },
  field: { width: "100%", padding: "8px 10px", borderRadius: 6,
    border: "1px solid #2a2a34", background: "#0e0e12", color: "#e7e7ee",
    fontSize: 13 },
  overlay: { position: "fixed", inset: 0, zIndex: 60, background: "rgba(0,0,0,.45)",
    display: "flex", alignItems: "flex-start", justifyContent: "center",
    paddingTop: 90 },
};
