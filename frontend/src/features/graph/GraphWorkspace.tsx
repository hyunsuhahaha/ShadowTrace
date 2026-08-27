import { lazy, Suspense, useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../api";
import type { FileDragPayload } from "../../fileTree";
import { parseLinkExtractResults } from "../../serviceIntel";
import { setPendingServiceNav } from "../../pendingServiceNav";
import { consumePendingGraphFocus } from "../../pendingGraphFocus";
import { S } from "./graphStyles";
import { OutlineView } from "./OutlineView";
import { AddNodeForm, BlankCanvasQuickMenu, DeleteNodeDialog, ElapsedTimer, Empty, NodeQuickMenu,
  OnboardingPane, Tab, TaskQueue } from "./graphLeaves";
import { Inspector } from "./Inspector";
import { GraphRequestPanel } from "./GraphRequestPanel";
import { GraphCanvas } from "./GraphCanvas";
import GraphTimeMachine, {graphAt, type GraphTimelineEvent} from "./GraphTimeMachine";
import ProjectOperatorSession from "./ProjectOperatorSession";
import { ActivityItem, ActivityKind, ActivityPanelState, ActivityStatusFilter,
  ACTIVITY_PANEL_KEY, AddForm, ADD_TYPES, buildActivityFeed, clampActivityPanel,
  color, CredentialHandoff, DeepLink, defaultActivityPanel, defaultRelation,
  EXECUTION_STATUS_LABEL, filterActivityFeed, filterGraph, getNodeActivity,
  GLYPH, GraphEdge, GraphFilter, GraphNode, GraphOut, GraphPosition,
  GraphRequestDraft, initialGraphPosition, initialGraphPositionNearParent,
  isCrackableCredential, LINK_KIND_LABEL, LINK_KIND_ORDER, NodeActivity, nodeMeta, NodeType,
  nodeStatusReason, nodeSummary, pathToObjective, readActivityPanel, RELATIONS, Sim, STATUS_COLOR,
  STATUS_LABEL, STATUS_ORDER, STATUS_REASON, TreeItem, TreeNode, TreeRef,
  useActiveProjectId } from "./graphModel";

// Existing workspaces embedded (their own chrome hidden) so the graph is the
// primary interface: service node -> Enumeration, root node -> Scan Center.
const EmbeddedEnumeration = lazy(() => import("../../App"));
const EmbeddedScanCenter = lazy(() => import("../../ScanCenter"));
const EmbeddedHashCracking = lazy(() => import("../../HashCrackingWorkspace"));
const EmbeddedPostExploitation = lazy(() => import("../../PostExploitationWorkspace"));
const EmbeddedReports = lazy(() => import("../../ReportWorkspace"));

type AutoReconRun = { status: string; target_ids: string };

// Vertical slice: nmap-derived host/service nodes -> API -> Graph + Outline.
// Graph renders on Canvas 2D (renderer boundary from spec 3.4; the Pixi/WebGL
// swap is M4 and isolated to <GraphCanvas>). No new dependencies in this slice.


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
  // Ctrl/Cmd+click toggles membership here, separate from `selected` (the
  // Inspector's single focus) -- only an explicit toggle or the bulk bar's
  // own "선택 해제" clears it, so a stray plain click elsewhere never
  // silently throws away a selection mid-bulk-action.
  const [multiSelected, setMultiSelected] = useState<Set<string>>(new Set());
  const toggleMultiSelect = (id: string) => setMultiSelected((current) => {
    const next = new Set(current);
    if (next.has(id)) next.delete(id); else next.add(id);
    return next;
  });
  const [filter, setFilter] = useState<GraphFilter>({ query: "", type: "all",
    status: "all", focusDepth: 0, pinnedOnly: false });
  const [queueOpen, setQueueOpen] = useState(false);
  const [contextMenu, setContextMenu] = useState<
    { id: string | null; x: number; y: number } | null>(null);
  const [deleteCandidates, setDeleteCandidates] = useState<GraphNode[]>([]);
  const [showHidden, setShowHidden] = useState(false);
  const [credentialOverlay, setCredentialOverlay] = useState(true);
  const [pathHighlight, setPathHighlight] = useState(false);
  const [replayAt, setReplayAt] = useState<number | null>(null);
  const [focus, setFocus] = useState<{ id: string; nonce: number } | null>(null);
  const [addOpen, setAddOpen] = useState(false);
  const [webRequest, setWebRequest] = useState<GraphRequestDraft | null>(null);
  const [hashPanel, setHashPanel] = useState<CredentialHandoff | null>(null);
  const [postPanel, setPostPanel] = useState<CredentialHandoff | null>(null);
  const [fileTreePanel, setFileTreePanel] = useState<{ targetId: number } | null>(null);
  const [reportPanel, setReportPanel] = useState(false);
  const [dropFileError, setDropFileError] = useState("");
  const [dropFileBusy, setDropFileBusy] = useState(false);
  useEffect(() => {
    setWebRequest(null);
    setHashPanel(null);
    setPostPanel(null);
    setFileTreePanel(null);
    setReportPanel(false);
  }, [selected]);
  const [paneWidth, setPaneWidth] = useState(() => {
    const saved = Number(localStorage.getItem("oscp-graph-pane"));
    return saved >= 320 ? saved : 640;
  });
  const stageRef = useRef<HTMLDivElement>(null);
  const clampPaneWidth = (width: number) => {
    const sidebarWidth = document.querySelector(".appSidebar")
      ?.getBoundingClientRect().width || 0;
    const stageWidth = stageRef.current?.getBoundingClientRect().width
      || window.innerWidth - sidebarWidth;
    return Math.max(320, Math.min(width, stageWidth - 426));
  };
  useEffect(() => {
    localStorage.setItem("oscp-graph-pane", String(paneWidth));
  }, [paneWidth]);
  useEffect(() => {
    const resize = () => setPaneWidth((width) => clampPaneWidth(width));
    const observer = new ResizeObserver(resize);
    if (stageRef.current) observer.observe(stageRef.current);
    addEventListener("resize", resize);
    resize();
    return () => { observer.disconnect(); removeEventListener("resize", resize); };
  }, []);
  useEffect(() => {
    if (!projectId) { setReplayAt(null); return; }
    const saved = Number(localStorage.getItem(`oscp-graph-replay:${projectId}`));
    setReplayAt(saved > 0 ? saved : null);
  }, [projectId]);
  const changeReplay = (value: number | null) => {
    setReplayAt(value);
    if (!projectId) return;
    const key = `oscp-graph-replay:${projectId}`;
    if (value == null) localStorage.removeItem(key);
    else localStorage.setItem(key, String(value));
    setContextMenu(null);
    setAddOpen(false);
  };
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
    setPaneWidth(clampPaneWidth(dragRef.current.startWidth + delta));
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
    queryClient.invalidateQueries({ queryKey: ["graphTimeline", projectId] });
  };
  useQuery({
    queryKey: ["responderCaptureSync", projectId],
    enabled: !!projectId && replayAt == null,
    refetchInterval: 4000,
    queryFn: async () => {
      const result = await api<{ created: number }>(
        `/projects/${projectId}/responder-captures/sync`, { method: "POST" });
      if (result.created) invalidateGraph();
      return result;
    },
  });
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
    mutationFn: (v: { id: string; notes?: string; pinned?: boolean; label?: string }) =>
      api(`/graph/nodes/${v.id}`, { method: "PATCH",
        headers: { "Content-Type": "application/json" }, body: JSON.stringify(v) }),
    onSuccess: invalidateGraph,
  });
  const deleteNode = useMutation({
    mutationFn: (ids: string[]) => Promise.all(
      ids.map((id) => api(`/graph/nodes/${id}`, { method: "DELETE" }))),
    onSuccess: (_data, ids) => {
      if (selected && ids.includes(selected)) setSelected(null);
      setDeleteCandidates([]);
      setMultiSelected(new Set());
      invalidateGraph();
    },
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

  // A memo is a freestanding sticky note, not a domain finding/technique/etc
  // -- no edge to a source node the way addNode's other types always get one
  // (see graph_service.create_node's own "manually-created nodes (no
  // source_ref) are never pruned" -- the same protection applies here with
  // no edge either).
  const addMemo = useMutation({
    mutationFn: () => api<{ id: string }>(`/projects/${projectId}/graph/nodes`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: "memo", label: "새 메모", status: "untried" }),
    }),
    onSuccess: (node) => { invalidateGraph(); setSelected(node.id); },
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
      query.state.data?.nodes.some((node) => getNodeActivity(node)) ? 2000 : 4000,
  });
  const tree = useQuery({
    queryKey: ["graphTree", projectId, graph.dataUpdatedAt],
    enabled: !!projectId && graph.isSuccess,
    queryFn: () => api<TreeNode>(`/projects/${projectId}/graph/tree`),
  });
  const timeline = useQuery({
    queryKey: ["graphTimeline", projectId, graph.dataUpdatedAt],
    enabled: !!projectId && graph.isSuccess,
    queryFn: () => api<GraphTimelineEvent[]>(`/projects/${projectId}/graph/timeline`),
  });
  const autoReconRuns = useQuery({
    queryKey: ["autoReconRuns", projectId],
    enabled: !!projectId && replayAt == null,
    queryFn: () => api<AutoReconRun[]>(`/autorecon?project_id=${projectId}`),
    refetchInterval: 2000,
  });
  const autoReconTargetIds = useMemo(() => {
    const ids = new Set<number>();
    autoReconRuns.data?.filter((run) => run.status === "queued" || run.status === "running")
      .forEach((run) => {
        try { (JSON.parse(run.target_ids || "[]") as number[]).forEach((id) => ids.add(id)); }
        catch { /* malformed persisted run -- no target effect */ }
      });
    return [...ids];
  }, [autoReconRuns.data]);

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
      if (capture) {
        const host = nodeById.get(capture.target);
        if (!host?.source_ref) return null;
        try {
          const ref = JSON.parse(host.source_ref);
          return ref.kind === "target" ? { targetId: ref.id } : null;
        } catch { return null; }
      }
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
      if (ref.kind === "target") return { targetId: ref.id };
    } catch { return null; }
    // A session opened from a finding (e.g. "익명으로 접속하기") is parented
    // one level deeper than the usual host/service -- walk up once more to
    // whatever enumerated/yielded that finding, same as the host/service
    // case above.
    if (parent.type !== "finding") return null;
    const findingEdge = graph.data?.edges.find((item) => item.target === parent.id);
    if (!findingEdge) return null;
    const findingService = serviceHandoff(findingEdge.source);
    if (findingService) return findingService;
    const grandparent = nodeById.get(findingEdge.source);
    if (!grandparent?.source_ref) return null;
    try {
      const gref = JSON.parse(grandparent.source_ref);
      return gref.kind === "target" ? { targetId: gref.id } : null;
    } catch { return null; }
  };

  // Scope the embedded Enumeration workspace to the selected service node.
  const selectedType = selected ? nodeById.get(selected)?.type : undefined;
  useEffect(() => {
    const h = serviceHandoff(selected);
    if (h && projectId) {
      setPendingServiceNav({...h, projectId});
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

  // Same effect as each list's own "노드로 추가"/"그래프에 남기기" button --
  // dragging onto the canvas is just an alternative trigger for it, not a
  // second code path (the graph's force-directed layout has no meaningful
  // "drop position" to honor, see GraphCanvas's own comment on this).
  const dropFile = async (payload: FileDragPayload) => {
    setDropFileError("");
    setDropFileBusy(true);
    try {
      if (payload.kind === "post-exploitation") {
        // promote-file re-reads the file over the run's live connection
        // (WinRM/SSH), which routinely takes several seconds -- graph_node_id
        // is the technique node the tree was opened from (i.e. whatever's
        // selected right now, since that's what's rendering the tree the
        // drag came out of), so the finding attaches there instead of the
        // bare host sync()'s own projection would otherwise fall back to.
        await api(`/post-exploitation/${payload.runId}/promote-file`, {
          method: "POST", headers: {"Content-Type": "application/json"},
          body: JSON.stringify({path: payload.path, graph_node_id: selected}),
        });
      } else if (payload.kind === "autorecon-result") {
        await api(`/autorecon/results/${payload.jobId}/promote`, {
          method: "POST", headers: {"Content-Type": "application/json"},
          body: JSON.stringify({path: payload.path, graph_node_id: payload.graphNodeId}),
        });
      } else if (payload.kind === "archive") {
        await api(`/evidence/${payload.evidenceId}/extract`, {
          method: "POST", headers: {"Content-Type": "application/json"},
          body: JSON.stringify({entry: payload.entry}),
        });
      } else if (payload.kind === "ftp-tree") {
        // Reconnects over FTP itself (same as the click-to-promote path) --
        // the dragged file may never have been `get`-ed into the session's
        // own cwd, so there's nothing local to read the way promote-download
        // reads back an operator-typed `get`.
        await api(`/executions/${payload.executionId}/promote-ftp-file`, {
          method: "POST", headers: {"Content-Type": "application/json"},
          body: JSON.stringify({path: payload.path, graph_node_id: payload.graphNodeId}),
        });
      } else {
        await api(`/interactive-sessions/${payload.sessionId}/promote-download`, {
          method: "POST", headers: {"Content-Type": "application/json"},
          body: JSON.stringify({filename: payload.filename, graph_node_id: payload.graphNodeId}),
        });
      }
      void queryClient.invalidateQueries({queryKey: ["graph"]});
    } catch (reason) {
      setDropFileError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setDropFileBusy(false);
    }
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
  const replayData = graphAt(data, noProject ? null : replayAt, timeline.data);
  const replayNodeById = new Map(replayData.nodes.map((node) => [node.id, node]));
  const visibleData = filterGraph(replayData, filter, selected);
  const hostCount = replayData.nodes.filter((n) => n.type === "host" && !n.hidden).length;
  const hiddenCount = data.nodes.filter((n) => n.hidden).length;
  const selectedNode = selected
    ? replayNodeById.get(selected)
    : undefined;
  const objectivePath = pathHighlight && selected
    ? pathToObjective(replayData, selected) : null;
  const selectedTargetId = selectedNode?.type === "host" && selectedNode.source_ref
    ? (() => { try {
      const ref = JSON.parse(selectedNode.source_ref);
      return ref.kind === "target" ? Number(ref.id) : undefined;
    } catch { return undefined; } })() : undefined;
  // Right-clicking blank canvas has no node of its own to attach a new one
  // under -- the project root is always there and is a sensible default.
  const rootNode = data.nodes.find((n) => n.type === "project-root");

  return (
    <div style={S.wrap}>
      <div style={S.bar}>
        <div style={S.tabs}>
          <Tab on={view === "graph"} onClick={() => setView("graph")}>그래프</Tab>
          <Tab on={view === "tree"} onClick={() => setView("tree")}>트리</Tab>
          <Tab on={view === "outline"} onClick={() => setView("outline")}>Outline</Tab>
        </div>
        {selectedNode && !noProject && replayAt == null && (
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
        {multiSelected.size > 0 && !noProject && replayAt == null && (
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{ ...S.hiddenChip, background: "#123038", color: "#5ce1e6",
              cursor: "default" }}>
              {multiSelected.size}개 선택됨
            </span>
            <button style={S.hiddenChip} onClick={() => {
              for (const id of multiSelected) setHidden.mutate({ id, hidden: true });
              setMultiSelected(new Set());
            }}>숨기기</button>
            <button style={S.hiddenChip} onClick={() => {
              deleteNode.reset();
              setDeleteCandidates([...multiSelected].map((id) => nodeById.get(id)).filter(
                (node): node is GraphNode => !!node && node.type !== "project-root"));
            }}>삭제</button>
            <button style={S.hiddenChip} onClick={() => setMultiSelected(new Set())}>
              선택 해제
            </button>
          </div>
        )}
        {!noProject && <ElapsedTimer
          startIso={data.nodes.find((n) => n.type === "project-root")?.created_at} />}
        <div style={S.legend}>
          {Object.entries(STATUS_REASON).map(([k, v]) => (
            <span key={k} style={{ display: "flex", alignItems: "center", gap: 5 }}>
              <span style={{ width: 9, height: 9, borderRadius: 9, background: color(k) }} />
              {v}
            </span>
          ))}
        </div>
      </div>
      {!noProject && <GraphTimeMachine data={data} events={timeline.data}
        timestamp={replayAt} onChange={changeReplay} />}
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
        <button style={{ ...S.graphControl, ...(credentialOverlay ? S.credentialOverlayActive : {}) }}
          aria-pressed={credentialOverlay}
          onClick={() => setCredentialOverlay((value) => !value)}>
          🔑 ACCESS LINEAGE
        </button>
        <button style={{ ...S.graphControl, ...(pathHighlight ? S.toolActive : {}) }}
          aria-pressed={pathHighlight}
          title={!data.nodes.some((n) => n.objective)
            ? "목표로 표시된 노드가 없습니다 (노드 상세에서 🎯 목표로 지정)"
            : !selected ? "먼저 시작할 노드를 선택하세요"
            : objectivePath ? "" : "선택한 노드에서 목표까지 이어지는 경로가 없습니다"}
          onClick={() => setPathHighlight((value) => !value)}>
          🎯 PATH TO OBJECTIVE
        </button>
        <button style={S.graphControl} onClick={() => setFilter({ query: "", type: "all", status: "all",
          focusDepth: 0, pinnedOnly: false })}>필터 초기화</button>
        <button style={S.graphControl} onClick={() => setQueueOpen((value) => !value)}>작업 큐</button>
        <span style={S.filterCount}>{visibleData.nodes.length}/{data.nodes.length} nodes</span>
      </div>
      {dropFileError && (
        <div style={S.dropFileError}>
          파일을 Finding으로 추가하지 못했습니다: {dropFileError}
          <button style={S.resultAction} onClick={() => setDropFileError("")}>✕</button>
        </div>
      )}
      <div style={S.stage} ref={stageRef}>
        {view !== "outline" ? (
          <GraphCanvas data={visibleData} hostCount={hostCount} showHidden={showHidden}
            credentialOverlay={credentialOverlay} objectivePath={objectivePath}
            autoReconTargetIds={autoReconTargetIds}
            selected={selected} onSelect={setSelected} focus={focus} layoutMode={view}
            multiSelected={multiSelected} onToggleMultiSelect={toggleMultiSelect}
            onContext={(id, x, y) => replayAt == null && setContextMenu({ id, x, y })}
            onActivitySelect={(id) => { setSelected(id); setFocus({ id, nonce: Date.now() }); }}
            onDropFile={(payload) => void dropFile(payload)} dropFileBusy={dropFileBusy} />
        ) : (
          <OutlineView tree={tree.data} onSelect={setSelected} selected={selected} />
        )}
        <div style={S.splitter} onPointerDown={onSplitDown}
          onPointerMove={onSplitMove} onPointerUp={onSplitUp} />
        <div style={{ width: paneWidth, flexShrink: 0, display: "flex",
          minWidth: 0, minHeight: 0, containerType: "inline-size", containerName: "graph-pane" }}>
          {replayAt != null ? (
            <div style={S.inspector}>
              <div className="graphReplayLock"><b>TIME-MACHINE · READ ONLY</b>
                <span>{new Date(replayAt).toLocaleString("ko-KR")}</span>
                <p>노드를 선택해 당시 상세를 확인할 수 있습니다. 명령 실행과 편집은 LIVE에서만 가능합니다.</p>
                {selectedNode ? <section className="graphReplayNode" aria-label="선택한 과거 노드">
                  <div><i>{GLYPH[selectedNode.type]}</i><span>
                    <small>{selectedNode.type}</small><strong>{selectedNode.label}</strong>
                  </span></div>
                  <dl>
                    <div><dt>상태</dt><dd>{nodeStatusReason(selectedNode)}</dd></div>
                    <div><dt>요약</dt><dd>{nodeSummary(selectedNode)}</dd></div>
                    {selectedNode.notes && <div><dt>메모</dt><dd>{selectedNode.notes}</dd></div>}
                    <div><dt>기록 시각</dt><dd>{selectedNode.updated_at || selectedNode.created_at
                      ? new Date(selectedNode.updated_at || selectedNode.created_at!).toLocaleString("ko-KR")
                      : "기록 없음"}</dd></div>
                  </dl>
                </section> : <div className="graphReplayEmpty">확인할 노드를 선택하세요.</div>}
                <button type="button" onClick={() => changeReplay(null)}>RETURN LIVE ↵</button>
              </div>
            </div>
          ) : reportPanel ? (
            <div style={S.embedPane}><Suspense fallback={<Empty text="Findings 불러오는 중…" />}>
              <EmbeddedReports embedded initialProjectId={projectId || undefined}
                onBack={() => setReportPanel(false)} />
            </Suspense></div>
          ) : hashPanel ? (
            <div style={S.embedPane}><Suspense fallback={<Empty text="Hash Cracking 불러오는 중…" />}>
              <EmbeddedHashCracking embedded initialProjectId={hashPanel.project_id}
                initialTargetId={hashPanel.target_id} initialHash={hashPanel.secret}
                initialCredentialId={hashPanel.id} initialUsername={hashPanel.username}
                initialGraphNodeId={hashPanel.graph_node_id}
                initialMode={hashPanel.hash_mode_id ?? (hashPanel.source_kind === "responder"
                  || /NTLMv2/i.test(hashPanel.secret_hint || "") ? "netntlmv2" : undefined)}
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
          ) : fileTreePanel ? (
            <div style={S.embedPane}><Suspense fallback={<Empty text="폴더·파일 트리 불러오는 중…" />}>
              <EmbeddedPostExploitation embedded initialProjectId={projectId || undefined}
                initialTargetId={fileTreePanel.targetId} initialCategory="file_tree"
                onBack={() => setFileTreePanel(null)} />
            </Suspense></div>
          ) : noProject ? (
            <OnboardingPane creating={createProject.isPending}
              onCreate={() => createProject.mutate()} />
          ) : selectedNode?.type === "project-root" ? (
            <div style={S.embedPane}>
              <ProjectOperatorSession project={selectedNode} nodes={data.nodes}
                onSelect={(id) => { setSelected(id); setFocus({id, nonce: Date.now()}); }} />
            </div>
          ) : selectedNode?.type === "host" ? (
            <div style={S.embedPane}>
              <Suspense fallback={<Empty text="Scan Center 불러오는 중…" />}>
                <EmbeddedScanCenter key={selectedNode.id} embedded initialTargetId={selectedTargetId} />
              </Suspense>
            </div>
          ) : selectedNode?.type === "service" ? (
            <div style={S.embedPane}>
              <Suspense fallback={<Empty text="도구 불러오는 중…" />}>
                <EmbeddedEnumeration embedded onOpenRequestInGraph={(draft) => {
                  setHashPanel(null); setPostPanel(null); setReportPanel(false); setFileTreePanel(null); setWebRequest(draft);
                }} />
              </Suspense>
            </div>
          ) : (
            <Inspector node={selectedNode} projectId={projectId || undefined}
              links={selected ? deepLinks(selected) : []}
              executionContext={executionHandoff(selected)}
              onOpenRequest={(draft) => {
                setHashPanel(null); setPostPanel(null); setReportPanel(false); setFileTreePanel(null); setWebRequest(draft);
              }}
              onOpenHashCrack={(handoff) => {
                setPostPanel(null); setReportPanel(false); setWebRequest(null); setHashPanel(handoff);
              }}
              onOpenFileTree={(targetId) => {
                setHashPanel(null); setPostPanel(null); setReportPanel(false); setWebRequest(null);
                setFileTreePanel({ targetId });
              }}
              busy={addNode.isPending}
              onToggleHidden={(id, hidden) => setHidden.mutate({ id, hidden })}
              onSetStatus={(id, status) => setStatus.mutate({ id, status })}
              onSetDetails={(id, details) => setDetails.mutate({ id, ...details })}
              onAddNode={(v) => addNode.mutate(v)} />
          )}
        </div>
      </div>
      {replayAt == null && queueOpen && <TaskQueue nodes={data.nodes} onClose={() => setQueueOpen(false)}
        onSelect={(id) => { setSelected(id); setFocus({ id, nonce: Date.now() }); }}
        onStatus={(id, status) => setStatus.mutate({ id, status })}
        onAdd={() => selectedNode && setAddOpen(true)} canAdd={!!selectedNode} />}
      {replayAt == null && contextMenu && contextMenu.id && nodeById.get(contextMenu.id) && (() => {
        const menuNodeId = contextMenu.id;
        return <NodeQuickMenu
          node={nodeById.get(menuNodeId)!} x={contextMenu.x} y={contextMenu.y}
          onClose={() => setContextMenu(null)}
          onOpen={() => { setSelected(menuNodeId); setContextMenu(null); }}
          onAdd={() => { setSelected(menuNodeId); setAddOpen(true); setContextMenu(null); }}
          onPin={() => { const node = nodeById.get(menuNodeId)!;
            setDetails.mutate({ id: node.id, pinned: !node.pinned }); setContextMenu(null); }}
          onHide={() => { setHidden.mutate({ id: menuNodeId, hidden: true }); setContextMenu(null); }}
          onDelete={() => { deleteNode.reset(); setDeleteCandidates([nodeById.get(menuNodeId)!]);
            setContextMenu(null); }}
          onStatus={(status) => { setStatus.mutate({ id: menuNodeId, status }); setContextMenu(null); }} />;
      })()}
      {replayAt == null && contextMenu && contextMenu.id === null && (
        <BlankCanvasQuickMenu x={contextMenu.x} y={contextMenu.y}
          onClose={() => setContextMenu(null)}
          onAdd={() => { if (rootNode) { setSelected(rootNode.id); setAddOpen(true); }
            setContextMenu(null); }}
          onAddMemo={() => { addMemo.mutate(); setContextMenu(null); }} />
      )}
      {replayAt == null && deleteCandidates.length > 0 && <DeleteNodeDialog
        label={deleteCandidates[0].label} count={deleteCandidates.length}
        busy={deleteNode.isPending} error={deleteNode.error ? String(deleteNode.error) : undefined}
        onCancel={() => !deleteNode.isPending && setDeleteCandidates([])}
        onConfirm={() => deleteNode.mutate(deleteCandidates.map((node) => node.id))} />}
      {replayAt == null && addOpen && selectedNode && (
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
