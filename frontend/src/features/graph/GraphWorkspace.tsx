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

// Vertical slice: nmap-derived host/service nodes -> API -> Graph + Outline.
// Graph renders on Canvas 2D (renderer boundary from spec 3.4; the Pixi/WebGL
// swap is M4 and isolated to <GraphCanvas>). No new dependencies in this slice.

type NodeType = "project-root" | "host" | "service" | "finding" | "technique" | "credential";
type GraphNode = {
  id: string; type: NodeType; status: string; label: string; objective: boolean;
  source_ref: string; hidden: boolean; meta?: string;
};
type DeepLink = { label: string; open: () => void };
type GraphEdge = {
  id: string; source: string; target: string; relation: string; status: string;
};
type GraphOut = { root_node_id: string | null; nodes: GraphNode[]; edges: GraphEdge[] };

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
const LINK_KIND_LABEL: Record<string, string> = {
  page: "페이지", asset: "정적 리소스", absolute: "절대경로", anchor: "앵커",
};
const LINK_KIND_ORDER = ["page", "absolute", "asset", "anchor"];
const EXECUTION_STATUS_LABEL: Record<string, string> = {
  queued: "대기", running: "실행 중", completed: "완료", failed: "실패",
  interrupted: "중단됨",
};
const GLYPH: Record<NodeType, string> = {
  "project-root": "◎", host: "▣", service: "◉", finding: "◇",
  technique: "⚡", credential: "🔑",
};
const color = (s: string) => STATUS_COLOR[s] ?? "#8b8b93";

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
  const [view, setView] = useState<"graph" | "outline">("graph");
  const [selected, setSelected] = useState<string | null>(null);
  const [showHidden, setShowHidden] = useState(false);
  const [focus, setFocus] = useState<{ id: string; nonce: number } | null>(null);
  const [addOpen, setAddOpen] = useState(false);
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
    try {
      if (JSON.parse(node.source_ref).kind !== "execution") return null;
    } catch { return null; }
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
  const deepLink = (id: string): DeepLink | undefined => {
    const node = nodeById.get(id);
    if (!node?.source_ref) return undefined;
    let ref: { module: string; kind: string; id: number };
    try { ref = JSON.parse(node.source_ref); } catch { return undefined; }
    const go = (hash: string) => (): void => { location.hash = hash; };
    if (ref.kind === "service") {
      const h = serviceHandoff(id);
      if (!h) return undefined;
      return {
        label: "전체 화면으로 열기 →",
        open: () => {
          setPendingServiceNav(h);
          location.hash = "#enumeration";
          dispatchEvent(new CustomEvent("oscp-service-nav"));
        },
      };
    }
    if (ref.kind === "target") return { label: "Scan Center 열기 →", open: go("#scans") };
    if (ref.kind === "finding") return { label: "Reports 열기 →", open: go("#reports") };
    if (ref.kind === "credential")
      return { label: "Post-Exploitation 열기 →", open: go("#post-exploitation") };
    return undefined;
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
  const hostCount = data.nodes.filter((n) => n.type === "host" && !n.hidden).length;
  const hiddenCount = data.nodes.filter((n) => n.hidden).length;
  const selectedNode = selected
    ? (noProject ? data.nodes.find((n) => n.id === selected) : nodeById.get(selected))
    : undefined;

  return (
    <div style={S.wrap}>
      <div style={S.bar}>
        <div style={S.tabs}>
          <Tab on={view === "graph"} onClick={() => setView("graph")}>Graph</Tab>
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
          {Object.entries(STATUS_LABEL).map(([k, v]) => (
            <span key={k} style={{ display: "flex", alignItems: "center", gap: 5 }}>
              <span style={{ width: 9, height: 9, borderRadius: 9, background: color(k) }} />
              {v}
            </span>
          ))}
        </div>
      </div>
      <div style={S.stage}>
        {view === "graph" ? (
          <GraphCanvas data={data} hostCount={hostCount} showHidden={showHidden}
            selected={selected} onSelect={setSelected} focus={focus} />
        ) : (
          <OutlineView tree={tree.data} onSelect={setSelected} selected={selected} />
        )}
        <div style={S.splitter} onPointerDown={onSplitDown}
          onPointerMove={onSplitMove} onPointerUp={onSplitUp} />
        <div style={{ width: paneWidth, flexShrink: 0, display: "flex",
          minWidth: 0, minHeight: 0 }}>
          {noProject ? (
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
            <Inspector node={selectedNode} link={selected ? deepLink(selected) : undefined}
              executionContext={executionHandoff(selected)}
              busy={addNode.isPending}
              onToggleHidden={(id, hidden) => setHidden.mutate({ id, hidden })}
              onSetStatus={(id, status) => setStatus.mutate({ id, status })}
              onAddNode={(v) => addNode.mutate(v)} />
          )}
        </div>
      </div>
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

function GraphCanvas(props: {
  data: GraphOut; hostCount: number; showHidden: boolean;
  selected: string | null; onSelect: (id: string) => void;
  focus: { id: string; nonce: number } | null;
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
    let W = 0, H = 0, raf = 0, render = () => {};
    let panX = 0, panY = 0, panning = false, panStart = { x: 0, y: 0 };
    let dragging: Sim | null = null, hover: Sim | null = null;

    const visible = (n: GraphNode) =>
      !(hideRoot && n.type === "project-root") && (showHidden || !n.hidden);
    const nodes: Sim[] = data.nodes.filter(visible).map((n, i) => {
      const a = (i / data.nodes.length) * Math.PI * 2;
      return { ...n, x: 400 + Math.cos(a) * 180, y: 300 + Math.sin(a) * 140, vx: 0, vy: 0 };
    });
    const index = new Map(nodes.map((n) => [n.id, n]));
    const edges = data.edges.filter((e) => index.has(e.source) && index.has(e.target));
    const structural = new Set(["discovered", "enumerated", "attempted", "yielded", "pivoted-to"]);

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
      for (let i = 0; i < nodes.length; i++)
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i], b = nodes[j];
          let dx = a.x - b.x, dy = a.y - b.y, d2 = dx * dx + dy * dy || 0.01;
          const d = Math.sqrt(d2), f = 2600 / d2;
          a.vx += (dx / d) * f; a.vy += (dy / d) * f;
          b.vx -= (dx / d) * f; b.vy -= (dy / d) * f;
        }
      for (const e of edges) {
        const a = index.get(e.source)!, b = index.get(e.target)!;
        let dx = b.x - a.x, dy = b.y - a.y, d = Math.hypot(dx, dy) || 0.01;
        const rest = structural.has(e.relation) ? 110 : 150, k = (d - rest) * 0.015;
        a.vx += (dx / d) * k; a.vy += (dy / d) * k;
        b.vx -= (dx / d) * k; b.vy -= (dy / d) * k;
      }
      const cx = W / 2, cy = H / 2;
      for (const n of nodes) {
        if (n.id === anchorId) { n.x = cx; n.y = cy; n.vx = n.vy = 0; continue; }
        n.vx += (cx - n.x) * 0.0015; n.vy += (cy - n.y) * 0.0015;
        n.vx *= 0.86; n.vy *= 0.86;
        if (n !== dragging) { n.x += n.vx; n.y += n.vy; }
      }
    };

    const draw = () => {
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, W, H);
      ctx.translate(panX, panY);
      ctx.scale(zoomRef.current, zoomRef.current);  // camera zoom: sizes AND spacing
      for (const e of edges) {
        const a = index.get(e.source)!, b = index.get(e.target)!;
        const hot = !!hover && (e.source === hover.id || e.target === hover.id);
        const struct = structural.has(e.relation);
        ctx.beginPath(); ctx.moveTo(a.x, a.y);
        if (struct) { ctx.lineTo(b.x, b.y); ctx.setLineDash([]); }
        else {
          ctx.quadraticCurveTo((a.x + b.x) / 2, (a.y + b.y) / 2 - 34, b.x, b.y);
          ctx.setLineDash([4, 5]);
        }
        ctx.strokeStyle = hot ? color(e.status) : struct ? "#33333f" : "#3a2f45";
        ctx.lineWidth = hot ? 2 : 1;
        ctx.globalAlpha = hover && !hot ? 0.25 : 0.9; ctx.stroke();
        ctx.globalAlpha = 1; ctx.setLineDash([]);
      }
      for (const n of nodes) {
        const isAnchor = n.id === anchorId, isSel = n.id === selectedRef.current;
        const isHost = n.type === "host", isRoot = n.type === "project-root";
        const r = isRoot ? 26 : isAnchor ? 24 : isHost ? 16 : 11;
        ctx.globalAlpha = n.hidden ? 0.3 : 1;   // dim user-hidden nodes
        if (isAnchor) {
          ctx.beginPath(); ctx.arc(n.x, n.y, r + 10, 0, Math.PI * 2);
          ctx.strokeStyle = "rgba(106,169,255,.4)"; ctx.lineWidth = 1.5;
          ctx.setLineDash([3, 4]); ctx.stroke(); ctx.setLineDash([]);
        }
        if (n.objective) {
          ctx.beginPath(); ctx.arc(n.x, n.y, r + 6, 0, Math.PI * 2);
          ctx.strokeStyle = n.status === "succeeded" ? "#f5c518" : "rgba(245,197,24,.5)";
          ctx.lineWidth = 2.5; ctx.stroke();
        }
        ctx.save();
        ctx.shadowColor = isAnchor ? "#6aa9ff" : color(n.status);
        ctx.shadowBlur = isAnchor ? 30 : isSel ? 24 : 12;
        ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
        ctx.fillStyle = color(n.status); ctx.fill();
        ctx.restore();
        ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
        ctx.lineWidth = isSel ? 2.5 : isAnchor || isHost ? 2 : 1;
        ctx.strokeStyle = isSel ? "#fff" : isAnchor ? "#6aa9ff"
          : isHost ? "rgba(255,255,255,.7)" : "rgba(255,255,255,.35)";
        if (n.hidden) ctx.setLineDash([2, 3]);
        ctx.stroke();
        ctx.setLineDash([]);
        ctx.fillStyle = "#0c0c10"; ctx.textAlign = "center"; ctx.textBaseline = "middle";
        ctx.font = `${Math.round(r * 0.95)}px sans-serif`;
        ctx.fillText(GLYPH[n.type], n.x, n.y + 0.5);
        if (hover === n || isSel || isHost || isRoot || n.hidden) {
          ctx.fillStyle = "#e7e7ee"; ctx.textBaseline = "top";
          ctx.font = isAnchor ? "600 12px sans-serif" : "11px sans-serif";
          ctx.fillText(n.label, n.x, n.y + r + 6);
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
      draw();
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
    const onClick = (ev: MouseEvent) => {
      const p = toWorld(ev), n = nodeAt(p.x, p.y);
      if (n) props.onSelect(n.id);
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
    canvas.addEventListener("wheel", onWheel, { passive: false });
    addEventListener("mouseup", onUp);
    addEventListener("keydown", onKey);
    return () => {
      cancelAnimationFrame(raf); ro.disconnect();
      canvas.removeEventListener("mousemove", onMove);
      canvas.removeEventListener("mousedown", onDown);
      canvas.removeEventListener("click", onClick);
      canvas.removeEventListener("wheel", onWheel);
      removeEventListener("mouseup", onUp);
      removeEventListener("keydown", onKey);
    };
  }, [data, anchorId, hideRoot, showHidden]);

  return (
    <div style={{ position: "relative", flex: 1, minWidth: 0 }}>
      <canvas ref={canvasRef} style={{ display: "block", width: "100%", height: "100%" }} />
      <div style={S.hint}>
        파란 헤일로 = 루트 · 노드 드래그로 이동 · 빈 공간 드래그로 화면 이동 · 마우스 휠 / Ctrl +/− 확대·축소
      </div>
    </div>
  );
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
          {(STATUS_LABEL[item.status] ?? item.status).toUpperCase()}
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
  node?: GraphNode; link?: DeepLink; busy: boolean;
  executionContext?: { targetId: number; serviceId?: number } | null;
  onToggleHidden: (id: string, hidden: boolean) => void;
  onSetStatus: (id: string, status: string) => void;
  onAddNode: (v: AddForm & { sourceId: string }) => void;
}) {
  const n = props.node;
  const [adding, setAdding] = useState(false);
  const executionId = (() => {
    if (!n?.source_ref) return null;
    try {
      const ref = JSON.parse(n.source_ref);
      return ref.kind === "execution" && Number.isInteger(ref.id) ? ref.id : null;
    } catch { return null; }
  })();
  const executionOutput = useQuery({
    queryKey: ["executionOutput", executionId],
    enabled: executionId !== null,
    queryFn: () => api<{ stdout?: string; stderr?: string; status: string;
      error?: string; exit_code?: number | null }>(`/executions/${executionId}/output`),
  });
  const targets = useQuery({
    queryKey: ["graphLinkTargets"],
    enabled: executionId !== null && !!props.executionContext,
    queryFn: () => api<Array<{ id: number; ip: string; hostname?: string }>>("/targets"),
  });
  const services = useQuery({
    queryKey: ["graphLinkServices", props.executionContext?.targetId],
    enabled: executionId !== null && !!props.executionContext?.serviceId,
    queryFn: () => api<Array<{ id: number; port: number; name: string;
      product?: string; tls?: boolean }>>(
      `/targets/${props.executionContext!.targetId}/services`),
  });
  const [evidenceState, setEvidenceState] = useState<"idle" | "saving" | "saved" | "error">("idle");
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
    if (!props.executionContext?.serviceId || !base) return;
    localStorage.setItem("oscp-web-launch", JSON.stringify({
      targetId: props.executionContext.targetId,
      serviceId: props.executionContext.serviceId,
      url: new URL(url, base).toString(),
    }));
    location.hash = "#web/request";
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
  if (!n)
    return <aside style={S.inspector}>
      <div style={{ color: "#6b6b76", fontSize: 13 }}>노드를 선택하세요.</div>
    </aside>;
  return (
    <aside style={S.inspector}>
      <h3 style={{ margin: "0 0 4px", fontSize: 15 }}>{n.label}</h3>
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
            }}>{STATUS_LABEL[s] ?? s}</button>
          ))}
        </div>
      </div>
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
      {executionId !== null && n.label === "http-link-extract" && (
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
      {props.link && (
        <button onClick={props.link.open} style={S.openBtn}>{props.link.label}</button>
      )}
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
  tabs: { display: "flex", gap: 4, background: "#16161c", padding: 4,
    borderRadius: 10, border: "1px solid #2a2a34" },
  legend: { marginLeft: "auto", display: "flex", gap: 12, color: "#9a9aa6", fontSize: 12 },
  stage: { flex: 1, display: "flex", minHeight: 0 },
  hint: { position: "absolute", left: 16, bottom: 14, color: "#6b6b76", fontSize: 12,
    pointerEvents: "none" },
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
