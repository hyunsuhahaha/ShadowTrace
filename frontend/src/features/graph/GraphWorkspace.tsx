import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../api";
import { setPendingServiceNav } from "../../pendingServiceNav";
import { consumePendingGraphFocus } from "../../pendingGraphFocus";

// Vertical slice: nmap-derived host/service nodes -> API -> Graph + Outline.
// Graph renders on Canvas 2D (renderer boundary from spec 3.4; the Pixi/WebGL
// swap is M4 and isolated to <GraphCanvas>). No new dependencies in this slice.

type NodeType = "project-root" | "host" | "service" | "finding" | "technique" | "credential";
type GraphNode = {
  id: string; type: NodeType; status: string; label: string; objective: boolean;
  source_ref: string; hidden: boolean;
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

  const setHidden = useMutation({
    mutationFn: (v: { id: string; hidden: boolean }) =>
      api(`/graph/nodes/${v.id}`, {
        method: "PATCH", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hidden: v.hidden }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["graph", projectId] });
      queryClient.invalidateQueries({ queryKey: ["graphTree", projectId] });
    },
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
      const edge = graph.data?.edges.find(
        (e) => e.target === id && e.relation === "discovered");
      const host = edge ? nodeById.get(edge.source) : undefined;
      let targetId: number | undefined;
      if (host?.source_ref) {
        try {
          const h = JSON.parse(host.source_ref);
          if (h.kind === "target") targetId = h.id;
        } catch { /* ignore */ }
      }
      if (targetId === undefined) return undefined;
      return {
        label: "Service Enumeration 열기 →",
        open: () => {
          setPendingServiceNav({ targetId: targetId!, serviceId: ref.id });
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

  if (!projectId)
    return <Empty text="상단에서 프로젝트를 먼저 선택하세요." />;
  if (graph.isLoading) return <Empty text="그래프 동기화 중…" />;
  if (graph.isError)
    return <Empty text={`불러오기 실패: ${(graph.error as Error).message}`} />;

  const data = graph.data!;
  const hostCount = data.nodes.filter((n) => n.type === "host" && !n.hidden).length;
  const hiddenCount = data.nodes.filter((n) => n.hidden).length;
  const selectedNode = selected ? nodeById.get(selected) : undefined;
  if (data.nodes.length <= 1)
    return <Empty text="아직 노드가 없습니다. Scan Center에서 nmap 결과를 먼저 가져오세요." />;

  return (
    <div style={S.wrap}>
      <div style={S.bar}>
        <div style={S.tabs}>
          <Tab on={view === "graph"} onClick={() => setView("graph")}>Graph</Tab>
          <Tab on={view === "outline"} onClick={() => setView("outline")}>Outline</Tab>
        </div>
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
        <Inspector node={selectedNode} link={selected ? deepLink(selected) : undefined}
          onToggleHidden={(id, hidden) => setHidden.mutate({ id, hidden })} />
      </div>
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
  // one-shot recenter request from the reverse bridge; consumed in the loop so
  // it doesn't re-init the simulation.
  const focusReq = useRef<{ id: string; nonce: number } | null>(null);
  useEffect(() => { focusReq.current = props.focus; }, [props.focus]);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  // adaptive root (decision B): single host => that host is the visual anchor.
  const anchorId = hostCount <= 1
    ? (data.nodes.find((n) => n.type === "host")?.id ?? data.root_node_id)
    : data.root_node_id;
  const hideRoot = hostCount <= 1;

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    let W = 0, H = 0, raf = 0;
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
      canvas.width = W * dpr; canvas.height = H * dpr;
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
        const isAnchor = n.id === anchorId, isSel = n.id === props.selected;
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
        panX = W / 2 - focusNode.x; panY = H / 2 - focusNode.y; focusFrames--;
      }
      draw();
      raf = requestAnimationFrame(loop);
    };
    loop();

    const toWorld = (ev: MouseEvent) => {
      const r = canvas.getBoundingClientRect();
      return { x: ev.clientX - r.left - panX, y: ev.clientY - r.top - panY };
    };
    const nodeAt = (x: number, y: number) => {
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
    canvas.addEventListener("mousemove", onMove);
    canvas.addEventListener("mousedown", onDown);
    canvas.addEventListener("click", onClick);
    addEventListener("mouseup", onUp);
    return () => {
      cancelAnimationFrame(raf); ro.disconnect();
      canvas.removeEventListener("mousemove", onMove);
      canvas.removeEventListener("mousedown", onDown);
      canvas.removeEventListener("click", onClick);
      removeEventListener("mouseup", onUp);
    };
  }, [data, anchorId, hideRoot, showHidden, props.selected]);

  return (
    <div style={{ position: "relative", flex: 1, minWidth: 0 }}>
      <canvas ref={canvasRef} style={{ display: "block", width: "100%", height: "100%" }} />
      <div style={S.hint}>
        파란 헤일로 = 루트 · 노드 드래그로 이동 · 빈 공간 드래그로 화면 이동
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

function Inspector(props: {
  node?: GraphNode; link?: DeepLink;
  onToggleHidden: (id: string, hidden: boolean) => void;
}) {
  const n = props.node;
  return (
    <aside style={S.inspector}>
      {n ? (
        <>
          <h3 style={{ margin: "0 0 4px", fontSize: 15 }}>{n.label}</h3>
          <div style={{ color: "#6b6b76", fontSize: 12 }}>
            {GLYPH[n.type]} {n.type}
            {n.objective && <span style={{ color: "#f5c518" }}> · 🎯 목표</span>}
            {n.hidden && <span style={{ color: "#6b6b76" }}> · 숨김</span>}
          </div>
          <div style={{ marginTop: 14, fontSize: 12 }}>
            <span style={{ color: "#9a9aa6" }}>상태 </span>
            <span style={{ color: color(n.status) }}>
              {STATUS_LABEL[n.status] ?? n.status}
            </span>
          </div>
          {props.link && (
            <button onClick={props.link.open} style={S.openBtn}>
              {props.link.label}
            </button>
          )}
          {n.type !== "project-root" && (
            <button onClick={() => props.onToggleHidden(n.id, !n.hidden)}
              style={S.hideBtn}>
              {n.hidden ? "복원" : "그래프에서 숨기기"}
            </button>
          )}
        </>
      ) : (
        <div style={{ color: "#6b6b76", fontSize: 13 }}>노드를 선택하세요.</div>
      )}
    </aside>
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
  inspector: { width: 280, borderLeft: "1px solid #2a2a34", background: "#16161c",
    padding: 16, overflow: "auto", flexShrink: 0 },
  openBtn: { marginTop: 18, width: "100%", padding: "9px 12px", borderRadius: 8,
    border: "1px solid #6aa9ff55", background: "#6aa9ff14", color: "#6aa9ff",
    fontWeight: 600, cursor: "pointer" },
  hideBtn: { marginTop: 10, width: "100%", padding: "8px 12px", borderRadius: 8,
    border: "1px solid #2a2a34", background: "transparent", color: "#9a9aa6",
    fontWeight: 500, cursor: "pointer" },
  hiddenChip: { padding: "5px 12px", borderRadius: 8, border: "1px solid #2a2a34",
    background: "#16161c", color: "#9a9aa6", fontSize: 12, fontWeight: 600,
    cursor: "pointer" },
};
