import { useEffect, useRef, useState, type DragEvent as ReactDragEvent } from "react";
import { ActivityItem, ActivityKind, ACTIVITY_PANEL_KEY, ActivityStatusFilter,
  buildActivityFeed, clampActivityPanel, color, evidenceCount, fileFindingGlyph, filterActivityFeed,
  getNodeActivity, credentialBadge, GLYPH, GraphNode, GraphOut, GraphPosition,
  initialGraphPosition, initialGraphPositionNearParent, isFlagFinding, justUnlockedAt, NodeActivity,
  nodeStatusReason, nodeSummary, ObjectivePath, readActivityPanel, Sim } from "./graphModel";
import { S } from "./graphStyles";
import { FILE_DRAG_MIME, type FileDragPayload } from "../../fileTree";

export function GraphCanvas(props: {
  data: GraphOut; hostCount: number; showHidden: boolean; credentialOverlay: boolean;
  selected: string | null; onSelect: (id: string) => void;
  focus: { id: string; nonce: number } | null;
  layoutMode: "graph" | "tree"; onActivitySelect: (id: string) => void;
  // null id -- the right-click landed on blank canvas, not a node -- still
  // gets a callback (with the browser's own menu suppressed either way) so
  // the caller can offer a "여기에 노드 추가" affordance instead of nothing.
  onContext: (id: string | null, x: number, y: number) => void;
  objectivePath?: ObjectivePath | null;
  onDropFile?: (payload: FileDragPayload) => void;
  dropFileBusy?: boolean;
}) {
  const { data, hostCount, showHidden } = props;
  // These are read through refs inside the render loop so selection/zoom changes
  // do NOT re-run the effect (which would reseed positions and make the graph
  // "jump" on every click). The sim only re-inits when the node set changes.
  const focusReq = useRef<{ id: string; nonce: number } | null>(null);
  useEffect(() => { focusReq.current = props.focus; }, [props.focus]);
  const selectedRef = useRef(props.selected);
  useEffect(() => { selectedRef.current = props.selected; }, [props.selected]);
  const pathRef = useRef<ObjectivePath | null>(props.objectivePath ?? null);
  useEffect(() => { pathRef.current = props.objectivePath ?? null; }, [props.objectivePath]);
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
      !(hideRoot && n.type === "project-root")
      && (props.credentialOverlay || n.type !== "credential")
      && (showHidden || !n.hidden);
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
    const edges = data.edges.filter((e) => index.has(e.source) && index.has(e.target)
      && (props.credentialOverlay
        || !["reused-credential", "pivoted-to"].includes(e.relation)));
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
    // Four activity languages, one per meaning: green = actively searching
    // (scan output still streaming, outcome unknown), red = armed and
    // waiting on something external (Responder), blue = an interactive
    // shell attached and settled -- any InteractiveSession, floating PTY or
    // desktop (reuses the app's existing anchor/selection blue rather than
    // inventing a hue), violet = hashcat grinding a wordlist -- distinct
    // from the other three so it doesn't read as "just another scan."
    const signal = "#59f59a";
    const listenerSignal = "#ff4d67";
    const connectedSignal = "#6aa9ff";
    const crackSignal = "#b388ff";
    type SignalKind = "scan" | "listener" | "connected" | "crack";
    const SIGNAL_RGB: Record<SignalKind, string> = {
      scan: "89,245,154", listener: "255,77,103", connected: "106,169,255", crack: "179,136,255",
    };
    const signalKindOf = (a: NodeActivity | null): SignalKind | null => !a ? null
      : a.kind === "listener" ? "listener" : a.kind === "crack" ? "crack"
      // A live shell reads as settled/attached, not still searching --
      // every InteractiveSession activity is kind:"shell" regardless of
      // whether it's a floating PTY ("running") or a desktop launch
      // ("launched"), so both get the same calm breathing-ring treatment
      // instead of only "launched" qualifying before.
      : a.kind === "shell" ? "connected" : "scan";
    const signalHex = (kind: SignalKind) =>
      kind === "listener" ? listenerSignal : kind === "connected" ? connectedSignal
      : kind === "crack" ? crackSignal : signal;
    const signalRgba = (kind: SignalKind, alpha: number) => `rgba(${SIGNAL_RGB[kind]},${alpha})`;
    const FILL_BG: Record<SignalKind, string> = {
      scan: "#10251a", listener: "#2a1016", connected: "#0e1a2a", crack: "#1c1430",
    };
    const BADGE_BG: Record<SignalKind, string> = {
      scan: "rgba(5,18,12,.9)", listener: "rgba(25,5,10,.92)", connected: "rgba(6,14,26,.92)",
      crack: "rgba(20,12,30,.92)",
    };
    const signalLabel = (a: NodeActivity, kind: SignalKind) => kind === "listener" ? "LISTENING"
      : kind === "connected" ? "CONNECTED" : kind === "crack" ? "CRACKING"
      : a.kind === "scan" ? "SCANNING" : a.status.toUpperCase();

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
      const activePath = pathRef.current;
      const pathEdgeIds = activePath ? new Set(activePath.edgeIds) : null;
      const pathNodeIds = activePath ? new Set(activePath.nodeIds) : null;
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
        const credentialUse = e.relation === "reused-credential";
        const lateral = e.relation === "pivoted-to" && edge.status === "succeeded";
        const lineageColor = credentialUse ? "#e3b341" : lateral ? "#55d6e8" : "";
        ctx.beginPath(); ctx.moveTo(a.x, a.y);
        // reused-credential is a confirmed "I logged in here with this"
        // fact, same weight as pivoted-to (already structural/solid) --
        // it shouldn't read as the same tentative dashed maybe-relation
        // every other non-structural edge gets.
        if (struct || credentialUse) { ctx.lineTo(b.x, b.y); ctx.setLineDash([]); }
        else {
          ctx.quadraticCurveTo((a.x + b.x) / 2, (a.y + b.y) / 2 - 34, b.x, b.y);
          ctx.setLineDash([4, 5]);
        }
        // A solid gold halo under the edge's own color/dash -- highlights the
        // route to the selected objective without hiding what the edge itself
        // already means (a reused-credential arrow on the path stays amber
        // *and* gets the halo).
        if (pathEdgeIds?.has(e.id)) {
          ctx.save(); ctx.setLineDash([]); ctx.lineWidth = 5;
          ctx.strokeStyle = "rgba(245,197,24,.5)";
          ctx.shadowColor = "#f5c518"; ctx.shadowBlur = 6;
          ctx.stroke(); ctx.restore();
        }
        const strokeColor = lineageColor || (edgeKind
          ? signalRgba(edgeKind, edgeKind === "scan" ? .42 : .47)
          : hot ? color(edge.status) : struct ? "#33333f" : "#3a2f45");
        ctx.strokeStyle = strokeColor;
        ctx.lineWidth = lineageColor ? 1.8 : active ? 1.35 : hot ? 2 : 1;
        const edgeAlpha = hover && !hot ? 0.25 : 0.9;
        ctx.globalAlpha = edgeAlpha; ctx.stroke();
        ctx.globalAlpha = 1; ctx.setLineDash([]);
        // Structural edges (discovered/enumerated/attempted/...) previously had
        // no direction marker at all, unlike captures-from/lineage below --
        // a plain arrowhead closes that ambiguity without competing with the
        // colored, labeled overlays those two special cases already draw.
        if (struct && !lineageColor) {
          const targetRadius = b.type === "project-root" ? 40 : b.id === anchorId ? 38
            : b.type === "host" || b.type === "operator" ? 26 : 19;
          const angle = Math.atan2(b.y - a.y, b.x - a.x);
          const tipX = b.x - Math.cos(angle) * (targetRadius + 4);
          const tipY = b.y - Math.sin(angle) * (targetRadius + 4);
          ctx.beginPath(); ctx.moveTo(tipX, tipY);
          ctx.lineTo(tipX - Math.cos(angle - .45) * 6, tipY - Math.sin(angle - .45) * 6);
          ctx.lineTo(tipX - Math.cos(angle + .45) * 6, tipY - Math.sin(angle + .45) * 6);
          ctx.closePath();
          ctx.globalAlpha = edgeAlpha; ctx.fillStyle = strokeColor; ctx.fill();
          ctx.globalAlpha = 1;
        }
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
        if (lineageColor) {
          // Both are straight lines now (see the credentialUse check above),
          // so both get the same straight-line arrow angle. Sized well
          // above the plain structural arrowhead below (4-6px wings) --
          // "I logged in here with this credential" is a bigger deal than
          // an ordinary discovered/enumerated hop and should read as one
          // at a glance, not blend in as just another thin marker.
          // Retraction has to track the target's own radius (same as the
          // structural arrowhead above) rather than one fixed distance --
          // a fixed number tuned to look right against a host (r=26) left
          // a visible gap in front of the smaller service/finding/credential
          // nodes (r=19) this same arrow just as often points at.
          const targetRadius = b.type === "project-root" ? 40 : b.id === anchorId ? 38
            : b.type === "host" || b.type === "operator" ? 26 : 19;
          const angle = Math.atan2(b.y - a.y, b.x - a.x);
          const tipX = b.x - Math.cos(angle) * (targetRadius + 4);
          const tipY = b.y - Math.sin(angle) * (targetRadius + 4);
          ctx.beginPath(); ctx.moveTo(tipX, tipY);
          ctx.lineTo(tipX - Math.cos(angle - .5) * 16, tipY - Math.sin(angle - .5) * 16);
          ctx.lineTo(tipX - Math.cos(angle + .5) * 16, tipY - Math.sin(angle + .5) * 16);
          ctx.closePath();
          ctx.save(); ctx.shadowColor = lineageColor; ctx.shadowBlur = 6;
          ctx.fillStyle = lineageColor; ctx.fill();
          ctx.restore();
          const label = edge.label || (credentialUse ? "CREDENTIAL REUSE" : "LATERAL ACCESS");
          ctx.font = "600 8px ui-monospace,monospace";
          const labelWidth = Math.min(190, ctx.measureText(label).width + 12);
          const labelX = (a.x + b.x) / 2, labelY = (a.y + b.y) / 2 - 10;
          ctx.fillStyle = "rgba(5,9,8,.92)";
          ctx.fillRect(labelX - labelWidth / 2, labelY - 10, labelWidth, 16);
          ctx.strokeStyle = lineageColor; ctx.lineWidth = 1;
          ctx.strokeRect(labelX - labelWidth / 2, labelY - 10, labelWidth, 16);
          ctx.fillStyle = lineageColor; ctx.textAlign = "center"; ctx.textBaseline = "middle";
          ctx.fillText(label.length > 30 ? `${label.slice(0, 29)}…` : label,
            labelX, labelY - 2, labelWidth - 8);
        }
      }
      // A small corner badge marking "at least one human-attached Evidence
      // backs this node" -- reinterprets NodeZero's auto-verified PROOF badge
      // around this project's human-approved-only principle (evidenceCount is
      // a plain Evidence-row count, never an automated correctness judgment).
      const drawEvidenceBadge = (count: number, bx: number, by: number) => {
        if (!count) return;
        ctx.save();
        ctx.beginPath(); ctx.arc(bx, by, 7, 0, Math.PI * 2);
        ctx.fillStyle = "#0c1210"; ctx.fill();
        ctx.strokeStyle = "#59f59a"; ctx.lineWidth = 1; ctx.stroke();
        ctx.fillStyle = "#59f59a"; ctx.font = "600 8px ui-monospace,monospace";
        ctx.textAlign = "center"; ctx.textBaseline = "middle";
        ctx.fillText(count > 9 ? "9+" : String(count), bx, by + 0.5);
        ctx.restore();
      };
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
        const isFlag = isFlagFinding(current);
        const r = isRoot ? 40 : isAnchor ? 38 : isHost || isOperator ? 26 : 19;
        // A one-shot "just unlocked" burst instead of the flag's looping
        // rings -- this is a fact about how the node came to exist, not an
        // ongoing state, so it plays once and settles rather than pulsing
        // forever the way an active/flagged node does.
        // now (this draw loop's own timer) is performance.now() -- monotonic
        // since page load, not wall-clock -- while unlockedAt is a real ISO
        // timestamp from the backend, so this has to compare against
        // Date.now() specifically or the two time bases don't line up at
        // all (confirmed live: the effect never fired, comparing against
        // `now` gave a wildly wrong elapsed value every time).
        const unlockedAt = justUnlockedAt(current);
        const unlockElapsed = unlockedAt ? Date.now() - Date.parse(unlockedAt) : Infinity;
        // Long enough to survive the invalidateQueries round-trip eating into
        // it before the node's first paint, and to actually be noticed
        // rather than a blink-and-you-miss-it flash.
        const unlockWindow = 6000;
        const unlocking = unlockElapsed >= 0 && unlockElapsed < unlockWindow;
        // Appears locked, then visibly unlocks, then settles into its real
        // glyph -- not just a static "open" icon the whole time.
        const unlockShowsLocked = unlocking && unlockElapsed < unlockWindow * 0.35;
        ctx.globalAlpha = current.hidden ? 0.3 : 1;   // dim user-hidden nodes
        const credential = credentialBadge(current);
        if (credential) {
          ctx.font = "600 9px ui-monospace,monospace";
          const width = Math.max(112, Math.min(190,
            Math.max(ctx.measureText(credential.identity).width + 36,
              ctx.measureText(credential.kind).width + 36)));
          const height = 38, x = n.x - width / 2, y = n.y - height / 2;
          ctx.save();
          ctx.shadowColor = isSel ? "#fff" : "#e3b341";
          ctx.shadowBlur = isSel ? 18 : 8;
          ctx.fillStyle = "#111006"; ctx.fillRect(x, y, width, height);
          ctx.restore();
          ctx.strokeStyle = isSel ? "#fff" : "#806b31";
          ctx.lineWidth = isSel ? 2 : 1; ctx.strokeRect(x, y, width, height);
          ctx.fillStyle = "#e3b341"; ctx.font = "13px sans-serif";
          ctx.textAlign = "left"; ctx.textBaseline = "middle"; ctx.fillText("🔑", x + 9, n.y);
          ctx.fillStyle = "#e8dfc7"; ctx.font = "600 9px ui-monospace,monospace";
          ctx.fillText(credential.identity.length > 24
            ? `${credential.identity.slice(0, 23)}…` : credential.identity, x + 30, n.y - 6);
          ctx.fillStyle = "#8f8157"; ctx.font = "7px ui-monospace,monospace";
          ctx.fillText(`${credential.kind} · ${credential.state}`, x + 30, n.y + 8);
          drawEvidenceBadge(evidenceCount(current), x + width - 8, y + 2);
          ctx.globalAlpha = 1;
          continue;
        }
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
          if (kind !== "crack") {
            for (let i = 0; i < (reduceMotion ? 1 : 3); i++) {
              const p = reduceMotion ? .38 : (phase + i / 3) % 1;
              ctx.beginPath(); ctx.arc(n.x, n.y, r + 14 + p * 52, 0, Math.PI * 2);
              const alpha = (reduceMotion ? .38 : (1 - p) * .42) * fade;
              ctx.strokeStyle = signalRgba(kind, kind === "listener" ? alpha * 1.15 : alpha);
              ctx.lineWidth = reduceMotion ? 1.5 : Math.max(.5, 1.8 - p);
              ctx.stroke();
            }
          }
          if (kind === "crack") {
            // No breathing-ring pulse and no rotating sweep here -- hashcat
            // grinding a wordlist reads as falling matrix-style binary rain
            // instead, the one effect this node gets. Each column trails
            // several digits behind its head (dimming toward the tail) so
            // it reads as a dense stream, not a few scattered dots.
            const DIGITS = "01";
            const columns = 8, trail = 3, step = 8, band = r + 34;
            let seed = 0;
            for (let i = 0; i < n.id.length; i++) seed = (seed * 31 + n.id.charCodeAt(i)) | 0;
            ctx.font = "600 9px ui-monospace,monospace";
            ctx.textAlign = "center"; ctx.textBaseline = "middle";
            for (let c = 0; c < columns; c++) {
              const colX = n.x + (c - (columns - 1) / 2) * 7.5;
              const colPhase = (seed + c * 733) % 997;
              const headPos = reduceMotion ? .5
                : (((now * .06) + colPhase) % (band * 2)) / (band * 2);
              const headY = n.y - band + headPos * band * 2;
              for (let t = 0; t <= trail; t++) {
                const ty = headY - t * step;
                const relPos = (ty - (n.y - band)) / (band * 2);
                if (relPos < 0 || relPos > 1) continue;
                const edgeFade = Math.min(1, Math.min(relPos, 1 - relPos) * 4);
                const tailFade = 1 - t / (trail + 1);
                const tick = reduceMotion ? 0 : Math.floor(now / 160) + c;
                let h = (seed + c * 97 + t * 41 + tick * 2654435761) | 0;
                h = (h ^ (h >>> 13)) | 0;
                ctx.fillStyle = signalRgba("crack", (.2 + .6 * edgeFade) * tailFade * fade);
                ctx.fillText(DIGITS[Math.abs(h) % 2], colX, ty);
              }
            }
          } else if (!reduceMotion && activity.status !== "queued") {
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
        } else if (pathNodeIds?.has(n.id)) {
          ctx.beginPath(); ctx.arc(n.x, n.y, r + 6, 0, Math.PI * 2);
          ctx.strokeStyle = "rgba(245,197,24,.55)"; ctx.lineWidth = 1.5; ctx.stroke();
        }
        if (isFlag) {
          // A found flag doesn't just get the graph's usual dull "untried"
          // gray -- three slow rings breathing outward in gold, the same
          // way a live scan pulses in its own signal color, so the one
          // node in the whole graph that actually matters keeps drawing
          // the eye back to it instead of reading as just another Draft.
          if (!activityStarted.current.has(`flag:${n.id}`))
            activityStarted.current.set(`flag:${n.id}`, now);
          const fade = Math.min(1, (now - activityStarted.current.get(`flag:${n.id}`)!) / 320);
          ctx.save(); ctx.shadowColor = "#f5c518"; ctx.shadowBlur = 20;
          const period = 2200;
          for (let i = 0; i < (reduceMotion ? 1 : 3); i++) {
            const p = reduceMotion ? .4 : ((now % period) / period + i / 3) % 1;
            const ease = 1 - Math.pow(1 - p, 3);
            ctx.beginPath(); ctx.arc(n.x, n.y, r + 8 + ease * 34, 0, Math.PI * 2);
            ctx.strokeStyle = `rgba(245,197,24,${(1 - ease) * .55 * fade})`;
            ctx.lineWidth = 1.5; ctx.stroke();
          }
          ctx.restore();
        } else activityStarted.current.delete(`flag:${n.id}`);
        if (unlocking && !reduceMotion) {
          // A single ring bursting outward and fading once -- reduceMotion
          // skips it outright rather than freezing it mid-burst, since a
          // static ring frozen at one radius would just look like stray
          // clutter, unlike the other effects' reduced-motion fallbacks
          // (which still convey an ongoing state at rest).
          const p = Math.min(1, unlockElapsed / unlockWindow);
          const ease = 1 - Math.pow(1 - p, 3);
          ctx.save(); ctx.shadowColor = "#ffe9a8"; ctx.shadowBlur = 22;
          ctx.beginPath(); ctx.arc(n.x, n.y, r + 6 + ease * 30, 0, Math.PI * 2);
          ctx.strokeStyle = `rgba(255,225,160,${(1 - ease) * .8})`;
          ctx.lineWidth = 2; ctx.stroke();
          ctx.restore();
        }
        ctx.save();
        ctx.shadowColor = isFlag ? "#f5c518" : activity ? nodeSignal
          : awaitingReview ? color(current.status) : isAnchor ? "#6aa9ff" : color(current.status);
        ctx.shadowBlur = isFlag ? 26 : activity ? 28 : isAnchor ? 30 : isSel ? 24
          : awaitingReview ? 10 : 12;
        ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
        ctx.fillStyle = isFlag ? "#3a2e08" : awaitingReview ? "rgba(0,0,0,0)"
          : signalKind ? FILL_BG[signalKind] : isOperator ? "#123038" : color(current.status);
        ctx.fill();
        ctx.restore();
        ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
        ctx.lineWidth = isFlag ? 2.5 : isSel ? 2.5 : isAnchor || isHost ? 2
          : awaitingReview ? 1.6 : 1;
        ctx.strokeStyle = isFlag ? "#f5c518" : activity ? nodeSignal
          : awaitingReview ? color(current.status)
          : isSel ? "#fff" : isOperator ? "#55d6e8"
          : isAnchor ? "#6aa9ff"
          : isHost ? "rgba(255,255,255,.7)" : "rgba(255,255,255,.35)";
        if (current.hidden) ctx.setLineDash([2, 3]);
        ctx.stroke();
        ctx.setLineDash([]);
        ctx.fillStyle = "#0c0c10"; ctx.textAlign = "center"; ctx.textBaseline = "middle";
        ctx.font = `${Math.round(r * 0.95)}px sans-serif`;
        ctx.fillText(isFlag ? "🚩" : unlockShowsLocked ? "🔒" : unlocking ? "🔓"
          : fileFindingGlyph(current) ?? GLYPH[current.type],
          n.x, n.y + 0.5);
        drawEvidenceBadge(evidenceCount(current), n.x + r * 0.7, n.y - r * 0.7);
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
        if (n.type === "credential"
            && Math.abs(n.x - x) <= 95 && Math.abs(n.y - y) <= 20) return n;
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
      // Confirmed live: right-clicking blank canvas used to fall straight
      // through to the browser's own "이미지를 다른 이름으로 저장…" menu (the
      // canvas is just a raster surface to the browser) since this handler
      // did nothing at all on a miss -- preventDefault has to run
      // unconditionally, not only when a node was actually hit.
      ev.preventDefault();
      const p = toWorld(ev), n = nodeAt(p.x, p.y);
      props.onContext(n ? n.id : null, ev.clientX, ev.clientY);
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
  }, [nodeSet, edgeSet, anchorId, hideRoot, showHidden,
    props.credentialOverlay, props.layoutMode]);

  const activity = buildActivityFeed(data);
  const [fileDragOver, setFileDragOver] = useState(false);
  // The graph's own layout is a force-directed sim pulling every node to a
  // ring by type/stage (see Sim above) -- there's no meaningful "place it
  // at this pixel" position to honor, so a drop anywhere just triggers the
  // same promote-to-finding as the file modal's button; only the file's own
  // drag data decides what happens, not where on the canvas it lands.
  const acceptsFileDrag = (event: ReactDragEvent) =>
    event.dataTransfer.types.includes(FILE_DRAG_MIME);

  return (
    <div style={{ position: "relative", flex: 1, minWidth: 0 }}
      onDragOver={(event) => {
        if (!props.onDropFile || !acceptsFileDrag(event)) return;
        event.preventDefault();
        event.dataTransfer.dropEffect = "copy";
        if (!fileDragOver) setFileDragOver(true);
      }}
      onDragLeave={(event) => {
        if (event.currentTarget.contains(event.relatedTarget as Node)) return;
        setFileDragOver(false);
      }}
      onDrop={(event) => {
        setFileDragOver(false);
        if (!props.onDropFile || !acceptsFileDrag(event)) return;
        event.preventDefault();
        const raw = event.dataTransfer.getData(FILE_DRAG_MIME);
        if (!raw) return;
        try { props.onDropFile(JSON.parse(raw) as FileDragPayload); }
        catch { /* malformed payload -- ignore */ }
      }}>
      <canvas ref={canvasRef} style={{ display: "block", width: "100%", height: "100%" }} />
      <ActivityStream items={activity} onSelect={props.onActivitySelect} />
      <div style={S.hint}>
        초록 신호 = 실행 중 · 파란 신호 = 연결됨 · 빨간 신호 = 리스너 대기 · 드래그 / 휠로 이동·확대
      </div>
      {fileDragOver && (
        <div style={S.fileDropOverlay} aria-hidden="true">
          여기에 놓으면 Finding 노드로 추가됩니다
        </div>
      )}
      {props.dropFileBusy && (
        <div style={S.fileDropBusyOverlay} aria-hidden="true">
          파일을 Finding으로 저장하는 중… (원격 세션에서 다시 읽는 중이라 몇 초 걸릴 수 있습니다)
        </div>
      )}
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
    minWidth: panel.collapsed ? 184 : 0,
    maxWidth: "calc(100% - 28px)", maxHeight: "calc(100% - 28px)",
    width: panel.collapsed ? 184 : panel.width,
    height: panel.collapsed ? 34 : panel.height,
  }} aria-label="최근 활동">
    <header style={S.activityHead} onPointerDown={startDrag} onPointerMove={moveDrag}
      onPointerUp={stopDrag} onPointerCancel={stopDrag} title="드래그하여 이동">
      <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <span className="termDots" aria-hidden="true">
          <i className="termDot" /><i className="termDot termDot--yellow" />
          <i className="termDot termDot--green" />
        </span>
        ACTIVITY STREAM
      </span>
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
            <time style={S.activityTime}>
              [{new Date(item.at).toLocaleTimeString("ko-KR", { hour12: false })}]
            </time>
            <span style={{ ...S.activityDot, background: color(item.status) }} />
            <span style={S.activityCopy}>{item.text}
              <span style={S.activityMeta}> — {item.kind.toUpperCase()} · {item.reason}</span>
            </span>
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
