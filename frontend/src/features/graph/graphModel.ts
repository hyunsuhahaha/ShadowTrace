import { useEffect, useState } from "react";

// Vertical slice: nmap-derived host/service nodes -> API -> Graph + Outline.
// Types, constants and pure/hook helpers shared across the graph feature's
// files (GraphWorkspace.tsx, GraphCanvas.tsx, Inspector.tsx,
// GraphRequestPanel.tsx, OutlineView.tsx, graphLeaves.tsx).

export type NodeType = "project-root" | "operator" | "host" | "service" | "finding"
  | "technique" | "credential";
export type GraphNode = {
  id: string; type: NodeType; status: string; label: string; objective: boolean;
  source_ref: string; hidden: boolean; meta?: string; created_at?: string; updated_at?: string;
  notes?: string; tags?: string; pinned?: boolean;
};
export type DeepLink = { label: string; open: () => void };
export type GraphEdge = {
  id: string; source: string; target: string; relation: string; status: string;
  label?: string; meta?: string; created_at?: string; updated_at?: string;
};
export type GraphOut = { root_node_id: string | null; nodes: GraphNode[]; edges: GraphEdge[] };
export type GraphFilter = { query: string; type: "all" | NodeType; status: string;
  focusDepth: number; pinnedOnly: boolean };
export type GraphRequestDraft = {
  projectId: number; targetId: number; serviceId: number; url: string;
};
export type CredentialHandoff = {
  // id/username are unset for a handoff with no Credential row behind it
  // yet (e.g. a zip2john hash pulled straight from an archive) -- Hash
  // Cracking's own initialCredentialId/initialUsername props are already
  // optional for exactly this case.
  id?: number; project_id: number; target_id?: number; username?: string; secret: string;
  secret_hint?: string; source_kind?: string; hash_mode_id?: string;
  // The finding/evidence node this hash came from (e.g. a zip2john'd
  // archive) -- lets the resulting crack job parent under it instead of
  // the bare host.
  graph_node_id?: string;
};
export type NodeActivity = {
  kind: "scan" | "execution" | "listener" | "crack" | "shell";
  status: "queued" | "running" | "processing" | "launched";
  label: string; startedAt?: string | null;
};

export type TreeRef = { kind: "ref" | "cycle"; edgeId: string; source: string; target: string };
export type TreeNode = {
  kind: "node"; id: string; path: number[]; type: NodeType; label: string;
  status: string; children: TreeItem[];
};
export type TreeItem = TreeNode | TreeRef;

export const STATUS_COLOR: Record<string, string> = {
  untried: "#8b8b93", "in-progress": "#f5a524", "attempt-failed": "#e5484d",
  succeeded: "#30a46c", blocked: "#8e4ec6", "not-applicable": "#5a5a60",
};
export const STATUS_LABEL: Record<string, string> = {
  untried: "미시도", "in-progress": "진행중", "attempt-failed": "실패",
  succeeded: "성공", blocked: "차단", "not-applicable": "N/A",
};
export const STATUS_REASON: Record<string, string> = {
  untried: "준비됨", "in-progress": "실행 중",
  "attempt-failed": "실패 후 재시도 가능", succeeded: "완료",
  blocked: "선행 정보 부족", "not-applicable": "적용 불가",
};
export const LINK_KIND_LABEL: Record<string, string> = {
  page: "페이지", asset: "정적 리소스", absolute: "절대경로", anchor: "앵커",
};
export const LINK_KIND_ORDER = ["page", "absolute", "asset", "anchor"];
export const EXECUTION_STATUS_LABEL: Record<string, string> = {
  queued: "대기", running: "실행 중", completed: "완료", failed: "실패",
  interrupted: "중단됨",
};
export const GLYPH: Record<NodeType, string> = {
  "project-root": "◎", operator: "⌁", host: "▣", service: "◉", finding: "◇",
  technique: "⚡", credential: "🔑",
};
export const color = (s: string) => STATUS_COLOR[s] ?? "#8b8b93";

// Both promote-file ("파일 발견: <path>") and promote-download
// ("파일 다운로드: <filename>") title findings with the source filename
// right after a fixed Korean prefix; anything else (a finding created
// another way that just happens to have a path-shaped label) is taken
// as the path itself, unprefixed.
const FILE_FINDING_PREFIX = /^파일 (?:발견|다운로드): (.+)$/;
function findingFileName(node: Pick<GraphNode, "type" | "label">): string | undefined {
  if (node.type !== "finding") return undefined;
  const path = FILE_FINDING_PREFIX.exec(node.label)?.[1] ?? node.label;
  return path.split(/[\\/]/).pop()?.trim() || undefined;
}

// A found flag deserves to look like one instead of blending into every
// other Draft finding at the same dull gray "untried" status -- matches
// the usual OSCP/HTB deliverable filenames.
const FLAG_FILENAME = /^(flag\d*|local|proof|root|user)\.txt$/i;
export function isFlagFinding(node: Pick<GraphNode, "type" | "label">): boolean {
  return FLAG_FILENAME.test(findingFileName(node) ?? "");
}

// A quick per-extension pictogram so a promoted file reads as "this is a
// zip" / "this is a screenshot" at a glance on the canvas instead of every
// file-backed finding collapsing into the same plain finding diamond.
const FILE_KIND_GLYPH: Record<string, string> = {
  zip: "📦", rar: "📦", "7z": "📦", tar: "📦", gz: "📦", tgz: "📦", bz2: "📦", xz: "📦",
  json: "🧾", xml: "🧾", yaml: "🧾", yml: "🧾", csv: "🧾", ini: "🧾", conf: "🧾",
  cfg: "🧾", env: "🧾", toml: "🧾",
  pdf: "📕", doc: "📄", docx: "📄", txt: "📄", log: "📄", md: "📄",
  xls: "📊", xlsx: "📊",
  db: "🗄️", sqlite: "🗄️", sqlite3: "🗄️", sql: "🗄️",
  pem: "🔐", key: "🔐", crt: "🔐", cer: "🔐", p12: "🔐", pfx: "🔐", ppk: "🔐",
  jpg: "🖼️", jpeg: "🖼️", png: "🖼️", gif: "🖼️", bmp: "🖼️",
  exe: "⚙️", dll: "⚙️", bin: "⚙️", msi: "⚙️",
  sh: "📜", py: "📜", ps1: "📜", bat: "📜", pl: "📜", php: "📜", rb: "📜",
  html: "🌐", htm: "🌐", css: "🎨", js: "📜", ts: "📜", jsx: "📜", tsx: "📜",
};
export function fileFindingGlyph(node: Pick<GraphNode, "type" | "label">): string | undefined {
  const filename = findingFileName(node);
  const ext = filename?.includes(".") ? filename.split(".").pop()!.toLowerCase() : undefined;
  return ext ? FILE_KIND_GLYPH[ext] : undefined;
}

export function nodeMeta(node: Pick<GraphNode, "meta">): Record<string, any> {
  try { return JSON.parse(node.meta || "{}"); } catch { return {}; }
}

// Set once, server-side, the moment a password-protected archive entry gets
// successfully extracted (see extract_archive_entry) -- a fact about how
// this node came to exist, not an ongoing state, so the canvas only plays
// the one-shot "unlock" effect for a short window after creation rather
// than forever.
export function justUnlockedAt(node: Pick<GraphNode, "meta">): string | undefined {
  const value = nodeMeta(node).unlockedAt;
  return typeof value === "string" ? value : undefined;
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

export function evidenceCount(node: Pick<GraphNode, "meta">): number {
  const value = nodeMeta(node).evidenceCount;
  return typeof value === "number" && Number.isFinite(value) && value > 0
    ? Math.floor(value) : 0;
}

// NodeZero-style elapsed readout, reinterpreted for this project's manual
// workflow: purely a passive wall-clock display against the project's own
// creation time, not a counter tied to automated execution steps.
export function formatElapsed(startIso: string | undefined, nowMs: number): string {
  if (!startIso) return "";
  const start = Date.parse(startIso);
  if (!Number.isFinite(start)) return "";
  const totalSeconds = Math.max(0, Math.floor((nowMs - start) / 1000));
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${hours}:${pad(minutes)}:${pad(seconds)}`;
}

export function credentialBadge(node: Pick<GraphNode, "type" | "label" | "meta">) {
  if (node.type !== "credential") return null;
  const meta = nodeMeta(node);
  const identity = [meta.domain, meta.username || node.label].filter(Boolean).join("\\");
  const cracked = meta.credType === "password" && meta.sourceExecutionKind === "hash_crack_job";
  return {identity: identity || "credential",
    kind: String(meta.credType || "credential").toUpperCase(),
    state: cracked ? "CRACKED" : meta.credType === "hash" ? "CAPTURED" : "READY"};
}

export type ActivityKind = "live" | "service" | "task" | "credential" | "finding" | "target";
export type ActivityItem = { nodeId: string; at: string; text: string; kind: ActivityKind;
  status: string; reason: string };
export type ActivityPanelState = { x?: number; y?: number; width: number; height: number; collapsed: boolean };
export const ACTIVITY_PANEL_KEY = "oscp-graph-activity-panel";
export const defaultActivityPanel: ActivityPanelState = {
  width: 380, height: 340, collapsed: false,
};

export function clampActivityPanel(x: number, y: number, width: number, height: number,
  boundsWidth: number, boundsHeight: number) {
  const resizeHandleClearance = 28;
  return { x: Math.max(0, Math.min(x, Math.max(0, boundsWidth - width - resizeHandleClearance))),
    y: Math.max(0, Math.min(y, Math.max(0, boundsHeight - height - resizeHandleClearance))) };
}

export function readActivityPanel(): ActivityPanelState {
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
        : activity.kind === "shell" ? "connected" : "started"}`,
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

export type ActivityStatusFilter = "all" | "running" | "review" | "failed" | "complete";
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
    if (!value || !["scan", "execution", "listener", "crack", "shell"].includes(value.kind)
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

export function useActiveProjectId(): number | null {
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

export type Sim = GraphNode & { x: number; y: number; vx: number; vy: number };
export type GraphPosition = { x: number; y: number };

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

// BloodHound-style "shortest path to the goal", scoped to this graph: BFS over
// edges treated as undirected (same connectivity rule filterGraph's focusDepth
// already uses), from `fromId` to the nearest node flagged `objective`. Not a
// recommendation or an automated judgment -- purely a reachability trace over
// relations a human already recorded.
export type ObjectivePath = { nodeIds: string[]; edgeIds: string[] };
export function pathToObjective(data: GraphOut, fromId: string): ObjectivePath | null {
  if (!data.nodes.some((node) => node.id === fromId)) return null;
  const objectiveIds = new Set(data.nodes.filter((node) => node.objective).map((node) => node.id));
  if (!objectiveIds.size) return null;
  if (objectiveIds.has(fromId)) return { nodeIds: [fromId], edgeIds: [] };
  const cameFrom = new Map<string, { node: string; edge: string }>();
  const visited = new Set([fromId]);
  let frontier = [fromId];
  while (frontier.length) {
    const next: string[] = [];
    for (const id of frontier) {
      for (const edge of data.edges) {
        const neighbor = edge.source === id ? edge.target : edge.target === id ? edge.source : null;
        if (neighbor == null || visited.has(neighbor)) continue;
        visited.add(neighbor);
        cameFrom.set(neighbor, { node: id, edge: edge.id });
        if (objectiveIds.has(neighbor)) {
          const nodeIds = [neighbor], edgeIds: string[] = [];
          let cursor = neighbor;
          while (cursor !== fromId) {
            const step = cameFrom.get(cursor)!;
            edgeIds.unshift(step.edge); nodeIds.unshift(step.node);
            cursor = step.node;
          }
          return { nodeIds, edgeIds };
        }
        next.push(neighbor);
      }
    }
    frontier = next;
  }
  return null;
}

export const ADD_TYPES: NodeType[] = ["finding", "technique", "credential", "service", "host"];
export const STATUS_ORDER = ["untried", "in-progress", "attempt-failed", "succeeded",
  "blocked", "not-applicable"];
export const RELATIONS = ["discovered", "enumerated", "attempted", "yielded",
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
export const defaultRelation = (src: string, dst: string) =>
  RELATION_DEFAULT[`${src}>${dst}`] ?? "attempted";

export type AddForm = { type: string; label: string; relation: string; status: string };
