import { useEffect, useState, type ReactNode } from "react";
import { ADD_TYPES, AddForm, defaultRelation, formatElapsed, GraphNode, nodeStatusReason,
  RELATIONS, STATUS_LABEL, STATUS_ORDER } from "./graphModel";
import { S } from "./graphStyles";

// Small presentational pieces shared across the graph feature.
// Tab/Empty/OnboardingPane are one-liners left without dedicated tests
// (YAGNI) -- they render incidentally wherever their parent is tested.

export function OnboardingPane(props: { creating: boolean; onCreate: () => void }) {
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


export function TaskQueue(props: { nodes: GraphNode[]; onClose: () => void;
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

export function NodeQuickMenu(props: { node: GraphNode; x: number; y: number; onClose: () => void;
  onOpen: () => void; onAdd: () => void; onPin: () => void; onHide: () => void;
  onDelete: () => void; onStatus: (status: string) => void }) {
  const item = (icon: string, label: string, onClick: () => void, danger = false) =>
    <button style={{ ...S.quickMenuItem, ...(danger ? S.quickMenuDanger : {}) }} onClick={onClick}>
      <span aria-hidden="true" style={{ ...S.quickMenuIcon,
        ...(danger ? S.quickMenuDanger : {}) }}>{icon}</span><span>{label}</span>
    </button>;
  return <div style={S.quickMenuBackdrop} onPointerDown={props.onClose}>
    <menu aria-label={`${props.node.label} 노드 작업`} style={{ ...S.quickMenu,
      left: Math.max(8, Math.min(props.x, window.innerWidth - 244)),
      top: Math.max(8, Math.min(props.y, window.innerHeight - 340)) }}
      onPointerDown={(e) => e.stopPropagation()}>
      <header style={S.quickMenuHead}><b style={S.quickMenuTitle}>{props.node.label}</b>
        <small style={S.quickMenuStatus}>{props.node.type} · {nodeStatusReason(props.node)}</small></header>
      <div style={S.quickMenuGroup}>
        {item("↗", "상세 및 결과 열기", props.onOpen)}
        {item("+", "연결 작업 추가", props.onAdd)}
        {item("★", props.node.pinned ? "북마크 해제" : "북마크", props.onPin)}
      </div>
      <div style={S.quickMenuGroup}>
        {item("▶", "실행 중으로 표시", () => props.onStatus("in-progress"))}
        {item("✓", "완료로 표시", () => props.onStatus("succeeded"))}
      </div>
      <div style={S.quickMenuGroup}>
        {item("−", "그래프에서 숨기기", props.onHide)}
        {props.node.type !== "project-root" && item("×", "노드 제거", props.onDelete, true)}
      </div>
    </menu>
  </div>;
}

export function DeleteNodeDialog(props: { label: string; count?: number; busy?: boolean; error?: string;
  onCancel: () => void; onConfirm: () => void }) {
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !props.busy) props.onCancel();
    };
    addEventListener("keydown", onKey);
    return () => removeEventListener("keydown", onKey);
  }, [props.busy, props.onCancel]);
  return <div style={S.overlay} role="presentation"
    onPointerDown={() => !props.busy && props.onCancel()}>
    <section role="dialog" aria-modal="true" aria-labelledby="delete-node-title"
      style={{width: 420, maxWidth: "calc(100vw - 32px)", marginTop: 80,
        border: "1px solid #5b3034", background: "#101314", padding: 20}}
      onPointerDown={(event) => event.stopPropagation()}>
      <small style={{color: "#ff8a8a", font: "600 9px ui-monospace,monospace",
        letterSpacing: ".08em"}}>DESTRUCTIVE GRAPH ACTION</small>
      <h2 id="delete-node-title" style={{margin: "10px 0 6px", fontSize: 17}}>노드를 제거할까요?</h2>
      <p style={{margin: 0, color: "#8d9b96", fontSize: 12, lineHeight: 1.6}}>
        {props.count && props.count > 1 ? `선택한 ${props.count}개 노드` : `「${props.label}」 노드`}와
        연결 관계가 그래프에서 제거됩니다.
      </p>
      {props.error && <p role="alert" style={{color: "#ff8a8a", fontSize: 11}}>{props.error}</p>}
      <footer style={{display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 20}}>
        <button type="button" autoFocus disabled={props.busy} onClick={props.onCancel}
          style={S.resultAction}>취소</button>
        <button type="button" disabled={props.busy} onClick={props.onConfirm}
          style={{...S.resultAction, borderColor: "#8b4048", color: "#ff9a9a"}}>
          {props.busy ? "제거 중…" : "노드 제거"}
        </button>
      </footer>
    </section>
  </div>;
}


// Right-clicking blank canvas (no node under the cursor) still deserves a
// menu instead of falling through to the browser's own -- just the one
// action that makes sense with no specific node to act on.
export function BlankCanvasQuickMenu(props: { x: number; y: number;
  onClose: () => void; onAdd: () => void; onAddMemo: () => void }) {
  return <div style={S.quickMenuBackdrop} onPointerDown={props.onClose}>
    <menu aria-label="캔버스 작업" style={{ ...S.quickMenu,
      left: Math.max(8, Math.min(props.x, window.innerWidth - 244)),
      top: Math.max(8, Math.min(props.y, window.innerHeight - 340)) }}
      onPointerDown={(e) => e.stopPropagation()}>
      <div style={S.quickMenuGroup}>
        <button style={S.quickMenuItem} onClick={props.onAdd}>
          <span aria-hidden="true" style={S.quickMenuIcon}>+</span><span>노드 추가</span>
        </button>
        <button style={S.quickMenuItem} onClick={props.onAddMemo}>
          <span aria-hidden="true" style={S.quickMenuIcon}>🗒️</span><span>메모 추가</span>
        </button>
      </div>
    </menu>
  </div>;
}

export function AddNodeForm(props: {
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

// Passive wall-clock display, not tied to any automated step -- purely a
// convenience for OSCP+'s 23:45:00 exam window, updated once a second.
export function ElapsedTimer(props: { startIso?: string }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!props.startIso) return;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [props.startIso]);
  const elapsed = formatElapsed(props.startIso, now);
  if (!elapsed) return null;
  return <span style={S.graphControl} title="프로젝트 시작 이후 경과 시간">⏱ {elapsed}</span>;
}

export function Tab(props: { on: boolean; onClick: () => void; children: ReactNode }) {
  return (
    <div onClick={props.onClick} style={{
      padding: "4px 11px", borderRadius: 3, cursor: "pointer", fontSize: 11, fontWeight: 600,
      color: props.on ? "#e7e7ee" : "#9a9aa6",
      background: props.on ? "#1a211d" : "transparent",
    }}>{props.children}</div>
  );
}

export function Empty(props: { text: string }) {
  return <div style={{ padding: 40, color: "#9a9aa6" }}>{props.text}</div>;
}
