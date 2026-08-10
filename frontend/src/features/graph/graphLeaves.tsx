import { useState, type ReactNode } from "react";
import { ADD_TYPES, AddForm, defaultRelation, GraphNode, nodeStatusReason, RELATIONS,
  STATUS_LABEL, STATUS_ORDER } from "./graphModel";
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

export function Tab(props: { on: boolean; onClick: () => void; children: ReactNode }) {
  return (
    <div onClick={props.onClick} style={{
      padding: "6px 14px", borderRadius: 7, cursor: "pointer", fontWeight: 500,
      color: props.on ? "#e7e7ee" : "#9a9aa6",
      background: props.on ? "#1c1c24" : "transparent",
    }}>{props.children}</div>
  );
}

export function Empty(props: { text: string }) {
  return <div style={{ padding: 40, color: "#9a9aa6" }}>{props.text}</div>;
}
