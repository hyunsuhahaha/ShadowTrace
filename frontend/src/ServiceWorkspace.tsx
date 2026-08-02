import type {Target} from "./enumerationModel";

export type ServiceDraft = {
  product: string;
  version: string;
  tags: string;
  notes: string;
};

export default function ServiceWorkspace({
  target,
  draft,
  saveState,
  disabled,
  collapsed,
  onDraft,
  onSave,
  onToggle,
}: {
  target?: Target;
  draft: ServiceDraft;
  saveState: "idle" | "saving" | "saved" | "error";
  disabled: boolean;
  collapsed: boolean;
  onDraft: (draft: ServiceDraft) => void;
  onSave: () => void;
  onToggle: () => void;
}) {
  const set = (key: keyof ServiceDraft, value: string) =>
    onDraft({...draft, [key]: value});
  return <section className={`serviceWorkspacePanel${collapsed ? " isCollapsed" : ""}`}>
    <div className="panelTitle">
      <span>서비스 작업 공간</span>
      <button type="button" className="workspaceCollapseButton"
        aria-expanded={!collapsed} onClick={onToggle}>
        {collapsed ? "펼치기 ↑" : "접기 ↓"}
      </button>
    </div>
    {!collapsed && <div className="serviceWorkspaceBody">
      <div className="meta">
        <label>Hostname<b>{target?.hostname || "알 수 없음"}</b></label>
        <label>추정 OS<b>{target?.os_guess || "탐지되지 않음"}</b></label>
      </div>
      <h3>Enumeration 체크리스트</h3>
      {[
        "서비스 Banner 확인", "기본 Credential 정책 검토", "버전 증적 저장",
        "주요 경로 기록", "다음 수동 작업 계획",
      ].map((item, index) => (
        <label className="check" key={item}>
          <input type="checkbox" /><span>{item}</span>
          <small>0{index + 1}</small>
        </label>
      ))}
      <h3>검토한 제품·버전</h3>
      <input value={draft.product} onChange={(event) => set("product", event.target.value)}
        placeholder="예: Linux telnetd" aria-label="검토한 서비스 제품" />
      <input value={draft.version} onChange={(event) => set("version", event.target.value)}
        placeholder="예: 0.17" aria-label="검토한 서비스 버전" />
      <h3>서비스 태그</h3>
      <input value={draft.tags} onChange={(event) => set("tags", event.target.value)}
        placeholder="web, reviewed" />
      <h3>서비스 메모</h3>
      <textarea value={draft.notes} onChange={(event) => set("notes", event.target.value)}
        placeholder="이 포트에 대한 Markdown 메모…" />
      <button onClick={onSave} disabled={disabled || saveState === "saving"}>
        {saveState === "saving" ? "저장 중…" :
          saveState === "saved" ? "저장됨" : "작업 공간 저장"}
      </button>
      {saveState === "error" && <p className="webError" role="alert">
        제품·버전과 작업 공간을 저장하지 못했습니다.
      </p>}
      <div className="warning">
        <b>실행 안내</b>
        <p>명령은 이 Kali 호스트에서 실행됩니다. 허가 범위와 최종 명령을 확인하세요.</p>
      </div>
    </div>}
  </section>;
}
