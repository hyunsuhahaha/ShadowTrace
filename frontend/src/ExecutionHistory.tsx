import {summarizeExecutionResult} from "./serviceIntel";
import {statusCopy as statusLabel} from "./ui";
import OutputColumnExtractor from "./OutputColumnExtractor";

export type ExecutionRecord = {
  id: number;
  template_id: string;
  status: string;
  command: string;
  started_at: string;
  ended_at?: string;
  exit_code?: number | null;
};

export type ExecutionDetail = {
  status?: string;
  stdout?: string;
  stderr?: string;
  exit_code?: number | null;
};

export default function ExecutionHistory({
  executions,
  view,
  selected,
  detail,
  onView,
  onOpen,
  onStop,
  onDelete,
  onDerived,
}: {
  executions: ExecutionRecord[];
  view: "list" | "detail";
  selected?: ExecutionRecord;
  detail?: ExecutionDetail;
  onView: (view: "list" | "detail") => void;
  onOpen: (id: number) => void;
  onStop: () => void;
  onDelete: (id: number) => void;
  onDerived?: (filePath: string) => void;
}) {
  const outcome = selected && detail
    ? summarizeExecutionResult(
      selected.template_id,
      detail.status || selected.status,
      detail.stdout,
      detail.stderr,
      selected.command,
    )
    : null;

  return <section className="executionPanel">
    <div className="panelTitle">
      <span>실행 이력</span>
      <em>{executions.length}개</em>
    </div>
    <div className="executionTabs" role="tablist" aria-label="실행 이력 보기">
      <button role="tab" aria-selected={view === "list"}
        onClick={() => onView("list")}>목록</button>
      <button role="tab" aria-selected={view === "detail"}
        disabled={!selected} onClick={() => onView("detail")}>상세보기</button>
    </div>
    {view === "list" ? (
      <div className="executionHistory">
        {executions.map((execution) => (
          <div key={execution.id} role="button" tabIndex={0} className="executionRow"
            onClick={() => onOpen(execution.id)}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                onOpen(execution.id);
              }
            }}>
            <b>#{execution.id} {execution.template_id}</b>
            <small>
              {statusLabel[execution.status] || execution.status}
              {execution.exit_code == null ? "" : ` · exit ${execution.exit_code}`}
            </small>
            {!["queued", "running"].includes(execution.status) && (
              <button type="button" className="executionDelete"
                onClick={(e) => {
                  e.stopPropagation();
                  onDelete(execution.id);
                }}>
                삭제
              </button>
            )}
          </div>
        ))}
        {!executions.length && <p>아직 실행 기록이 없습니다.</p>}
      </div>
    ) : selected ? (
      <div className="executionDetail">
        <header>
          <b>#{selected.id} {selected.template_id}</b>
          <span>{statusLabel[detail?.status || selected.status] || selected.status}</span>
        </header>
        {outcome && (
          <div className={`executionOutcome executionOutcome--${outcome.tone}`}>
            <b>{outcome.title}</b>
            <span>{outcome.detail}</span>
          </div>
        )}
        <dl>
          <div><dt>시작</dt><dd>{new Date(selected.started_at).toLocaleString()}</dd></div>
          <div><dt>종료</dt><dd>{selected.ended_at
            ? new Date(selected.ended_at).toLocaleString() : "실행 중"}</dd></div>
          <div><dt>종료 코드</dt><dd>{detail?.exit_code ??
            selected.exit_code ?? "—"}</dd></div>
        </dl>
        <code>{selected.command}</code>
        {detail?.stdout && <details open>
          <summary>표준 출력</summary><pre>{detail.stdout}</pre>
        </details>}
        {detail?.stdout && (
          <OutputColumnExtractor executionId={selected.id} stdout={detail.stdout}
            onSaved={onDerived} />
        )}
        {detail?.stderr && <details>
          <summary>오류 출력</summary><pre>{detail.stderr}</pre>
        </details>}
        {!detail?.stdout && !detail?.stderr && <p>저장된 출력이 없습니다.</p>}
        {["queued", "running"].includes(detail?.status || selected.status) ? (
          <button className="executionStop" onClick={onStop}>실행 중단</button>
        ) : (
          <button className="executionDelete" onClick={() => onDelete(selected.id)}>
            삭제
          </button>
        )}
      </div>
    ) : null}
  </section>;
}
