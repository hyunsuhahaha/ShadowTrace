import type {RunState} from "./enumerationModel";

export default function ExecutionMonitor({
  runs,
  focusedId,
  now,
  onFocus,
  onStop,
}: {
  runs: RunState[];
  focusedId?: string;
  now: number;
  onFocus: (templateId: string) => void;
  onStop: (templateId: string) => void;
}) {
  if (!runs.length) return null;
  return <aside className="executionMonitor" aria-live="polite"
    aria-label="현재 실행 중인 작업">
    {runs.map((run) => {
      const elapsed = Math.max(0, Math.floor((now - run.startedAt) / 1000));
      const focus = () => onFocus(run.templateId);
      return <div key={run.templateId}
        className={`executionMonitor__job${
          run.templateId === focusedId ? " isFocused" : ""}`}
        role="button" tabIndex={0} aria-label={`${run.name} 작업으로 전환`}
        onClick={focus}
        onKeyDown={(event) => {
          if (event.key === "Enter" || event.key === " ") focus();
        }}>
        <div className="executionMonitor__head">
          <span className="executionMonitor__pulse" aria-hidden="true" />
          <div>
            <b>{run.name}</b>
            <small>{run.status === "starting"
              ? "실행 요청을 보내는 중"
              : run.processAlive
                ? "프로세스 실행 확인됨"
                : "프로세스 상태 확인 중"}</small>
          </div>
          <strong>{elapsed < 60
            ? `${elapsed}초`
            : `${Math.floor(elapsed / 60)}분 ${elapsed % 60}초`}</strong>
        </div>
        <div className="executionMonitor__track" aria-hidden="true"><span /></div>
        <div className="executionMonitor__meta">
          <span>작업 #{run.id || "생성 중"}</span>
          <span>마지막 서버 응답 {run.lastEventAt
            ? `${Math.max(0, Math.floor((now - run.lastEventAt) / 1000))}초 전`
            : "대기 중"}</span>
          {run.status === "running" && run.id && (
            <button onClick={(event) => {
              event.stopPropagation();
              onStop(run.templateId);
            }}>작업 중단</button>
          )}
        </div>
        {run.lastEventAt && now - run.lastEventAt > 30000 && (
          <p role="alert">30초 이상 상태 신호가 없습니다. 연결 또는 백엔드 상태를 확인하세요.</p>
        )}
      </div>;
    })}
  </aside>;
}
