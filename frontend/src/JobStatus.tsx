import type {RunState} from "./enumerationModel";
import {statusCopy as statusLabel} from "./ui";

export default function JobStatus({run, clock, activeCount}: {
  run?: RunState; clock: number; activeCount: number;
}) {
  if (!run) return null;
  const elapsed = Math.max(0, Math.floor((clock - run.startedAt) / 1000));
  return <section className={`jobStatus jobStatus--${run.status}`} aria-live="polite"
    aria-label="현재 명령 실행 상태">
    <span className="jobStatus__dot" aria-hidden="true" />
    <div><b>작업 #{run.id || "준비"} · {statusLabel[run.status] || run.status}</b>
      <small>
        {run.status === "starting" && "실행 요청을 준비하고 있습니다."}
        {run.status === "running" && (run.processAlive
          ? "백엔드가 명령 프로세스 실행을 확인했습니다."
          : "명령을 실행했으며 다음 상태 신호를 기다리고 있습니다.")}
        {run.status === "completed" && "명령 실행과 결과 저장이 완료되었습니다."}
        {run.status === "no_response" && "대상 응답 또는 식별 결과가 없습니다."}
        {["failed", "error"].includes(run.status)
          && (run.message || "명령 실행에 실패했습니다.")}
        {run.status === "stopped" && "명령 실행이 중단되었습니다."}
      </small>
    </div>
    <dl>
      <div><dt>경과 시간</dt><dd>{elapsed < 60 ? `${elapsed}s`
        : `${Math.floor(elapsed / 60)}m ${elapsed % 60}s`}</dd></div>
      <div><dt>프로세스</dt><dd>{run.status === "running"
        ? run.processAlive ? "실행 확인됨" : "확인 중" : "종료됨"}</dd></div>
      <div><dt>마지막 서버 응답</dt><dd>{run.lastEventAt
        ? `${Math.max(0, Math.floor((clock - run.lastEventAt) / 1000))}초 전`
        : "대기 중"}</dd></div>
    </dl>
    {run.status === "running" && run.lastEventAt && clock - run.lastEventAt > 30000
      ? <p className="jobStatus__warning" role="alert">
        30초 이상 서버 상태 신호가 없습니다. 백엔드 연결을 확인하세요.
      </p> : null}
    {activeCount > 1 && <p className="jobStatus__parallelNote">
      다른 작업 {activeCount - 1}개가 백그라운드에서 함께 실행 중입니다.
      아래 실행 모니터에서 전환할 수 있습니다.
    </p>}
  </section>;
}
