import type {RunState} from "./enumerationModel";
import type {ExecutionSummary} from "./serviceIntel";
import {statusCopy as statusLabel} from "./ui";

export default function LiveOutputPanel({run, elapsed, outcome, output}: {
  run?: RunState; elapsed: number; outcome: ExecutionSummary | null; output: string;
}) {
  return <div className="terminal">
    <div className={`terminalStatus${run ? ` terminalStatus--${run.status}` : ""}`}>
      <span aria-hidden="true" />
      <b>실시간 출력</b>
      <small role="status" aria-live="polite">
        {!run
          ? "명령 실행 대기"
          : `${run.name} · ${statusLabel[run.status] ||
            (run.status === "starting" ? "실행 준비 중" : run.status)} · ${elapsed}초${
            run.exitCode == null ? "" : ` · 종료 코드 ${run.exitCode}`
          }`}
      </small>
    </div>
    {run?.message && <p className="terminalError">{run.message}</p>}
    {outcome && (
      <div className={`executionOutcome executionOutcome--${outcome.tone}`}>
        <b>{outcome.title}</b>
        <span>{outcome.detail}</span>
      </div>
    )}
    <pre>{output}</pre>
  </div>;
}
