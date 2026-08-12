import type {RunState, Service, Target} from "./enumerationModel";
import {riskLabel} from "./enumerationModel";
import {remainingInvestigationCommands} from "./serviceIntel";
import {statusCopy as statusLabel} from "./ui";

type Command = {
  id: string; name: string; description: string; preview: string; risk: string;
  execution_mode: string;
};
type Execution = {
  id: number; template_id: string; status: string; stdout?: string; stderr?: string;
};
type Props = {
  commands: Command[]; executions: Execution[]; target?: Target; service?: Service;
  runStates: Record<string, RunState>; clock: number;
  onReview: (command: Command) => void;
};

export default function InvestigationCommandList({commands, executions, target, service,
  runStates, clock, onReview}: Props) {
  // Hostname/OS/version prompts still drop off once the fact is known some
  // other way — but everything else (Actuator probes, git-dumper, etc.)
  // stays listed after it runs so its result is visible instead of the card
  // just vanishing with no trace.
  const investigationCommands = remainingInvestigationCommands(commands, {
    hostname: target?.hostname || "",
    osGuess: target?.os_guess || "",
    product: service?.product || "",
    version: service?.version || "",
    completedTemplateIds: new Set(),
  });

  if (!investigationCommands.length) return <p className="investigationEmpty">
    operation queue 밖의 추가 명령이 없습니다.
  </p>;

  return <details className="investigationCatalog">
    <summary><span>&gt; additional command catalog</span>
      <small>{investigationCommands.length} commands · 필요할 때 확장</small></summary>
    <div className="cards">
    {investigationCommands.map((command) => {
      const run = runStates[command.id];
      const busy = !!run && ["starting", "running"].includes(run.status);
      const elapsed = run
        ? Math.max(0, Math.floor((clock - run.startedAt) / 1000)) : 0;
      const latestExecution = executions
        .filter((item) => item.template_id === command.id)
        .sort((a, b) => b.id - a.id)[0];
      return <article key={command.id} className={busy ? "isRunning" : ""}>
        <div>
          {run ? <span className={`commandStatus commandStatus--${run.status}`}>
            {statusLabel[run.status] || (run.status === "starting" ? "실행 준비 중" : run.status)}
          </span> : latestExecution ? <span
            className={`commandStatus commandStatus--${latestExecution.status}`}>
            {statusLabel[latestExecution.status] || latestExecution.status}
          </span> : <span className="badge">
            위험: {riskLabel[command.risk] || command.risk}
          </span>}
          <h3>{command.name}</h3>
          <p>{command.description}</p>
        </div>
        <code>{command.preview}</code>
        <div className="actions">
          <button onClick={() => navigator.clipboard.writeText(command.preview)}>복사</button>
          <button className="primary" disabled={busy} onClick={() => onReview(command)}>
            {busy ? `실행 중 · ${elapsed}초` : latestExecution ? "다시 실행" : "검토 후 실행 →"}
          </button>
        </div>
        {!busy && latestExecution && <details className="investigationResult">
          <summary>결과 보기</summary>
          <pre>{latestExecution.stdout || latestExecution.stderr || "출력 없음"}</pre>
        </details>}
      </article>;
    })}
    </div>
  </details>;
}
