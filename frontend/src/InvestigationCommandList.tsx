import type {RunState, Service, Target} from "./enumerationModel";
import {riskLabel} from "./enumerationModel";
import {remainingInvestigationCommands} from "./serviceIntel";
import {statusCopy as statusLabel} from "./ui";

type Command = {
  id: string; name: string; description: string; preview: string; risk: string;
  execution_mode: string;
};
type Execution = {template_id: string; status: string};
type Props = {
  commands: Command[]; executions: Execution[]; target?: Target; service?: Service;
  runStates: Record<string, RunState>; clock: number;
  onReview: (command: Command) => void;
};

export default function InvestigationCommandList({commands, executions, target, service,
  runStates, clock, onReview}: Props) {
  const completedTemplateIds = new Set(executions
    .filter((item) => item.status === "completed")
    .map((item) => item.template_id));
  const investigationCommands = remainingInvestigationCommands(commands, {
    hostname: target?.hostname || "",
    osGuess: target?.os_guess || "",
    product: service?.product || "",
    version: service?.version || "",
    completedTemplateIds,
  });

  return <div className="cards">
    {investigationCommands.map((command) => {
      const run = runStates[command.id];
      const busy = !!run && ["starting", "running"].includes(run.status);
      const elapsed = run
        ? Math.max(0, Math.floor((clock - run.startedAt) / 1000)) : 0;
      return <article key={command.id} className={busy ? "isRunning" : ""}>
        <div>
          {run ? <span className={`commandStatus commandStatus--${run.status}`}>
            {statusLabel[run.status] || (run.status === "starting" ? "실행 준비 중" : run.status)}
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
            {busy ? `실행 중 · ${elapsed}초` : "검토 후 실행 →"}
          </button>
        </div>
      </article>;
    })}
    {!investigationCommands.length && <p className="investigationEmpty">
      이미 확인된 항목을 제외하면 실행할 명령이 없습니다.
    </p>}
  </div>;
}
