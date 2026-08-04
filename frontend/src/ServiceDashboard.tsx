import type {RunState, Service, Target} from "./enumerationModel";
import {missingServiceFacts, parseScriptObservations, rankInvestigationCommands} from "./serviceIntel";

type Command = {id: string; name: string; risk: string; execution_mode: string};
type Execution = {template_id: string; status: string};
type Props = {
  service?: Service; target?: Target; commands?: Command[]; targetCommands?: Command[];
  executions: Execution[]; runStates: Record<string, RunState>; clock: number;
  onReview: (command: Command) => void;
};

export default function ServiceDashboard({service, target, commands, targetCommands,
  executions, runStates, clock, onReview}: Props) {
  if (!service) return null;
  const observations = parseScriptObservations(service.scripts);
  const missingFacts = missingServiceFacts(service);
  const missingCount = missingFacts.length + (target?.hostname ? 0 : 1)
    + (target?.os_guess ? 0 : 1);
  const completedChecks = executions.filter((item) => item.status === "completed").length;
  const autoCheckState = (templateIds: string[]) => {
    const run = templateIds.map((id) => runStates[id])
      .filter((item): item is RunState => !!item)
      .sort((a, b) => b.startedAt - a.startedAt)[0];
    if (!run) return null;
    if (["starting", "running"].includes(run.status)) {
      const elapsed = Math.max(0, Math.floor((clock - run.startedAt) / 1000));
      return {busy: true, content: <><span className="buttonSpinner"
        aria-hidden="true" />{elapsed}s · 확인 중</>};
    }
    if (run.status === "completed")
      return {busy: false, content: <>값 미확인 · 다른 명령 시도</>};
    if (run.status === "no_response")
      return {busy: false, content: <>결과 없음 · 재시도</>};
    if (["failed", "error", "stopped"].includes(run.status))
      return {busy: false, content: <>실패 · 재시도</>};
    return null;
  };
  const reviewTargetCommand = (id: string) => {
    const command = targetCommands?.find((item) => item.id === id);
    if (command) onReview(command);
  };

  return <section className="serviceIntel" aria-labelledby="service-intel-title">
    <header><div><span>선택한 포트 요약</span>
      <h2 id="service-intel-title">서비스 대시보드</h2></div>
      <strong>{missingCount ? `${missingCount}개 미확인` : "핵심 정보 확인됨"}</strong>
    </header>
    <div className="serviceIntel__facts">
      <dl>
        <div><dt>Target</dt><dd>{target?.ip || "미확인"}</dd></div>
        <div><dt>Hostname</dt><dd className={!target?.hostname ? "unknown" : ""}>{target?.hostname || "미확인"}</dd></div>
        <div><dt>운영체제</dt><dd className={!target?.os_guess ? "unknown" : ""}>{target?.os_guess || "미확인"}</dd></div>
        <div><dt>서비스</dt><dd>{service.name || "unknown"} · {service.port}/{service.protocol}</dd></div>
        <div><dt>제품</dt><dd className={!service.product ? "unknown" : ""}>{service.product || "미확인"}</dd></div>
        <div><dt>버전</dt><dd className={!service.version ? "unknown" : ""}>{service.version || "미확인"}</dd></div>
      </dl>
      <div className="serviceIntel__progress"><span>조사 진행</span>
        <b>{completedChecks}<small>회 완료</small></b>
        <p>실행 기록 {executions.length}개 · 스캔 관찰 {observations.length}개</p>
      </div>
    </div>
    <div className="serviceIntel__lower">
      <section><h3>미확인 항목</h3><div className="missingFacts">
        {!target?.hostname && (() => {
          const state = autoCheckState(["target-hostname-redirect",
            "target-hostname-ntlm", "target-hostname-identity"]);
          return <div><span>Hostname</span><button
            className={state?.busy ? "isChecking" : ""}
            disabled={state?.busy || !targetCommands}
            onClick={() => reviewTargetCommand("target-hostname-redirect")}>
            {state?.content || "자동 확인하기"}</button></div>;
        })()}
        {!target?.os_guess && (() => {
          const state = autoCheckState(["target-os-identity"]);
          return <div><span>운영체제</span><button
            className={state?.busy ? "isChecking" : ""}
            disabled={state?.busy || !targetCommands}
            onClick={() => reviewTargetCommand("target-os-identity")}>
            {state?.content || "자동 확인하기"}</button></div>;
        })()}
        {!!missingFacts.length && (() => {
          const candidates = rankInvestigationCommands("정확한 버전", commands || []);
          const state = autoCheckState(candidates.map((item) => item.id));
          const command = candidates.find((item) => !executions.some((execution) =>
            execution.template_id === item.id && ["completed", "no_response"]
              .includes(execution.status))) || candidates[0];
          return <div><span>{missingFacts.join(" · ")}</span><button
            className={state?.busy ? "isChecking" : ""}
            disabled={state?.busy || !commands}
            onClick={() => command && onReview(command)}>
            {state?.content || "한 번에 확인하기"}</button></div>;
        })()}
        {target?.hostname && target.os_guess && !missingFacts.length &&
          <p>현재 표시할 미확인 항목이 없습니다.</p>}
      </div></section>
      <section><h3>스캔에서 수집한 관찰</h3>
        {observations.length ? observations.map((item) => <details key={item.id}>
          <summary>{item.id}</summary><pre>{item.output}</pre></details>)
          : <p>아직 저장된 NSE 관찰 결과가 없습니다.</p>}
      </section>
      <section><h3>바로 실행할 확인 명령</h3>
        <p>전체 명령을 검토한 후 실행하세요.</p><div>
          {commands?.filter((item) => ["service-version", "service-version-udp",
            "telnet-info", "telnet-banner", "telnet-version-trace"].includes(item.id))
            .slice(0, 3).map((item) => <button key={item.id}
              onClick={() => onReview(item)}>{item.name}</button>)}
        </div></section>
    </div>
  </section>;
}
