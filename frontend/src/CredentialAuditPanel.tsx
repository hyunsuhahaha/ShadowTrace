import {forwardRef} from "react";
import {summarizeCredentialAudit} from "./credentialAuditResult";
import type {RunState} from "./enumerationModel";
import {statusCopy as statusLabel} from "./ui";

type AuditProfile = {
  title: string;
  description: string;
  identityLabel: string;
  identities: string;
  secretLabel: string;
  secrets: string;
  limits: string;
};

type AuditCommand = {
  id: string;
  name: string;
  description: string;
  risk: string;
};

type Props = {
  profile: AuditProfile;
  serviceName?: string;
  commands: AuditCommand[];
  runStates: Record<string, RunState>;
  clock: number;
  onReview: (command: AuditCommand) => void;
};

const CredentialAuditPanel = forwardRef<HTMLElement, Props>(function CredentialAuditPanel({
  profile,
  serviceName,
  commands,
  runStates,
  clock,
  onReview,
}, ref) {
  if (!commands.length) return null;

  return <section ref={ref} className="credentialAudit"
    aria-labelledby="credential-audit-title">
    <header>
      <div>
        <span>프로토콜별 인증 점검</span>
        <h2 id="credential-audit-title">{profile.title}</h2>
      </div>
      <strong>선택한 {serviceName || "서비스"}에만 실행</strong>
    </header>
    <p>
      {profile.description} 각 작업은 자동 실행되지 않으며 전체 명령과 잠금 위험을
      검토한 뒤 시작됩니다.
    </p>
    <a className="intruderLaunch" href="#web">
      <span>HTTP 요청 후보를 직접 구성하려면</span>
      <b>Web Testing · Intruder 열기 →</b>
    </a>
    <div className="credentialDataset">
      <div><b>{profile.identityLabel}</b><code>{profile.identities}</code></div>
      <div><b>{profile.secretLabel}</b><code>{profile.secrets}</code></div>
      <small>{profile.limits}</small>
    </div>
    <div className="credentialActions">
      {commands.map((command) => {
        const run = runStates[command.id];
        const busy = !!run && ["starting", "running"].includes(run.status);
        const elapsed = run
          ? Math.max(0, Math.floor((clock - run.startedAt) / 1000)) : 0;
        const summary = run?.status === "completed" && run.stdout != null
          ? summarizeCredentialAudit(command.id, run.stdout, run.stderr || "")
          : null;
        const output = run ? `${run.stdout || ""}${run.stderr || ""}` : "";
        return <article key={command.id} className={busy ? "isRunning" : ""}
          aria-busy={busy}>
          <div>
            <b>{command.name}</b>
            <small>{command.description}</small>
            {run && (
              <span className={`credentialRun credentialRun--${run.status}`}>
                <i aria-hidden="true" />
                {busy
                  ? `${run.status === "starting" ? "실행 준비" : "프로세스 실행 중"} · ${elapsed}초`
                  : `${statusLabel[run.status] || run.status} · ${elapsed}초`}
              </span>
            )}
          </div>
          <span className={`credentialRisk credentialRisk--${command.risk}`}>
            {command.risk === "high" ? "잠금 위험" : "노출 확인"}
          </span>
          <button disabled={busy} onClick={() => onReview(command)}>
            {busy ? "대입 중…" : "대입 공격 검토·실행"}
          </button>
          {summary && (
            <section className={`credentialResult credentialResult--${summary.status}`}>
              <b>{summary.label}</b>
              <details>
                <summary>검사 원문 보기</summary>
                <pre>{output || "명령이 출력 없이 완료되었습니다."}</pre>
              </details>
            </section>
          )}
        </article>;
      })}
    </div>
  </section>;
});

export default CredentialAuditPanel;
