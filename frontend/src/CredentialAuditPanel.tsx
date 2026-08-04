import {forwardRef, useState} from "react";
import {parseCandidates} from "./credentialCandidates";
import {summarizeCredentialAudit} from "./credentialAuditResult";
import {getDbExplorationGuide} from "./dbExplorationCommands";
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
  command?: string;
  variables?: Record<string, string>;
};

const BLANK_TOKEN = "빈 값";
// Commands only take the edited candidates when their own template
// actually has a place to put them — every other command in this panel
// (nmap's own brute/empty-password scripts) just ignores extra variables.
const needsCandidates = (command: AuditCommand) =>
  !!command.command?.includes("{username}") && command.command.includes("{password}");

type Props = {
  profile: AuditProfile;
  serviceName?: string;
  commands: AuditCommand[];
  runStates: Record<string, RunState>;
  clock: number;
  onReview: (command: AuditCommand) => void;
  onOpenTerminal?: (username: string) => void;
};

const CredentialAuditPanel = forwardRef<HTMLElement, Props>(function CredentialAuditPanel({
  profile,
  serviceName,
  commands,
  runStates,
  clock,
  onReview,
  onOpenTerminal,
}, ref) {
  const [userText, setUserText] = useState(() => profile.identities.replaceAll(" · ", "\n"));
  const [passwordText, setPasswordText] = useState(() => profile.secrets.replaceAll(" · ", "\n"));
  const [copiedCommand, setCopiedCommand] = useState<string>();
  if (!commands.length) return null;

  const explorationGuide = getDbExplorationGuide(serviceName);
  const copyCommand = async (value: string) => {
    await navigator.clipboard.writeText(value);
    setCopiedCommand(value);
    window.setTimeout(() => setCopiedCommand((current) =>
      current === value ? undefined : current), 1500);
  };

  const userCandidates = parseCandidates(userText);
  const passwordCandidates = parseCandidates(passwordText)
    .map((value) => value === BLANK_TOKEN ? "" : value);
  const combinationCount = userCandidates.length * passwordCandidates.length;
  const review = (command: AuditCommand) => onReview(needsCandidates(command)
    ? {...command, variables: {
        username: userCandidates.join(","), password: passwordCandidates.join(","),
      }}
    : command);

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
      <label><b>{profile.identityLabel}</b>
        <textarea value={userText} onChange={(event) => setUserText(event.target.value)}
          placeholder="한 줄에 하나씩" rows={3} /></label>
      <label><b>{profile.secretLabel}</b>
        <textarea value={passwordText} onChange={(event) => setPasswordText(event.target.value)}
          placeholder={`빈 비밀번호는 "${BLANK_TOKEN}"이라고 쓰세요`} rows={3} /></label>
      <small>{profile.limits} · 편집한 후보는 직접 대입 명령에만 적용됩니다 · {userCandidates.length}
        × {passwordCandidates.length} = {combinationCount}개 조합</small>
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
            <span className={needsCandidates(command)
              ? "credentialSource credentialSource--live" : "credentialSource"}>
              {needsCandidates(command) ? "↑ 위 후보 사용" : "고정 검사 (후보 미반영)"}
            </span>
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
          {needsCandidates(command) && combinationCount > 40 && (
            <small className="credentialOverLimit">
              {userCandidates.length} × {passwordCandidates.length}개 조합은 스크립트 상한(40개)을 초과해 실행이 거부됩니다. 후보를 줄이세요.
            </small>
          )}
          <button disabled={busy || (needsCandidates(command) &&
            (combinationCount > 40 || !userCandidates.length || !passwordCandidates.length))}
            onClick={() => review(command)}>
            {busy ? "대입 중…" : "대입 공격 검토·실행"}
          </button>
          {summary && (
            <section className={`credentialResult credentialResult--${summary.status}`}>
              <b>{summary.label}</b>
              {summary.status === "exposed" && summary.credential && onOpenTerminal && (
                <div className="credentialTerminalLaunch">
                  <button onClick={() => onOpenTerminal(summary.credential!.username)}>
                    터미널 열기
                  </button>
                  <small>
                    비밀번호 프롬프트가 뜨면 {summary.credential.password
                      ? `"${summary.credential.password}"를 입력하세요` : "그냥 Enter를 누르세요 (빈 비밀번호)"}
                  </small>
                </div>
              )}
              {summary.status === "exposed" && explorationGuide && (
                <details className="credentialExplorationGuide">
                  <summary>{explorationGuide.title} · 접속 후 입력할 명령</summary>
                  {explorationGuide.commands.map((item) => (
                    <div className="credentialExplorationRow" key={item.label}>
                      <div>
                        <b>{item.label}</b>
                        <code>{item.command}</code>
                        {item.note && <small>{item.note}</small>}
                      </div>
                      <button type="button" onClick={() => void copyCommand(item.command)}>
                        {copiedCommand === item.command ? "복사됨" : "복사"}
                      </button>
                    </div>
                  ))}
                </details>
              )}
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
