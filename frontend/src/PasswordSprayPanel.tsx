import { useState } from "react";
import { parseNetexecSprayHits } from "./serviceIntel";

export type SprayExecution = {
  id: number; template_id: string; status: string;
  stdout?: string; stderr?: string;
};

export type SprayRunState = {
  id?: number; templateId: string; status: string; stdout?: string; stderr?: string;
};

// A spray needs a username list and a single password, neither of which
// come from the detected service, so — like Kerbrute and AS-REP Roasting —
// it lives in its own panel with a direct run() call. OSCP methodology
// expects every found credential to be tried everywhere, but each attempt
// still risks an account lockout, so this stays a manual, reviewed action
// rather than something that auto-fires after enumeration.
export default function PasswordSprayPanel({
  target, runState, serviceExecutions, evidenceMsg, wordlistSuggestion,
  onSpray, onCaptureEvidence,
}: {
  target?: { ip: string };
  runState?: SprayRunState;
  serviceExecutions: SprayExecution[];
  evidenceMsg: string;
  wordlistSuggestion?: string;
  onSpray: (wordlist: string, password: string) => void;
  onCaptureEvidence: (
    execution: { id: number; stdout?: string; stderr?: string }, title: string,
  ) => void;
}) {
  const [wordlist, setWordlist] = useState("");
  const [password, setPassword] = useState("");
  const sprayRunState = runState?.templateId === "ad-password-spray-netexec" ? runState : undefined;
  const latestSpray = serviceExecutions
    .filter((item) => item.template_id === "ad-password-spray-netexec" && item.status === "completed")
    .sort((a, b) => b.id - a.id)[0];
  const output = sprayRunState?.stdout || latestSpray?.stdout || "";
  const hits = parseNetexecSprayHits(output);
  const busy = !!sprayRunState && ["starting", "running"].includes(sprayRunState.status);
  const activeExecution = sprayRunState?.id
    ? { id: sprayRunState.id, stdout: sprayRunState.stdout, stderr: sprayRunState.stderr }
    : latestSpray
      ? { id: latestSpray.id, stdout: latestSpray.stdout, stderr: latestSpray.stderr }
      : undefined;

  return (
    <section className="netexecCredCheck" aria-labelledby="spray-heading">
      <header>
        <h2 id="spray-heading">패스워드 스프레이 (NetExec)</h2>
        <small>사용자 목록에 비밀번호 하나를 대입합니다. 찾은 모든 자격증명을 모든 서비스에
          시도하는 것은 OSCP 시험 방법론상 허용되는 기법이지만, 대입 자체이므로 계정 잠금
          위험이 있습니다.</small>
      </header>
      <p className="intruderWarning">
        실행 전 대상의 계정 잠금 정책(시도 횟수·기간)을 반드시 확인하세요.
      </p>
      <div className="netexecCredForm netexecCredForm--save">
        <input value={wordlist} onChange={(e) => setWordlist(e.target.value)}
          placeholder="사용자명 목록 파일 경로" aria-label="사용자명 목록 파일 경로" />
        <input value={password} onChange={(e) => setPassword(e.target.value)}
          placeholder="비밀번호 1개" aria-label="비밀번호" />
        <button disabled={busy || !wordlist.trim() || !password.trim()}
          onClick={() => onSpray(wordlist.trim(), password.trim())}>
          {busy ? "스프레이 중…" : "스프레이 시작"}
        </button>
      </div>
      {wordlistSuggestion && wordlistSuggestion !== wordlist && (
        <button type="button" className="asrepUseSaved"
          onClick={() => setWordlist(wordlistSuggestion)}>
          방금 저장한 목록 사용 ({wordlistSuggestion.split("/").pop()})
        </button>
      )}
      {!!hits.length && (
        <div className="intruderResults">
          <header><div><b>유효한 자격증명</b><span>{hits.length}개</span></div>
            {activeExecution && (
              <button onClick={() => onCaptureEvidence(
                activeExecution, `패스워드 스프레이 유효 자격증명 · ${target?.ip}`,
              )}>Evidence로 저장</button>
            )}
          </header>
          {evidenceMsg && <p className="netexecEvidenceMsg">{evidenceMsg}</p>}
          <ul>{hits.map((hit) => <li key={hit}><code>{hit}</code></li>)}</ul>
        </div>
      )}
    </section>
  );
}
