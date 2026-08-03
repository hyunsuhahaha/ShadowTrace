import { useState } from "react";
import { parseKerbruteResults } from "./serviceIntel";

export type KerbruteExecution = {
  id: number; template_id: string; status: string;
  stdout?: string; stderr?: string;
};

export type KerbruteRunState = {
  id?: number; templateId: string; status: string; stdout?: string; stderr?: string;
};

// Kerberos username enumeration (kerbrute userenum) needs a domain and a
// username wordlist neither of which come from the detected service, so —
// like directory fuzzing — it lives in its own panel with a direct run()
// call instead of the generic reviewed-command list.
export default function KerbruteEnumPanel({
  target, service, runState, serviceExecutions, evidenceMsg, wordlistSuggestion,
  onEnum, onCaptureEvidence,
}: {
  target?: { ip: string };
  service?: { port: number; name: string };
  runState?: KerbruteRunState;
  serviceExecutions: KerbruteExecution[];
  evidenceMsg: string;
  wordlistSuggestion?: string;
  onEnum: (domain: string, wordlist: string) => void;
  onCaptureEvidence: (
    execution: { id: number; stdout?: string; stderr?: string }, title: string,
  ) => void;
}) {
  const [domain, setDomain] = useState("");
  const [wordlist, setWordlist] = useState("/usr/share/seclists/Usernames/top-usernames-shortlist.txt");
  const enumRunState = runState?.templateId === "kerberos-user-enum-kerbrute" ? runState : undefined;
  const latestEnum = serviceExecutions
    .filter((item) => item.template_id === "kerberos-user-enum-kerbrute" && item.status === "completed")
    .sort((a, b) => b.id - a.id)[0];
  const output = enumRunState?.stdout || latestEnum?.stdout || "";
  const usernames = parseKerbruteResults(output);
  const busy = !!enumRunState && ["starting", "running"].includes(enumRunState.status);
  const activeExecution = enumRunState?.id
    ? { id: enumRunState.id, stdout: enumRunState.stdout, stderr: enumRunState.stderr }
    : latestEnum
      ? { id: latestEnum.id, stdout: latestEnum.stdout, stderr: latestEnum.stderr }
      : undefined;
  return (
    <section className="netexecCredCheck" aria-labelledby="kerbrute-heading">
      <header>
        <h2 id="kerbrute-heading">사용자명 열거 (kerbrute)</h2>
        <small>비밀번호를 대입하지 않고 Kerberos Pre-Auth 응답만으로 존재하는 계정명을 확인합니다.
          계정 잠금을 유발하지 않습니다.</small>
      </header>
      <div className="netexecCredForm netexecCredForm--save">
        <input value={domain} onChange={(e) => setDomain(e.target.value)}
          placeholder="도메인 (예: corp.local)" aria-label="도메인" />
        <input value={wordlist} onChange={(e) => setWordlist(e.target.value)}
          placeholder="사용자명 워드리스트 경로" aria-label="사용자명 워드리스트 경로" />
        <button disabled={busy || !domain.trim() || !wordlist.trim()}
          onClick={() => onEnum(domain.trim(), wordlist.trim())}>
          {busy ? "열거 중…" : "열거 시작"}
        </button>
      </div>
      {wordlistSuggestion && wordlistSuggestion !== wordlist && (
        <button type="button" className="asrepUseSaved"
          onClick={() => setWordlist(wordlistSuggestion)}>
          방금 저장한 목록 사용 ({wordlistSuggestion.split("/").pop()})
        </button>
      )}
      {!!usernames.length && (
        <div className="intruderResults">
          <header><div><b>확인된 사용자명</b><span>{usernames.length}개</span></div>
            {activeExecution && (
              <button onClick={() => onCaptureEvidence(
                activeExecution, `Kerberos 사용자명 열거 · ${target?.ip}:${service?.port}`,
              )}>Evidence로 저장</button>
            )}
          </header>
          {evidenceMsg && <p className="netexecEvidenceMsg">{evidenceMsg}</p>}
          <ul>{usernames.map((name) => <li key={name}><code>{name}</code></li>)}</ul>
        </div>
      )}
    </section>
  );
}
