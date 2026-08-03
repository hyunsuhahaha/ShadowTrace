import { useState } from "react";
import { parseFfufVhostResults } from "./serviceIntel";

export type VhostFuzzExecution = {
  id: number; template_id: string; status: string;
  stdout?: string; stderr?: string;
};
export type VhostFuzzRunState = {
  id?: number; templateId: string; status: string; stdout?: string; stderr?: string;
};

// Virtual-host fuzzing (ffuf with a Host-header FUZZ) needs a base domain
// that isn't nmap-derived, so — like directory fuzzing next to it — this
// lives in its own panel with a direct run() call.
export default function VhostFuzzPanel({
  target, runState, serviceExecutions, evidenceMsg, onFuzz, onCaptureEvidence,
}: {
  target?: { ip: string };
  runState?: VhostFuzzRunState;
  serviceExecutions: VhostFuzzExecution[];
  evidenceMsg: string;
  onFuzz: (domain: string, wordlist: string) => void;
  onCaptureEvidence: (
    execution: { id: number; stdout?: string; stderr?: string }, title: string,
  ) => void;
}) {
  const [domain, setDomain] = useState("");
  const [wordlist, setWordlist] = useState(
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt");
  const fuzzRunState = runState?.templateId === "http-vhost-fuzz" ? runState : undefined;
  const latestFuzz = serviceExecutions
    .filter((item) => item.template_id === "http-vhost-fuzz" && item.status === "completed")
    .sort((a, b) => b.id - a.id)[0];
  const output = fuzzRunState?.stdout || latestFuzz?.stdout || "";
  const results = parseFfufVhostResults(output);
  const busy = !!fuzzRunState && ["starting", "running"].includes(fuzzRunState.status);
  const activeExecution = fuzzRunState?.id
    ? { id: fuzzRunState.id, stdout: fuzzRunState.stdout, stderr: fuzzRunState.stderr }
    : latestFuzz
      ? { id: latestFuzz.id, stdout: latestFuzz.stdout, stderr: latestFuzz.stderr }
      : undefined;

  return (
    <section className="netexecCredCheck" aria-labelledby="vhost-heading">
      <header>
        <h2 id="vhost-heading">가상 호스트 퍼징 (ffuf)</h2>
        <small>Host 헤더를 대입해 같은 IP·포트에 라우팅되는 다른 서브도메인을 찾습니다.
          모든 응답을 보여주므로 baseline과 크기가 다른 결과 위주로 확인하세요.</small>
      </header>
      <div className="netexecCredForm netexecCredForm--save">
        <input value={domain} onChange={(e) => setDomain(e.target.value)}
          placeholder="기본 도메인 (예: editor.htb)" aria-label="기본 도메인" />
        <input value={wordlist} onChange={(e) => setWordlist(e.target.value)}
          placeholder="워드리스트 경로" aria-label="워드리스트 경로" />
        <button disabled={busy || !domain.trim() || !wordlist.trim()}
          onClick={() => onFuzz(domain.trim(), wordlist.trim())}>
          {busy ? "탐색 중…" : "퍼징 시작"}
        </button>
      </div>
      {!!results.length && (
        <div className="intruderResults">
          <header><div><b>발견된 가상 호스트</b><span>{results.length}개</span></div>
            {activeExecution && (
              <button onClick={() => onCaptureEvidence(
                activeExecution, `가상 호스트 퍼징 · ${target?.ip}`,
              )}>Evidence로 저장</button>
            )}
          </header>
          {evidenceMsg && <p className="netexecEvidenceMsg">{evidenceMsg}</p>}
          <table>
            <thead><tr><th>호스트</th><th>Status</th><th>크기</th></tr></thead>
            <tbody>{results.map((item) => (
              <tr key={item.name}>
                <td><code>{item.name}.{domain || "<domain>"}</code></td>
                <td>{item.status}</td>
                <td>{item.size}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      )}
    </section>
  );
}
