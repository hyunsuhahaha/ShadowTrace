import { useState } from "react";
import { parseGobusterDnsResults } from "./serviceIntel";

export type DnsFuzzExecution = {
  id: number; template_id: string; status: string;
  stdout?: string; stderr?: string;
};
export type DnsFuzzRunState = {
  id?: number; templateId: string; status: string; stdout?: string; stderr?: string;
};

// gobuster dns queries the DNS server directly (via the system resolver),
// so — like vhost fuzzing next to it — this needs a domain that isn't
// nmap-derived and lives in its own panel with a direct run() call.
export default function DnsSubdomainPanel({
  target, runState, serviceExecutions, evidenceMsg, onFuzz, onCaptureEvidence,
}: {
  target?: { ip: string };
  runState?: DnsFuzzRunState;
  serviceExecutions: DnsFuzzExecution[];
  evidenceMsg: string;
  onFuzz: (domain: string, wordlist: string) => void;
  onCaptureEvidence: (
    execution: { id: number; stdout?: string; stderr?: string }, title: string,
  ) => void;
}) {
  const [domain, setDomain] = useState("");
  const [wordlist, setWordlist] = useState(
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt");
  const fuzzRunState = runState?.templateId === "dns-subdomain-enum" ? runState : undefined;
  const latestFuzz = serviceExecutions
    .filter((item) => item.template_id === "dns-subdomain-enum" && item.status === "completed")
    .sort((a, b) => b.id - a.id)[0];
  const output = fuzzRunState?.stdout || latestFuzz?.stdout || "";
  const results = parseGobusterDnsResults(output);
  const busy = !!fuzzRunState && ["starting", "running"].includes(fuzzRunState.status);
  const activeExecution = fuzzRunState?.id
    ? { id: fuzzRunState.id, stdout: fuzzRunState.stdout, stderr: fuzzRunState.stderr }
    : latestFuzz
      ? { id: latestFuzz.id, stdout: latestFuzz.stdout, stderr: latestFuzz.stderr }
      : undefined;

  return (
    <section className="netexecCredCheck" aria-labelledby="dns-subdomain-heading">
      <header>
        <h2 id="dns-subdomain-heading">서브도메인 브루트포스 (gobuster dns)</h2>
      </header>
      <div className="netexecCredForm netexecCredForm--save">
        <input value={domain} onChange={(e) => setDomain(e.target.value)}
          placeholder="도메인 (예: corp.local)" aria-label="도메인" />
        <input value={wordlist} onChange={(e) => setWordlist(e.target.value)}
          placeholder="워드리스트 경로" aria-label="워드리스트 경로" />
        <button disabled={busy || !domain.trim() || !wordlist.trim()}
          onClick={() => onFuzz(domain.trim(), wordlist.trim())}>
          {busy ? "탐색 중…" : "탐색 시작"}
        </button>
      </div>
      <p className="netexecEvidenceMsg">
        시스템에 설정된 DNS 리졸버로 질의합니다 — VPN 패널에서 이 대상을 DNS로 지정한 뒤 실행하세요.
      </p>
      {!!results.length && (
        <div className="intruderResults">
          <header><div><b>발견된 서브도메인</b><span>{results.length}개</span></div>
            {activeExecution && (
              <button onClick={() => onCaptureEvidence(
                activeExecution, `서브도메인 브루트포스 · ${target?.ip}`,
              )}>Evidence로 저장</button>
            )}
          </header>
          {evidenceMsg && <p className="netexecEvidenceMsg">{evidenceMsg}</p>}
          <table>
            <thead><tr><th>호스트</th><th>IP</th></tr></thead>
            <tbody>{results.map((item) => (
              <tr key={item.name}>
                <td><code>{item.name}</code></td>
                <td>{item.ip || "—"}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      )}
    </section>
  );
}
