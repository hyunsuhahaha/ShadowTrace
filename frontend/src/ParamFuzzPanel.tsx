import { useState } from "react";
import { parseFfufVhostResults } from "./serviceIntel";

export type ParamFuzzExecution = {
  id: number; template_id: string; status: string;
  stdout?: string; stderr?: string;
};
export type ParamFuzzRunState = {
  id?: number; templateId: string; status: string; stdout?: string; stderr?: string;
};

// GET-parameter fuzzing (ffuf with FUZZ swapped into the query string) needs
// a page path that isn't nmap-derived, so — like vhost fuzzing next to it —
// this lives in its own panel with a direct run() call. Reuses the vhost
// result parser since ffuf's default text output is identical either way.
export default function ParamFuzzPanel({
  target, runState, serviceExecutions, evidenceMsg, onFuzz, onCaptureEvidence,
}: {
  target?: { ip: string };
  runState?: ParamFuzzRunState;
  serviceExecutions: ParamFuzzExecution[];
  evidenceMsg: string;
  onFuzz: (path: string, wordlist: string) => void;
  onCaptureEvidence: (
    execution: { id: number; stdout?: string; stderr?: string }, title: string,
  ) => void;
}) {
  const [path, setPath] = useState("/index.php");
  const [wordlist, setWordlist] = useState(
    "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt");
  const fuzzRunState = runState?.templateId === "http-param-fuzz" ? runState : undefined;
  const latestFuzz = serviceExecutions
    .filter((item) => item.template_id === "http-param-fuzz" && item.status === "completed")
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
    <section className="netexecCredCheck" aria-labelledby="param-fuzz-heading">
      <header>
        <h2 id="param-fuzz-heading">GET 파라미터 이름 퍼징 (ffuf)</h2>
        <small>지정한 경로에서 워드리스트의 이름을 GET 파라미터로 하나씩 대입합니다.
          page·file·include 같은 파일 포함(LFI) 후보를 찾을 때 씁니다.
          모든 응답을 보여주므로 baseline과 크기가 다른 결과 위주로 확인하세요.</small>
      </header>
      <div className="netexecCredForm netexecCredForm--save">
        <input value={path} onChange={(e) => setPath(e.target.value)}
          placeholder="경로 (예: /index.php)" aria-label="경로" />
        <input value={wordlist} onChange={(e) => setWordlist(e.target.value)}
          placeholder="워드리스트 경로" aria-label="파라미터 워드리스트 경로" />
        <button disabled={busy || !path.trim() || !wordlist.trim()}
          onClick={() => onFuzz(path.trim(), wordlist.trim())}>
          {busy ? "탐색 중…" : "퍼징 시작"}
        </button>
      </div>
      {!!results.length && (
        <div className="intruderResults">
          <header><div><b>반응한 파라미터</b><span>{results.length}개</span></div>
            {activeExecution && (
              <button onClick={() => onCaptureEvidence(
                activeExecution, `GET 파라미터 퍼징 · ${target?.ip}${path}`,
              )}>Evidence로 저장</button>
            )}
          </header>
          {evidenceMsg && <p className="netexecEvidenceMsg">{evidenceMsg}</p>}
          <table>
            <thead><tr><th>파라미터</th><th>Status</th><th>크기</th></tr></thead>
            <tbody>{results.map((item) => (
              <tr key={item.name}>
                <td><code>?{item.name}=</code></td>
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
