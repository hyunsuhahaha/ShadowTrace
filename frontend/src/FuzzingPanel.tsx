import { useState } from "react";
import { parseFeroxbusterResults } from "./serviceIntel";

export type FuzzExecution = {
  id: number; template_id: string; status: string;
  stdout?: string; stderr?: string;
};

export type FuzzRunState = {
  id?: number; templateId: string; status: string; stdout?: string; stderr?: string;
};

// Directory/file fuzzing (feroxbuster) is a single self-contained section —
// unlike the credential store, nothing outside it reads fuzzWordlist/filter,
// so both live here rather than in App.tsx. run()/runState stay in App.tsx
// (shared execution machinery), reached only through onFuzz/runState props.
export default function FuzzingPanel({
  target, service, runState, serviceExecutions, evidenceMsg, onFuzz, onCaptureEvidence,
}: {
  target?: { ip: string };
  service?: { port: number; name: string };
  runState?: FuzzRunState;
  serviceExecutions: FuzzExecution[];
  evidenceMsg: string;
  onFuzz: (wordlist: string, extensions: string) => void;
  onCaptureEvidence: (
    execution: { id: number; stdout?: string; stderr?: string }, title: string,
  ) => void;
}) {
  const [wordlist, setWordlist] = useState("/usr/share/wordlists/dirb/common.txt");
  const [extensions, setExtensions] = useState("");
  const [filter, setFilter] = useState("");
  const [excludeStatus, setExcludeStatus] = useState("");
  const [excludeExt, setExcludeExt] = useState("");
  const fuzzTemplateIds = ["http-directory-fuzz", "http-directory-fuzz-ext"];
  const fuzzRunState = runState && fuzzTemplateIds.includes(runState.templateId) ? runState : undefined;
  const latestFuzz = serviceExecutions
    .filter((item) => fuzzTemplateIds.includes(item.template_id) && item.status === "completed")
    .sort((a, b) => b.id - a.id)[0];
  const output = fuzzRunState?.stdout || latestFuzz?.stdout || "";
  const results = parseFeroxbusterResults(output);
  const excludedStatuses = new Set(
    excludeStatus.split(",").map((code) => code.trim()).filter(Boolean));
  const excludedExtensions = new Set(
    excludeExt.split(",").map((ext) => ext.trim().replace(/^\./, "").toLowerCase()).filter(Boolean));
  const visible = results.filter((item) => {
    if (filter && !`${item.path} ${item.status}`.toLowerCase().includes(filter.toLowerCase()))
      return false;
    if (excludedStatuses.has(String(item.status))) return false;
    const ext = item.path.match(/\.([a-zA-Z0-9]+)$/)?.[1].toLowerCase();
    if (ext && excludedExtensions.has(ext)) return false;
    return true;
  });
  const busy = !!fuzzRunState && ["starting", "running"].includes(fuzzRunState.status);
  const scheme = service?.name.toLowerCase().includes("ssl") ? "https" : "http";
  const activeExecution = fuzzRunState?.id
    ? { id: fuzzRunState.id, stdout: fuzzRunState.stdout, stderr: fuzzRunState.stderr }
    : latestFuzz
      ? { id: latestFuzz.id, stdout: latestFuzz.stdout, stderr: latestFuzz.stderr }
      : undefined;
  return (
    <section className="netexecCredCheck" aria-labelledby="fuzz-heading">
      <header>
        <h2 id="fuzz-heading">디렉터리·파일 퍼징 (feroxbuster)</h2>
      </header>
      <div className="netexecCredForm netexecCredForm--save">
        <select value={wordlist} onChange={(e) => setWordlist(e.target.value)}>
          <option value="/usr/share/wordlists/dirb/small.txt">dirb small (~950개)</option>
          <option value="/usr/share/wordlists/dirb/common.txt">dirb common (~4,600개)</option>
          <option value="/usr/share/wordlists/dirb/big.txt">dirb big (~2만개)</option>
        </select>
        <input value={extensions} onChange={(e) => setExtensions(e.target.value)}
          placeholder="확장자(선택, 예: php,txt,html)" aria-label="확장자" />
        <button disabled={busy} onClick={() => onFuzz(wordlist, extensions.trim())}>
          {busy ? "탐색 중…" : "퍼징 시작"}
        </button>
      </div>
      {!!results.length && (
        <div className="intruderResults">
          <header><div><b>발견된 경로</b><span>{visible.length}/{results.length}개 표시</span></div>
            <input aria-label="결과 필터" value={filter} placeholder="경로, Status 필터"
              onChange={(e) => setFilter(e.target.value)} />
            <input aria-label="제외할 Status" value={excludeStatus} placeholder="제외 Status (예: 404,403)"
              onChange={(e) => setExcludeStatus(e.target.value)} />
            <input aria-label="제외할 확장자" value={excludeExt} placeholder="제외 확장자 (예: png,jpg,css,js)"
              onChange={(e) => setExcludeExt(e.target.value)} />
            {activeExecution && (
              <button onClick={() => onCaptureEvidence(
                activeExecution, `디렉터리 퍼징 · ${target?.ip}:${service?.port}`,
              )}>Evidence로 저장</button>
            )}
          </header>
          {evidenceMsg && <p className="netexecEvidenceMsg">{evidenceMsg}</p>}
          <table>
            <thead><tr><th>경로</th><th>Status</th><th>길이</th><th>단어/줄</th><th></th></tr></thead>
            <tbody>{visible.map((item) => (
              <tr key={item.path}>
                <td><code>{item.path}</code></td>
                <td>{item.status}</td>
                <td>{item.length}</td>
                <td>{item.words}/{item.lines}</td>
                <td><a href={`${scheme}://${target?.ip}:${service?.port}${item.path}`}
                  target="_blank" rel="noreferrer">열기</a></td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      )}
    </section>
  );
}
