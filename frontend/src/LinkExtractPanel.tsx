import { useState } from "react";
import { parseLinkExtractResults } from "./serviceIntel";

export type LinkExtractExecution = {
  id: number; template_id: string; status: string;
  stdout?: string; stderr?: string;
};
export type LinkExtractRunState = {
  id?: number; templateId: string; status: string; stdout?: string; stderr?: string;
};

const KIND_LABEL: Record<string, string> = {
  page: "페이지", asset: "정적 리소스", absolute: "절대경로", anchor: "앵커",
};
const KIND_ORDER = ["page", "absolute", "asset", "anchor"];

// Every other request UI in this app (Request tab, cURL import) takes a
// full URL pasted straight from the browser, so a bare full URL here would
// otherwise silently glue onto {host}:{port} and produce a malformed URL
// that curl rejects with no visible error — just an empty result list.
const toPath = (value: string): string => {
  const trimmed = value.trim();
  if (!/^https?:\/\//i.test(trimmed)) return trimmed;
  try {
    const url = new URL(trimmed);
    return `${url.pathname}${url.search}` || "/";
  } catch {
    return trimmed;
  }
};

// One fetch of one path — no recursion, no auto-follow. Extends past <a> to
// also cover <script src>/<img src>/<form action>, since those answer the
// same "what does this page point to" question. Deciding whether to look at
// a discovered link is left to the user re-running this with that path;
// the tool never chains into it on its own (OSCP bans automated crawling).
export default function LinkExtractPanel({
  target, service, runState, serviceExecutions, evidenceMsg, onFuzz, onCaptureEvidence,
  onOpenInRequest,
}: {
  target?: { ip: string; hostname?: string };
  service?: { port: number; name: string };
  runState?: LinkExtractRunState;
  serviceExecutions: LinkExtractExecution[];
  evidenceMsg: string;
  onFuzz: (path: string) => void;
  onCaptureEvidence: (
    execution: { id: number; stdout?: string; stderr?: string }, title: string,
  ) => void;
  onOpenInRequest: (url: string) => void;
}) {
  const [path, setPath] = useState("/");
  const fuzzRunState = runState?.templateId === "http-link-extract" ? runState : undefined;
  const latestFuzz = serviceExecutions
    .filter((item) => item.template_id === "http-link-extract" && item.status === "completed")
    .sort((a, b) => b.id - a.id)[0];
  const output = fuzzRunState?.stdout || latestFuzz?.stdout || "";
  const results = parseLinkExtractResults(output)
    .sort((a, b) => KIND_ORDER.indexOf(a.kind) - KIND_ORDER.indexOf(b.kind));
  const hasCompletedRun = fuzzRunState?.status === "completed" || !!latestFuzz;
  const busy = !!fuzzRunState && ["starting", "running"].includes(fuzzRunState.status);
  const activeExecution = fuzzRunState?.id
    ? { id: fuzzRunState.id, stdout: fuzzRunState.stdout, stderr: fuzzRunState.stderr }
    : latestFuzz
      ? { id: latestFuzz.id, stdout: latestFuzz.stdout, stderr: latestFuzz.stderr }
      : undefined;
  const scheme = service?.name.toLowerCase().includes("ssl") ? "https" : "http";
  const base = target && service
    ? `${scheme}://${target.hostname || target.ip}:${service.port}${path}` : "";
  const resolve = (value: string) => {
    try { return new URL(value, base).toString(); } catch { return value; }
  };

  return (
    <section className="netexecCredCheck" aria-labelledby="link-extract-heading">
      <header>
        <h2 id="link-extract-heading">페이지 링크 추출</h2>
      </header>
      <p className="netexecEvidenceMsg">
        입력한 경로 하나에만 요청을 보내 응답 HTML의 href·src·action 값을 그대로 나열합니다.
        발견된 링크를 자동으로 따라 들어가지 않으니, 더 볼 경로는 아래 목록에서 골라 직접 다시 실행하세요.
      </p>
      <div className="netexecCredForm netexecCredForm--save">
        <input value={path} onChange={(e) => setPath(e.target.value)}
          placeholder="경로 또는 전체 URL (예: / 또는 http://unika.htb/index.php?page=french.html)"
          aria-label="경로" />
        <button disabled={busy || !path.trim()}
          onClick={() => { const normalized = toPath(path); setPath(normalized); onFuzz(normalized); }}>
          {busy ? "추출 중…" : "링크 추출"}
        </button>
      </div>
      {!busy && !results.length && hasCompletedRun && (
        <p className="netexecEvidenceMsg">이 경로에서 찾은 링크가 없습니다.</p>
      )}
      {!!results.length && (
        <div className="intruderResults">
          <header><div><b>발견된 링크</b><span>{results.length}개</span></div>
            {activeExecution && (
              <button onClick={() => onCaptureEvidence(
                activeExecution, `링크 추출 · ${target?.ip}${path}`,
              )}>Evidence로 저장</button>
            )}
          </header>
          {evidenceMsg && <p className="netexecEvidenceMsg">{evidenceMsg}</p>}
          <table>
            <thead><tr><th>링크</th><th>유형</th><th></th></tr></thead>
            <tbody>{results.map((item) => (
              <tr key={item.url}>
                <td><code>{item.url}</code></td>
                <td>{KIND_LABEL[item.kind]}</td>
                <td>{(item.kind === "page" || item.kind === "absolute") && (
                  <button onClick={() => onOpenInRequest(resolve(item.url))}>
                    Request 탭에 채우기
                  </button>
                )}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      )}
    </section>
  );
}
