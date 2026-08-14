import { useEffect, useState } from "react";

export type DotDotPwnExecution = {
  id: number; template_id: string; status: string;
  stdout?: string; stderr?: string;
};
export type DotDotPwnRunState = {
  id?: number; templateId: string; status: string; stdout?: string; stderr?: string;
};

// http-url module only: give DotDotPwn a URL with the injection point marked
// TRAVERSAL and a text pattern to look for in the response (e.g. "root:" for
// /etc/passwd), matching this app's "fixed, reviewed command" catalog -- no
// freeform argv, just those two values slotted into one pinned invocation.
export default function DotDotPwnPanel({
  target, service, runState, serviceExecutions, evidenceMsg, onFuzz, onCaptureEvidence,
}: {
  target?: { ip: string; hostname?: string };
  service?: { port: number; name: string };
  runState?: DotDotPwnRunState;
  serviceExecutions: DotDotPwnExecution[];
  evidenceMsg: string;
  onFuzz: (url: string, pattern: string) => void;
  onCaptureEvidence: (
    execution: { id: number; stdout?: string; stderr?: string }, title: string,
  ) => void;
}) {
  const [url, setUrl] = useState("");
  const [pattern, setPattern] = useState("");
  useEffect(() => {
    if (!target || !service) return;
    const scheme = service.name.toLowerCase().includes("ssl") ? "https" : "http";
    setUrl(`${scheme}://${target.hostname || target.ip}:${service.port}/TRAVERSAL`);
  }, [target?.ip, target?.hostname, service?.port, service?.name]);
  const fuzzRunState = runState?.templateId === "dotdotpwn-traversal-fuzz" ? runState : undefined;
  const latestFuzz = serviceExecutions
    .filter((item) => item.template_id === "dotdotpwn-traversal-fuzz" && item.status === "completed")
    .sort((a, b) => b.id - a.id)[0];
  const output = fuzzRunState?.stdout || latestFuzz?.stdout || "";
  const busy = !!fuzzRunState && ["starting", "running"].includes(fuzzRunState.status);
  const activeExecution = fuzzRunState?.id
    ? { id: fuzzRunState.id, stdout: fuzzRunState.stdout, stderr: fuzzRunState.stderr }
    : latestFuzz
      ? { id: latestFuzz.id, stdout: latestFuzz.stdout, stderr: latestFuzz.stderr }
      : undefined;
  const ready = url.includes("TRAVERSAL") && !!pattern.trim();

  return (
    <section className="netexecCredCheck" aria-labelledby="dotdotpwn-heading">
      <header>
        <h2 id="dotdotpwn-heading">디렉터리 트래버설 퍼징 (DotDotPwn)</h2>
      </header>
      <p className="netexecEvidenceMsg">
        URL 안의 TRAVERSAL 자리에 여러 깊이의 순회 페이로드를 자동으로 대입합니다.
        응답에 지정한 패턴이 나타나는 첫 요청에서 멈춥니다.
      </p>
      <div className="netexecCredForm netexecCredForm--save">
        <input value={url} onChange={(e) => setUrl(e.target.value)}
          placeholder="URL (TRAVERSAL 토큰 포함, 예: http://host/index.php?page=TRAVERSAL)"
          aria-label="TRAVERSAL 토큰이 포함된 URL" />
        <input value={pattern} onChange={(e) => setPattern(e.target.value)}
          placeholder="응답에서 찾을 패턴 (예: root:)" aria-label="매칭 패턴" />
        <button disabled={busy || !ready} onClick={() => onFuzz(url.trim(), pattern.trim())}>
          {busy ? "퍼징 중…" : "퍼징 시작"}
        </button>
      </div>
      {!!output && (
        <div className="intruderResults">
          <header><div><b>결과</b></div>
            {activeExecution && (
              <button onClick={() => onCaptureEvidence(
                activeExecution, `DotDotPwn 트래버설 퍼징 · ${target?.ip}`,
              )}>Evidence로 저장</button>
            )}
          </header>
          {evidenceMsg && <p className="netexecEvidenceMsg">{evidenceMsg}</p>}
          <pre>{output}</pre>
        </div>
      )}
    </section>
  );
}
