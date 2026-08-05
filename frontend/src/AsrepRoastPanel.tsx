import { useState } from "react";
import { api } from "./api";

export type AsrepExecution = {
  id: number; template_id: string; status: string;
  stdout?: string; stderr?: string;
};

export type AsrepRunState = {
  id?: number; templateId: string; status: string; stdout?: string; stderr?: string;
};

const HASH_FILE = "asrep-hashes.txt";

// AS-REP Roasting needs no credentials at all, only a list of usernames
// (typically harvested from anonymous LDAP enumeration), so — like
// Kerbrute — it lives in its own panel with a direct run() call. The
// resulting hash is written by impacket-GetNPUsers straight to a file
// (-outputfile), not printed cleanly to stdout, so this panel reads that
// file back through the backend rather than parsing stdout.
export default function AsrepRoastPanel({
  target, runState, serviceExecutions, evidenceMsg, wordlistSuggestion,
  onRoast, onCaptureEvidence, onOpenHashcat,
}: {
  target?: { ip: string };
  runState?: AsrepRunState;
  serviceExecutions: AsrepExecution[];
  evidenceMsg: string;
  wordlistSuggestion?: string;
  onRoast: (domain: string, wordlist: string) => void;
  onCaptureEvidence: (
    execution: { id: number; stdout?: string; stderr?: string }, title: string,
  ) => void;
  onOpenHashcat: () => void;
}) {
  const [domain, setDomain] = useState("");
  const [wordlist, setWordlist] = useState("");
  const [fileState, setFileState] = useState<"idle" | "loading" | "loaded" | "missing" | "error">("idle");
  const [fileContent, setFileContent] = useState("");
  const [fileError, setFileError] = useState("");

  const roastRunState = runState?.templateId === "ad-asreproast-impacket" ? runState : undefined;
  const latestRoast = serviceExecutions
    .filter((item) => item.template_id === "ad-asreproast-impacket" && item.status === "completed")
    .sort((a, b) => b.id - a.id)[0];
  const busy = !!roastRunState && ["starting", "running"].includes(roastRunState.status);
  const activeExecution = roastRunState?.id
    ? { id: roastRunState.id, stdout: roastRunState.stdout, stderr: roastRunState.stderr }
    : latestRoast
      ? { id: latestRoast.id, stdout: latestRoast.stdout, stderr: latestRoast.stderr }
      : undefined;
  const activeId = activeExecution?.id;
  const hasHash = fileState === "loaded" && fileContent.includes("$krb5asrep$");

  const checkOutputFile = async () => {
    if (!activeId) return;
    setFileState("loading");
    setFileError("");
    try {
      const data = await api<{ content: string }>(
        `/executions/${activeId}/file?name=${encodeURIComponent(HASH_FILE)}`,
      );
      setFileContent(data.content);
      setFileState(data.content.trim() ? "loaded" : "missing");
    } catch (reason) {
      setFileState("error");
      setFileError(String(reason).replace(/^Error:\s*/, ""));
    }
  };

  return (
    <section className="netexecCredCheck" aria-labelledby="asrep-heading">
      <header>
        <h2 id="asrep-heading">AS-REP Roasting (Impacket)</h2>
      </header>
      <div className="netexecCredForm netexecCredForm--save">
        <input value={domain} onChange={(e) => setDomain(e.target.value)}
          placeholder="도메인 (예: htb.local)" aria-label="도메인" />
        <input value={wordlist} onChange={(e) => setWordlist(e.target.value)}
          placeholder="사용자명 목록 파일 경로" aria-label="사용자명 목록 파일 경로" />
        <button disabled={busy || !domain.trim() || !wordlist.trim()}
          onClick={() => onRoast(domain.trim(), wordlist.trim())}>
          {busy ? "실행 중…" : "AS-REP Roasting 시작"}
        </button>
      </div>
      {wordlistSuggestion && wordlistSuggestion !== wordlist && (
        <button type="button" className="asrepUseSaved"
          onClick={() => setWordlist(wordlistSuggestion)}>
          방금 저장한 목록 사용 ({wordlistSuggestion.split("/").pop()})
        </button>
      )}
      {activeId && (
        <div className="intruderResults">
          <header><div><b>결과 파일</b><span>{HASH_FILE}</span></div>
            <button onClick={() => void checkOutputFile()}>
              {fileState === "loading" ? "확인 중…" : "output 파일 확인하기"}
            </button>
          </header>
          {fileState === "loaded" && <pre>{fileContent}</pre>}
          {fileState === "missing" && <p>파일이 비어 있습니다 — Pre-Auth 미요구 계정이 없거나
            아직 실행이 끝나지 않았을 수 있습니다.</p>}
          {fileState === "error" && <p role="alert">확인 실패: {fileError}</p>}
          {hasHash && <button onClick={onOpenHashcat}>
            AS-REP 해시 → hashcat 명령 준비
          </button>}
          {activeExecution && (
            <button onClick={() => onCaptureEvidence(
              activeExecution, `AS-REP Roasting · ${target?.ip}`,
            )}>Evidence로 저장</button>
          )}
          {evidenceMsg && <p className="netexecEvidenceMsg">{evidenceMsg}</p>}
        </div>
      )}
    </section>
  );
}
