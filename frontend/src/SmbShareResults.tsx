import { useEffect, useRef, useState } from "react";
import { parseSmbFiles, type SmbShare } from "./serviceIntel";

// Local api helper mirrors App.tsx's until a shared client lands (roadmap P0).
const api = async <T,>(path: string, init?: RequestInit): Promise<T> => {
  const r = await fetch("/api" + path, init);
  if (!r.ok) throw new Error((await r.json()).detail || r.statusText);
  return r.status === 204 ? (null as T) : r.json();
};

export type SmbSpiderRunState = {
  templateId: string; status: string; stdout?: string;
};

export type SmbSpiderExecution = {
  id: number; template_id: string; status: string; stdout?: string;
};

// SMB share connect/spider/view is a single self-contained section — like
// FuzzingPanel, run()/runState stay in App.tsx (shared execution machinery)
// and are only reached through onSpider/onViewFile. Connecting to a share is
// its own async flow (create session, open desktop terminal) that never
// touches run(), so it — and its busy/error state — lives entirely here,
// mirroring useCredentialStore's self-contained save()/remove().
export default function SmbShareResults({
  targetId, serviceId, shares, activeShare, runState, serviceExecutions,
  onSpider, onViewFile, onLog,
}: {
  targetId?: number;
  serviceId?: number;
  shares: SmbShare[];
  activeShare?: string;
  runState?: SmbSpiderRunState;
  serviceExecutions: SmbSpiderExecution[];
  onSpider: (share: string) => void;
  onViewFile: (path: string) => void;
  onLog: (line: string) => void;
}) {
  const [connecting, setConnecting] = useState<string>();
  const [connectError, setConnectError] = useState("");
  const resultsRef = useRef<HTMLElement>(null);

  const latestSpider = serviceExecutions
    .filter((item) => item.template_id === "smb-share-spider" && item.status === "completed")
    .sort((a, b) => b.id - a.id)[0];
  const spiderOutput = runState?.templateId === "smb-share-spider"
    ? runState.stdout || "" : latestSpider?.stdout || "";
  const files = activeShare ? parseSmbFiles(spiderOutput) : [];

  const shareKey = shares.map((share) => `${share.name}:${share.type}`).join("|");
  useEffect(() => {
    if (!shareKey) return;
    requestAnimationFrame(() => resultsRef.current?.scrollIntoView?.({
      behavior: "smooth", block: "start",
    }));
  }, [shareKey]);

  const connect = async (share: string) => {
    if (!targetId || !serviceId) return;
    setConnectError("");
    setConnecting(share);
    try {
      const session = await api<any>("/interactive-sessions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_id: targetId,
          service_id: serviceId,
          template_id: "smb-share-client",
          variables: { share },
          run_as_root: false,
        }),
      });
      // Every other interactive session (SSH/FTP/Telnet) opens in a real Kali
      // desktop terminal; the embedded xterm.js panel used here previously
      // was a one-off that didn't match, and its blank rendering was reported
      // as a bug against the desktop pattern users already expect.
      await api<any>(`/interactive-sessions/${session.id}/desktop`, {
        method: "POST",
      });
      onLog(`[Kali 데스크톱 터미널에서 ${share} 공유에 접속했습니다.]`);
    } catch (reason) {
      setConnectError(
        reason instanceof Error ? reason.message : "SMB 공유 세션을 만들지 못했습니다.",
      );
    } finally {
      setConnecting(undefined);
    }
  };

  if (!shares.length) return null;
  return (
    <section ref={resultsRef} className="smbShareResults"
      aria-labelledby="smb-shares-title">
      <header>
        <div>
          <span>익명 열거 결과</span>
          <h2 id="smb-shares-title">SMB 공유 {shares.length}개</h2>
        </div>
        <small>Disk 공유는 아래에서 바로 접속할 수 있습니다.</small>
      </header>
      <div className="smbShareTable" role="table" aria-label="SMB 공유 목록">
        <div role="row" className="smbShareHead">
          <span role="columnheader">공유 이름</span>
          <span role="columnheader">형식</span>
          <span role="columnheader">설명</span>
          <span role="columnheader">작업</span>
        </div>
        {shares.map((share) => (
          <div role="row" key={`${share.name}-${share.type}`}>
            <b role="cell">{share.name}</b>
            <span role="cell">{share.type}</span>
            <span role="cell">{share.comment || "—"}</span>
            <span role="cell" className="smbShareAction">
              <button
                disabled={share.type.toLowerCase() !== "disk"
                  || connecting === share.name}
                onClick={() => void connect(share.name)}
              >
                {connecting === share.name ? "여는 중…" : "접속"}
              </button>
              <button
                disabled={share.type.toLowerCase() !== "disk"}
                title="smbclient recurse ON; ls로 이 공유의 파일을 재귀적으로 나열합니다."
                onClick={() => onSpider(share.name)}
              >
                재귀 목록
              </button>
            </span>
          </div>
        ))}
      </div>
      {connectError && (
        <p className="smbConnectError" role="alert">{connectError}</p>
      )}
      {!!files.length && (
        <div className="smbFileList">
          <b>{activeShare} 재귀 목록 · 파일 {files.length}개</b>
          {files.map((file) => (
            <div key={file.path} className="smbFileRow">
              <code>{file.path}</code>
              <span>{file.size}B</span>
              <button onClick={() => onViewFile(file.path)}>원문 보기</button>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
