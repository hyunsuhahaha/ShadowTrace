import { useEffect, useRef, useState } from "react";
import { parseSmbFiles, type SmbShare, type SmbShareAccess } from "./serviceIntel";

// nmap smb-enum-shares reports "<none>" (no access), "READ", "READ/WRITE" —
// anything containing READ actually got in, so this doesn't need to
// enumerate every exact string nmap might print.
function accessTone(access: string): "open" | "closed" {
  return /read/i.test(access) ? "open" : "closed";
}

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
  targetId, serviceId, shares, shareAccess, activeShare, runState, serviceExecutions,
  onSpider, onViewFile, onLog,
}: {
  targetId?: number;
  serviceId?: number;
  shares: SmbShare[];
  shareAccess?: Record<string, SmbShareAccess>;
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
  const hasAccessData = !!shareAccess && Object.keys(shareAccess).length > 0;

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
      {!hasAccessData && (
        <p className="smbAccessHint">
          설명 칸은 서버가 붙인 이름표일 뿐 접근 가능 여부와 무관합니다. 실제 열려있는지
          확인하려면 <b>SMB 공유별 접근 권한 확인 (nmap)</b> 명령을 실행하거나, 아래에서
          공유별로 직접 접속/재귀 목록을 눌러보세요.
        </p>
      )}
      <div className={`smbShareTable${hasAccessData ? " smbShareTable--withAccess" : ""}`}
        role="table" aria-label="SMB 공유 목록">
        <div role="row" className="smbShareHead">
          <span role="columnheader">공유 이름</span>
          <span role="columnheader">형식</span>
          <span role="columnheader">설명</span>
          {hasAccessData && (
            <span role="columnheader" className="smbAccessCell">접근 권한 (nmap)</span>
          )}
          <span role="columnheader" className="smbActionHead">작업</span>
        </div>
        {shares.map((share) => {
          const access = shareAccess?.[share.name]
            ?? Object.entries(shareAccess ?? {}).find(
              ([name]) => name.toLowerCase() === share.name.toLowerCase())?.[1];
          return (
          <div role="row" key={`${share.name}-${share.type}`}>
            <b role="cell">{share.name}</b>
            <span role="cell">{share.type}</span>
            <span role="cell">{share.comment || "—"}</span>
            {hasAccessData && (
              <span role="cell" className="smbAccessCell">
                {access ? (
                  <span className={`smbAccessBadge smbAccessBadge--${accessTone(access.anonymous)}`}>
                    익명: {access.anonymous}
                  </span>
                ) : "확인 안 됨"}
              </span>
            )}
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
          );
        })}
      </div>
      {connectError && (
        <p className="smbConnectError" role="alert">{connectError}</p>
      )}
      {!!files.length && (
        <div className="smbFileList">
          <b>{activeShare} 재귀 목록 · 파일 {files.length}개</b>
          <p className="smbAccessHint">
            "원문 보기"는 SMB 프로토콜로 파일을 직접 읽어옵니다 — 셸을 거치지 않으므로
            proof.txt/local.txt는 여기서 읽지 말고, 위 "접속" 버튼으로 연 데스크톱 터미널에서
            cat/type으로 캡처하세요.
          </p>
          {files.map((file) => (
            <div key={file.path} className="smbFileRow">
              <code>{file.path}</code>
              <span>{file.size}B</span>
              <button
                title="SMB 프로토콜로 직접 읽습니다 — proof.txt/local.txt는 여기서 읽지 마세요."
                onClick={() => onViewFile(file.path)}>원문 보기</button>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
