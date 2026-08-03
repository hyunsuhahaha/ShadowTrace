import { useState } from "react";

// NTLM coercion (xp_dirtree, a malicious .library-ms/.searchConnector-ms
// file, PetitPotam, etc.) is only useful with something listening to catch
// the authentication attempt — Responder is the standard listener for that,
// same "prep a listener in a manual shell" shape as the reverse shell and
// chisel panels next to this one.
export default function ResponderPanel({ onStartListener }: {
  onStartListener: (command: string) => void;
}) {
  const [interfaceName, setInterfaceName] = useState("tun0");

  return (
    <section className="netexecCredCheck" aria-labelledby="responder-heading">
      <header>
        <h2 id="responder-heading">Responder 리스너</h2>
        <small>xp_dirtree, .library-ms 강제 인증, PetitPotam 등으로 유도한 NTLM 인증 시도를
          캡처합니다. NetNTLMv2 해시가 잡히면 Hash Cracking 워크스페이스로 넘겨 크랙하세요.</small>
      </header>
      <div className="netexecCredForm">
        <input value={interfaceName} onChange={(e) => setInterfaceName(e.target.value)}
          placeholder="인터페이스 (예: tun0)" aria-label="인터페이스" />
        <button disabled={!interfaceName.trim()}
          onClick={() => onStartListener(`sudo responder -I ${interfaceName.trim()}`)}>
          리스너 준비 (Responder)
        </button>
      </div>
    </section>
  );
}
