import { useState } from "react";

// NTLM coercion (xp_dirtree, a malicious .library-ms/.searchConnector-ms
// file, PetitPotam, etc.) is only useful with something listening to catch
// the authentication attempt — Responder is the standard listener for that.
// Unlike the manual-shell panels next to this one, it needs to keep running
// while the tester works in other tabs to trigger the coercion, so it opens
// in a real desktop terminal window (not this app's in-page xterm panel,
// which disappears whenever the SPA navigates away from this screen).
export default function ResponderPanel({ onStartListener }: {
  onStartListener: (interfaceName: string) => void;
}) {
  const [interfaceName, setInterfaceName] = useState("tun0");

  return (
    <section className="netexecCredCheck" aria-labelledby="responder-heading">
      <header>
        <h2 id="responder-heading">Responder 리스너</h2>
      </header>
      <div className="netexecCredForm">
        <input value={interfaceName} onChange={(e) => setInterfaceName(e.target.value)}
          placeholder="인터페이스 (예: tun0)" aria-label="인터페이스" />
        <button disabled={!interfaceName.trim()}
          onClick={() => onStartListener(interfaceName.trim())}>
          리스너 준비 (Responder)
        </button>
      </div>
      <p className="netexecEvidenceMsg">
        Kali 데스크톱에 별도 터미널 창을 열어 실행합니다 — 다른 탭으로 이동해도 계속 실행됩니다.
      </p>
    </section>
  );
}
