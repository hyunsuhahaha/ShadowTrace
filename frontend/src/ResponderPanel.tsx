import { useState } from "react";
import { useQuery } from "@tanstack/react-query";

export type ResponderCapture = {
  label: string; username: string; value: string; cleartext: boolean; captured_at: string;
};

// NTLM coercion (xp_dirtree, a malicious .library-ms/.searchConnector-ms
// file, PetitPotam, etc.) is only useful with something listening to catch
// the authentication attempt — Responder is the standard listener for that.
// Unlike the manual-shell panels next to this one, it needs to keep running
// while the tester works in other tabs to trigger the coercion, so it opens
// in a real desktop terminal window (not this app's in-page xterm panel,
// which disappears whenever the SPA navigates away from this screen).
export default function ResponderPanel({
  targetId, onStartListener, onSendHashToCracking, onSaveCredential, evidenceMsg,
}: {
  targetId?: number;
  onStartListener: (interfaceName: string) => void;
  onSendHashToCracking: (capture: ResponderCapture) => void;
  onSaveCredential: (capture: ResponderCapture) => void;
  evidenceMsg: string;
}) {
  const [interfaceName, setInterfaceName] = useState("tun0");
  const [revealed, setRevealed] = useState<Set<string>>(new Set());
  // Responder's own log files are the one de-duplicated, authoritative
  // record of what it has captured — polling them here means seeing a
  // capture never depends on catching the right moment in a separate
  // desktop terminal, or on Responder's own "skip a repeat" dedup deciding
  // whether anything gets printed at all.
  const captures = useQuery({
    queryKey: ["responderCaptures", targetId],
    queryFn: () => fetch(`/api/targets/${targetId}/responder-captures`)
      .then((r) => r.json() as Promise<ResponderCapture[]>),
    enabled: !!targetId,
    refetchInterval: 4000,
  });
  const toggle = (key: string) => setRevealed((current) => {
    const next = new Set(current);
    next.has(key) ? next.delete(key) : next.add(key);
    return next;
  });

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
      {!!captures.data?.length && (
        <div className="intruderResults">
          <header><div><b>캡처된 자격증명</b><span>{captures.data.length}개</span></div></header>
          {evidenceMsg && <p className="netexecEvidenceMsg">{evidenceMsg}</p>}
          <table>
            <thead><tr><th>종류</th><th>계정</th><th>값</th><th>캡처 시각</th><th></th></tr></thead>
            <tbody>{captures.data.map((capture) => {
              const key = `${capture.label}:${capture.username}`;
              const shown = revealed.has(key);
              return (
                <tr key={key}>
                  <td>{capture.label}</td>
                  <td>{capture.username}</td>
                  <td>
                    <code>{shown ? capture.value : "••••••••"}</code>{" "}
                    <button type="button" onClick={() => toggle(key)}>
                      {shown ? "숨기기" : "보기"}
                    </button>
                  </td>
                  <td>{new Date(capture.captured_at).toLocaleString()}</td>
                  <td>
                    {!capture.cleartext && <button type="button"
                      onClick={() => onSendHashToCracking(capture)}>
                      Hash Cracking으로
                    </button>}
                    <button type="button" onClick={() => onSaveCredential(capture)}>
                      Credential Store에 저장
                    </button>
                  </td>
                </tr>
              );
            })}</tbody>
          </table>
        </div>
      )}
    </section>
  );
}
