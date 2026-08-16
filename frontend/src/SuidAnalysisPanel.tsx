import { useState } from "react";

type SuidMatch = { path: string; binary: string; command: string; reference: string };
type SuidScanResult = { matches: SuidMatch[]; evidence_id: number };

const post = async <T,>(path: string, body: unknown): Promise<T> => {
  const r = await fetch("/api" + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error((await r.json()).detail || r.statusText);
  return r.json();
};

// Paste-and-classify `find / -perm -4000` output against a GTFOBins reference,
// with a one-click promote to a Draft Finding. Same paste-analyze-promote
// pattern as LinpeasAnalysisPanel, shared by PostExploitationWorkspace and
// the graph Inspector's manual-shell session block.
export default function SuidAnalysisPanel({ targetId, projectId, onAnalyzed }: {
  targetId?: number; projectId?: number; onAnalyzed?: () => void;
}) {
  const [suidInput, setSuidInput] = useState("");
  const [suidResult, setSuidResult] = useState<SuidScanResult>();
  const [suidBusy, setSuidBusy] = useState(false);
  const [suidMsg, setSuidMsg] = useState("");

  const analyzeSuid = async () => {
    if (!targetId || !suidInput.trim()) return;
    setSuidBusy(true); setSuidMsg("");
    try {
      setSuidResult(await post<SuidScanResult>(
        `/targets/${targetId}/suid-scan`, { output: suidInput }));
      onAnalyzed?.();
    } catch (reason) { setSuidMsg(String(reason)); }
    finally { setSuidBusy(false); }
  };
  const promoteSuidFinding = async (match: SuidMatch) => {
    if (!projectId || !targetId || !suidResult) return;
    setSuidMsg("");
    try {
      await post("/findings", {
        project_id: projectId, target_id: targetId, title: `SUID: ${match.binary}`,
        status: "Draft",
        reproduction_steps: `SUID 바이너리 발견: ${match.path}\n\nGTFOBins 기법:\n${match.command}\n\n` +
          `참고: ${match.reference}`,
        evidence: [{ evidence_id: suidResult.evidence_id, is_primary: true }],
      });
      setSuidMsg(`Finding(Draft)으로 승격됨: ${match.binary}`);
      onAnalyzed?.();
    } catch (reason) { setSuidMsg(String(reason)); }
  };

  return (
    <section className="netexecCredCheck" aria-labelledby="suid-heading">
      <header>
        <h2 id="suid-heading">SUID/GTFOBins 분석</h2>
      </header>
      <textarea rows={6}
        placeholder={"find / -perm -4000 -type f 2>/dev/null 결과를 붙여넣으세요"}
        value={suidInput} onChange={(e) => setSuidInput(e.target.value)} />
      <button type="button" disabled={!targetId || suidBusy || !suidInput.trim()}
        onClick={analyzeSuid}>
        {suidBusy ? "SUID 분석 중…" : "SUID 분석"}
      </button>
      {suidMsg && <span>{suidMsg}</span>}
      {suidResult && (
        suidResult.matches.length > 0 ? (
          <div className="lootCategory">
            <h3>GTFOBins 매칭 {suidResult.matches.length}건</h3>
            {suidResult.matches.map((match) => (
              <div key={match.path} className="lootRow">
                <span>
                  <code>{match.path}</code>
                  <br /><code>{match.command}</code>
                  <br /><a href={match.reference} target="_blank" rel="noreferrer">
                    {match.reference}
                  </a>
                </span>
                <button type="button" onClick={() => promoteSuidFinding(match)}>
                  Finding(Draft)으로 승격
                </button>
              </div>
            ))}
          </div>
        ) : <p className="empty">알려진 GTFOBins SUID 기법과 일치하는 바이너리가 없습니다.</p>
      )}
    </section>
  );
}
