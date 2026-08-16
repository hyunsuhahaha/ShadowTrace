import { useState } from "react";

type LinpeasResult = {
  critical: string[]; high: string[]; medium: string[]; evidence_id: number;
};
const linpeasSeverityLabels: Record<string, string> = {
  critical: "Critical (RED/YELLOW · 95% PE vector)", high: "High (RED)", medium: "Medium (YELLOW)",
};

const post = async <T,>(path: string, body: unknown): Promise<T> => {
  const r = await fetch("/api" + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error((await r.json()).detail || r.statusText);
  return r.json();
};

// Paste-and-classify LinPEAS output into Critical/High/Medium findings, with
// a one-click promote to a Draft Finding. Shared by PostExploitationWorkspace
// (the standalone page) and the graph Inspector (inline on a manual-shell
// session node), so a LinPEAS run started from either place can be analyzed
// without navigating away.
export default function LinpeasAnalysisPanel({ targetId, projectId, onAnalyzed }: {
  targetId?: number; projectId?: number; onAnalyzed?: () => void;
}) {
  const [linpeasInput, setLinpeasInput] = useState("");
  const [linpeasResult, setLinpeasResult] = useState<LinpeasResult>();
  const [linpeasBusy, setLinpeasBusy] = useState(false);
  const [linpeasMsg, setLinpeasMsg] = useState("");

  const analyzeLinpeas = async () => {
    if (!targetId || !linpeasInput.trim()) return;
    setLinpeasBusy(true); setLinpeasMsg("");
    try {
      setLinpeasResult(await post<LinpeasResult>(
        `/targets/${targetId}/linpeas`, { output: linpeasInput }));
      onAnalyzed?.();
    } catch (reason) { setLinpeasMsg(String(reason)); }
    finally { setLinpeasBusy(false); }
  };
  const promoteLinpeasFinding = async (severity: string, text: string) => {
    if (!projectId || !targetId || !linpeasResult) return;
    setLinpeasMsg("");
    try {
      await post("/findings", {
        project_id: projectId, target_id: targetId, title: text.slice(0, 200),
        status: "Draft",
        reproduction_steps: `LinPEAS 출력에서 ${severity} 등급으로 분류된 항목:\n\n${text}`,
        evidence: [{ evidence_id: linpeasResult.evidence_id, is_primary: true }],
      });
      setLinpeasMsg(`Finding(Draft)으로 승격됨: ${text.slice(0, 60)}`);
      onAnalyzed?.();
    } catch (reason) { setLinpeasMsg(String(reason)); }
  };

  return (
    <section className="netexecCredCheck" aria-labelledby="linpeas-heading">
      <header>
        <h2 id="linpeas-heading">LinPEAS 결과 분석</h2>
      </header>
      <textarea rows={6} placeholder="linpeas.sh 실행 결과 전체를 붙여넣으세요"
        value={linpeasInput} onChange={(e) => setLinpeasInput(e.target.value)} />
      <button type="button" disabled={!targetId || linpeasBusy || !linpeasInput.trim()}
        onClick={analyzeLinpeas}>
        {linpeasBusy ? "분석 중…" : "분석"}
      </button>
      {linpeasMsg && <span>{linpeasMsg}</span>}
      {linpeasResult && (["critical", "high", "medium"] as const).map((severity) => (
        linpeasResult[severity].length > 0 && (
          <div key={severity} className="lootCategory">
            <h3>{linpeasSeverityLabels[severity]} · {linpeasResult[severity].length}건</h3>
            {linpeasResult[severity].map((text, index) => (
              <div key={index} className="lootRow">
                <span><code>{text}</code></span>
                <button type="button" onClick={() => promoteLinpeasFinding(severity, text)}>
                  Finding(Draft)으로 승격
                </button>
              </div>
            ))}
          </div>
        )
      ))}
    </section>
  );
}
