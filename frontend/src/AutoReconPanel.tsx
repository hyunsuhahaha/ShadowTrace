import { useEffect, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge, Button, ErrorState } from "./ui";
import { get, terminal, type Target } from "./scanCenterModel";

type AutoReconRun = {
  id: number; project_id: number; target_ids: string; command: string;
  output_dir: string; status: string; exit_code?: number | null; stopped: boolean;
  error: string; imported_count: number;
  started_at?: string; ended_at?: string; created_at: string;
};

function runTargets(run: AutoReconRun, targets: Target[]): Target[] {
  try {
    const ids: number[] = JSON.parse(run.target_ids || "[]");
    return ids.map((id) => targets.find((t) => t.id === id)).filter((t): t is Target => !!t);
  } catch {
    return [];
  }
}

export default function AutoReconPanel({ projectId, targets, selectedIds, onToggle,
  onSelectAll, onClear, onStart, starting, startError, activeRunId, onSelectRun }: {
  projectId?: number;
  targets: Target[];
  selectedIds: Set<number>;
  onToggle: (id: number) => void;
  onSelectAll: () => void;
  onClear: () => void;
  onStart: () => void;
  starting: boolean;
  startError?: string;
  activeRunId?: number;
  onSelectRun: (id: number) => void;
}) {
  const [scopeConfirmed, setScopeConfirmed] = useState(false);
  const [output, setOutput] = useState("");
  const [streamState, setStreamState] = useState<
    "idle" | "connecting" | "connected" | "disconnected"
  >("idle");
  const transcript = useRef<HTMLPreElement>(null);
  const qc = useQueryClient();

  const runs = useQuery({
    queryKey: ["autoReconRuns", projectId],
    queryFn: () => get<AutoReconRun[]>(`/autorecon?project_id=${projectId}`),
    enabled: !!projectId,
    refetchInterval: 4000,
  });
  const activeRun = runs.data?.find((r) => r.id === activeRunId);

  // Mirrors ScanCenter's own single-scan SSE useEffect (same event shape:
  // {stream: "stdout"|"stderr"|"status", ...}) -- a real `autorecon`
  // invocation is one process for however many targets were selected, so
  // there's exactly one transcript to show, not one per target.
  useEffect(() => {
    if (!activeRunId) return;
    setStreamState("connecting");
    setOutput("");
    const events = new EventSource(`/api/autorecon/${activeRunId}/events`);
    events.onopen = () => setStreamState("connected");
    events.onmessage = async (e) => {
      const item = JSON.parse(e.data);
      if (item.stream === "stdout") setOutput((v) => v + item.data);
      if (item.stream === "stderr") setOutput((v) => v + `[stderr] ${item.data}`);
      if (item.stream === "status") {
        setStreamState("idle");
        setOutput((v) => v + (item.error ? `\n[${item.status}] ${item.error}\n`
          : `\n[${item.status}${item.exit_code == null ? "" : ` · exit ${item.exit_code}`}]\n`));
        events.close();
        await qc.invalidateQueries({ queryKey: ["autoReconRuns", projectId] });
        dispatchEvent(new CustomEvent("oscp-graph-refresh"));
      }
    };
    events.onerror = () => { setStreamState("disconnected"); events.close(); };
    return () => events.close();
  }, [activeRunId, projectId, qc]);

  useEffect(() => {
    const panel = transcript.current;
    if (panel) panel.scrollTop = panel.scrollHeight;
  }, [output]);

  const stopRun = async (id: number) => {
    await fetch(`/api/autorecon/${id}/stop`, { method: "POST" });
    await qc.invalidateQueries({ queryKey: ["autoReconRuns", projectId] });
  };

  return (
    <section className="autoReconPanel">
      <div className="panelTitle">
        <span className="panelTitle__label">
          <span className="termDots" aria-hidden="true">
            <i className="termDot" /><i className="termDot termDot--yellow" />
            <i className="termDot termDot--green" />
          </span>
          AutoRecon · 여러 대상 동시 정찰
        </span>
        <em>{selectedIds.size}개 선택됨</em>
      </div>
      <p className="autoReconPanel__hint">
        선택한 대상 전체를 실제 AutoRecon(Tib3rius) 한 번의 실행으로 넘깁니다 — 전체 포트
        스캔 후 발견된 서비스마다 맞는 열거 도구를 자동으로 병렬 실행하고, 결과를 대상별
        폴더(scans/tcp&lt;포트&gt;/)에 정리합니다. 완료되면 서비스와 각 명령 결과가 그래프에
        자동으로 반영됩니다.
      </p>
      <div className="autoReconTargetPicker">
        <div className="autoReconTargetPicker__actions">
          <Button type="button" variant="quiet" onClick={onSelectAll}>전체 선택</Button>
          <Button type="button" variant="quiet" onClick={onClear}>전체 해제</Button>
        </div>
        {targets.map((t) => (
          <label key={t.id} className="autoReconTargetRow">
            <input type="checkbox" checked={selectedIds.has(t.id)}
              onChange={() => onToggle(t.id)} />
            <b>{t.name || t.ip}</b>{t.name && <span>{t.ip}</span>}
          </label>
        ))}
        {!targets.length && <p className="empty">이 프로젝트에 등록된 대상이 없습니다.</p>}
      </div>
      <label className="executionScope autoReconPanel__scope">
        <input type="checkbox" checked={scopeConfirmed}
          onChange={(e) => setScopeConfirmed(e.target.checked)} />
        <span><b>SCOPE ACKNOWLEDGEMENT</b> 선택한 대상 전부가 허가된 Scope에 포함됨을 확인합니다.</span>
      </label>
      {startError && <ErrorState message={startError} />}
      <Button type="button" disabled={!scopeConfirmed || !selectedIds.size || starting}
        onClick={onStart}>
        {starting ? "시작하는 중…" : `AutoRecon 시작 (${selectedIds.size}개 대상)`}
      </Button>
      <div className="autoReconRuns">
        {(runs.data || []).map((run) => (
          <div key={run.id} role="button" tabIndex={0}
            className={`scanRow autoReconRunRow${run.id === activeRunId ? " active" : ""}`}
            onClick={() => onSelectRun(run.id)}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onSelectRun(run.id); }
            }}>
            <span>
              <b>실행 #{run.id}</b>
              <Badge status={run.status} />
            </span>
            <small>{runTargets(run, targets).map((t) => t.ip).join(", ") || "대상 정보 없음"}</small>
            {run.imported_count > 0 && <small>{run.imported_count}개 명령 결과 임포트됨</small>}
          </div>
        ))}
        {!runs.isLoading && !runs.data?.length &&
          <p className="empty">아직 실행한 AutoRecon이 없습니다.</p>}
      </div>
      {activeRun && <div className="terminal autoReconTranscript">
        <div className="terminalStatus">
          <span className="termDots" aria-hidden="true">
            <i className="termDot" /><i className="termDot termDot--yellow" />
            <i className="termDot termDot--green" />
          </span>
          <span>실행 #{activeRun.id} · {activeRun.status}</span>
          <small role="status" aria-live="polite">
            {streamState === "connected" ? "RX LIVE"
              : streamState === "connecting" ? "ATTACHING"
              : streamState === "disconnected" ? "LINK LOST"
              : terminal.includes(activeRun.status) ? "STREAM CLOSED" : "IDLE"}
          </small>
          {["queued", "running"].includes(activeRun.status) &&
            <Button type="button" variant="quiet" onClick={() => void stopRun(activeRun.id)}>
              중지
            </Button>}
        </div>
        <pre ref={transcript} tabIndex={0} aria-label="AutoRecon 실행 출력">
          {output || "..."}
        </pre>
      </div>}
    </section>
  );
}
