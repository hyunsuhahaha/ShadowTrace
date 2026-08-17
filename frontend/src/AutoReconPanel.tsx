import { useEffect, useRef, useState, type PointerEvent as ReactPointerEvent } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useFloatingTerminal } from "./FloatingTerminal";
import { Badge, Button, ErrorState } from "./ui";
import { get, serverTime, terminal, type Target } from "./scanCenterModel";

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

export function formatAutoReconElapsed(run: AutoReconRun, clock = Date.now()): string {
  const start = serverTime(run.started_at || run.created_at);
  const end = run.ended_at ? serverTime(run.ended_at) : clock;
  if (!Number.isFinite(start) || !Number.isFinite(end)) return "0초";
  const seconds = Math.max(0, Math.floor((end - start) / 1000));
  const minutes = Math.floor(seconds / 60);
  return minutes ? `${minutes}분 ${seconds % 60}초` : `${seconds}초`;
}

export default function AutoReconPanel({ projectId, targets, selectedIds, onToggle,
  onSelectAll, onClear, onStart, starting, startError, activeRunId, onSelectRun }: {
  projectId?: number;
  targets: Target[];
  selectedIds: Set<number>;
  onToggle: (id: number) => void;
  onSelectAll: () => void;
  onClear: () => void;
  onStart: (argumentsText: string) => void;
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
  const [clock, setClock] = useState(Date.now());
  const [lastEventAt, setLastEventAt] = useState<number>();
  const [argumentsText, setArgumentsText] = useState("");
  const transcript = useRef<HTMLPreElement>(null);
  const transcriptPanel = useRef<HTMLDivElement>(null);
  const detachDrag = useRef<{x: number; y: number; pointerId: number}>();
  const qc = useQueryClient();
  const {floatingScanId, floatingEndpoint, floatScan} = useFloatingTerminal();

  const runs = useQuery({
    queryKey: ["autoReconRuns", projectId],
    queryFn: () => get<AutoReconRun[]>(`/autorecon?project_id=${projectId}`),
    enabled: !!projectId,
    refetchInterval: 4000,
  });
  const activeRun = runs.data?.find((r) => r.id === activeRunId);
  const activeRunTargets = activeRun ? runTargets(activeRun, targets) : [];
  const isFloated = floatingEndpoint === "autorecon" && floatingScanId === activeRunId;

  useEffect(() => {
    if (!activeRun || terminal.includes(activeRun.status)) return;
    const timer = setInterval(() => setClock(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [activeRun?.id, activeRun?.status]);

  // Mirrors ScanCenter's own single-scan SSE useEffect (same event shape:
  // {stream: "stdout"|"stderr"|"status"|"snapshot"|"imported", ...}) -- a
  // real `autorecon` invocation is one process for however many targets
  // were selected, so there's exactly one transcript to show, not one per
  // target. Once floated, FloatingTerminalProvider owns this run's SSE
  // connection instead (see FloatingTerminal.tsx) -- skip subscribing again
  // here so the two don't fight over the same event stream.
  useEffect(() => {
    if (!activeRunId || isFloated) return;
    setStreamState("connecting");
    setLastEventAt(undefined);
    setOutput("");
    const events = new EventSource(`/api/autorecon/${activeRunId}/events`);
    events.onopen = () => setStreamState("connected");
    events.onmessage = async (e) => {
      setLastEventAt(Date.now());
      const item = JSON.parse(e.data);
      // The backend replays everything captured so far as one "snapshot"
      // event on every new connection -- without it, switching to another
      // workspace and back (which unmounts this component) looked like the
      // log had been wiped, even though the run itself was still going.
      if (item.stream === "snapshot") setOutput(item.data);
      if (item.stream === "stdout") setOutput((v) => v + item.data);
      if (item.stream === "stderr") setOutput((v) => v + `[stderr] ${item.data}`);
      if (item.stream === "imported") {
        await qc.invalidateQueries({ queryKey: ["autoReconRuns", projectId] });
        dispatchEvent(new CustomEvent("oscp-graph-refresh"));
      }
      if (item.stream === "status") {
        setOutput((v) => v + (item.error ? `\n[${item.status}] ${item.error}\n`
          : `\n[${item.status}${item.exit_code == null ? "" : ` · exit ${item.exit_code}`}]\n`));
        await qc.invalidateQueries({ queryKey: ["autoReconRuns", projectId] });
        if (terminal.includes(item.status)) {
          setStreamState("idle");
          events.close();
          dispatchEvent(new CustomEvent("oscp-graph-refresh"));
        }
      }
    };
    events.onerror = () => { setStreamState("disconnected"); events.close(); };
    return () => events.close();
  }, [activeRunId, projectId, qc, isFloated]);

  useEffect(() => {
    const panel = transcript.current;
    if (panel) panel.scrollTop = panel.scrollHeight;
  }, [output]);

  const stopRun = async (id: number) => {
    await fetch(`/api/autorecon/${id}/stop`, { method: "POST" });
    await qc.invalidateQueries({ queryKey: ["autoReconRuns", projectId] });
  };

  const beginDetach = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (!activeRun || event.button !== 0) return;
    // The header also holds the "중지" button -- don't start a drag capture
    // from a press that's actually aimed at it.
    if ((event.target as HTMLElement).closest("button")) return;
    detachDrag.current = {x: event.clientX, y: event.clientY, pointerId: event.pointerId};
    event.currentTarget.setPointerCapture(event.pointerId);
  };
  const moveDetach = (event: ReactPointerEvent<HTMLDivElement>) => {
    const start = detachDrag.current;
    if (!start || !activeRun || !transcriptPanel.current) return;
    if (Math.hypot(event.clientX - start.x, event.clientY - start.y) < 5) return;
    const firstTarget = activeRunTargets[0];
    floatScan({
      scanId: activeRun.id, projectId: projectId || 0,
      targetId: firstTarget?.id || 0,
      targetIp: activeRunTargets.map((t) => t.ip).join(", ") || "multiple targets",
      command: activeRun.command, source: "autorecon", status: activeRun.status,
      exitCode: activeRun.exit_code ?? undefined, linkType: "local",
      initialOutput: output, endpoint: "autorecon",
    }, transcriptPanel.current.getBoundingClientRect());
    detachDrag.current = undefined;
    if (event.currentTarget.hasPointerCapture(event.pointerId))
      event.currentTarget.releasePointerCapture(event.pointerId);
  };
  const finishDetach = (event: ReactPointerEvent<HTMLDivElement>) => {
    detachDrag.current = undefined;
    if (event.currentTarget.hasPointerCapture(event.pointerId))
      event.currentTarget.releasePointerCapture(event.pointerId);
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
      <details className="autoReconOptions">
        <summary>AutoRecon 고급 옵션</summary>
        <label>
          <span>CLI 인자</span>
          <textarea value={argumentsText} onChange={(e) => setArgumentsText(e.target.value)}
            placeholder="--tags safe --heartbeat 30 --timeout 120" />
        </label>
        <small>대상과 출력 경로는 앱이 관리합니다. 나머지 AutoRecon 옵션은 원본 문법 그대로 전달됩니다.</small>
      </details>
      <p className="autoReconPanel__hint">
        선택한 대상 전체를 실제 AutoRecon(Tib3rius) 한 번의 실행으로 넘깁니다 — 전체 포트
        스캔 후 발견된 서비스마다 맞는 열거 도구를 자동으로 병렬 실행하고, 결과를 대상별
        폴더(scans/tcp&lt;포트&gt;/)에 정리합니다. 실행 중에도 15초마다 지금까지 나온 결과를
        그래프에 반영합니다.
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
        onClick={() => onStart(argumentsText)}>
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
      {activeRun && !isFloated && <div ref={transcriptPanel} className="terminal autoReconTranscript">
        <div className="terminalStatus" onPointerDown={beginDetach} onPointerMove={moveDetach}
          onPointerUp={finishDetach} onPointerCancel={finishDetach}>
          <span className="termDots" aria-hidden="true">
            <i className="termDot" /><i className="termDot termDot--yellow" />
            <i className="termDot termDot--green" />
          </span>
          <span>실행 #{activeRun.id} · {activeRun.status} · 경과 {formatAutoReconElapsed(activeRun, clock)}</span>
          <small role="status" aria-live="polite">
            {lastEventAt ? `마지막 응답 ${Math.max(0, Math.floor((clock - lastEventAt) / 1000))}초 전`
              : streamState === "connected" ? "RX LIVE"
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
      {activeRun && isFloated &&
        <p className="empty">플로팅 창으로 이동됨 — [ 원위치 ] 버튼으로 되돌릴 수 있습니다.</p>}
    </section>
  );
}
