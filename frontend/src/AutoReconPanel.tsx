import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Badge, Button, ErrorState } from "./ui";
import { get, terminal, type Scan, type Target } from "./scanCenterModel";

type ServiceExecution = { id: number; status: string; template_id: string };

function autoReconTags(scan: Scan): string[] {
  try {
    return JSON.parse(scan.tags || "[]");
  } catch {
    return [];
  }
}

// One row = one target's most recent AutoRecon-tagged scan chain. Polls the
// same /scans and /scans/{id}/service-executions endpoints the single-target
// flow already uses -- this is just a second, lighter-weight consumer of
// them, not a new backend concept.
function AutoReconJobRow({ target, active, onOpen }: {
  target: Target; active: boolean;
  onOpen: (targetId: number, scanId: number) => void;
}) {
  const jobs = useQuery({
    queryKey: ["autoReconScans", target.id],
    queryFn: () => get<Scan[]>(`/scans?target_id=${target.id}`),
    refetchInterval: 4000,
  });
  const job = (jobs.data || [])
    .filter((scan) => autoReconTags(scan).includes("autorecon"))
    .sort((a, b) => b.id - a.id)[0];
  const executions = useQuery({
    queryKey: ["autoReconExecutions", job?.id],
    queryFn: () => get<ServiceExecution[]>(`/scans/${job!.id}/service-executions`),
    enabled: !!job,
    refetchInterval: 4000,
  });
  const counts = (executions.data || []).reduce((acc, execution) => {
    const bucket = terminal.includes(execution.status)
      ? (execution.status === "completed" ? "completed" : "failed")
      : "running";
    acc[bucket] = (acc[bucket] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  return (
    <div role="button" tabIndex={job ? 0 : -1}
      className={`scanRow autoReconJobRow${active ? " active" : ""}${!job ? " autoReconJobRow--idle" : ""}`}
      onClick={() => job && onOpen(target.id, job.id)}
      onKeyDown={(e) => {
        if (!job) return;
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onOpen(target.id, job.id); }
      }}>
      <span>
        <b>{target.name || target.ip}</b>
        {target.name && <em>{target.ip}</em>}
      </span>
      {job ? <>
        <Badge status={job.status} />
        {!!executions.data?.length && <small>
          서비스 명령 {executions.data.length}개 ·
          완료 {counts.completed || 0} · 진행중 {counts.running || 0} · 실패 {counts.failed || 0}
        </small>}
      </> : <small>대기 · 아직 시작되지 않음</small>}
    </div>
  );
}

export default function AutoReconPanel({ targets, selectedIds, onToggle, onSelectAll,
  onClear, onStart, starting, startError, activeTargetId, onOpenJob }: {
  targets: Target[];
  selectedIds: Set<number>;
  onToggle: (id: number) => void;
  onSelectAll: () => void;
  onClear: () => void;
  onStart: () => void;
  starting: boolean;
  startError?: string;
  activeTargetId?: number;
  onOpenJob: (targetId: number, scanId: number) => void;
}) {
  const [scopeConfirmed, setScopeConfirmed] = useState(false);
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
        위에서 고른 도구·프로파일·포트로 각 대상을 전체 포트 스캔합니다. 스캔이 끝나면
        발견된 서비스마다 매칭되는 열거 명령(nikto, enum4linux, whatweb 등)이 자동으로
        병렬 실행되고, 결과는 대상별 outputs/tcp&lt;포트&gt;-&lt;서비스&gt;/ 폴더에 정리됩니다.
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
      {!!selectedIds.size && <div className="autoReconJobs">
        {targets.filter((t) => selectedIds.has(t.id)).map((t) => (
          <AutoReconJobRow key={t.id} target={t}
            active={t.id === activeTargetId} onOpen={onOpenJob} />
        ))}
      </div>}
    </section>
  );
}
