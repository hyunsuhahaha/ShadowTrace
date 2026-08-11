import {Button, ErrorState, LoadingState, statusCopy as statusLabel} from "./ui";
import {elapsed, terminal, type Scan} from "./scanCenterModel";

const statusOptions =
  ["all", "queued", "running", "completed", "failed", "stopped", "interrupted"];

type Diff = {
  added: any[]; removed: any[]; changed: any[];
};

export default function ScanHistoryPanel({visibleScans, allScans, scanId, isLoading,
  error, query, statusFilter, onQueryChange, onStatusFilterChange, onSelectScan,
  onStop, onRerun, onDelete, baseId, onSelectBase, diff}: {
  visibleScans: Scan[]; allScans?: Scan[]; scanId?: number;
  isLoading: boolean; error: unknown;
  query: string; statusFilter: string;
  onQueryChange: (value: string) => void;
  onStatusFilterChange: (value: string) => void;
  onSelectScan: (id: number) => void;
  onStop: (id: number) => void; onRerun: (id: number) => void;
  onDelete: (id: number) => void;
  baseId?: number; onSelectBase: (id: number) => void;
  diff?: Diff;
}) {
  return <aside className="scanHistory">
    <div className="panelTitle">
      <span className="panelTitle__label">
        <span className="termDots" aria-hidden="true">
          <i className="termDot" /><i className="termDot termDot--yellow" />
          <i className="termDot termDot--green" />
        </span>
        스캔 대기열 및 이력
      </span>
      <em>대상</em>
    </div>
    <div className="historyFilters">
      <input
        placeholder="스캔 검색"
        value={query}
        onChange={(e) => onQueryChange(e.target.value)}
      />
      <select
        value={statusFilter}
        onChange={(e) => onStatusFilterChange(e.target.value)}
      >
        {statusOptions.map((v) => (
          <option key={v} value={v}>{statusLabel[v] || v}</option>
        ))}
      </select>
    </div>
    {isLoading && <LoadingState label="스캔 이력을 불러오는 중" />}
    {!!error && <ErrorState message={String(error)} />}
    {!isLoading && !visibleScans.length &&
      <p className="empty">조건에 맞는 스캔이 없습니다.</p>}
    {visibleScans.map((s) => (
      <div
        key={s.id}
        role="button"
        tabIndex={0}
        className={`scanRow ${s.id === scanId ? "active" : ""}`}
        onClick={() => onSelectScan(s.id)}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            onSelectScan(s.id);
          }
        }}
      >
        <span>
          <b>{s.alias || `#${s.id}`}</b>
          <em>{statusLabel[s.status] || s.status}</em>
        </span>
        <small>
          {s.source} · {elapsed(s)} ·{" "}
          {new Date(s.created_at).toLocaleString()}
        </small>
        <code>{s.error || s.command}</code>
        <span className="jobActions">
          {["queued", "running"].includes(s.status) && (
            <Button
              variant="quiet"
              onClick={(e) => {
                e.stopPropagation();
                onStop(s.id);
              }}
            >
              취소
            </Button>
          )}
          {s.source === "executed" && terminal.includes(s.status) && (
            <Button
              variant="quiet"
              onClick={(e) => {
                e.stopPropagation();
                onRerun(s.id);
              }}
            >
              재실행
            </Button>
          )}
          {terminal.includes(s.status) && (
            <Button
              variant="quiet"
              onClick={(e) => {
                e.stopPropagation();
                onDelete(s.id);
              }}
            >
              삭제
            </Button>
          )}
          {s.exit_code != null && <small>exit {s.exit_code}</small>}
        </span>
      </div>
    ))}
    <div className="compare">
      <h3>비교</h3>
      <select
        value={baseId || ""}
        onChange={(e) => onSelectBase(+e.target.value)}
      >
        <option value="">기준 스캔 선택</option>
        {allScans
          ?.filter((s) => s.id !== scanId)
          .map((s) => (
            <option key={s.id} value={s.id}>
              {s.alias || `스캔 #${s.id}`}
            </option>
          ))}
      </select>
      {diff && (
        <>
          <div className="delta">
            <span>+{diff.added.length}</span>
            <span>−{diff.removed.length}</span>
            <span>~{diff.changed.length}</span>
          </div>
          <a
            className="diffExport"
            href={`/api/scans/compare/${baseId}/${scanId}/export`}
          >
            변경 내역 내보내기
          </a>
          <div className="diffDetails">
            {diff.added.map((item: any) => (
              <div key={`add-${item.protocol}-${item.port}`}>
                <b>추가 {item.port}/{item.protocol}</b>
                <small>{item.name} {item.product} {item.version}</small>
              </div>
            ))}
            {diff.removed.map((item: any) => (
              <div key={`remove-${item.protocol}-${item.port}`}>
                <b>제거 {item.port}/{item.protocol}</b>
                <small>{item.name} {item.product} {item.version}</small>
              </div>
            ))}
            {diff.changed.map((item: any) => (
              <div key={`change-${item.protocol}-${item.port}`}>
                <b>변경 {item.port}/{item.protocol}</b>
                <small>{Object.keys(item.changes).join(", ")}</small>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  </aside>;
}
