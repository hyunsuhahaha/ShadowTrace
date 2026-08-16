import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { EmptyState, ErrorState, LoadingState } from "./ui";
const api = async <T,>(p: string, i?: RequestInit): Promise<T> => {
  const r = await fetch("/api" + p, i);
  if (!r.ok) throw new Error((await r.json()).detail || r.statusText);
  return r.json();
};
type Result = {
  type: string;
  id: number;
  title: string;
  subtitle: string;
  path: string;
};
type Audit = {
  id: number;
  method: string;
  path: string;
  status_code: number;
  occurred_at: string;
};
export default function OperationsWorkspace() {
  const [query, setQuery] = useState(""),
    [backup, setBackup] = useState<{ name: string; size: number }>(),
    [error, setError] = useState(""),
    // In-app modal instead of window.prompt() -- native OS dialogs can fail
    // to surface at all on a bare/root Kali Chrome, so the button just
    // silently hangs with zero visible sign anything happened.
    [concurrencyOpen, setConcurrencyOpen] = useState(false),
    [concurrencyValue, setConcurrencyValue] = useState("");
  const results = useQuery({
      queryKey: ["globalSearch", query],
      queryFn: () =>
        api<Result[]>(`/operations/search?query=${encodeURIComponent(query)}`),
      enabled: query.trim().length > 1,
    }),
    audit = useQuery({
      queryKey: ["audit"],
      queryFn: () => api<Audit[]>("/operations/audit?limit=500"),
    });
  const createBackup = async () => {
    try {
      setError("");
      setBackup(await api("/operations/backups", { method: "POST" }));
    } catch (e) {
      setError(String(e));
    }
  };
  const openConcurrency = async () => {
    try {
      setError("");
      const current = await api<{ concurrency: number }>("/scans/settings");
      setConcurrencyValue(String(current.concurrency));
      setConcurrencyOpen(true);
    } catch (e) {
      setError(String(e));
    }
  };
  const submitConcurrency = async () => {
    const value = Number(concurrencyValue);
    if (!Number.isInteger(value) || value < 1 || value > 8) return;
    try {
      setError("");
      await api("/scans/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ concurrency: value }),
      });
      setConcurrencyOpen(false);
    } catch (e) {
      setError(String(e));
    }
  };
  return (
    <div className="operationsPage">
      <header>
        <div className="brand">
          <span className="mark">OW</span>
          <div>
            <b>OSCP Workspace</b>
            <small>검색 · 감사 · 백업</small>
          </div>
        </div>
        <a href="#scans">← Scan Center</a>
      </header>
      <main>
        <section>
          <h1>전체 검색</h1>
          <input
            autoFocus
            placeholder="대상, 서비스, 증적, AD 데이터 및 보고서 검색"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <div className="searchResults">
            {query.trim().length > 1 && results.isLoading &&
              <LoadingState label="검색 중" />}
            {results.error && <ErrorState message={String(results.error)} />}
            {query.trim().length > 1 && !results.isLoading && !results.data?.length &&
              <EmptyState title="검색 결과가 없습니다" description="다른 키워드로 다시 검색하세요." />}
            {results.data?.map((r, i) => (
              <a key={`${r.type}-${r.id}-${i}`} href={r.path}>
                <span>{r.type}</span>
                <b>{r.title}</b>
                <small>{r.subtitle}</small>
              </a>
            ))}
          </div>
          <h2>백업</h2>
          <button onClick={createBackup}>전체 백업 생성</button>
          <button onClick={() => void openConcurrency()}>동시 스캔 수 설정</button>
          {backup && (
            <a
              className="backupDownload"
              href={`/api/operations/backups/${backup.name}`}
            >
              Download {backup.name} · {backup.size} bytes
            </a>
          )}
          {error && <p className="webError">{error}</p>}
        </section>
        <section>
          <h2>로컬 변경 감사 기록</h2>
          <div className="auditList">
            {audit.isLoading && <LoadingState label="감사 기록을 불러오는 중" />}
            {audit.error && <ErrorState message={String(audit.error)} />}
            {!audit.isLoading && !audit.data?.length &&
              <EmptyState title="기록된 변경이 없습니다" description="로컬 변경 사항이 발생하면 여기에 기록됩니다." />}
            {audit.data?.map((x) => (
              <div key={x.id}>
                <b>{x.method}</b>
                <code>{x.path}</code>
                <span>{x.status_code}</span>
                <small>{new Date(x.occurred_at).toLocaleString()}</small>
              </div>
            ))}
          </div>
        </section>
      </main>
      {concurrencyOpen && (
        <div className="modal" role="presentation">
          <div role="dialog" aria-modal="true" aria-labelledby="concurrency-title">
            <span>스캔 설정</span>
            <h2 id="concurrency-title">최대 동시 스캔 수</h2>
            <label htmlFor="concurrency-input">1–8</label>
            <input
              id="concurrency-input"
              autoFocus
              type="number"
              min={1}
              max={8}
              value={concurrencyValue}
              onChange={(e) => setConcurrencyValue(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") { e.preventDefault(); void submitConcurrency(); }
                if (e.key === "Escape") setConcurrencyOpen(false);
              }}
            />
            <footer>
              <button onClick={() => setConcurrencyOpen(false)}>취소</button>
              <button onClick={() => void submitConcurrency()}>저장</button>
            </footer>
          </div>
        </div>
      )}
    </div>
  );
}
