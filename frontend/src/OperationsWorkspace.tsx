import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
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
    [error, setError] = useState("");
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
  const setConcurrency = async () => {
    try {
      setError("");
      const current = await api<{ concurrency: number }>("/scans/settings");
      const value = Number(
        prompt("최대 동시 스캔 수(1–8)", String(current.concurrency)),
      );
      if (!Number.isInteger(value)) return;
      await api("/scans/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ concurrency: value }),
      });
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
        <a href="#">← Scan Center</a>
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
            {results.data?.map((r, i) => (
              <a key={`${r.type}-${r.id}-${i}`} href={r.path}>
                <span>{r.type}</span>
                <b>{r.title}</b>
                <small>{r.subtitle}</small>
              </a>
            ))}
          </div>
          <h2>백업</h2>
          <p>
            Create a consistent SQLite snapshot with the preserved artifact
            tree. Backup files remain local.
          </p>
          <button onClick={createBackup}>전체 백업 생성</button>
          <button onClick={setConcurrency}>동시 스캔 수 설정</button>
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
    </div>
  );
}
