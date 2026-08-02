import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { EmptyState, ErrorState, LoadingState } from "./ui";
type Target = { id: number; project_id: number; name: string; ip: string };
type Tunnel = {
  id: number;
  name: string;
  kind: string;
  command: string;
  status: string;
  pid?: number;
  error: string;
  started_at?: string;
  log_path: string;
};
type Session = {
  id: number;
  template_id: string;
  command: string;
  status: string;
  pid?: number;
  error: string;
  started_at?: string;
  log_path: string;
};
const api = async <T,>(p: string, i?: RequestInit): Promise<T> => {
  const r = await fetch("/api" + p, i);
  if (!r.ok) throw new Error((await r.json()).detail || r.statusText);
  return r.json();
};
export default function SessionWorkspace() {
  const qc = useQueryClient();
  const [targetId, setTargetId] = useState<number>(),
    [form, setForm] = useState({
      name: "Manual tunnel",
      kind: "local",
      ssh_host: "",
      ssh_port: 22,
      username: "",
      bind_host: "127.0.0.1",
      local_port: 8080,
      remote_host: "",
      remote_port: 80,
      confirmed: false,
    }),
    [error, setError] = useState("");
  const targets = useQuery({
      queryKey: ["allTargets"],
      queryFn: () => api<Target[]>("/targets"),
    }),
    target = targets.data?.find((x) => x.id === targetId),
    tunnels = useQuery({
      queryKey: ["tunnels", target?.project_id],
      queryFn: () => api<Tunnel[]>(`/tunnels?project_id=${target?.project_id}`),
      enabled: !!target,
      refetchInterval: 3000,
    }),
    sessions = useQuery({
      queryKey: ["interactiveSessions", targetId],
      queryFn: () =>
        api<Session[]>(`/interactive-sessions?target_id=${targetId}`),
      enabled: !!targetId,
      refetchInterval: 3000,
    });
  useEffect(() => {
    if (!targetId && targets.data?.[0]) {
      setTargetId(targets.data[0].id);
      setForm((x) => ({ ...x, ssh_host: targets.data![0].ip }));
    }
  }, [targets.data, targetId]);
  useEffect(() => {
    if (targetId) dispatchEvent(new CustomEvent("oscp-target-change", {detail: targetId}));
  }, [targetId]);
  const set = (k: string, v: any) => setForm((x) => ({ ...x, [k]: v }));
  const start = async () => {
    if (!target) return;
    try {
      setError("");
      await api("/tunnels", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...form,
          project_id: target.project_id,
          target_id: target.id,
          remote_port: form.kind === "dynamic" ? null : form.remote_port,
        }),
      });
      set("confirmed", false);
      qc.invalidateQueries({ queryKey: ["tunnels"] });
    } catch (e) {
      setError(String(e));
    }
  };
  const stop = async (kind: "tunnels" | "interactive-sessions", id: number) => {
    const label = kind === "tunnels" ? "터널" : "세션";
    if (!window.confirm(`활성 ${label}을 중지합니다. 재연결이 필요할 수 있습니다. 계속할까요?`)) return;
    await fetch(`/api/${kind}/${id}/stop`, { method: "POST" });
    qc.invalidateQueries();
  };
  return (
    <div className="sessionPage">
      <header>
        <div className="brand">
          <span className="mark">OW</span>
          <div>
            <b>OSCP Workspace</b>
            <small>Tunnel 및 세션</small>
          </div>
        </div>
        <a href="#">← Scan Center</a>
      </header>
      <nav>
        <select
          value={targetId || ""}
          onChange={(e) => setTargetId(+e.target.value)}
        >
          {targets.data?.map((t) => (
            <option key={t.id} value={t.id}>
              {t.name} · {t.ip}
            </option>
          ))}
        </select>
      </nav>
      <main className="sessionLayout">
        <aside>
          <h3>새 SSH Tunnel</h3>
          {(["name", "ssh_host", "username", "bind_host", "remote_host"] as const).map(
            (k) => (
              <input
                key={k}
                placeholder={{
                  name: "Tunnel 이름", ssh_host: "SSH 호스트", username: "사용자명",
                  bind_host: "Bind 호스트", remote_host: "원격 호스트",
                }[k]}
                value={(form as any)[k]}
                onChange={(e) => set(k, e.target.value)}
              />
            ),
          )}
          <select
            value={form.kind}
            onChange={(e) => set("kind", e.target.value)}
          >
            <option>local</option>
            <option>remote</option>
            <option>dynamic</option>
          </select>
          <label>
            SSH 포트
            <input
              type="number"
              value={form.ssh_port}
              onChange={(e) => set("ssh_port", +e.target.value)}
            />
          </label>
          <label>
            로컬/Bind 포트
            <input
              type="number"
              value={form.local_port}
              onChange={(e) => set("local_port", +e.target.value)}
            />
          </label>
          {form.kind !== "dynamic" && (
            <label>
              원격 포트
              <input
                type="number"
                value={form.remote_port}
                onChange={(e) => set("remote_port", +e.target.value)}
              />
            </label>
          )}
          <label>
            <input
              type="checkbox"
              checked={form.confirmed}
              onChange={(e) => set("confirmed", e.target.checked)}
            />{" "}
            허가된 Tunnel 설정을 검토했습니다.
          </label>
          <button disabled={!form.confirmed} onClick={start}>
            Tunnel 시작
          </button>
          {error && <p className="webError">{error}</p>}
        </aside>
        <section>
          <h2>SSH Tunnel</h2>
          <div className="connectionList">
            {tunnels.isLoading && <LoadingState label="터널 목록을 불러오는 중" />}
            {tunnels.error && <ErrorState message={String(tunnels.error)} />}
            {!tunnels.isLoading && !tunnels.data?.length &&
              <EmptyState title="열린 터널이 없습니다" description="왼쪽에서 새 터널을 시작하세요." />}
            {tunnels.data?.map((t) => (
              <article key={t.id}>
                <div>
                  <b>{t.name}</b>
                  <span>
                    {t.kind} · {t.status === "running" ? "실행 중" : t.status === "ready" ? "준비됨" : t.status}
                    {t.pid ? ` · PID ${t.pid}` : ""}
                  </span>
                </div>
                <code>{t.error || t.command}</code>
                <footer>
                  {t.log_path && <a href={`/api/tunnels/${t.id}/log`}>로그</a>}
                  {["running", "ready"].includes(t.status) && (
                    <button onClick={() => stop("tunnels", t.id)}>중지</button>
                  )}
                </footer>
              </article>
            ))}
          </div>
          <h2>대화형 세션</h2>
          <div className="connectionList">
            {sessions.isLoading && <LoadingState label="세션 목록을 불러오는 중" />}
            {sessions.error && <ErrorState message={String(sessions.error)} />}
            {!sessions.isLoading && !sessions.data?.length &&
              <EmptyState title="대화형 세션이 없습니다" description="Service Enumeration에서 대화형 명령을 실행하면 여기에 표시됩니다." />}
            {sessions.data?.map((s) => (
              <article key={s.id}>
                <div>
                  <b>
                    #{s.id} {s.template_id}
                  </b>
                  <span>
                    {s.status === "running" ? "실행 중" : s.status === "stopped" ? "중단" : s.status}
                    {s.pid ? ` · PID ${s.pid}` : ""}
                  </span>
                </div>
                <code>{s.error || s.command}</code>
                <footer>
                  {s.log_path && (
                    <a href={`/api/interactive-sessions/${s.id}/log`}>
                      출력 로그
                    </a>
                  )}
                  {s.status === "running" && (
                    <button onClick={() => stop("interactive-sessions", s.id)}>
                      중지
                    </button>
                  )}
                </footer>
              </article>
            ))}
          </div>
        </section>
      </main>
    </div>
  );
}
