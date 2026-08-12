import { useEffect, useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { syncSelectedProject } from "./scanCenterModel";
import { ErrorState, LoadingState, statusCopy as statusLabel } from "./ui";
import CommandReviewModal from "./CommandReviewModal";

type Project = { id: number; name: string };
type Target = { id: number; project_id: number; name: string; ip: string; hostname: string };
type Service = { id: number; target_id: number; port: number; protocol: string; name: string };
type ToolCommand = {
  id: string; name: string; description: string; risk: string; tool: string;
  execution_mode: string; command: string; needs_service: boolean; variables: string[];
};
type ToolGroup = { key: string; display_name: string; commands: ToolCommand[] };
type Execution = {
  id: number; target_id: number; service_id: number | null; template_id: string;
  command: string; stdout: string; stderr: string; status: string; error: string;
  started_at: string;
};

const terminal = ["completed", "failed"];
const VARIABLE_LABELS: Record<string, string> = {
  wordlist: "워드리스트 경로", domain: "도메인 / Base 도메인", path: "경로",
  username: "사용자명", password: "비밀번호", share: "공유 이름", keyword: "키워드",
  extensions: "확장자 (쉼표 구분)", lhost: "리버스 리스너 IP (LHOST)",
  lport: "리버스 리스너 포트 (LPORT)", nthash: "NT 해시", domain_sid: "도메인 SID",
  spn: "SPN", groups: "그룹 (쉼표 구분)", target_username: "대상 사용자명",
  interface: "네트워크 인터페이스 (예: tun0)",
};

const get = async <T,>(path: string): Promise<T> => {
  const r = await fetch("/api" + path);
  if (!r.ok) throw new Error((await r.json()).detail || r.statusText);
  return r.json();
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

const buildPreview = (template: string, values: Record<string, string>) =>
  template.replace(/\{([a-z_]+)\}/g, (match, key: string) => values[key] ?? match);

// Every panel elsewhere in the app only shows commands for a service Nmap
// already identified and classified correctly. This page is the fallback
// for when that classification missed or misfired (unusual port, WinRM
// read as plain HTTP) — the full command catalog, addressable by picking
// a target and, if needed, typing the port/scheme by hand.
export default function ToolsWorkspace() {
  const qc = useQueryClient();
  const [projectId, setProjectId] = useState<number>();
  const [targetId, setTargetId] = useState<number>();
  const [serviceId, setServiceId] = useState<number>();
  const [manualPort, setManualPort] = useState("");
  const [manualScheme, setManualScheme] = useState("http");
  const [search, setSearch] = useState("");
  const [activeGroup, setActiveGroup] = useState("");
  const [selectedId, setSelectedId] = useState<string>();
  const [variableValues, setVariableValues] = useState<Record<string, string>>({});
  const [reviewOpen, setReviewOpen] = useState(false);
  const [runWithSudo, setRunWithSudo] = useState(false);
  const [outputFilename, setOutputFilename] = useState("");
  const [runId, setRunId] = useState<number>();
  const [output, setOutput] = useState("실행을 선택하면 실시간 출력이 표시됩니다.\n");
  const [error, setError] = useState("");

  const projects = useQuery({
      queryKey: ["projects"],
      queryFn: () => get<Project[]>("/projects"),
    }),
    targets = useQuery({
      queryKey: ["allTargets"],
      queryFn: () => get<Target[]>("/targets"),
    }),
    services = useQuery({
      queryKey: ["toolsTargetServices", targetId],
      queryFn: () => get<Service[]>(`/targets/${targetId}/services`),
      enabled: !!targetId,
    }),
    catalog = useQuery({
      queryKey: ["toolCatalog"],
      queryFn: () => get<{ groups: ToolGroup[] }>("/tool-catalog"),
    }),
    history = useQuery({
      queryKey: ["toolExecutions", targetId],
      queryFn: () => get<Execution[]>(`/executions?target_id=${targetId}`),
      enabled: !!targetId,
      refetchInterval: 3000,
    });

  useEffect(() => {
    if (!projectId && projects.data?.length) {
      const saved = Number(localStorage.getItem("oscp-workspace-project"));
      setProjectId(projects.data.some((p) => p.id === saved) ? saved : projects.data[0].id);
    }
  }, [projectId, projects.data]);
  useEffect(() => {
    const candidates = targets.data?.filter((item) => item.project_id === projectId);
    if (candidates?.length && !candidates.some((item) => item.id === targetId)) {
      setTargetId(candidates[0].id);
    }
  }, [projectId, targets.data, targetId]);
  useEffect(() => {
    if (targetId) dispatchEvent(new CustomEvent("oscp-target-change", { detail: targetId }));
  }, [targetId]);
  const target = targets.data?.find((item) => item.id === targetId);
  useEffect(() => {
    if (target) syncSelectedProject(target.project_id);
  }, [target]);
  useEffect(() => {
    setServiceId(undefined); setManualPort(""); setManualScheme("http");
  }, [targetId]);
  useEffect(() => {
    setVariableValues({}); setServiceId(undefined); setManualPort(""); setManualScheme("http");
  }, [selectedId]);
  useEffect(() => {
    if (history.data?.length && !history.data.some((r) => r.id === runId)) {
      setRunId(history.data[0].id);
    }
  }, [history.data, runId]);

  const filteredGroups = useMemo(() => {
    const term = search.trim().toLowerCase();
    return (catalog.data?.groups || [])
      .filter((group) => !activeGroup || group.key === activeGroup)
      .map((group) => ({
        ...group,
        commands: group.commands.filter((command) => !term
          || command.name.toLowerCase().includes(term)
          || command.description.toLowerCase().includes(term)
          || command.id.includes(term)),
      }))
      .filter((group) => group.commands.length);
  }, [catalog.data, search, activeGroup]);
  const selected = catalog.data?.groups
    .flatMap((group) => group.commands).find((c) => c.id === selectedId);
  const selectedService = services.data?.find((s) => s.id === serviceId);
  const contextReady = !!targetId && (!selected?.needs_service
    || !!serviceId || (manualPort.trim() && manualScheme.trim()));
  const variablesReady = !selected
    || selected.variables.every((name) => variableValues[name]?.trim());
  const previewValues: Record<string, string> = {
    host: target?.hostname || target?.ip || "{host}",
    port: selectedService ? String(selectedService.port) : manualPort || "{port}",
    scheme: selectedService
      ? (selectedService.name === "https" ? "https" : "http") : manualScheme || "{scheme}",
    ...variableValues,
  };
  const preview = selected ? buildPreview(selected.command, previewValues) : "";
  const selectedRun = history.data?.find((r) => r.id === runId);

  const openReview = () => { setError(""); setOutputFilename(""); setReviewOpen(true); };
  const run = async () => {
    if (!selected || !targetId) return;
    setReviewOpen(false);
    try {
      const variables = { ...variableValues } as Record<string, string>;
      if (!serviceId && selected.needs_service) {
        variables.port = manualPort.trim();
        variables.scheme = manualScheme.trim();
      }
      if (selected.execution_mode === "interactive") {
        // A shell/client session isn't something to stream inline here —
        // it opens in a real desktop terminal, same as Responder, so the
        // review-and-run flow just confirms it launched.
        const session = await post<{ id: number }>("/interactive-sessions", {
          target_id: targetId, service_id: serviceId || null, template_id: selected.id,
          variables, run_as_root: runWithSudo,
        });
        await post(`/interactive-sessions/${session.id}/desktop`, {});
        setOutput((v) => `${v}\n$ ${preview}\n\n[Kali 데스크톱 터미널에서 실행했습니다.]\n`);
        return;
      }
      const execution = await post<Execution>("/executions", {
        target_id: targetId, service_id: serviceId || null, template_id: selected.id,
        variables, run_as_root: runWithSudo, output_filename: outputFilename.trim(),
      });
      setRunId(execution.id);
      await qc.invalidateQueries({ queryKey: ["toolExecutions", targetId] });
    } catch (reason) {
      setError(String(reason));
    }
  };

  useEffect(() => {
    if (!runId) return;
    setOutput("");
    const events = new EventSource(`/api/executions/${runId}/events`);
    events.onmessage = (e) => {
      const item = JSON.parse(e.data);
      if (item.stream === "stdout") setOutput((v) => v + item.data);
      if (item.stream === "stderr") setOutput((v) => v + `[stderr] ${item.data}`);
      if (item.stream === "status") {
        setOutput((v) => v + (item.error ? `\n[오류] ${item.error}\n`
          : `\n[${terminal.includes(item.status) ? item.status : "종료"}]\n`));
        events.close();
        qc.invalidateQueries({ queryKey: ["toolExecutions", targetId] });
      }
    };
    events.onerror = () => events.close();
    return () => events.close();
  }, [runId, targetId, qc]);

  return (
    <div className="lootPage">
      <header>
        <div><h1>Tools</h1><p>Nmap이 놓치거나 잘못 분류한 서비스에서, 카탈로그 전체(111개)를 직접 찾아 실행합니다.</p></div>
        <div className="lootSelectors">
          <select aria-label="프로젝트 선택" value={projectId || ""}
            onChange={(e) => setProjectId(+e.target.value)}>
            {projects.data?.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
          <select aria-label="대상 선택" value={targetId || ""}
            onChange={(e) => setTargetId(+e.target.value)}>
            {targets.data?.filter((t) => t.project_id === projectId).map((t) => (
              <option key={t.id} value={t.id}>{t.name} · {t.ip}</option>
            ))}
          </select>
        </div>
      </header>
      <main className="lootLayout">
        <aside className="lootCatalog">
          <input aria-label="명령 검색" placeholder="이름·설명으로 검색"
            value={search} onChange={(e) => setSearch(e.target.value)} />
          <select aria-label="카테고리 필터" value={activeGroup}
            onChange={(e) => setActiveGroup(e.target.value)}>
            <option value="">전체 카테고리</option>
            {catalog.data?.groups.map((g) => (
              <option key={g.key} value={g.key}>{g.display_name} ({g.commands.length})</option>
            ))}
          </select>
          {catalog.isLoading && <LoadingState label="명령 카탈로그 불러오는 중" />}
          {filteredGroups.map((group) => (
            <div key={group.key} className="lootCategory">
              <h3>{group.display_name}</h3>
              {group.commands.map((item) => (
                <button key={item.id} type="button"
                  className={selectedId === item.id ? "active" : ""}
                  onClick={() => setSelectedId(item.id)}>
                  <b>{item.name}</b>
                  <small>{item.description}</small>
                  <em>{item.tool} · 위험도 {item.risk}</em>
                </button>
              ))}
            </div>
          ))}
          {!catalog.isLoading && !filteredGroups.length && (
            <p className="empty">검색어와 일치하는 명령이 없습니다.</p>
          )}
        </aside>
        <section className="lootMain">
          {selected && (
            <div className="lootPreview">
              <b>{selected.name}</b>
              <small>{selected.description}</small>
              {selected.needs_service && (
                <label>
                  서비스 (있으면 선택 · 없으면 아래 직접 입력)
                  <select value={serviceId || ""}
                    onChange={(e) => setServiceId(e.target.value ? +e.target.value : undefined)}>
                    <option value="">직접 입력</option>
                    {services.data?.map((s) => (
                      <option key={s.id} value={s.id}>{s.port}/{s.protocol} · {s.name}</option>
                    ))}
                  </select>
                </label>
              )}
              {selected.needs_service && !serviceId && (
                <div className="lootCredential">
                  <input placeholder="포트 (예: 8080)" value={manualPort}
                    onChange={(e) => setManualPort(e.target.value)} />
                  <select value={manualScheme} onChange={(e) => setManualScheme(e.target.value)}>
                    <option value="http">http</option>
                    <option value="https">https</option>
                  </select>
                </div>
              )}
              {selected.variables.map((name) => (
                <label key={name}>
                  {VARIABLE_LABELS[name] || name}
                  <input value={variableValues[name] || ""}
                    onChange={(e) => setVariableValues((v) => ({ ...v, [name]: e.target.value }))} />
                </label>
              ))}
              <code>{preview}</code>
              <span>위험도 {selected.risk} · {selected.tool}</span>
              <button type="button" disabled={!contextReady || !variablesReady}
                onClick={openReview}>
                실행 내용 검토
              </button>
            </div>
          )}
          {!selected && <p className="empty">왼쪽 목록에서 실행할 명령을 선택하세요.</p>}
          {error && <ErrorState message={error} />}
          <CommandReviewModal
            command={reviewOpen && selected ? { name: selected.name, preview, risk: selected.risk } : undefined}
            targetLabel={target?.ip} routeLabel="kali / local"
            runWithSudo={runWithSudo} onSudo={setRunWithSudo}
            outputFilename={outputFilename} onOutputFilename={setOutputFilename}
            onCancel={() => setReviewOpen(false)} onRun={() => void run()} />
          <div className="terminal lootTerminal">
            <div className={`terminalStatus${selectedRun ? ` terminalStatus--${selectedRun.status}` : ""}`}>
              <span className="termDots" aria-hidden="true">
                <i className="termDot" /><i className="termDot termDot--yellow" />
                <i className="termDot termDot--green" />
              </span>
              <b>실시간 출력</b>
              <small>
                {selectedRun
                  ? `실행 #${selectedRun.id} · ${statusLabel[selectedRun.status] || selectedRun.status}`
                  : "실행 대기"}
              </small>
            </div>
            <pre>{output}</pre>
          </div>
        </section>
        <aside className="lootHistory">
          <div className="panelTitle"><span>실행 이력</span></div>
          {history.isLoading && <LoadingState label="이력을 불러오는 중" />}
          {!history.isLoading && !history.data?.length && (
            <p className="empty">이 대상에서 실행한 기록이 없습니다.</p>
          )}
          {history.data?.map((r) => (
            <div key={r.id} role="button" tabIndex={0}
              className={`lootRow ${r.id === runId ? "active" : ""}`}
              onClick={() => setRunId(r.id)}>
              <span><b>#{r.id} · {r.template_id}</b>
                <em>{statusLabel[r.status] || r.status}</em></span>
              <small>{new Date(r.started_at).toLocaleString()}</small>
            </div>
          ))}
        </aside>
      </main>
    </div>
  );
}
