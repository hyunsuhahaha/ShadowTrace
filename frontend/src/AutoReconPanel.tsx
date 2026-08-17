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
type AutoReconCapability = {
  installed: boolean; version: string; help: string;
  plugins: Array<{type: "PortScan" | "ServiceScan" | "Report"; name: string;
    slug: string; description: string}>;
  options: Array<{flag: string; signature: string; description: string}>;
};

type AutoReconOptions = {
  mode: "default" | "quick" | "forced" | "custom";
  ports: string; tags: string; excludeTags: string; portScans: string;
  serviceScans: string; reports: string; forceServices: string; config: string;
  maxScans: string; maxPortScans: string; heartbeat: string; timeout: string;
  targetTimeout: string; globalFile: string; pluginDirs: string; additionalPluginDir: string;
  nmapAppend: string; maxPluginTargetInstances: string; maxPluginGlobalInstances: string;
  onlyScansDir: boolean; noPortDirs: boolean; proxychains: boolean;
  disableSanityChecks: boolean; accessible: boolean; verbose: boolean; raw: string;
};

const initialOptions: AutoReconOptions = {
  mode: "default", ports: "", tags: "default", excludeTags: "", portScans: "",
  serviceScans: "", reports: "", forceServices: "", config: "", maxScans: "",
  maxPortScans: "", heartbeat: "60", timeout: "", targetTimeout: "",
  globalFile: "", pluginDirs: "", additionalPluginDir: "", nmapAppend: "",
  maxPluginTargetInstances: "", maxPluginGlobalInstances: "", onlyScansDir: false,
  noPortDirs: false, proxychains: false, disableSanityChecks: false,
  accessible: false, verbose: false, raw: "",
};

const quoteArg = (value: string) => `'${value.replaceAll("'", `'\\''`)}'`;

export function buildAutoReconArguments(options: AutoReconOptions): string {
  const args: string[] = [];
  const add = (flag: string, value: string) => {
    if (value.trim()) args.push(flag, quoteArg(value.trim()));
  };
  if (options.mode === "quick") args.push("--port-scans", "top-tcp-ports");
  if (options.mode === "forced") {
    const services = options.forceServices.trim().split(/\s+/).filter(Boolean);
    if (services.length) args.push("--force-services", ...services.map(quoteArg));
  }
  if (options.mode === "custom") add("--port-scans", options.portScans);
  add("--ports", options.ports);
  if (options.tags.trim() && options.tags.trim() !== "default") add("--tags", options.tags);
  add("--exclude-tags", options.excludeTags);
  add("--service-scans", options.serviceScans);
  add("--reports", options.reports);
  add("--config", options.config);
  add("--max-scans", options.maxScans);
  add("--max-port-scans", options.maxPortScans);
  add("--heartbeat", options.heartbeat);
  add("--timeout", options.timeout);
  add("--target-timeout", options.targetTimeout);
  add("--global-file", options.globalFile);
  add("--plugins-dir", options.pluginDirs);
  add("--add-plugins-dir", options.additionalPluginDir);
  add("--nmap-append", options.nmapAppend);
  add("--max-plugin-target-instances", options.maxPluginTargetInstances);
  add("--max-plugin-global-instances", options.maxPluginGlobalInstances);
  if (options.onlyScansDir) args.push("--only-scans-dir");
  if (options.noPortDirs) args.push("--no-port-dirs");
  if (options.proxychains) args.push("--proxychains");
  if (options.disableSanityChecks) args.push("--disable-sanity-checks");
  if (options.accessible) args.push("--accessible");
  if (options.verbose) args.push("--verbose");
  if (options.raw.trim()) args.push(options.raw.trim());
  return args.join(" ");
}

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
  const [options, setOptions] = useState<AutoReconOptions>(initialOptions);
  const [capabilitySearch, setCapabilitySearch] = useState("");
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
  const capabilities = useQuery({
    queryKey: ["autoReconCapabilities"],
    queryFn: () => get<AutoReconCapability>("/autorecon/capabilities"),
    staleTime: Infinity,
  });
  const visiblePlugins = (capabilities.data?.plugins || []).filter((plugin) =>
    `${plugin.type} ${plugin.name} ${plugin.slug} ${plugin.description}`.toLowerCase()
      .includes(capabilitySearch.toLowerCase()));
  const visibleOptions = (capabilities.data?.options || []).filter((option) =>
    `${option.flag} ${option.signature} ${option.description}`.toLowerCase()
      .includes(capabilitySearch.toLowerCase()));
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
        <summary>실행 범위 및 프로필 {capabilities.data?.version && `· ${capabilities.data.version}`}</summary>
        <div className="autoReconOptionGrid">
          <label><span>실행 모드</span><select value={options.mode}
            onChange={(e) => setOptions({...options, mode: e.target.value as AutoReconOptions["mode"]})}>
            <option value="default">기본 전체 파이프라인</option>
            <option value="quick">Quick TCP + 서비스 열거</option>
            <option value="forced">포트 스캔 없이 서비스 강제 지정</option>
            <option value="custom">포트 스캔 플러그인 직접 선택</option>
          </select></label>
          <label><span>포트 범위</span><input value={options.ports} placeholder="T:21-25,80,443,U:53,161"
            onChange={(e) => setOptions({...options, ports: e.target.value})} /></label>
          {options.mode === "forced" && <label className="autoReconOptionWide"><span>강제 서비스</span>
            <input value={options.forceServices} placeholder="tcp/80/http tcp/443/https/secure"
              onChange={(e) => setOptions({...options, forceServices: e.target.value})} /></label>}
          {options.mode === "custom" && <label className="autoReconOptionWide"><span>PortScan 플러그인</span>
            <input list="autorecon-port-plugins" value={options.portScans} placeholder="top-tcp-ports,all-tcp-ports,top-100-udp-ports"
              onChange={(e) => setOptions({...options, portScans: e.target.value})} /></label>}
          <label><span>포함 태그</span><input value={options.tags}
            onChange={(e) => setOptions({...options, tags: e.target.value})} /></label>
          <label><span>제외 태그</span><input value={options.excludeTags} placeholder="long,udp"
            onChange={(e) => setOptions({...options, excludeTags: e.target.value})} /></label>
          <label><span>ServiceScan 플러그인</span><input list="autorecon-service-plugins" value={options.serviceScans} placeholder="nmap-http,dirbuster,whatweb"
            onChange={(e) => setOptions({...options, serviceScans: e.target.value})} /></label>
          <label><span>Report 플러그인</span><input list="autorecon-report-plugins" value={options.reports} placeholder="markdown,cherrytree"
            onChange={(e) => setOptions({...options, reports: e.target.value})} /></label>
          <label><span>동시 스캔</span><input type="number" min="1" value={options.maxScans}
            onChange={(e) => setOptions({...options, maxScans: e.target.value})} /></label>
          <label><span>동시 포트 스캔</span><input type="number" min="1" value={options.maxPortScans}
            onChange={(e) => setOptions({...options, maxPortScans: e.target.value})} /></label>
          <label><span>Heartbeat(초)</span><input type="number" min="1" value={options.heartbeat}
            onChange={(e) => setOptions({...options, heartbeat: e.target.value})} /></label>
          <label><span>전체 제한(분)</span><input type="number" min="1" value={options.timeout}
            onChange={(e) => setOptions({...options, timeout: e.target.value})} /></label>
          <label><span>대상별 제한(분)</span><input type="number" min="1" value={options.targetTimeout}
            onChange={(e) => setOptions({...options, targetTimeout: e.target.value})} /></label>
          <label><span>TOML 설정 파일</span><input value={options.config} placeholder="~/.config/AutoRecon/config.toml"
            onChange={(e) => setOptions({...options, config: e.target.value})} /></label>
          <label><span>전역 TOML</span><input value={options.globalFile} placeholder="~/.config/AutoRecon/global.toml"
            onChange={(e) => setOptions({...options, globalFile: e.target.value})} /></label>
          <label><span>플러그인 디렉터리</span><input value={options.pluginDirs}
            onChange={(e) => setOptions({...options, pluginDirs: e.target.value})} /></label>
          <label><span>추가 플러그인 디렉터리</span><input value={options.additionalPluginDir}
            onChange={(e) => setOptions({...options, additionalPluginDir: e.target.value})} /></label>
          <label><span>Nmap 추가 인자</span><input value={options.nmapAppend} placeholder="-T3 --min-rate 500"
            onChange={(e) => setOptions({...options, nmapAppend: e.target.value})} /></label>
          <label><span>대상별 플러그인 제한</span><input value={options.maxPluginTargetInstances} placeholder="nmap-http:2 dirbuster:1"
            onChange={(e) => setOptions({...options, maxPluginTargetInstances: e.target.value})} /></label>
          <label><span>전역 플러그인 제한</span><input value={options.maxPluginGlobalInstances} placeholder="nmap-http:2 dirbuster:1"
            onChange={(e) => setOptions({...options, maxPluginGlobalInstances: e.target.value})} /></label>
          <label className="autoReconCheck"><input type="checkbox" checked={options.onlyScansDir}
            onChange={(e) => setOptions({...options, onlyScansDir: e.target.checked})} /><span>scans/만 생성</span></label>
          <label className="autoReconCheck"><input type="checkbox" checked={options.accessible}
            onChange={(e) => setOptions({...options, accessible: e.target.checked})} /><span>스크린리더 출력</span></label>
          <label className="autoReconCheck"><input type="checkbox" checked={options.noPortDirs}
            onChange={(e) => setOptions({...options, noPortDirs: e.target.checked})} /><span>포트별 폴더 생략</span></label>
          <label className="autoReconCheck"><input type="checkbox" checked={options.proxychains}
            onChange={(e) => setOptions({...options, proxychains: e.target.checked})} /><span>Proxychains 사용</span></label>
          <label className="autoReconCheck"><input type="checkbox" checked={options.disableSanityChecks}
            onChange={(e) => setOptions({...options, disableSanityChecks: e.target.checked})} /><span>사전 검사 생략</span></label>
          <label className="autoReconCheck"><input type="checkbox" checked={options.verbose}
            onChange={(e) => setOptions({...options, verbose: e.target.checked})} /><span>상세 출력</span></label>
          <label className="autoReconOptionWide"><span>추가 CLI 인자</span><textarea value={options.raw}
            onChange={(e) => setOptions({...options, raw: e.target.value})}
            placeholder="--nmap-append '-T3' --dirbuster.threads 20" /></label>
        </div>
        <datalist id="autorecon-port-plugins">{(capabilities.data?.plugins || [])
          .filter((p) => p.type === "PortScan").map((p) => <option key={p.slug} value={p.slug}>{p.name}</option>)}</datalist>
        <datalist id="autorecon-service-plugins">{(capabilities.data?.plugins || [])
          .filter((p) => p.type === "ServiceScan").map((p) => <option key={p.slug} value={p.slug}>{p.name}</option>)}</datalist>
        <datalist id="autorecon-report-plugins">{(capabilities.data?.plugins || [])
          .filter((p) => p.type === "Report").map((p) => <option key={p.slug} value={p.slug}>{p.name}</option>)}</datalist>
        <small>대상과 출력 경로만 앱이 관리합니다. 현재 설정: <code>{buildAutoReconArguments(options) || "AutoRecon 기본값"}</code></small>
        <details className="autoReconCapabilities">
          <summary>설치된 전체 기능·옵션·플러그인</summary>
          <input aria-label="AutoRecon 기능 검색" value={capabilitySearch} placeholder="플러그인 또는 옵션 검색"
            onChange={(e) => setCapabilitySearch(e.target.value)} />
          <div className="autoReconPluginCatalog">{visiblePlugins.map((plugin) =>
            <button type="button" key={`${plugin.type}-${plugin.slug}`} title={plugin.description}
              onClick={() => {
                const key: "portScans" | "serviceScans" | "reports" = plugin.type === "PortScan" ? "portScans"
                  : plugin.type === "ServiceScan" ? "serviceScans" : "reports";
                const current = options[key];
                setOptions({...options, [key]: [current, plugin.slug].filter(Boolean).join(",")});
              }}>
              <b>{plugin.slug}</b><span>{plugin.type} · {plugin.name}</span>
            </button>)}</div>
          <div className="autoReconPluginCatalog">{visibleOptions.map((option) =>
            <button type="button" key={option.signature} title={option.description}
              onClick={() => setOptions({...options,
                raw: `${options.raw}${options.raw.trim() ? " " : ""}${option.flag} `})}>
              <b>{option.flag}</b><span>{option.signature}</span>
            </button>)}</div>
          <pre>{capabilities.data?.help || "AutoRecon 기능 정보를 불러오는 중..."}</pre>
        </details>
      </details>
      <p className="autoReconPanel__hint">
        선택한 대상 전체를 실제 AutoRecon(Tib3rius) 한 번의 실행으로 넘깁니다. 선택한
        포트·태그·플러그인 구성에 따라 서비스를 병렬 열거하고, 결과를 대상별
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
      <Button type="button" disabled={!scopeConfirmed || !selectedIds.size || starting
        || (options.mode === "forced" && !options.forceServices.trim())}
        onClick={() => onStart(buildAutoReconArguments(options))}>
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
