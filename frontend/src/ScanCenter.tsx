import { useEffect, useMemo, useRef, useState,
  type PointerEvent as ReactPointerEvent } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import VpnControl from "./VpnControl";
import ScanToolPicker from "./ScanToolPicker";
import ScanProfileComposer from "./ScanProfileComposer";
import ScanJobStatus from "./ScanJobStatus";
import ScanHistoryPanel from "./ScanHistoryPanel";
import AutoReconPanel from "./AutoReconPanel";
import {useFloatingTerminal} from "./FloatingTerminal";
import SmartTerminalOutput from "./SmartTerminalOutput";
import { ErrorState, LoadingState, statusCopy as statusLabel } from "./ui";
import {
  bytes, elapsed, get, selectVisibleScan, syncSelectedProject, terminal, toolProfileGroups,
  type Artifact, type Automation, type Obs, type Profile, type Project,
  type Scan, type Target, type VpnStatus,
} from "./scanCenterModel";

export default function ScanCenter({ embedded = false, initialTargetId }: {
  embedded?: boolean; initialTargetId?: number;
} = {}) {
  const qc = useQueryClient();
  const {floatingScanId, floatScan} = useFloatingTerminal();
  const pendingDock = (() => {
    try { return JSON.parse(localStorage.getItem("oscp-scan-dock") || "null"); }
    catch { return null; }
  })();
  const [targetId, setTargetId] = useState<number | undefined>(
    pendingDock?.targetId || initialTargetId),
    [targetIp, setTargetIp] = useState(""),
    [targetError, setTargetError] = useState(""),
    [activeProjectId, setActiveProjectId] = useState<number | undefined>(() => {
      const saved = Number(localStorage.getItem("oscp-workspace-project"));
      return saved > 0 ? saved : undefined;
    }),
    [scanId, setScanId] = useState<number>(),
    [baseId, setBaseId] = useState<number>(),
    [tool, setTool] = useState<"nmap" | "masscan">("nmap"),
    [profileId, setProfileId] = useState<number>(),
    [ports, setPorts] = useState("80,443"),
    [topPorts, setTopPorts] = useState("100"),
    [review, setReview] = useState(false),
    [scope, setScope] = useState(false),
    [commandDraft, setCommandDraft] = useState(""),
    [commandDirty, setCommandDirty] = useState(false),
    [output, setOutput] = useState("저장된 출력을 보려면 스캔을 선택하세요.\n"),
    [statusFilter, setStatusFilter] = useState("all"),
    [query, setQuery] = useState(""),
    [serviceFilter, setServiceFilter] = useState(""),
    [portFilter, setPortFilter] = useState(""),
    [openOnly, setOpenOnly] = useState(true),
    // In-app modal instead of window.prompt() -- native OS dialogs can fail
    // to surface at all on a bare/root Kali Chrome, so the button just
    // silently hangs with zero visible sign anything happened.
    [metadataOpen, setMetadataOpen] = useState(false),
    [aliasDraft, setAliasDraft] = useState(""),
    [tagsDraft, setTagsDraft] = useState(""),
    [changedOnly, setChangedOnly] = useState(false),
    [sort, setSort] = useState<"port" | "service">("port"),
    [portsCopied, setPortsCopied] = useState(false),
    [clock, setClock] = useState(Date.now()),
    [lastEventAt, setLastEventAt] = useState<number>(),
    [processAlive, setProcessAlive] = useState<boolean>(),
    [streamState, setStreamState] = useState<
      "idle" | "connecting" | "connected" | "disconnected"
    >("idle"),
    [autoReconMode, setAutoReconMode] = useState(false),
    [autoReconSelected, setAutoReconSelected] = useState<Set<number>>(new Set()),
    [autoReconStarting, setAutoReconStarting] = useState(false),
    [autoReconError, setAutoReconError] = useState(""),
    [autoReconRunId, setAutoReconRunId] = useState<number>();
  const transcript = useRef<HTMLPreElement>(null);
  const transcriptPanel = useRef<HTMLDivElement>(null);
  const detachDrag = useRef<{x: number; y: number; pointerId: number}>();
  const projects = useQuery({
      queryKey: ["projects"],
      queryFn: () => get<Project[]>("/projects"),
    }),
    targets = useQuery({
      queryKey: ["allTargets"],
      queryFn: () => get<Target[]>("/targets"),
    }),
    profiles = useQuery({
      queryKey: ["scanProfiles"],
      queryFn: () => get<Profile[]>("/scans/profiles"),
    }),
    scans = useQuery({
      queryKey: ["scans", targetId],
      queryFn: () => get<Scan[]>(`/scans?target_id=${targetId}`),
      enabled: !!targetId,
      refetchInterval: 3000,
    }),
    obs = useQuery({
      queryKey: ["scanObs", scanId],
      queryFn: () => get<Obs[]>(`/scans/${scanId}/observations`),
      enabled: !!scanId,
    }),
    artifacts = useQuery({
      queryKey: ["scanArtifacts", scanId],
      queryFn: () => get<Artifact[]>(`/scans/${scanId}/artifacts`),
      enabled: !!scanId,
    }),
    automation = useQuery({
      queryKey: ["scanAutomation", scanId],
      queryFn: () => get<Automation>(`/scans/${scanId}/automation`),
      enabled: !!scanId,
    }),
    diff = useQuery({
      queryKey: ["scanDiff", baseId, scanId],
      queryFn: () => get<any>(`/scans/compare/${baseId}/${scanId}`),
      enabled: !!baseId && !!scanId && baseId !== scanId,
    }),
    vpnStatus = useQuery({
      queryKey: ["vpnStatus"],
      queryFn: () => get<VpnStatus>("/vpn/status"),
      refetchInterval: 3000,
    });
  const masscanBlockedByVpn =
    !!vpnStatus.data?.connected && vpnStatus.data?.link_type === "tun";
  // The project is chosen once, in AppShell's header dropdown; every other
  // page (including this one) just follows it, so it can't be picked twice.
  const effectiveProjectId = activeProjectId || projects.data?.[0]?.id;
  useEffect(() => {
    const change = (e: Event) =>
      setActiveProjectId((e as CustomEvent<number>).detail || undefined);
    addEventListener("oscp-project-change", change);
    return () => removeEventListener("oscp-project-change", change);
  }, []);
  useEffect(() => {
    if (!effectiveProjectId || !targets.data) return;
    if (targets.data.some(
      (item) => item.id === targetId && item.project_id === effectiveProjectId,
    )) return;
    setTargetId(targets.data.find((item) => item.project_id === effectiveProjectId)?.id);
    setScanId(undefined);
  }, [effectiveProjectId, targets.data]);
  useEffect(() => {
    const selectedTarget = targets.data?.find((item) => item.id === targetId);
    if (selectedTarget) syncSelectedProject(selectedTarget.project_id);
  }, [targetId, targets.data]);
  useEffect(() => {
    if (targetId) dispatchEvent(new CustomEvent("oscp-target-change", {detail: targetId}));
  }, [targetId]);
  useEffect(() => {
    if (!scans.data) return;
    const pending = (() => {
      try { return JSON.parse(localStorage.getItem("oscp-scan-dock") || "null"); }
      catch { return null; }
    })();
    if (pending?.scanId && scans.data.some((scan) => scan.id === pending.scanId)) {
      setScanId(pending.scanId);
      localStorage.removeItem("oscp-scan-dock");
      requestAnimationFrame(() => transcriptPanel.current?.scrollIntoView({block: "center"}));
      return;
    }
    setScanId(selectVisibleScan(scanId, scans.data));
  }, [scans.data, scanId]);
  useEffect(() => {
    if (tool === "masscan" && masscanBlockedByVpn) setTool("nmap");
  }, [tool, masscanBlockedByVpn]);
  useEffect(() => {
    if (!profiles.data?.length) return;
    const kinds = toolProfileGroups[tool].flatMap((group) => group.kinds);
    const current = profiles.data.find((p) => p.id === profileId);
    if (current && kinds.includes(current.kind)) return;
    const first = [...profiles.data]
      .filter((p) => kinds.includes(p.kind))
      .sort((a, b) => kinds.indexOf(a.kind) - kinds.indexOf(b.kind))[0];
    if (first) setProfileId(first.id);
  }, [tool, profiles.data]);
  const profile = profiles.data?.find((x) => x.id === profileId),
    target = targets.data?.find((x) => x.id === targetId),
    selected = scans.data?.find((x) => x.id === scanId),
    payload = () => ({
      target_id: targetId,
      target_ip: targetIp.trim(),
      profile_id: profileId,
      ports: profile?.arguments.includes("{ports}") ? ports : "",
      top_ports: Number(topPorts),
      extra_arguments: [],
      command_override: commandDirty ? commandDraft : null,
    });
  // Keep the IP input showing whichever target is current (picked from the
  // dropdown, or auto-selected), so "review scan" reuses it by IP instead
  // of always minting a new target.
  useEffect(() => {
    if (target) setTargetIp(target.ip);
  }, [target?.id]);
  const preview = useQuery({
    queryKey: ["scanPreview", targetIp.trim(), profileId, ports, topPorts],
    queryFn: async () => {
      const r = await fetch("/api/scans/preview", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload()),
      });
      if (!r.ok) throw new Error((await r.json()).detail);
      return r.json();
    },
    enabled:
      !!targetIp.trim() &&
      !!profileId &&
      (!profile?.arguments.includes("{top_ports}") ||
        (Number(topPorts) >= 1 && Number(topPorts) <= 65535)),
  });
  useEffect(() => {
    setCommandDraft(preview.data?.command || "");
    setCommandDirty(false);
    setScope(false);
  }, [preview.data?.command]);
  const commandContextBound = !!targetIp.trim() && commandDraft.trim().endsWith(targetIp.trim());
  const commandEngineBound = (() => {
    const words = commandDraft.trim().split(/\s+/);
    return (words[0] === "sudo" ? words[1] : words[0]) === profile?.engine;
  })();
  const editCommand = (value: string) => {
    setCommandDraft(value);
    setCommandDirty(value.trim() !== (preview.data?.command || "").trim());
    setScope(false);
    setTargetError("");
  };
  const changeTargetIp = (value: string) => {
    const previous = targetIp.trim();
    setTargetIp(value);
    setScope(false);
    if (!previous || !commandDraft.trim().endsWith(previous)) return;
    const injected = commandDraft.trimEnd().slice(0, -previous.length) + value.trim();
    setCommandDraft(injected);
    setCommandDirty(commandDirty);
  };
  useEffect(() => {
    if (!scanId || floatingScanId === scanId) return;
    setStreamState("connecting");
    setLastEventAt(Date.now());
    setOutput("");
    const events = new EventSource(`/api/scans/${scanId}/events`);
    events.onopen = () => setStreamState("connected");
    events.onmessage = async (e) => {
      const item = JSON.parse(e.data);
      setLastEventAt(Date.now());
      if (item.stream === "heartbeat")
        setProcessAlive(Boolean(item.process_alive));
      if (item.stream === "snapshot") setOutput(item.data);
      if (item.stream === "stdout") setOutput((v) => v + item.data);
      if (item.stream === "stderr")
        setOutput((v) => v + `[stderr] ${item.data}`);
      if (item.stream === "status" && terminal.includes(item.status)) {
        setStreamState("idle");
        setOutput(
          (v) =>
            v +
            (item.error
              ? `\n[${item.status}] ${item.error}\n`
              : `\n[${item.status}${item.exit_code == null ? "" : ` · exit ${item.exit_code}`}]\n`),
        );
        events.close();
        await qc.invalidateQueries({ queryKey: ["scans", targetId] });
        await qc.invalidateQueries({ queryKey: ["scanObs", scanId] });
        await qc.invalidateQueries({ queryKey: ["scanArtifacts", scanId] });
        await qc.invalidateQueries({ queryKey: ["scanAutomation", scanId] });
        // Let the progress graph pull the freshly-parsed services in as nodes.
        dispatchEvent(new CustomEvent("oscp-graph-refresh"));
      }
      if (item.stream === "status" && item.status === "running") {
        await qc.invalidateQueries({ queryKey: ["scans", targetId] });
        dispatchEvent(new CustomEvent("oscp-graph-refresh"));
      }
    };
    events.onerror = () => {
      setStreamState("disconnected");
      events.close();
    };
    return () => events.close();
  }, [scanId, targetId, qc, floatingScanId]);
  useEffect(() => {
    if (!selected || !["queued", "running", "processing"].includes(selected.status))
      return;
    const timer = window.setInterval(() => setClock(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [selected?.id, selected?.status]);
  useEffect(() => {
    const panel = transcript.current;
    if (panel) panel.scrollTop = panel.scrollHeight;
  }, [output]);
  const beginDetach = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (!selected || event.button !== 0) return;
    detachDrag.current = {x: event.clientX, y: event.clientY, pointerId: event.pointerId};
    event.currentTarget.setPointerCapture(event.pointerId);
  };
  const moveDetach = (event: ReactPointerEvent<HTMLDivElement>) => {
    const start = detachDrag.current;
    if (!start || !selected || !target || !transcriptPanel.current) return;
    if (Math.hypot(event.clientX - start.x, event.clientY - start.y) < 5) return;
    floatScan({
      scanId: selected.id, projectId: target.project_id, targetId: target.id, targetIp: target.ip,
      command: selected.command, source: selected.source, status: selected.status,
      exitCode: selected.exit_code, linkType: vpnStatus.data?.link_type || "local",
      initialOutput: output,
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
  const visibleScans = useMemo(
      () =>
        (scans.data || []).filter(
          (s) =>
            (statusFilter === "all" || s.status === statusFilter) &&
            (!query ||
              `${s.id} ${s.alias} ${s.command} ${s.tags}`
                .toLowerCase()
                .includes(query.toLowerCase())),
        ),
      [scans.data, statusFilter, query],
    ),
    changedPorts = useMemo(
      () =>
        new Set<string>(
          (diff.data?.changed || []).map((x: any) => `${x.protocol}:${x.port}`),
        ),
      [diff.data],
    ),
    visibleObs = useMemo(
      () =>
        (obs.data || [])
          .filter(
            (o) =>
              (!openOnly || o.state === "open") &&
              (!serviceFilter ||
                o.name.toLowerCase().includes(serviceFilter.toLowerCase())) &&
              (!portFilter || String(o.port).includes(portFilter)) &&
              (!changedOnly || changedPorts.has(`${o.protocol}:${o.port}`)),
          )
          .sort((a, b) =>
            sort === "port"
              ? a.port - b.port
              : a.name.localeCompare(b.name) || a.port - b.port,
          ),
      [
        obs.data,
        openOnly,
        serviceFilter,
        portFilter,
        changedOnly,
        changedPorts,
        sort,
      ],
    ),
    selectedProfile = useMemo(
      () => profiles.data?.find((p) => p.id === selected?.profile_id),
      [profiles.data, selected?.profile_id],
    ),
    openTcpPorts = useMemo(
      () =>
        Array.from(
          new Set(
            (obs.data || [])
              .filter((o) => o.state === "open" && o.protocol === "tcp")
              .map((o) => o.port),
          ),
        ).sort((a, b) => a - b),
      [obs.data],
    ),
    chainedScan = useMemo(
      () => scans.data?.find((s) => s.parent_scan_id === selected?.id),
      [scans.data, selected?.id],
    ),
    xmlArtifact = useMemo(
      () => artifacts.data?.find((a) => a.kind === "xml"),
      [artifacts.data],
    );
  const useDiscoveredPorts = () => {
    const detail =
      profiles.data?.find((p) => p.kind === "selected_syn_detail") ||
      profiles.data?.find((p) => p.kind === "selected_ports");
    if (!detail || !openTcpPorts.length) return;
    setPorts(openTcpPorts.join(","));
    setProfileId(detail.id);
  };
  const copyVisiblePorts = async () => {
    const ports = Array.from(new Set(visibleObs.map((o) => o.port))).sort((a, b) => a - b);
    if (!ports.length) return;
    await navigator.clipboard.writeText(ports.join(","));
    setPortsCopied(true);
    window.setTimeout(() => setPortsCopied(false), 1500);
  };
  const refresh = async () =>
    Promise.all([
      qc.invalidateQueries({ queryKey: ["scans", targetId] }),
      qc.invalidateQueries({ queryKey: ["services", targetId] }),
    ]);
  // One button: IP -> pick a tool/profile -> review. No separate "add target"
  // step - typing an existing target's IP reuses it (by IP, within the
  // active project), anything new is created on the fly via /targets/ensure.
  const beginReview = async () => {
    const ip = targetIp.trim();
    if (!ip || !profileId) return;
    setTargetError("");
    const existing = targets.data?.find(
      (item) => item.ip === ip && item.project_id === effectiveProjectId,
    );
    const validateAndReview = async (id: number) => {
      setTargetId(id);
      const response = await fetch("/api/scans/preview", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({...payload(), target_id: id}),
      });
      const data = await response.json();
      if (!response.ok) {
        setTargetError(typeof data.detail === "string" ? data.detail : "명령을 검증할 수 없습니다.");
        return;
      }
      setCommandDraft(data.command);
      setScope(false);
      setReview(true);
    };
    if (existing) {
      await validateAndReview(existing.id);
      return;
    }
    const r = await fetch("/api/targets/ensure", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ip,
        name: "",
        project_id: effectiveProjectId ?? null,
      }),
    });
    if (!r.ok) {
      const data = await r.json();
      setTargetError(
        typeof data.detail === "string"
          ? data.detail
          : "유효한 IP 주소를 입력하세요.",
      );
      return;
    }
    const created: Target = await r.json();
    await Promise.all([
      qc.invalidateQueries({ queryKey: ["allTargets"] }),
      qc.invalidateQueries({ queryKey: ["projects"] }),
    ]);
    await validateAndReview(created.id);
  };
  const upload = async (f: File) => {
    if (!targetId) return;
    const d = new FormData();
    d.append("file", f);
    const r = await fetch(`/api/scans/import/${targetId}`, {
      method: "POST",
      body: d,
    });
    if (!r.ok) throw new Error((await r.json()).detail);
    await refresh();
  };
  const execute = async () => {
    if (!scope) return;
    const r = await fetch("/api/scans/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload()),
    });
    if (!r.ok) {
      setOutput(`[error] ${(await r.json()).detail}\n`);
      setReview(false);
      return;
    }
    const job: Scan = await r.json();
    setReview(false);
    setScanId(job.id);
    setOutput(`$ ${job.command}\n`);
    await refresh();
  };
  const toggleAutoReconTarget = (id: number) =>
    setAutoReconSelected((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  const selectAllAutoReconTargets = () => setAutoReconSelected(new Set(
    (targets.data || []).filter((t) => t.project_id === effectiveProjectId).map((t) => t.id)));
  const clearAutoReconTargets = () => setAutoReconSelected(new Set());
  // The real `autorecon` binary batches every target into one process/output
  // tree, so this is a single POST -- not a loop like the single-target
  // "review scan" flow above.
  const startAutoRecon = async () => {
    if (!effectiveProjectId || !autoReconSelected.size) return;
    setAutoReconStarting(true);
    setAutoReconError("");
    try {
      const r = await fetch("/api/autorecon/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          project_id: effectiveProjectId, target_ids: Array.from(autoReconSelected),
        }),
      });
      if (!r.ok) {
        setAutoReconError((await r.json()).detail);
        return;
      }
      const run = await r.json();
      setAutoReconRunId(run.id);
      await qc.invalidateQueries({ queryKey: ["autoReconRuns", effectiveProjectId] });
    } finally {
      setAutoReconStarting(false);
    }
  };
  const stop = async (id: number) => {
      await fetch(`/api/scans/${id}/stop`, { method: "POST" });
      await refresh();
    },
    rerun = async (id: number) => {
      const r = await fetch(`/api/scans/${id}/rerun`, { method: "POST" });
      if (!r.ok) {
        setOutput(`[error] ${(await r.json()).detail}\n`);
        return;
      }
      const job: Scan = await r.json();
      setScanId(job.id);
      await refresh();
    },
    deleteScan = async (id: number) => {
      const r = await fetch(`/api/scans/${id}`, { method: "DELETE" });
      if (!r.ok) {
        setOutput(`[error] ${(await r.json()).detail}\n`);
        return;
      }
      if (scanId === id) setScanId(undefined);
      await refresh();
    },
    openMetadata = () => {
      if (!selected) return;
      setAliasDraft(selected.alias || "");
      setTagsDraft(JSON.parse(selected.tags || "[]").join(", "));
      setMetadataOpen(true);
    },
    saveMetadata = async () => {
      if (!selected) return;
      const tags = tagsDraft.split(",").map((x) => x.trim()).filter(Boolean);
      await fetch(`/api/scans/${selected.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alias: aliasDraft, tags }),
      });
      setMetadataOpen(false);
      await refresh();
    };
  return (
    <div className={embedded ? "scanPage scanPage--embedded" : "scanPage"}>
      {!embedded && <header>
        <div className="brand">
          <span className="mark">OW</span>
          <div>
            <b>OSCP Workspace</b>
            <small>Scan Center</small>
          </div>
        </div>
        <VpnControl targetIp={target?.ip} />
      </header>}
      <nav>
        <a href="#enumeration">Enumeration</a>
        <a href="#web">Web 테스트</a>
        <a href="#evidence">증적</a>
        <a href="#exploit-research">Exploit Research</a>
        <a href="#directory">AD 정보</a>
        <a href="#sessions">세션</a>
        <a href="#reports">보고서</a>
        <a href="#operations">운영</a>
        <select
          aria-label="대상 선택"
          title="이 프로젝트에 이미 등록된 대상 중에서 전환"
          value={targetId || ""}
          onChange={(e) => {
            setTargetId(+e.target.value);
            setScanId(undefined);
          }}
        >
          {targets.data
            ?.filter((item) => item.project_id === effectiveProjectId)
            .map((item) => (
              <option key={item.id} value={item.id}>
                {item.name} · {item.ip}
              </option>
            ))}
        </select>
        <span className="tools">스캔 기록 {scans.data?.length || 0}개</span>
        <span className="scanModeToggle" role="group" aria-label="스캔 모드">
          <button type="button" className={!autoReconMode ? "active" : ""}
            aria-pressed={!autoReconMode} onClick={() => setAutoReconMode(false)}>
            단일 대상
          </button>
          <button type="button" className={autoReconMode ? "active" : ""}
            aria-pressed={autoReconMode} onClick={() => setAutoReconMode(true)}>
            AutoRecon (여러 대상)
          </button>
        </span>
      </nav>
      <main className="scanLayout">
        <ScanToolPicker tool={tool} masscanBlockedByVpn={masscanBlockedByVpn}
          onSelect={setTool} />
        <section className="scanCenter">
          <ScanProfileComposer tool={tool}
            targetIp={targetIp} targetError={targetError}
            onTargetIpChange={changeTargetIp}
            profiles={profiles.data} profileId={profileId}
            onSelectProfile={setProfileId} profile={profile}
            ports={ports} topPorts={topPorts}
            onPortsChange={setPorts} onTopPortsChange={setTopPorts}
            onUpload={upload}
            previewCommand={preview.data?.command}
            commandDraft={commandDraft} commandDirty={commandDirty}
            commandContextBound={commandContextBound} commandEngineBound={commandEngineBound}
            onCommandChange={editCommand}
            onRestoreCommand={() => editCommand(preview.data?.command || "")}
            vpnConnected={vpnStatus.data?.connected}
            vpnAddress={vpnStatus.data?.tun0}
            scopeConfirmed={scope}
            canReview={!!targetIp.trim() && !!profileId && (
              !profile?.arguments.includes("{top_ports}") ||
              (Number(topPorts) >= 1 && Number(topPorts) <= 65535)
            )}
            onReviewScan={beginReview} />
          {autoReconMode && <AutoReconPanel
            projectId={effectiveProjectId}
            targets={(targets.data || []).filter((t) => t.project_id === effectiveProjectId)}
            selectedIds={autoReconSelected}
            onToggle={toggleAutoReconTarget}
            onSelectAll={selectAllAutoReconTargets}
            onClear={clearAutoReconTargets}
            onStart={() => void startAutoRecon()}
            starting={autoReconStarting}
            startError={autoReconError}
            activeRunId={autoReconRunId}
            onSelectRun={setAutoReconRunId} />}
          {!floatingScanId && <div key={selected?.id || "idle"} ref={transcriptPanel}
            className={`terminal scanTerminal scanTranscript${selected ? " scanTranscript--attached" : ""}`}>
            <div className={selected ? `terminalStatus terminalStatus--${selected.status}` : "terminalStatus"}
              onPointerDown={beginDetach} onPointerMove={moveDetach}
              onPointerUp={finishDetach} onPointerCancel={finishDetach}>
              <span className="termDots" aria-hidden="true">
                <i className="termDot" /><i className="termDot termDot--yellow" />
                <i className="termDot termDot--green" />
              </span>
              <div className="scanTranscript__identity">
                <b>{selected ? `scan://${target?.ip}/session/${selected.id}` : "scan://session/idle"}</b>
                <span>{selected ? selected.command : "stdout receiver"}</span>
              </div>
              <small role="status" aria-live="polite">
                {selected
                  ? `${statusLabel[selected.status] || selected.status} · ${elapsed(selected, clock)}`
                  : "대기"}
              </small>
              {lastEventAt && selected && <i key={lastEventAt}
                className="scanTranscript__rx" aria-hidden="true" />}
            </div>
            <div className="scanTranscript__route" aria-hidden="true">
              <span>operator@kali</span><b>→</b>
              <span>{vpnStatus.data?.link_type || "local"}</span><b>→</b>
              <strong>{target?.ip || "no-target"}</strong>
              <em>{selected && terminal.includes(selected.status)
                ? "STREAM CLOSED"
                : streamState === "connected" ? "RX LIVE"
                : streamState === "connecting" ? "ATTACHING"
                : streamState === "disconnected" ? "LINK LOST" : "IDLE"}</em>
            </div>
            <pre ref={transcript} tabIndex={0} aria-label="스캔 세션 출력">
              <SmartTerminalOutput output={output} context={{projectId: effectiveProjectId,
                targetId: target?.id, targetIp: target?.ip}}
                cursor={!!selected && ["queued", "running", "processing"].includes(selected.status)} />
            </pre>
            <footer className="scanTranscript__footer">
              <span>{selected ? `SESSION #${selected.id}` : "NO SESSION"}</span>
              <span>{selected?.source || "LOCAL"}</span>
              <span>{selected?.exit_code == null ? "stdout" : `EXIT ${selected.exit_code}`}</span>
              <strong>{selected && terminal.includes(selected.status) ? "DETACHED" : selected ? "ATTACHED" : "IDLE"}</strong>
            </footer>
          </div>}
          <ScanJobStatus selected={selected} clock={clock} streamState={streamState}
            lastEventAt={lastEventAt} processAlive={processAlive}
            selectedProfile={selectedProfile} automation={automation.data}
            chainedScan={chainedScan} openTcpPorts={openTcpPorts}
            vpnConnected={vpnStatus.data?.connected}
            onOpenChainedScan={setScanId} onUseDiscoveredPorts={useDiscoveredPorts} />
          <div className="scanStats">
            <div>
              <span>스캔</span>
              <b>{scans.data?.length || 0}</b>
            </div>
            <div>
              <span>열린 포트</span>
              <b>{obs.data?.filter((x) => x.state === "open").length || 0}</b>
            </div>
            <div>
              <span>변경됨</span>
              <b>{diff.data?.changed.length || 0}</b>
            </div>
          </div>
          <div className="scanFilters">
            <input
              placeholder="포트"
              value={portFilter}
              onChange={(e) => setPortFilter(e.target.value)}
            />
            <input
              placeholder="서비스"
              value={serviceFilter}
              onChange={(e) => setServiceFilter(e.target.value)}
            />
            <label>
              <input
                type="checkbox"
                checked={openOnly}
                onChange={(e) => setOpenOnly(e.target.checked)}
              />{" "}
              열린 포트만
            </label>
            <label>
              <input
                type="checkbox"
                checked={changedOnly}
                disabled={!diff.data}
                onChange={(e) => setChangedOnly(e.target.checked)}
              />{" "}
              변경 항목만
            </label>
            <select
              value={sort}
              onChange={(e) => setSort(e.target.value as "port" | "service")}
            >
              <option value="port">포트순</option>
              <option value="service">서비스순</option>
            </select>
            <button
              type="button"
              disabled={!visibleObs.length}
              onClick={() => void copyVisiblePorts()}
              title="위 필터와 일치하는 포트 번호를 쉼표로 구분해 복사합니다."
            >
              {portsCopied ? "복사됨" : `포트 복사 (${visibleObs.length})`}
            </button>
          </div>
          <div className="scanTable">
            <div className="scanObservationHeader">
              <b>&gt; observations</b>
              <span>{visibleObs.length} visible · {obs.data?.length || 0} captured</span>
            </div>
            <div className="tableHead">
              <span>포트</span>
              <span>서비스</span>
              <span>제품 / 버전</span>
              <span>상태</span>
            </div>
            {obs.isLoading && <LoadingState label="관찰 결과를 불러오는 중" />}
            {obs.error && <ErrorState message={String(obs.error)} />}
            {visibleObs.map((o) => (
              <div className="tableRow" key={o.id}>
                <b>
                  {o.port}/{o.protocol}
                </b>
                <span>{o.name}</span>
                <span>
                  {[o.product, o.version, o.extra_info]
                    .filter(Boolean)
                    .join(" ") || "—"}
                </span>
                <em>{o.state}</em>
              </div>
            ))}
            {!obs.isLoading && !visibleObs.length && (
              <div className="empty">
                현재 필터와 일치하는 관찰 결과가 없습니다.
              </div>
            )}
          </div>
          {scanId && (
            <div className="artifactPanel">
              <div>
                <b>산출물</b>
                <button onClick={openMetadata}>별칭 및 태그</button>
                <a href={`/api/scans/${scanId}/export?format=csv`}>CSV</a>
                <a href={`/api/scans/${scanId}/export?format=json`}>JSON</a>
                {xmlArtifact && (
                  <a href={`/api/scans/${scanId}/artifacts/${xmlArtifact.id}/download`}>
                    XML
                  </a>
                )}
              </div>
              {artifacts.data?.map((a) => (
                <a
                  key={a.id}
                  href={`/api/scans/${scanId}/artifacts/${a.id}/download`}
                >
                  <b>{a.kind}</b>
                  <span>
                    {a.original_name} · {bytes(a.size)}
                  </span>
                  <code>{a.sha256}</code>
                </a>
              ))}
            </div>
          )}
        </section>
        <ScanHistoryPanel
          visibleScans={visibleScans} allScans={scans.data} scanId={scanId}
          isLoading={scans.isLoading} error={scans.error}
          query={query} statusFilter={statusFilter}
          onQueryChange={setQuery} onStatusFilterChange={setStatusFilter}
          onSelectScan={setScanId} onStop={stop} onRerun={rerun} onDelete={deleteScan}
          baseId={baseId} onSelectBase={setBaseId} diff={diff.data} />
      </main>
      {review && (
        <div className="modal executionReviewOverlay" role="presentation">
          <div
            className="executionReview"
            role="dialog"
            aria-modal="true"
            aria-labelledby="scan-review-title"
            aria-describedby="scan-review-description"
            onKeyDown={(event) => {
              if (event.key === "Escape") setReview(false);
              if ((event.ctrlKey || event.metaKey) && event.key === "Enter" && scope) void execute();
            }}
          >
            <header className="executionReview__bar">
              <span className="termDots" aria-hidden="true"><i className="termDot" />
                <i className="termDot termDot--yellow" /><i className="termDot termDot--green" /></span>
              <code>ow://scan/stage</code><strong><i /> SCOPE PENDING</strong>
            </header>
            <div className="executionReview__body">
              <div className="executionReview__intro">
                <span>SCAN DISPATCH · {profile?.engine?.toUpperCase()}</span>
                <h2 id="scan-review-title">{profile?.name}</h2>
                <p id="scan-review-description"># Kali 호스트에서 실행할 최종 명령과 경로를 검토하세요.</p>
              </div>
              <div className="executionRoute" aria-label={`실행 경로: operator, ${vpnStatus.data?.link_type || "local"}, ${target?.ip}`}>
                <span>operator</span><b>→</b><span>{vpnStatus.data?.link_type || "local"}</span>
                <b>→</b><strong>{target?.ip}</strong><i aria-hidden="true" />
              </div>
              <section className="executionCommand" aria-label="실행할 명령">
                <header><span>ARGV / RENDERED</span><small>awaiting scope approval</small></header>
                <code><b>$</b> {commandDraft}<i aria-hidden="true" /></code>
              </section>
              <dl className="executionFacts">
                <div><dt>target</dt><dd>{target?.name} · {target?.ip}</dd></div>
                <div><dt>interface</dt><dd>{vpnStatus.data?.link_type || "local"}{vpnStatus.data?.tun0 ? ` · ${vpnStatus.data.tun0}` : ""}</dd></div>
                <div><dt>engine</dt><dd>{profile?.engine}</dd></div>
              </dl>
              {vpnStatus.data && !vpnStatus.data.connected && (
                <p className="executionAlert" role="alert"><b>IFACE OFFLINE</b> VPN 전용 대상이면 출력 없이 멈춘 것처럼 보일 수 있습니다.</p>
              )}
              <label className="executionScope">
                <input type="checkbox" checked={scope} autoFocus onChange={(e) => setScope(e.target.checked)} />
                <span><b>SCOPE ACKNOWLEDGEMENT</b> 이 대상이 허가된 Scope에 포함됨을 확인합니다.</span>
              </label>
            </div>
            <footer className="executionReview__footer">
              <small><kbd>esc</kbd> cancel · <kbd>ctrl</kbd> + <kbd>↵</kbd> dispatch</small>
              <div><button onClick={() => setReview(false)}>취소</button>
                <button className="executionReview__execute" disabled={!scope} onClick={execute}>[ DISPATCH ↵ ]</button></div>
            </footer>
          </div>
        </div>
      )}
      {metadataOpen && (
        <div className="modal" role="presentation">
          <div role="dialog" aria-modal="true" aria-labelledby="scan-metadata-title">
            <span>스캔 메타데이터</span>
            <h2 id="scan-metadata-title">별칭 및 태그</h2>
            <label htmlFor="scan-alias-input">Alias</label>
            <input id="scan-alias-input" autoFocus value={aliasDraft}
              onChange={(e) => setAliasDraft(e.target.value)} />
            <label htmlFor="scan-tags-input">태그(쉼표로 구분)</label>
            <input id="scan-tags-input" value={tagsDraft}
              onChange={(e) => setTagsDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") { e.preventDefault(); void saveMetadata(); }
                if (e.key === "Escape") setMetadataOpen(false);
              }} />
            <footer>
              <button onClick={() => setMetadataOpen(false)}>취소</button>
              <button onClick={() => void saveMetadata()}>저장</button>
            </footer>
          </div>
        </div>
      )}
    </div>
  );
}
