import { useEffect, useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import VpnControl from "./VpnControl";
import ScanToolPicker from "./ScanToolPicker";
import ScanProfileComposer from "./ScanProfileComposer";
import ScanJobStatus from "./ScanJobStatus";
import ScanHistoryPanel from "./ScanHistoryPanel";
import { ErrorState, LoadingState, statusCopy as statusLabel } from "./ui";
import {
  bytes, elapsed, get, syncSelectedProject, terminal, toolProfileGroups,
  type Artifact, type Automation, type Obs, type Profile, type Project,
  type Scan, type Target, type VpnStatus,
} from "./scanCenterModel";

export default function ScanCenter({ embedded = false }: { embedded?: boolean } = {}) {
  const qc = useQueryClient();
  const [targetId, setTargetId] = useState<number>(),
    [targetIp, setTargetIp] = useState(""),
    [targetName, setTargetName] = useState(""),
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
    [output, setOutput] = useState("저장된 출력을 보려면 스캔을 선택하세요.\n"),
    [statusFilter, setStatusFilter] = useState("all"),
    [query, setQuery] = useState(""),
    [serviceFilter, setServiceFilter] = useState(""),
    [portFilter, setPortFilter] = useState(""),
    [openOnly, setOpenOnly] = useState(true),
    [changedOnly, setChangedOnly] = useState(false),
    [sort, setSort] = useState<"port" | "service">("port"),
    [portsCopied, setPortsCopied] = useState(false),
    [clock, setClock] = useState(Date.now()),
    [lastEventAt, setLastEventAt] = useState<number>(),
    [processAlive, setProcessAlive] = useState<boolean>(),
    [streamState, setStreamState] = useState<
      "idle" | "connecting" | "connected" | "disconnected"
    >("idle");
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
    if (scans.data?.length && !scans.data.some((s) => s.id === scanId))
      setScanId(scans.data[0].id);
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
      profile_id: profileId,
      ports: profile?.arguments.includes("{ports}") ? ports : "",
      top_ports: Number(topPorts),
      extra_arguments: [],
    });
  // Keep the IP/name inputs showing whichever target is current (picked from
  // the dropdown, or auto-selected), so "review scan" reuses it by IP instead
  // of always minting a new target.
  useEffect(() => {
    if (target) { setTargetIp(target.ip); setTargetName(target.name); }
  }, [target?.id]);
  const preview = useQuery({
    queryKey: ["scanPreview", targetId, profileId, ports, topPorts],
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
      !!targetId &&
      !!profileId &&
      (!profile?.arguments.includes("{top_ports}") ||
        (Number(topPorts) >= 1 && Number(topPorts) <= 65535)),
  });
  useEffect(() => {
    if (!scanId) return;
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
      if (item.stream === "status" && item.status === "running")
        await qc.invalidateQueries({ queryKey: ["scans", targetId] });
    };
    events.onerror = () => {
      setStreamState("disconnected");
      events.close();
    };
    return () => events.close();
  }, [scanId, targetId, qc]);
  useEffect(() => {
    if (!selected || !["queued", "running", "processing"].includes(selected.status))
      return;
    const timer = window.setInterval(() => setClock(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [selected?.id, selected?.status]);
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
    if (existing) {
      setTargetId(existing.id);
      setScope(false);
      setReview(true);
      return;
    }
    const r = await fetch("/api/targets/ensure", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ip,
        name: targetName.trim(),
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
    setTargetId(created.id);
    setScope(false);
    setReview(true);
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
      await refresh();
    },
    saveMetadata = async () => {
      if (!selected) return;
      const alias = prompt("Scan alias", selected.alias);
      if (alias === null) return;
      const tagsInput = prompt(
        "태그(쉼표로 구분)",
        JSON.parse(selected.tags || "[]").join(", "),
      );
      if (tagsInput === null) return;
      const tags = tagsInput.split(",").map((x) => x.trim()).filter(Boolean);
      await fetch(`/api/scans/${selected.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alias, tags }),
      });
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
      </nav>
      <main className="scanLayout">
        <ScanToolPicker tool={tool} masscanBlockedByVpn={masscanBlockedByVpn}
          onSelect={setTool} />
        <section className="scanCenter">
          <ScanProfileComposer tool={tool}
            targetIp={targetIp} targetName={targetName} targetError={targetError}
            onTargetIpChange={setTargetIp} onTargetNameChange={setTargetName}
            profiles={profiles.data} profileId={profileId}
            onSelectProfile={setProfileId} profile={profile} target={target}
            ports={ports} topPorts={topPorts}
            onPortsChange={setPorts} onTopPortsChange={setTopPorts}
            onUpload={upload}
            previewCommand={preview.data?.command}
            canReview={!!targetIp.trim() && !!profileId && (
              !profile?.arguments.includes("{top_ports}") ||
              (Number(topPorts) >= 1 && Number(topPorts) <= 65535)
            )}
            onReviewScan={beginReview} />
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
                <button onClick={saveMetadata}>별칭 및 태그</button>
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
          <div className="terminal scanTerminal">
            <div className={selected ? `terminalStatus terminalStatus--${selected.status}` : ""}>
              <span aria-hidden="true" />
              <b>저장 / 실시간 출력</b>
              <small>
                {selected
                  ? `작업 #${selected.id} · ${statusLabel[selected.status] || selected.status} · ${elapsed(selected, clock)}`
                  : "스캔 실행 대기"}
              </small>
            </div>
            <pre>{output}</pre>
          </div>
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
        <div className="modal" role="presentation">
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="scan-review-title"
            aria-describedby="scan-review-description"
          >
            <span>스캔 Scope 검토</span>
            <h2 id="scan-review-title">{profile?.name}</h2>
            <p id="scan-review-description">
              대상과 최종 명령을 확인하세요. 선택한 도구는 Kali 호스트에서
              직접 실행됩니다.
            </p>
            <code>{preview.data?.command}</code>
            <p>
              <b>대상:</b> {target?.name} · {target?.ip}
            </p>
            {vpnStatus.data && !vpnStatus.data.connected && (
              <div className="warning" role="alert">
                <b>VPN 미연결</b>
                <p>
                  대상이 VPN을 통해서만 접근 가능하다면 스캔이 출력 없이 멈춘
                  것처럼 보일 수 있습니다.
                </p>
              </div>
            )}
            <label>
              <input
                type="checkbox"
                checked={scope}
                onChange={(e) => setScope(e.target.checked)}
              />{" "}
              이 대상이 허가된 Scope에 포함됨을 확인합니다.
            </label>
            <footer>
              <button onClick={() => setReview(false)}>취소</button>
              <button className="danger" disabled={!scope} onClick={execute}>
                스캔 대기열에 추가
              </button>
            </footer>
          </div>
        </div>
      )}
    </div>
  );
}
