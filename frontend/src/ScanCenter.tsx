import { useEffect, useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import VpnControl from "./VpnControl";
import { ErrorState, LoadingState, statusCopy as statusLabel } from "./ui";

type Project = { id: number; name: string };
type Target = { id: number; project_id: number; name: string; ip: string };
type VpnStatus = { connected: boolean; link_type: string };
type Profile = {
  id: number;
  name: string;
  kind: string;
  description: string;
  arguments: string;
  engine: string;
  chain_kind: string;
};
type Scan = {
  id: number;
  profile_id?: number | null;
  parent_scan_id?: number | null;
  source: string;
  status: string;
  command: string;
  created_at: string;
  started_at?: string;
  ended_at?: string;
  exit_code?: number;
  error: string;
  alias: string;
  tags: string;
};
type Obs = {
  id: number;
  port: number;
  protocol: string;
  state: string;
  name: string;
  product: string;
  version: string;
  extra_info: string;
  scripts: string;
};
type Artifact = {
  id: number;
  kind: string;
  sha256: string;
  size: number;
  original_name: string;
};
type Automation = {
  evidence_count: number;
  finding_count: number;
  finding_ids: number[];
  review_required: boolean;
};
const terminal = ["completed", "failed", "stopped", "interrupted"];
const profileLabel: Record<string, { name: string; description: string }> = {
  quick: {
    name: "주요 TCP 포트",
    description: "Nmap 빈도 기준 상위 포트 수를 직접 선택",
  },
  full_tcp: {
    name: "전체 TCP 빠른 탐색",
    description: "모든 TCP 포트 · 속도를 높여 불안정한 회선에서는 누락 가능",
  },
  full_tcp_syn: {
    name: "전체 TCP 빠른 탐색 (sudo)",
    description: "sudo nmap -Pn -p- --min-rate 1000 -T4 · Kali 비밀번호 필요",
  },
  full_tcp_balanced: {
    name: "전체 TCP 안정 탐색",
    description: "모든 TCP 포트 · 속도는 느리지만 회선 상태에 맞춰 조절",
  },
  selected_version: {
    name: "선택 포트 버전 확인",
    description: "지정 포트의 서비스와 버전 확인 · Script 실행 없음",
  },
  selected_ports: {
    name: "선택 포트 상세 스캔",
    description: "지정 포트에 기본 NSE Script와 버전 탐지 · 표준 상세 확인",
  },
  selected_syn_detail: {
    name: "선택 포트 상세 스캔 (sudo)",
    description: "sudo nmap -Pn -sC -sV -p 포트 -T3 · Kali 비밀번호 필요",
  },
  selected_deep: {
    name: "선택 포트 고정밀 확인",
    description: "모든 버전 Probe 시도 · 정확도는 높지만 가장 느림",
  },
  udp_top: {
    name: "주요 UDP 포트",
    description: "Nmap 빈도 기준 상위 포트 수를 직접 선택 · Kali 비밀번호 필요",
  },
  udp_full: {
    name: "전체 UDP 포트",
    description: "UDP 1–65535 전체 · 매우 오래 걸릴 수 있음 · Kali 비밀번호 필요",
  },
  selected_udp: {
    name: "특정 UDP 포트",
    description: "입력한 UDP 포트만 버전 탐지 · Kali 비밀번호 필요",
  },
  masscan_discovery: {
    name: "빠른 포트 탐색 (masscan)",
    description:
      "전체 TCP 포트를 masscan으로 초고속 스윕 · 발견된 포트는 직접 검토 후 상세 스캔 · Kali 비밀번호 필요",
  },
  masscan_auto_chain: {
    name: "빠른 탐색 + 자동 상세 스캔 (masscan)",
    description:
      "masscan으로 스윕 후 발견된 포트에 Nmap -sC -sV 상세 스캔을 자동으로 대기열에 추가 · Kali 비밀번호 필요",
  },
};
const privilegedKinds = new Set([
  "full_tcp_syn",
  "selected_syn_detail",
  "udp_top",
  "udp_full",
  "selected_udp",
  "masscan_discovery",
  "masscan_auto_chain",
]);
const nmapProfileGroups = [
  {
    label: "전체 TCP",
    kinds: ["full_tcp", "full_tcp_syn", "full_tcp_balanced"],
  },
  { label: "주요 TCP", kinds: ["quick"] },
  { label: "UDP", kinds: ["udp_top", "udp_full"] },
  {
    label: "특정 포트",
    kinds: [
      "selected_version",
      "selected_ports",
      "selected_syn_detail",
      "selected_deep",
      "selected_udp",
    ],
  },
];
const masscanProfileGroups = [
  {
    label: "masscan",
    kinds: ["masscan_discovery", "masscan_auto_chain"],
  },
];
const toolProfileGroups = { nmap: nmapProfileGroups, masscan: masscanProfileGroups };
const get = async <T,>(path: string): Promise<T> => {
  const r = await fetch("/api" + path);
  if (!r.ok) throw new Error((await r.json()).detail || r.statusText);
  return r.json();
};
export const serverTime = (value: string) =>
  Date.parse(/[zZ]|[+-]\d\d:\d\d$/.test(value) ? value : `${value}Z`);
const elapsed = (s: Scan, now = Date.now()) => {
  const seconds = Math.max(
    0,
    Math.floor(
      ((s.ended_at ? serverTime(s.ended_at) : now) -
        serverTime(s.started_at || s.created_at)) /
        1000,
    ),
  );
  return seconds < 60
    ? `${seconds}s`
    : `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
};
const bytes = (n: number) =>
  n < 1024
    ? `${n} B`
    : n < 1048576
      ? `${(n / 1024).toFixed(1)} KiB`
      : `${(n / 1048576).toFixed(1)} MiB`;

export function syncSelectedProject(projectId: number) {
  const value = String(projectId);
  if (localStorage.getItem("oscp-workspace-project") === value) return false;
  localStorage.setItem("oscp-workspace-project", value);
  dispatchEvent(new CustomEvent("oscp-project-change", {detail: projectId}));
  return true;
}

export default function ScanCenter() {
  const qc = useQueryClient();
  const [targetId, setTargetId] = useState<number>(),
    [targetIp, setTargetIp] = useState(""),
    [targetName, setTargetName] = useState(""),
    [targetError, setTargetError] = useState(""),
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
    [openOnly, setOpenOnly] = useState(false),
    [changedOnly, setChangedOnly] = useState(false),
    [sort, setSort] = useState<"port" | "service">("port"),
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
  useEffect(() => {
    if (!targetId && targets.data?.length) {
      const savedProjectId = Number(
        localStorage.getItem("oscp-workspace-project"),
      );
      const savedTarget = targets.data.find(
        (item) => item.project_id === savedProjectId,
      );
      setTargetId((savedTarget || targets.data[0]).id);
    }
  }, [targets.data, targetId]);
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
    );
  const useDiscoveredPorts = () => {
    const detail =
      profiles.data?.find((p) => p.kind === "selected_syn_detail") ||
      profiles.data?.find((p) => p.kind === "selected_ports");
    if (!detail || !openTcpPorts.length) return;
    setPorts(openTcpPorts.join(","));
    setProfileId(detail.id);
  };
  const refresh = async () =>
    Promise.all([
      qc.invalidateQueries({ queryKey: ["scans", targetId] }),
      qc.invalidateQueries({ queryKey: ["services", targetId] }),
    ]);
  const createTarget = async () => {
    const ip = targetIp.trim();
    if (!ip) return;
    setTargetError("");
    const r = await fetch("/api/targets/ensure", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ip,
        name: targetName.trim(),
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
    setTargetIp("");
    setTargetName("");
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
    <div className="scanPage">
      <header>
        <div className="brand">
          <span className="mark">OW</span>
          <div>
            <b>OSCP Workspace</b>
            <small>Scan Center</small>
          </div>
        </div>
        <VpnControl />
      </header>
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
          aria-label="프로젝트 선택"
          value={target?.project_id || ""}
          onChange={(e) => {
            const projectId = +e.target.value;
            const projectTarget = targets.data?.find(
              (item) => item.project_id === projectId,
            );
            setTargetId(projectTarget?.id);
            setScanId(undefined);
          }}
        >
          <option value="">프로젝트 선택</option>
          {projects.data?.map((project) => (
            <option key={project.id} value={project.id}>
              {project.name}
            </option>
          ))}
        </select>
        <select
          aria-label="대상 선택"
          value={targetId || ""}
          onChange={(e) => {
            setTargetId(+e.target.value);
            setScanId(undefined);
          }}
        >
          {targets.data
            ?.filter((item) => item.project_id === target?.project_id)
            .map((item) => (
              <option key={item.id} value={item.id}>
                {item.name} · {item.ip}
              </option>
            ))}
        </select>
        <span className="tools">스캔 기록 {scans.data?.length || 0}개</span>
      </nav>
      <main className="scanLayout">
        <aside className="scanProfiles">
          <div className="panelTitle">
            <span>스캔 도구</span>
          </div>
          <button
            type="button"
            className={tool === "nmap" ? "active" : ""}
            onClick={() => setTool("nmap")}
          >
            <b>Nmap</b>
            <small>포트 및 서비스 상세 스캔</small>
          </button>
          <button
            type="button"
            className={tool === "masscan" ? "active" : ""}
            disabled={masscanBlockedByVpn}
            title={
              masscanBlockedByVpn
                ? "tun0(VPN) 인터페이스는 이더넷/ARP 계층이 없어 masscan이 패킷을 보낼 수 없습니다. VPN 연결을 끊으면 사용할 수 있습니다."
                : undefined
            }
            onClick={() => setTool("masscan")}
          >
            <b>masscan</b>
            <small>
              {masscanBlockedByVpn
                ? "tun0(VPN)에서는 사용할 수 없음"
                : "초고속 포트 탐색 · 자동 Nmap 상세 스캔 연계"}
            </small>
          </button>
        </aside>
        <section className="scanCenter">
          <div className="targetSetup">
            <input
              aria-label="대상 IP"
              placeholder="대상 IP"
              value={targetIp}
              onChange={(e) => setTargetIp(e.target.value)}
            />
            <input
              aria-label="대상 이름"
              placeholder="대상 이름(선택)"
              value={targetName}
              onChange={(e) => setTargetName(e.target.value)}
            />
            <button
              disabled={!targetIp.trim()}
              onClick={createTarget}
            >
              대상 추가
            </button>
            {targetError && <span>{targetError}</span>}
          </div>
          <div className="profilePicker">
            <label htmlFor="nmap-profile">
              {tool === "masscan" ? "masscan 옵션" : "Nmap 옵션"}
            </label>
            <select
              id="nmap-profile"
              value={profileId || ""}
              onChange={(e) => setProfileId(+e.target.value)}
            >
              {toolProfileGroups[tool].map((group) => (
                <optgroup key={group.label} label={group.label}>
                  {group.kinds.flatMap((kind) => {
                    const item = profiles.data?.find(
                      (candidate) => candidate.kind === kind,
                    );
                    return item ? (
                      <option key={item.id} value={item.id}>
                        {profileLabel[item.kind]?.name || item.name}
                      </option>
                    ) : [];
                  })}
                </optgroup>
              ))}
            </select>
            {profile && (
              <div>
                <b>{profileLabel[profile.kind]?.name || profile.name}</b>
                <small>
                  {profileLabel[profile.kind]?.description ||
                    profile.description}
                </small>
                <code>
                  {`${privilegedKinds.has(profile.kind) ? "sudo " : ""}${
                    profile.engine || "nmap"
                  } ${profile.arguments
                    .replace("{ports}", ports)
                    .replace("{top_ports}", topPorts)} ${target?.ip || "<IP>"}`}
                </code>
              </div>
            )}
          </div>
          <div className="scanHero">
            <label className="importScan">
              기존 Nmap XML 결과 가져오기
              <input
                type="file"
                accept=".xml"
                onChange={(e) =>
                  e.target.files?.[0] && upload(e.target.files[0])
                }
              />
            </label>
          </div>
          <div className="scanComposer">
            {profile?.arguments.includes("{top_ports}") && (
              <input
                aria-label="상위 포트 수"
                type="text"
                inputMode="numeric"
                pattern="[0-9]*"
                value={topPorts}
                onChange={(e) =>
                  setTopPorts(e.target.value.replace(/[^0-9]/g, ""))
                }
                placeholder="상위 포트 수 (1–65535)"
              />
            )}
            {profile?.arguments.includes("{ports}") && (
              <input
                aria-label="특정 포트"
                value={ports}
                onChange={(e) => setPorts(e.target.value)}
                placeholder="예: 22,80,443,8000-8100"
              />
            )}
            <code>
              {preview.data?.command || "대상과 프로필을 선택하세요"}
            </code>
            <button
              disabled={!preview.data}
              onClick={() => {
                setScope(false);
                setReview(true);
              }}
            >
              새 {profile?.engine === "masscan" ? "masscan" : "Nmap"} 스캔 검토
            </button>
          </div>
          {selected && (
            <section
              className={`jobStatus jobStatus--${selected.status}`}
              aria-live="polite"
              aria-label="현재 스캔 상태"
            >
              <span className="jobStatus__dot" aria-hidden="true" />
              <div>
                <b>
                  스캔 #{selected.id} · {statusLabel[selected.status] || selected.status}
                </b>
                <small>
                  {selected.status === "queued" && "실행 순서를 기다리고 있습니다."}
                  {["running", "processing"].includes(selected.status) &&
                    (() => {
                      const engineName =
                        (selectedProfile?.engine === "masscan" ? "masscan" : "Nmap");
                      return processAlive
                        ? `백엔드가 ${engineName} 프로세스 실행을 확인했습니다. 전체 포트 탐색은 출력 없이 오래 걸릴 수 있습니다.`
                        : `${engineName}이(가) 실행 중입니다. 다음 상태 신호를 기다리고 있습니다.`;
                    })()}
                  {selected.status === "completed" && "스캔과 결과 처리가 완료되었습니다."}
                  {selected.status === "failed" &&
                    `스캔에 실패했습니다.${selected.error ? ` ${selected.error}` : ""}`}
                  {selected.status === "stopped" && "사용자가 스캔을 중단했습니다."}
                  {selected.status === "interrupted" && "서버 중단으로 스캔이 종료되었습니다."}
                </small>
              </div>
              <dl>
                <div>
                  <dt>경과 시간</dt>
                  <dd>{elapsed(selected, clock)}</dd>
                </div>
                <div>
                  <dt>실시간 연결</dt>
                  <dd>
                    {streamState === "connected"
                      ? "연결됨"
                      : streamState === "connecting"
                        ? "연결 중"
                        : streamState === "disconnected"
                          ? "끊김 · 상태 자동 확인 중"
                          : terminal.includes(selected.status) ? "완료" : "대기"}
                  </dd>
                </div>
                <div>
                  <dt>마지막 상태 신호</dt>
                  <dd>
                    {lastEventAt
                      ? `${Math.max(0, Math.floor((clock - lastEventAt) / 1000))}초 전`
                      : "대기 중"}
                  </dd>
                </div>
              </dl>
              {["running", "processing"].includes(selected.status) &&
                lastEventAt && clock - lastEventAt > 30000 && (
                  <p className="jobStatus__warning" role="alert">
                    30초 이상 상태 신호가 없습니다. 백엔드 연결을 확인하거나 스캔을 취소하세요.
                  </p>
                )}
            </section>
          )}
          {selected?.status === "completed" && automation.data && (
            <section className="scanAutomation" aria-label="자동 증적 처리 결과">
              <div>
                <b>자동 증적 처리 완료</b>
                <span>
                  Evidence {automation.data.evidence_count}개 저장 · 검토할 Finding 후보{" "}
                  {automation.data.finding_count}개
                </span>
              </div>
              <a href="#reports">
                {automation.data.review_required
                  ? "Reports에서 후보 검토"
                  : "Reports 열기"}
              </a>
              <small>
                후보는 오탐 검토 전까지 Internal · Needs Review 상태이며 Client 보고서에 포함되지 않습니다.
              </small>
            </section>
          )}
          {selected?.status === "completed" && chainedScan && (
            <section className="scanAutomation" aria-label="자동 생성된 상세 스캔">
              <div>
                <b>자동 상세 스캔 대기열에 추가됨</b>
                <span>
                  발견된 포트로 Nmap 상세 스캔 #{chainedScan.id} ·{" "}
                  {statusLabel[chainedScan.status] || chainedScan.status}
                </span>
              </div>
              <button type="button" onClick={() => setScanId(chainedScan.id)}>
                상세 스캔 열기
              </button>
            </section>
          )}
          {selected?.status === "completed" &&
            selectedProfile?.kind === "masscan_discovery" &&
            openTcpPorts.length > 0 && (
              <section className="scanAutomation" aria-label="발견된 포트로 상세 스캔 준비">
                <div>
                  <b>열린 포트 {openTcpPorts.length}개 발견</b>
                  <span>{openTcpPorts.join(", ")}</span>
                </div>
                <button type="button" onClick={useDiscoveredPorts}>
                  발견된 포트로 상세 스캔 준비
                </button>
                <small>
                  포트 필드와 프로필이 채워집니다. 검토 후 직접 스캔을 실행하세요.
                </small>
              </section>
            )}
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
        <aside className="scanHistory">
          <div className="panelTitle">
            <span>스캔 대기열 및 이력</span>
            <em>대상</em>
          </div>
          <div className="historyFilters">
            <input
              placeholder="스캔 검색"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
            >
              {[
                "all",
                "queued",
                "running",
                "completed",
                "failed",
                "stopped",
                "interrupted",
              ].map((v) => (
                <option key={v} value={v}>{statusLabel[v] || v}</option>
              ))}
            </select>
          </div>
          {scans.isLoading && <LoadingState label="스캔 이력을 불러오는 중" />}
          {scans.error && <ErrorState message={String(scans.error)} />}
          {!scans.isLoading && !visibleScans.length &&
            <p className="empty">조건에 맞는 스캔이 없습니다.</p>}
          {visibleScans.map((s) => (
            <div
              key={s.id}
              role="button"
              tabIndex={0}
              className={`scanRow ${s.id === scanId ? "active" : ""}`}
              onClick={() => setScanId(s.id)}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  setScanId(s.id);
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
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      stop(s.id);
                    }}
                  >
                    취소
                  </button>
                )}
                {s.source === "executed" && terminal.includes(s.status) && (
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      rerun(s.id);
                    }}
                  >
                    재실행
                  </button>
                )}
                {s.exit_code != null && <small>exit {s.exit_code}</small>}
              </span>
            </div>
          ))}
          <div className="compare">
            <h3>비교</h3>
            <select
              value={baseId || ""}
              onChange={(e) => setBaseId(+e.target.value)}
            >
              <option value="">기준 스캔 선택</option>
              {scans.data
                ?.filter((s) => s.id !== scanId)
                .map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.alias || `스캔 #${s.id}`}
                  </option>
                ))}
            </select>
            {diff.data && (
              <>
                <div className="delta">
                  <span>+{diff.data.added.length}</span>
                  <span>−{diff.data.removed.length}</span>
                  <span>~{diff.data.changed.length}</span>
                </div>
                <a
                  className="diffExport"
                  href={`/api/scans/compare/${baseId}/${scanId}/export`}
                >
                  변경 내역 내보내기
                </a>
                <div className="diffDetails">
                  {diff.data.added.map((item: any) => (
                    <div key={`add-${item.protocol}-${item.port}`}>
                      <b>추가 {item.port}/{item.protocol}</b>
                      <small>{item.name} {item.product} {item.version}</small>
                    </div>
                  ))}
                  {diff.data.removed.map((item: any) => (
                    <div key={`remove-${item.protocol}-${item.port}`}>
                      <b>제거 {item.port}/{item.protocol}</b>
                      <small>{item.name} {item.product} {item.version}</small>
                    </div>
                  ))}
                  {diff.data.changed.map((item: any) => (
                    <div key={`change-${item.protocol}-${item.port}`}>
                      <b>변경 {item.port}/{item.protocol}</b>
                      <small>{Object.keys(item.changes).join(", ")}</small>
                    </div>
                  ))}
                </div>
              </>
            )}
            <p>
              관찰된 변경만 표시하며 위험도나 취약점을 판단하지 않습니다.
            </p>
          </div>
        </aside>
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
