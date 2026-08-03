export type Project = { id: number; name: string };
export type Target = { id: number; project_id: number; name: string; ip: string };
export type VpnStatus = { connected: boolean; link_type: string };
export type Profile = {
  id: number;
  name: string;
  kind: string;
  description: string;
  arguments: string;
  engine: string;
  chain_kind: string;
};
export type Scan = {
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
export type Obs = {
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
export type Artifact = {
  id: number;
  kind: string;
  sha256: string;
  size: number;
  original_name: string;
};
export type Automation = {
  evidence_count: number;
  finding_count: number;
  finding_ids: number[];
  review_required: boolean;
};

export const terminal = ["completed", "failed", "stopped", "interrupted"];

export const profileLabel: Record<string, { name: string; description: string }> = {
  quick: {
    name: "주요 TCP 포트",
    description: "Nmap 빈도 기준 상위 포트 수를 직접 선택",
  },
  full_tcp: {
    name: "전체 TCP 빠른 탐색",
    description:
      "모든 TCP 포트 · 속도를 높여 불안정한 회선에서는 누락 가능 · 완료 후 발견된 포트에 -sC -sV 상세 스캔을 자동으로 대기열에 추가 (sudo 필요)",
  },
  full_tcp_syn: {
    name: "전체 TCP 빠른 탐색 (sudo)",
    description:
      "sudo nmap -Pn -p- --min-rate 1000 -T4 · Kali 비밀번호 필요 · 완료 후 발견된 포트에 -sC -sV 상세 스캔을 자동으로 대기열에 추가",
  },
  full_tcp_balanced: {
    name: "전체 TCP 안정 탐색",
    description:
      "모든 TCP 포트 · 속도는 느리지만 회선 상태에 맞춰 조절 · 완료 후 발견된 포트에 -sC -sV 상세 스캔을 자동으로 대기열에 추가 (sudo 필요)",
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
export const privilegedKinds = new Set([
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
export const toolProfileGroups = { nmap: nmapProfileGroups, masscan: masscanProfileGroups };

export const get = async <T,>(path: string): Promise<T> => {
  const r = await fetch("/api" + path);
  if (!r.ok) throw new Error((await r.json()).detail || r.statusText);
  return r.json();
};

export const serverTime = (value: string) =>
  Date.parse(/[zZ]|[+-]\d\d:\d\d$/.test(value) ? value : `${value}Z`);

export const elapsed = (s: Scan, now = Date.now()) => {
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

export const bytes = (n: number) =>
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
