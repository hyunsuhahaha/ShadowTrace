export type Project = {id: number; name: string; description: string};

export type Target = {
  id: number;
  project_id: number;
  name: string;
  ip: string;
  hostname: string;
  os_guess: string;
  vpn: string;
  notes: string;
};

export type Service = {
  id: number;
  target_id: number;
  port: number;
  protocol: string;
  state: string;
  name: string;
  product: string;
  version: string;
  extra_info: string;
  scripts: string;
  notes: string;
  tags: string;
  cpe: string;
  tls: boolean;
  detection_evidence: string;
};

export type RunState = {
  id?: number;
  templateId: string;
  name: string;
  status: "starting" | "running" | "completed" | "failed" | "stopped" |
    "no_response" | "error";
  startedAt: number;
  lastEventAt?: number;
  processAlive?: boolean;
  exitCode?: number | null;
  message?: string;
  stdout?: string;
  stderr?: string;
};

// Values are typed into a live PTY and do not pass through backend argv
// rendering, so every dynamic value must be one POSIX shell word.
export const shellQuote = (value: string) =>
  `'${value.replace(/'/g, "'\\''")}'`;

// A bare 32-hex string in the password field is almost certainly an NTLM
// hash (e.g. dumped via DCSync), not a literal password — swap tools to
// pass-the-hash instead of asking them to authenticate with the hash text
// as if it were the password itself, which would just fail.
export const isNtlmHash = (value: string) => /^[0-9a-fA-F]{32}$/.test(value.trim());

// impacket tools take "[domain/]user[:password]@host" normally, but
// pass-the-hash drops the password from that string entirely and moves it
// into a separate "-hashes :NTHASH" argument.
export const impacketAuthArgs = (
  domain: string, username: string, secret: string, host: string,
): string => {
  const userPart = [domain, username].filter(Boolean).join("/");
  if (isNtlmHash(secret)) {
    return `${shellQuote(`${userPart}@${host}`)} -hashes ${shellQuote(`:${secret.trim()}`)}`;
  }
  return shellQuote(`${userPart}${secret ? `:${secret}` : ""}@${host}`);
};

export const sourceLabel: Record<string, string> = {
  manual: "직접 입력",
  "share-file": "공유 파일",
  web: "웹",
  config: "설정 파일",
  kerberoast: "Kerberoast",
  reuse: "재사용",
  other: "기타",
};

export const riskLabel: Record<string, string> = {
  low: "낮음",
  medium: "주의",
  high: "높음",
};

export const authContextNotice: Record<string, string> = {
  domain: "DNS는 일반적인 사용자·비밀번호 로그인이 없습니다. 재귀 질의와 NSID 등 노출 상태를 확인하세요.",
  dns: "DNS는 일반적인 사용자·비밀번호 로그인이 없습니다. 재귀 질의와 NSID 등 노출 상태를 확인하세요.",
  nfs: "NFS는 보통 계정보다 호스트·Export·UID/GID로 접근을 제어합니다. 공개 Export를 먼저 확인하세요.",
  rpcbind: "RPC/NFS는 범용 로그인 대신 노출된 RPC 프로그램과 Export 권한을 조사하세요.",
  "kerberos-sec": "Kerberos 인증 점검에는 Realm·도메인과 검토한 사용자 목록이 필요합니다. AD Information에서 문맥을 먼저 기록하세요.",
  wsman: "WinRM 점검에는 도메인과 NTLM/Kerberos 인증 문맥이 필요합니다. 범용 HTTP 비밀번호 점검을 대신 실행하지 않습니다.",
  wsmans: "WinRM 점검에는 도메인과 NTLM/Kerberos 인증 문맥이 필요합니다. 범용 HTTP 비밀번호 점검을 대신 실행하지 않습니다.",
};
