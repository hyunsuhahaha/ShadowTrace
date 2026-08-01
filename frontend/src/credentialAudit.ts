export type CredentialAuditProfile = {
  title: string;
  description: string;
  identityLabel: string;
  identities: string;
  secretLabel: string;
  secrets: string;
  limits: string;
};

const accountAudit = (
  protocol = "계정 기반",
  identities = "확인된 계정",
  secrets = "확인된 제품의 공식 기본값",
): CredentialAuditProfile => ({
  title: `${protocol} 대입 후보`,
  description: "프로토콜에 공통 기본 계정은 없습니다. 제품 식별 결과와 해당 제품의 공식 기본값을 기준으로 제한 점검합니다.",
  identityLabel: "사용자 후보",
  identities,
  secretLabel: "비밀번호 후보",
  secrets,
  limits: "최대 2분 · 저속 실행 · 계정 잠금 위험 검토",
});

const profiles: Record<string, CredentialAuditProfile> = {
  ftp: {
    title: "FTP 익명 인증 데이터셋",
    description: "FTP에서 제품 식별 없이 적용할 프로토콜 기반 후보는 익명 인증 하나입니다.",
    identityLabel: "사용자 후보",
    identities: "anonymous",
    secretLabel: "비밀번호 후보",
    secrets: "anonymous@ · guest@ · 이메일 형식",
    limits: "첫 성공 시 즉시 중단 · 디렉터리 목록은 조회하지 않음",
  },
  telnet: accountAudit("Telnet", "admin · root · cisco · support", "admin · root · cisco · support"),
  ssh: accountAudit("SSH", "root · admin · ubuntu · pi", "root · admin · ubuntu · raspberry"),
  smtp: accountAudit("SMTP", "postmaster · admin · user · test", "postmaster · admin · password · test"),
  http: accountAudit("HTTP Basic·Digest·NTLM", "admin · administrator · manager · root", "admin · password · manager · root"),
  smb: {
    ...accountAudit("SMB", "guest · administrator · admin", "빈 값 · 사용자명과 동일 · 사용자명 역순 · password"),
    description: "NULL·Guest 세션을 먼저 확인한 뒤, SMB 잠금 감지를 유지하며 아래 후보만 대입합니다.",
    identities: "NULL session · guest · administrator · admin",
    limits: "NULL/Guest 확인 우선 · SMB 잠금 감지 사용 · 최대 2분",
  },
  ldap: accountAudit("LDAP", "admin · administrator · ldap · user", "admin · Password1 · ldap · password"),
  mysql: {
    ...accountAudit("MySQL", "root · mysql · admin", "빈 값 · root · mysql · password"),
    description: "빈 비밀번호를 먼저 확인한 뒤, Nmap 공식 내장 목록의 아래 후보만 제한적으로 대입합니다.",
  },
  postgresql: accountAudit("PostgreSQL", "postgres · admin", "빈 값 · postgres · password · admin"),
  "ms-sql-s": {
    ...accountAudit("MS SQL", "sa · administrator · admin", "빈 값 · sa · password · Password1"),
    description: "SQL 계정의 빈 비밀번호를 먼저 확인한 뒤, Nmap 공식 내장 목록의 아래 후보만 대입합니다.",
  },
  redis: {
    title: "Redis 대입 후보",
    description: "무인증 INFO를 먼저 확인한 뒤, Nmap 공식 내장 비밀번호 목록의 아래 후보만 대입합니다.",
    identityLabel: "사용자 후보",
    identities: "사용자명 없음 (Redis 5 이하) · Redis 6+는 확인된 ACL 사용자",
    secretLabel: "비밀번호 후보 (Nmap 상위 4개)",
    secrets: "redis · password · admin · 123456",
    limits: "무인증 확인 우선 · 최대 2분 · 저속 실행",
  },
  "ms-wbt-server": {
    title: "RDP 대입 후보",
    description: "Hydra가 Nmap 공식 사용자 목록과 계정별 특수 비밀번호 후보를 사용합니다.",
    identityLabel: "사용자 후보 (Nmap 전체 10개)",
    identities: "administrator · admin · guest · user",
    secretLabel: "계정별 비밀번호 후보",
    secrets: "빈 값 · 사용자명과 동일 · 사용자명 역순",
    limits: "동시 연결 2개 · 첫 성공 시 중단 · 도메인 계정 제외",
  },
  snmp: {
    title: "SNMP Community 대입 후보",
    description: "Nmap 공식 snmpcommunities.lst에서 실제 실행 제한에 포함되는 상위 12개입니다.",
    identityLabel: "인증 주체",
    identities: "사용자명 없음",
    secretLabel: "Community 후보 (Nmap 상위 12개)",
    secrets: "public · private · snmpd · mngt · cisco · admin · PUBLIC · PRIVATE · rmonmgmtuicommunity · secret · cascade · ANYCOM",
    limits: "UDP 응답 기반 · 최대 2분 · 재시도 1회",
  },
  imap: accountAudit("IMAP", "postmaster · admin · user · test", "postmaster · admin · password · test"),
  pop3: accountAudit("POP3", "postmaster · admin · user · test", "postmaster · admin · password · test"),
  vnc: {
    title: "VNC 대입 후보",
    description: "전통적인 VNC 인증은 사용자명 없이 Nmap 공식 내장 비밀번호 목록의 아래 후보만 대입합니다.",
    identityLabel: "사용자 후보",
    identities: "사용자명 없음",
    secretLabel: "비밀번호 후보 (Nmap 상위 4개)",
    secrets: "password · vnc · admin · 123456",
    limits: "보안 방식 확인 우선 · 최대 2분 · 저속 실행",
  },
  mongodb: accountAudit("MongoDB", "admin · root · mongodb · user", "admin · root · mongodb · password"),
  rsync: accountAudit("Rsync", "rsync · root · backup · admin", "rsync · root · backup · admin"),
};

const aliases: Record<string, string> = {
  "microsoft-ds": "smb",
  "netbios-ssn": "smb",
  "ssl/ftp": "ftp",
  smtps: "smtp",
  submission: "smtp",
  https: "http",
  "ssl/http": "http",
  "http-proxy": "http",
  ldaps: "ldap",
  imaps: "imap",
  pop3s: "pop3",
};

export const getCredentialAuditProfile = (service = "") => {
  const key = service.toLowerCase();
  return profiles[aliases[key] || key] || accountAudit();
};
