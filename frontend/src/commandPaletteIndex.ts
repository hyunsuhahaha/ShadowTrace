import {isDnsLikeService, isHttpLikeService, isWinrmHttpApi} from "./serviceIntel";

export type ServiceKind = "http" | "dns" | "any";

// Narrow shapes (not the full Service/Target from enumerationModel) so the
// palette only depends on what it actually needs to match and display a
// cross-target service picker.
export type ServiceSummary = {
  id: number; target_id: number; port: number; protocol: string;
  name: string; product: string; scripts: string;
};
export type TargetSummary = {id: number; name: string; ip: string};

export function matchesServiceKind(service: ServiceSummary, kind: ServiceKind): boolean {
  if (kind === "any") return true;
  if (kind === "dns") return isDnsLikeService(service.name);
  return isHttpLikeService(service.name, service.scripts)
    && !isWinrmHttpApi(service.name, service.port, service.product);
}

export type CommandPaletteEntry = {
  id: string;
  route: string;
  subroute?: string;
  anchorId?: string;
  // Which of the current target's services this anchor only renders under —
  // lets the palette offer every matching service across the project when
  // the currently selected one isn't it, instead of just failing silently.
  serviceKind?: ServiceKind;
  label: string;
  detail: string;
  category: string;
  keywords: string[];
};

const navEntries: CommandPaletteEntry[] = [
  { id: "scans", route: "scans", label: "Scan Center", detail: "대상 등록과 서비스 발견", category: "Discover",
    keywords: ["scan", "nmap", "스캔", "포트", "대상 등록"] },
  { id: "enumeration", route: "enumeration", label: "Service Enumeration", detail: "서비스 조사와 명령 실행", category: "Discover",
    keywords: ["enum", "enumeration", "서비스 조사", "명령 실행"] },
  { id: "web", route: "web", label: "Web Testing · Intruder", detail: "HTTP 요청 변형과 응답 비교", category: "Discover",
    keywords: ["web", "http", "웹 테스트"] },
  { id: "exploit-research", route: "exploit-research", label: "Exploit Research", detail: "후보와 PoC 기록", category: "Discover",
    keywords: ["exploit", "poc", "취약점", "익스플로잇", "cve"] },
  { id: "runbooks", route: "runbooks", label: "Runbooks", detail: "방법론과 수행 진행률", category: "Discover",
    keywords: ["runbook", "playbook", "방법론", "체크리스트"] },
  { id: "post-exploitation", route: "post-exploitation", label: "Post-Exploitation", detail: "자격 증명 헌팅", category: "Discover",
    keywords: ["postex", "post exploitation", "자격 증명", "credential hunting"] },
  { id: "hash-cracking", route: "hash-cracking", label: "Hash Cracking", detail: "탈취한 해시 크래킹", category: "Discover",
    keywords: ["hashcat", "john the ripper", "해시 크랙", "크랙"] },
  { id: "tools", route: "tools", label: "Tools", detail: "미탐지·오분류 서비스의 전체 명령 탐색", category: "Discover",
    keywords: ["tools", "catalog", "카탈로그", "전체 명령", "미탐지", "오분류", "111개"] },
  { id: "evidence", route: "evidence", label: "Evidence", detail: "증거 저장과 분류", category: "Document",
    keywords: ["evidence", "screenshot", "증거", "스크린샷"] },
  { id: "reports", route: "reports", label: "Reports", detail: "누락 확인과 보고서 작성", category: "Document",
    keywords: ["report", "보고서"] },
  { id: "directory", route: "directory", label: "AD Information", detail: "관찰 객체와 관계", category: "Workspace",
    keywords: ["active directory", "ad", "도메인", "kerberos"] },
  { id: "sessions", route: "sessions", label: "Sessions", detail: "터널과 PTY 상태", category: "Workspace",
    keywords: ["session", "shell", "tunnel", "터널", "세션", "pty"] },
  { id: "operations", route: "operations", label: "Operations", detail: "검색, 감사, 백업", category: "Workspace",
    keywords: ["search", "audit", "backup", "백업", "감사", "검색"] },
];

const webToolEntries: CommandPaletteEntry[] = [
  { id: "web/request", route: "web", subroute: "request", label: "Repeater", detail: "HTTP 요청 편집과 전송", category: "Web Testing 도구",
    keywords: ["repeater", "request", "리피터", "요청 편집"] },
  { id: "web/intruder", route: "web", subroute: "intruder", label: "Intruder", detail: "요청 변형 자동화와 응답 비교", category: "Web Testing 도구",
    keywords: ["intruder", "brute force", "fuzz", "퍼징", "인트루더"] },
  { id: "web/sqli", route: "web", subroute: "sqli", label: "SQLi 참고", detail: "SQL Injection 페이로드 참고자료", category: "Web Testing 도구",
    keywords: ["sql injection", "sqli", "sqlmap", "sql", "인젝션"] },
  { id: "web/lfi", route: "web", subroute: "lfi", label: "LFI 참고", detail: "Local File Inclusion 페이로드 참고자료", category: "Web Testing 도구",
    keywords: ["lfi", "local file inclusion", "path traversal", "파일 인클루전", "디렉토리 순회"] },
  { id: "web/log4shell", route: "web", subroute: "log4shell", label: "Log4Shell 참고", detail: "CVE-2021-44228 JNDI 페이로드 참고자료", category: "Web Testing 도구",
    keywords: ["log4shell", "log4j", "jndi", "cve-2021-44228"] },
  { id: "web/proxy", route: "web", subroute: "proxy", label: "Proxy", detail: "업스트림 프록시 설정", category: "Web Testing 도구",
    keywords: ["proxy", "burp", "프록시", "업스트림"] },
];

const enumerationToolEntries: CommandPaletteEntry[] = [
  { id: "enumeration/dir-fuzz", route: "enumeration", anchorId: "fuzz-heading",
    serviceKind: "http",
    label: "디렉터리·파일 퍼징 (feroxbuster)", detail: "웹 서비스 선택 후 페이지 하단에 표시 · gobuster dir 대체",
    category: "Service Enumeration 도구",
    keywords: ["gobuster", "gobuster dir", "dirbuster", "dirsearch", "feroxbuster", "디렉토리 브루트포스", "디렉터리 퍼징", "파일 탐색"] },
  { id: "enumeration/vhost-fuzz", route: "enumeration", anchorId: "vhost-heading",
    serviceKind: "http",
    label: "가상 호스트 퍼징 (ffuf)", detail: "웹 서비스 선택 후 페이지 하단에 표시",
    category: "Service Enumeration 도구",
    keywords: ["gobuster vhost", "vhost", "virtual host", "ffuf"] },
  { id: "enumeration/param-fuzz", route: "enumeration", anchorId: "param-fuzz-heading",
    serviceKind: "http",
    label: "GET 파라미터 퍼징 (ffuf)", detail: "웹 서비스 선택 후 페이지 하단에 표시",
    category: "Service Enumeration 도구",
    keywords: ["param fuzz", "파라미터 퍼징", "ffuf", "gobuster fuzz"] },
  { id: "enumeration/dns-subdomain", route: "enumeration", anchorId: "dns-subdomain-heading",
    serviceKind: "dns",
    label: "서브도메인 브루트포스 (gobuster dns)", detail: "DNS 서비스 선택 후 페이지 하단에 표시 · gobuster dns 대체",
    category: "Service Enumeration 도구",
    keywords: ["gobuster dns", "dns bruteforce", "dns enum", "서브도메인", "subdomain", "dns 브루트포스"] },
  { id: "enumeration/link-extract", route: "enumeration", anchorId: "link-extract-heading",
    serviceKind: "http",
    label: "페이지 링크 추출", detail: "웹 서비스 선택 후 페이지 하단에 표시",
    category: "Service Enumeration 도구",
    keywords: ["link extract", "href", "링크 추출", "크롤링"] },
  { id: "enumeration/responder", route: "enumeration", anchorId: "responder-heading",
    serviceKind: "any",
    label: "Responder 리스너", detail: "서비스 선택 후 페이지 하단에 표시 · 데스크톱 터미널에서 실행",
    category: "Service Enumeration 도구",
    keywords: ["responder", "llmnr", "nbt-ns", "poisoning", "ntlm", "리스너", "포이즈닝"] },
];

export const commandPaletteIndex: CommandPaletteEntry[] = [
  ...navEntries, ...webToolEntries, ...enumerationToolEntries,
];

const normalize = (value: string) => value.toLowerCase();

export const searchCommandPalette = (query: string): CommandPaletteEntry[] => {
  const q = normalize(query.trim());
  if (!q) return [];
  return commandPaletteIndex.filter((entry) =>
    [entry.label, entry.detail, entry.category, ...entry.keywords]
      .some((field) => normalize(field).includes(q)),
  );
};
