export type CommandPaletteEntry = {
  id: string;
  route: string;
  subroute?: string;
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

export const commandPaletteIndex: CommandPaletteEntry[] = [...navEntries, ...webToolEntries];

const normalize = (value: string) => value.toLowerCase();

export const searchCommandPalette = (query: string): CommandPaletteEntry[] => {
  const q = normalize(query.trim());
  if (!q) return [];
  return commandPaletteIndex.filter((entry) =>
    [entry.label, entry.detail, entry.category, ...entry.keywords]
      .some((field) => normalize(field).includes(q)),
  );
};
