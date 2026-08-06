export type ServiceIntelInput = {
  name: string;
  product: string;
  version: string;
  extra_info: string;
  scripts: string;
};

export type ScriptObservation = { id: string; output: string };
export type InvestigationCommand = {
  id: string;
  name: string;
  risk: string;
  execution_mode: string;
};

export type ExecutionSummary = {
  tone: "success" | "warning" | "danger" | "neutral";
  title: string;
  detail: string;
};
export type SmbShare = {name: string; type: string; comment: string};

export function parseSmbShares(output = ""): SmbShare[] {
  const shares: SmbShare[] = [];
  for (const line of output.split(/\r?\n/)) {
    const match = line.match(/^\s*(\S+)\s+(Disk|IPC|Printer)\s*(.*)$/i);
    if (!match || match[1].toLowerCase() === "sharename") continue;
    shares.push({name: match[1], type: match[2], comment: match[3].trim()});
  }
  return shares;
}

export type SmbShareAccess = {anonymous: string; currentUser: string};

// Parses nmap's `smb-enum-shares` NSE script output, which — unlike a plain
// `smbclient -L` listing — actually probes and reports each share's real
// access level instead of just its name/type/comment. Each share gets its
// own indented block under a "\\host\Share:" header; nmap prefixes every
// line of script output with "|" (and the block's last line with "|_"),
// so that prefix is stripped before the key: value lines are matched.
export function parseSmbEnumSharesAccess(output = ""): Record<string, SmbShareAccess> {
  const result: Record<string, SmbShareAccess> = {};
  let current = "";
  for (const rawLine of output.split(/\r?\n/)) {
    const line = rawLine.replace(/^\|_?/, "");
    const header = line.match(/^\s*\\\\[^\\]+\\(.+?):\s*$/);
    if (header) { current = header[1]; continue; }
    if (!current) continue;
    const anonymous = line.match(/^\s*Anonymous access:\s*(.+?)\s*$/i);
    if (anonymous) {
      result[current] = {...result[current], anonymous: anonymous[1], currentUser: result[current]?.currentUser ?? ""};
      continue;
    }
    const currentUser = line.match(/^\s*Current user access:\s*(.+?)\s*$/i);
    if (currentUser) {
      result[current] = {...result[current], currentUser: currentUser[1], anonymous: result[current]?.anonymous ?? ""};
    }
  }
  return result;
}

export type SmbFile = {path: string; size: string};

// Parses `smbclient -c 'recurse ON;ls'` output: a root-level block, then one
// `\Dir\Sub` header line per directory followed by its fixed-width entries.
export function parseSmbFiles(output = ""): SmbFile[] {
  const files: SmbFile[] = [];
  let currentDir = "";
  for (const line of output.split(/\r?\n/)) {
    const header = line.match(/^\\(.+)$/);
    if (header) {
      currentDir = header[1].replace(/\\/g, "/");
      continue;
    }
    const entry = line.match(
      /^\s{2,}(\S.*?)\s{2,}([A-Za-z]+)\s+(\d+)\s+\S+\s+\S+\s+\d+\s+[\d:]+\s+\d{4}\s*$/,
    );
    if (!entry) continue;
    const [, name, attrs, size] = entry;
    if (name === "." || name === ".." || /d/i.test(attrs)) continue;
    files.push({path: currentDir ? `${currentDir}/${name}` : name, size});
  }
  return files;
}

export type FuzzResult = {
  path: string; status: number; length: number; words: number; lines: number;
};

// feroxbuster --json --silent emits one JSON object per line; only "response"
// entries are discovered paths, everything else is progress/state noise.
export function parseFeroxbusterResults(output = ""): FuzzResult[] {
  const results: FuzzResult[] = [];
  for (const line of output.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("{")) continue;
    try {
      const row = JSON.parse(trimmed);
      if (row.type !== "response") continue;
      results.push({
        path: row.path ?? row.url ?? "", status: row.status ?? 0,
        length: row.content_length ?? 0, words: row.word_count ?? 0,
        lines: row.line_count ?? 0,
      });
    } catch {
      continue;
    }
  }
  return results;
}

export type VhostResult = { name: string; status: number; size: number };

// ffuf's default (non-JSON) output prints one line per match:
// "admin                   [Status: 200, Size: 154, Words: 10, Lines: 5, ...]"
// The FUZZ word itself, not the full hostname, so callers reattach the
// domain suffix that was fuzzed against.
export function parseFfufVhostResults(output = ""): VhostResult[] {
  const results: VhostResult[] = [];
  const pattern = /^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)/;
  for (const line of output.split(/\r?\n/)) {
    const match = line.match(pattern);
    if (!match) continue;
    results.push({ name: match[1], status: Number(match[2]), size: Number(match[3]) });
  }
  return results;
}

export type DnsSubdomainResult = { name: string; ip?: string };

// gobuster dns -i prints "Found: sub.example.com [1.2.3.4]" (or without the
// bracketed IP when a record resolves to something -i doesn't summarize).
export function parseGobusterDnsResults(output = ""): DnsSubdomainResult[] {
  const results: DnsSubdomainResult[] = [];
  const pattern = /^Found:\s*(\S+?)(?:\s*\[(.+?)\])?\s*$/;
  for (const line of output.split(/\r?\n/)) {
    const match = line.match(pattern);
    if (match) results.push({ name: match[1], ip: match[2] });
  }
  return results;
}

// kerbrute userenum prints "[+] VALID USERNAME:\t user@REALM" to stdout for
// every account that answers Kerberos pre-auth; everything else is log noise.
export function parseKerbruteResults(output = ""): string[] {
  const usernames: string[] = [];
  for (const line of output.split(/\r?\n/)) {
    const match = line.match(/\[\+\]\s*VALID USERNAME:\s*(\S+)/);
    if (match) usernames.push(match[1]);
  }
  return usernames;
}

export type SecretsdumpHash = {
  username: string; rid: string; lmhash: string; nthash: string;
};

// impacket-secretsdump prints one "user:rid:lmhash:nthash:::" line per
// dumped account (DCSync via -just-dc), interleaved with banner/progress
// text that never matches this exact shape.
export function parseSecretsdumpHashes(output = ""): SecretsdumpHash[] {
  const results: SecretsdumpHash[] = [];
  for (const line of output.split(/\r?\n/)) {
    const match = line.trim().match(
      /^([^\s:]+):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::$/,
    );
    if (match) {
      results.push({
        username: match[1], rid: match[2], lmhash: match[3], nthash: match[4],
      });
    }
  }
  return results;
}

// NetExec prints "[+] domain\username:password" for every account a spray
// (or single credential check) validates against; everything else — login
// failures, connection banners — never starts a line with "[+]".
export function parseNetexecSprayHits(output = ""): string[] {
  const hits: string[] = [];
  for (const line of output.split(/\r?\n/)) {
    const match = line.match(/\[\+\]\s*(\S+)/);
    if (match) hits.push(match[1]);
  }
  return hits;
}

export function keepSelectedService<T extends {id: number}>(
  current: number | undefined,
  services: T[] | undefined,
) {
  return current && services?.some((service) => service.id === current)
    ? current
    : services?.[0]?.id;
}

export type ServiceNavRequest = {targetId: number; serviceId: number; anchorId?: string};
export type ServiceNavResult =
  | {action: "none"}
  | {action: "pending"}
  | {action: "apply"; serviceId: number; anchorId?: string};

// A command palette pick can name a target this page didn't start on, and
// switching target is asynchronous (the services list for it has to load
// before the requested service can actually be selected) — this is the
// pure decision the target/service-selection effect makes on every tick
// while that handoff is in flight, kept separate from the effect itself so
// the three-way branch (wrong target yet / right target but not loaded yet
// / ready) is unit-testable without mounting the page.
export function reconcileServiceNav(
  nav: ServiceNavRequest | undefined,
  targetId: number | undefined,
  services: {id: number}[] | undefined,
): ServiceNavResult {
  if (!nav) return {action: "none"};
  if (nav.targetId !== targetId) return {action: "pending"};
  if (!services?.some((service) => service.id === nav.serviceId)) return {action: "pending"};
  return {action: "apply", serviceId: nav.serviceId, anchorId: nav.anchorId};
}

export function summarizeExecutionResult(
  templateId: string,
  status: string,
  stdout = "",
  stderr = "",
  command = "",
): ExecutionSummary {
  if (["failed", "error", "stopped", "no_response"].includes(status))
    return {
      tone: "danger",
      title: status === "no_response" ? "대상 응답을 확인하지 못했습니다" : "조사가 완료되지 않았습니다",
      detail: stderr.trim() || "오류 출력과 실행 명령을 확인한 뒤 다시 실행하세요.",
    };
  if (status !== "completed")
    return {tone: "neutral", title: "조사 실행 중", detail: "결과를 기다리고 있습니다."};
  if (templateId === "smb-enum") {
    const port = command.match(/(?:^|\s)-p\s*(\d+)/)?.[1];
    if (port && !["139", "445"].includes(port))
      return {
        tone: "danger",
        title: `SMB가 아닌 ${port}/tcp에서 실행된 무효한 결과입니다`,
        detail: "139/tcp 또는 445/tcp SMB 서비스를 선택하고 다시 실행하세요.",
      };
    if (parseSmbShares(stdout).length)
      return {
        tone: "success",
        title: "SMB 공유 목록을 가져왔습니다",
        detail: "아래 출력에서 Sharename, Type과 Comment를 확인하세요. 뒤쪽 SMB1 workgroup 오류는 공유 목록 수집 성공과 별개일 수 있습니다.",
      };
    if (/NT_STATUS_(?:ACCESS_DENIED|LOGON_FAILURE)/i.test(`${stdout}\n${stderr}`))
      return {
        tone: "warning",
        title: "서버가 익명 공유 열거를 거부했습니다",
        detail: "공유가 없다는 의미가 아니라 익명 세션에 목록 조회 권한이 없다는 의미입니다.",
      };
    return {
      tone: "warning",
      title: "공유 목록이 반환되지 않았습니다",
      detail: "연결 오류와 대상 포트를 확인하세요. 필요하면 445/tcp에서 다시 실행하거나 검토한 계정으로 수동 접속하세요.",
    };
  }
  if (templateId === "smb-null-session") {
    if (/user:\[[^\]]+\]\s+rid:\[/i.test(stdout))
      return {
        tone: "success",
        title: "익명 사용자 열거가 허용됩니다",
        detail: "아래 출력에서 계정명과 RID를 검토하세요.",
      };
    if (/NT_STATUS_(?:ACCESS_DENIED|LOGON_FAILURE)/i.test(`${stdout}\n${stderr}`))
      return {
        tone: "warning",
        title: "서버가 익명 사용자 열거를 거부했습니다",
        detail: "사용자가 없다는 의미가 아니라 Null 세션에 열거 권한이 없다는 의미입니다.",
      };
    return {
      tone: "warning",
      title: "사용자 정보가 반환되지 않았습니다",
      detail: "Null 세션 제한 여부와 RPC 오류 출력을 확인하세요.",
    };
  }
  if (templateId === "http-param-fuzz") {
    const results = parseFfufVhostResults(stdout);
    if (!results.length)
      return {
        tone: "warning",
        title: "반응한 파라미터가 없습니다",
        detail: "-mc all 옵션이라 매치 0건은 필터링이 아니라 대상이 요청 자체에 응답하지 않았다는 뜻입니다. 경로와 워드리스트를 확인하세요.",
      };
    const sizes = new Set(results.map((item) => item.size));
    return {
      tone: "success",
      title: `${results.length}개 파라미터가 응답했습니다`,
      detail: sizes.size === 1
        ? "모든 응답 크기가 동일합니다 — -mc all은 모든 상태 코드를 매치로 처리하므로 이 목록이 곧 실제 파라미터는 아닙니다. 서비스 화면의 결과 표에서 크기(Size)가 다른 행을 찾아보세요."
        : "서비스 화면의 결과 표에서 크기(Size)가 다른 행이 실제 파라미터일 가능성이 높습니다.",
    };
  }
  return {
    tone: "success",
    title: "명령 실행이 완료됐습니다",
    detail: stdout.trim() ? "저장된 출력을 검토하세요." : "명령은 성공했지만 표준 출력이 없습니다.",
  };
}

export function parseScriptObservations(value: string): ScriptObservation[] {
  try {
    const parsed = JSON.parse(value || "[]");
    return Array.isArray(parsed)
      ? parsed.filter((item) =>
          item && typeof item.id === "string" && typeof item.output === "string")
      : [];
  } catch {
    return [];
  }
}

const HTTP_SERVICE_NAMES = ["http", "https", "http-proxy", "ssl/http"];

// nmap's -sV service-name guess can be wrong on uncommon ports (e.g. HTB
// "Unified"'s UniFi controller on 8443 gets fingerprinted as
// "nagios-nsca"), which used to hide every HTTP-only panel (directory
// fuzzing, the "open site" link, …) even though the http-* NSE scripts it
// ran alongside that guess plainly found a real HTTP(S) response. Trust
// those script IDs over the possibly-wrong name.
export function isHttpLikeService(name: string, scripts = ""): boolean {
  if (HTTP_SERVICE_NAMES.includes(name.toLowerCase())) return true;
  return parseScriptObservations(scripts).some((item) => item.id.startsWith("http-"));
}

const WINRM_SERVICE_NAMES = ["wsman", "wsmans", "winrm"];
const WINRM_PORTS = [5985, 5986, 47001];

// WinRM's listener runs on top of HTTP.sys, so nmap's -sV guess frequently
// names it "http" with product "Microsoft HTTPAPI httpd" instead of "wsman" —
// that misclassification hides it from every WinRM-aware panel (netexec
// credential check, evil-winrm launch) while the generic "open site" link
// still shows, pointing at an endpoint that only ever answers WS-Management
// SOAP requests and 404s on a plain browser GET.
export function isWinrmHttpApi(name: string, port: number, product = ""): boolean {
  if (WINRM_SERVICE_NAMES.includes(name.toLowerCase())) return true;
  if (WINRM_PORTS.includes(port)) return true;
  return /microsoft httpapi|windows remote management/i.test(product);
}

const DNS_SERVICE_NAMES = ["domain", "dns"];

export function isDnsLikeService(name: string): boolean {
  return DNS_SERVICE_NAMES.includes(name.toLowerCase());
}

// A directory fuzz with no -x only ever requests bare wordlist entries, so
// "login" never becomes "login.php" unless the operator remembers to type
// an extension in first — this is the default that request should have had
// all along, not something to rediscover per-target. IIS/.NET boxes serve
// .aspx by default; everything else defaults to the much more common LAMP
// stack. Always editable/clearable in the UI, this just picks the starting
// point.
export function defaultFuzzExtensions(osGuess = ""): string {
  return /windows/i.test(osGuess) ? "aspx,asp,txt,html" : "php,html,txt";
}

export function missingServiceFacts(service: ServiceIntelInput) {
  return [
    !service.product && "제품",
    !service.version && "정확한 버전",
    !service.extra_info && "추가 배너 정보",
  ].filter(Boolean) as string[];
}

export function rankInvestigationCommands(
  fact: string,
  commands: InvestigationCommand[],
) {
  const unsafe = /brute|audit|password|login|null-session|anonymous|empty/i;
  const priority = fact === "추가 배너 정보"
    ? [/banner/i, /info|syst|headers|whatweb|enum|nsid|ntlm/i, /version/i]
    : [/version-trace/i, /version/i, /info|syst|banner|headers|whatweb|enum|nsid|ntlm/i];
  return commands
    .filter((command) =>
      command.execution_mode === "captured" &&
      command.risk !== "high" &&
      !unsafe.test(command.id))
    .map((command, index) => ({
      command,
      index,
      score: priority.findIndex((pattern) =>
        pattern.test(`${command.id} ${command.name}`)),
    }))
    .sort((left, right) =>
      (left.score < 0 ? 99 : left.score) -
        (right.score < 0 ? 99 : right.score) ||
      left.index - right.index)
    .map(({ command }) => command);
}

export function remainingInvestigationCommands<T extends InvestigationCommand>(
  commands: T[],
  facts: {
    hostname: string;
    osGuess: string;
    product: string;
    version: string;
    completedTemplateIds: Set<string>;
  },
) {
  return commands.filter((command) => {
    if (command.id === "target-hostname-identity") return !facts.hostname;
    if (command.id === "target-os-identity") return !facts.osGuess;
    if (["service-version", "service-version-udp"].includes(command.id))
      return !(facts.product && facts.version);
    return !facts.completedTemplateIds.has(command.id);
  });
}
